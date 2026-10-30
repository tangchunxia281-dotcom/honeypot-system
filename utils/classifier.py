"""Optional CPU-model adapter: bounded async work, independent evidence decisions.

The external model and weights are supplied separately. This module does not
mislabel a rule fallback as model inference and never changes captured rule scores.
"""
import configparser
import hashlib
import ipaddress
import json
import os
import queue
import sqlite3
import threading
import time
from contextlib import closing
from pathlib import Path
from urllib.parse import urlsplit
import requests
from investigation_core.store import clean

ROOT=Path(__file__).resolve().parents[1]
def endpoint(value):
    try:
        u=urlsplit(value)
        valid=u.scheme in ('http','https') and (u.hostname=='localhost' or ipaddress.ip_address(u.hostname).is_loopback) and not u.username and not u.password and not u.query and not u.fragment and u.path in ('/api/v1/detect','/detect') and 0<(u.port or 80)<65536
    except (ValueError,TypeError):valid=False
    if not valid:raise ValueError('classifier_local_endpoint_required')
    return value.rstrip('/')
def normalize_result(data):
    if not isinstance(data,dict) or type(data.get('is_attack'))is not bool:raise ValueError('classifier_invalid_output')
    label=data.get('attack_type');prob=data.get('attack_prob');points=data.get('ai_points',0)
    if not isinstance(label,str) or not label or len(label)>60 or type(prob)not in(int,float) or not 0<=prob<=1 or type(points)not in(int,float) or not 0<=points<=25:raise ValueError('classifier_invalid_output')
    if 'high_risk' in data and type(data['high_risk'])is not bool:raise ValueError('classifier_invalid_output')
    reasons=data.get('reasons',[])
    if not isinstance(reasons,list):reasons=[str(reasons)]
    return {'attack_type':clean(label,60),'is_attack':data['is_attack'],'attack_prob':prob,'ai_points':int(points),
            'effective_points':int(points)if data['is_attack'] and label.lower()!='normal' else 0,
            'high_risk':data.get('high_risk',False),'reasons':[clean(str(x),240)for x in reasons[:6]],'model_label':clean(str(data.get('model_label',label)),80)}
def config(path=None):
    p=configparser.ConfigParser(interpolation=None);p.read(path or os.environ.get('HONEYPOT_CLASSIFIER_CONFIG',ROOT/'classifier.ini'),encoding='utf-8-sig')
    return {'enabled':p.getboolean('classifier','enabled',fallback=False),'url':endpoint(p.get('classifier','url',fallback='http://127.0.0.1:8003/api/v1/detect')),'timeout':max(.1,min(5,p.getfloat('classifier','timeout',fallback=1)))}
class Classifier:
    def __init__(self,path,settings=None):
        self.path=Path(path);self.path.parent.mkdir(parents=True,exist_ok=True);self.settings=settings or config
        self.queue=queue.Queue(32);self.lock=threading.Lock();self.pending=set();self.started=False;self.last_error='';self.cooldown=0;self.failures=0;self.skipped=0
        with closing(self.connect()) as c,c:c.execute('CREATE TABLE IF NOT EXISTS classifications(id TEXT PRIMARY KEY,identity TEXT,status TEXT,result TEXT,reason TEXT,latency_ms INTEGER,created REAL)')
    def connect(self):
        c=sqlite3.connect(self.path,timeout=1);c.row_factory=sqlite3.Row;return c
    @staticmethod
    def key(snapshot):return hashlib.sha256(json.dumps({k:snapshot.get(k)for k in ('source','raw_request_id','request_time','ip','session_id')},sort_keys=True).encode()).hexdigest()
    def submit(self,snapshot):
        settings=self.settings()
        if not settings['enabled']:return 'disabled'
        key=self.key(snapshot)
        with self.lock:
            if self.cooldown>time.monotonic():self.skipped+=1;return 'cooldown'
            if key in self.pending:return 'duplicate'
            try:self.queue.put_nowait((key,dict(snapshot),settings));self.pending.add(key)
            except queue.Full:self.skipped+=1;return 'queue_full'
            if not self.started:self.started=True;threading.Thread(target=self.work,daemon=True,name='request-classifier').start()
        return 'queued'
    def work(self):
        while True:
            key,snapshot,settings=self.queue.get();start=time.monotonic();result={};reason='';status='completed'
            try:
                payload={k:clean(str(snapshot.get(k,'')),5000)for k in ('path','query','body','method','user_agent','source','ip','session_id')}
                with requests.Session() as client:
                    client.trust_env=False
                    with client.post(settings['url'],json=payload,timeout=(min(1,settings['timeout']),settings['timeout']),allow_redirects=False,stream=True) as response:
                        if response.status_code!=200:raise ValueError('classifier_http_error')
                        raw=bytearray()
                        for chunk in response.iter_content(1):
                            raw.extend(chunk)
                            if len(raw)>16384:raise ValueError('classifier_response_too_large')
                            if time.monotonic()-start>settings['timeout']:raise TimeoutError()
                        result=normalize_result(json.loads(raw))
                result['suggested_score']=min(100,int(snapshot.get('rule_score',0))+result['effective_points'])
                self.failures=0
            except Exception as error:
                status='failed';reason='timeout'if isinstance(error,(TimeoutError,requests.Timeout)) else 'service_unavailable'if isinstance(error,requests.RequestException)else str(error)[:80]
                self.last_error=reason;self.failures+=1
                if self.failures>=3:self.cooldown=time.monotonic()+30
            try:
                with closing(self.connect()) as c,c:
                    c.execute('INSERT OR REPLACE INTO classifications VALUES(?,?,?,?,?,?,?)',(key,json.dumps({k:snapshot.get(k)for k in ('source','raw_request_id','request_time','ip','session_id')},sort_keys=True),status,json.dumps(result,ensure_ascii=False),reason,round((time.monotonic()-start)*1000),time.time()))
                    c.execute('DELETE FROM classifications WHERE created<?',(time.time()-30*86400,))
                    c.execute('DELETE FROM classifications WHERE id NOT IN (SELECT id FROM classifications ORDER BY created DESC LIMIT 10000)')
            except (sqlite3.Error,OSError):
                self.last_error='storage_unavailable';self.skipped+=1
            finally:
                with self.lock:self.pending.discard(key)
                self.queue.task_done()
    def get(self,snapshot):
        with closing(self.connect()) as c:r=c.execute('SELECT * FROM classifications WHERE id=?',(self.key(snapshot),)).fetchone()
        if not r:return {'status':'queued'}if self.key(snapshot)in self.pending else None
        value=dict(r);value['result']=json.loads(value['result']);value.pop('identity',None);return value
    def status(self):
        with closing(self.connect()) as c:counts={r[0]:r[1]for r in c.execute('SELECT status,COUNT(*) FROM classifications GROUP BY status')}
        return dict(counts=counts,pending=len(self.pending),skipped=self.skipped,last_error=self.last_error,cooldown_seconds=max(0,round(self.cooldown-time.monotonic())),**self.settings())

_client=None;_lock=threading.Lock()
def client():
    global _client
    with _lock:
        if _client is None:_client=Classifier(os.environ.get('HONEYPOT_CLASSIFIER_DB',ROOT/'database/classifier.db'))
        return _client
def submit(snapshot):
    if not config()['enabled']:return 'disabled'
    return client().submit(snapshot)
