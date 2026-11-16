"""Durable central queue. No client-controlled endpoint, model or host actions."""
import argparse
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import sqlite3
import threading
import time
from contextlib import closing
from pathlib import Path
from urllib.parse import urlsplit
import requests
from flask import Flask,request,jsonify

TASKS={'probe':3,'ssh_reply':3,'web_reply':3,'log_chat':2,'general_chat':2,'active_plan':2,'active_story':1,'web_detect':1,'log_report':0}


class Gateway:
    def __init__(self,path,model,clients,url='http://127.0.0.1:11434',capacity=1,queue_limit=64,transport=None,provider='local',api_key=''):
        if not isinstance(model,str) or not model.strip() or len(model)>160 or not isinstance(clients,dict) or not 1<=len(clients)<=20:raise ValueError('gateway_configuration_invalid')
        for name,policy in clients.items():
            if not isinstance(name,str) or not 1<=len(name)<=64 or not isinstance(policy,dict) or not isinstance(policy.get('token_hash'),str) or len(policy['token_hash'])!=64 or any(ch not in '0123456789abcdef' for ch in policy['token_hash']):raise ValueError('gateway_client_configuration_invalid')
        self.path=Path(path);self.path.parent.mkdir(parents=True,exist_ok=True)
        target=urlsplit(url)
        is_loopback=target.hostname in ('127.0.0.1','localhost','::1')
        if target.scheme not in ('http','https') or (target.scheme=='http' and not is_loopback) or target.path not in ('','/') or target.username or target.password:raise ValueError('gateway model endpoint must be loopback or https')
        if provider not in ('local','deepseek'):raise ValueError('gateway_configuration_invalid')
        if provider=='deepseek' and (target.scheme!='https' or not re.fullmatch(r'sk-[A-Za-z0-9]{20,}',api_key or '')):raise ValueError('gateway_configuration_invalid')
        self.provider=provider;self.api_key=api_key
        self.model=model;self.url=url.rstrip('/');self.clients=clients;self.capacity=max(1,min(2,capacity));self.queue_limit=max(4,min(128,queue_limit));self.transport=transport or self.infer
        self.stop=threading.Event();self.wake=threading.Event();self.threads=[]
        self.health_cache={'until':0,'value':{}};self.health_lock=threading.Lock()
        with closing(self.connect()) as c:c.executescript('''
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY,client TEXT,request_id TEXT,task TEXT,priority INTEGER,
              status TEXT,created REAL,started REAL,finished REAL,deadline REAL,lease TEXT,cancel_requested INTEGER,
              input_json TEXT,result_json TEXT,reason TEXT,UNIQUE(client,request_id));
            CREATE INDEX IF NOT EXISTS jobs_queue ON jobs(status,priority,created);
            CREATE INDEX IF NOT EXISTS jobs_client ON jobs(client,created);
            CREATE TABLE IF NOT EXISTS gateway_state(id INTEGER PRIMARY KEY,failures INTEGER,blocked_until REAL,last_success REAL);
            INSERT OR IGNORE INTO gateway_state VALUES(1,0,0,0);
        ''')
        try:os.chmod(self.path,0o600)
        except OSError:pass

    def connect(self):
        c=sqlite3.connect(self.path,timeout=1);c.row_factory=sqlite3.Row;c.execute('PRAGMA busy_timeout=1000');return c

    def authenticate(self,token):
        if not token or len(token)>256:return None
        digest=hashlib.sha256(token.encode()).hexdigest()
        for name,policy in self.clients.items():
            if hmac.compare_digest(digest,policy['token_hash']):return name
        return None

    def enqueue(self,client,payload):
        if not isinstance(payload,dict) or set(payload)-{'request_id','task','messages','schema','options'}:raise ValueError('payload_invalid')
        identifier=payload.get('request_id');task=payload.get('task');messages=payload.get('messages')
        if not isinstance(identifier,str) or len(identifier)!=24 or any(c not in '0123456789abcdef' for c in identifier) or task not in TASKS:raise ValueError('task_invalid')
        if task not in self.clients[client].get('tasks',list(TASKS)):raise PermissionError('task_forbidden')
        if not isinstance(messages,list) or not 1<=len(messages)<=12:raise ValueError('messages_invalid')
        for m in messages:
            if not isinstance(m,dict) or set(m)!={'role','content'} or m['role'] not in ('system','user','assistant') or not isinstance(m['content'],str):raise ValueError('messages_invalid')
        schema=payload.get('schema');options=payload.get('options',{})
        if schema is not None and (not isinstance(schema,dict) or len(json.dumps(schema))>6000 or '$ref' in json.dumps(schema)):raise ValueError('schema_invalid')
        if not isinstance(options,dict) or set(options)-{'timeout','num_predict','num_ctx','think'}:raise ValueError('options_invalid')
        for name,low,high in (('timeout',5,30),('num_predict',64,1024),('num_ctx',512,8192)):
            v=options.get(name,20 if name=='timeout' else 512 if name=='num_predict' else 4096)
            if type(v) is not int or not low<=v<=high:raise ValueError('options_invalid')
        if 'think' in options and type(options['think']) is not bool:raise ValueError('options_invalid')
        raw=json.dumps(payload,ensure_ascii=False)
        if len(raw.encode())>24576:raise ValueError('input_too_large')
        now=time.time();policy=self.clients[client]
        with closing(self.connect()) as c,c:
            c.execute('BEGIN IMMEDIATE');self.cleanup(c,now)
            old=c.execute('SELECT id,status FROM jobs WHERE client=? AND request_id=?',(client,identifier)).fetchone()
            if old:return dict(old)
            if c.execute("SELECT COUNT(*) FROM jobs WHERE status IN ('queued','running')").fetchone()[0]>=self.queue_limit:raise OverflowError('gateway_queue_full')
            if c.execute("SELECT COUNT(*) FROM jobs WHERE client=? AND status IN ('queued','running')",(client,)).fetchone()[0]>=policy.get('max_pending',4):raise OverflowError('gateway_client_pending')
            if c.execute('SELECT COUNT(*) FROM jobs WHERE client=? AND created>?',(client,now-60)).fetchone()[0]>=policy.get('per_minute',30):raise OverflowError('gateway_client_budget')
            job=secrets.token_hex(12);c.execute('INSERT INTO jobs VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',(job,client,identifier,task,TASKS[task],'queued',now,0,0,now+120,'',0,raw,'{}',''))
        self.wake.set();return {'id':job,'status':'queued'}

    @staticmethod
    def cleanup(c,now):
        c.execute("UPDATE jobs SET status='fallback',reason='gateway_timeout',input_json='',finished=? WHERE status='queued' AND deadline<?",(now,now))
        # Expired workers retain capacity through their HTTP deadline. After the
        # bounded lease, stale results cannot be published by a restarted worker.
        c.execute("UPDATE jobs SET status='fallback',reason='gateway_worker_interrupted',input_json='',finished=? WHERE status='running' AND started<?",(now,now-75))
        c.execute("DELETE FROM jobs WHERE status NOT IN ('queued','running') AND finished<?",(now-3600,))

    def claim(self):
        now=time.time()
        with closing(self.connect()) as c,c:
            c.execute('BEGIN IMMEDIATE');self.cleanup(c,now)
            if c.execute("SELECT COUNT(*) FROM jobs WHERE status='running'").fetchone()[0]>=self.capacity:return None
            blocked=c.execute('SELECT blocked_until FROM gateway_state WHERE id=1').fetchone()[0]>now
            row=c.execute('''SELECT * FROM jobs j WHERE status='queued' AND (?=0 OR task='probe') AND NOT EXISTS
                (SELECT 1 FROM jobs a WHERE a.client=j.client AND a.status='running')
                ORDER BY priority+MIN(4,CAST((?-created)/15 AS INTEGER)) DESC,
                  (SELECT COALESCE(MAX(started),0) FROM jobs h WHERE h.client=j.client),created LIMIT 1''',(int(blocked),now)).fetchone()
            if not row:return None
            lease=secrets.token_hex(12);c.execute("UPDATE jobs SET status='running',started=?,lease=? WHERE id=?",(now,lease,row['id']))
            return {**dict(row),'lease':lease,'payload':json.loads(row['input_json'])}

    def finish(self,job,data,reason=''):
        with closing(self.connect()) as c,c:
            c.execute('BEGIN IMMEDIATE')
            row=c.execute('SELECT status,lease,cancel_requested FROM jobs WHERE id=?',(job['id'],)).fetchone()
            if not row or row['status']!='running' or row['lease']!=job['lease']:return False
            status='cancelled' if row['cancel_requested'] else 'fallback' if reason else 'completed'
            c.execute('UPDATE jobs SET status=?,finished=?,input_json=?,result_json=?,reason=? WHERE id=?',
                (status,time.time(),'',json.dumps(data,ensure_ascii=False) if status=='completed' else '{}',reason,job['id']))
            if reason in ('model_unavailable','model_http_error'):
                c.execute('UPDATE gateway_state SET failures=failures+1 WHERE id=1')
                if c.execute('SELECT failures FROM gateway_state').fetchone()[0]>=3:c.execute('UPDATE gateway_state SET blocked_until=?',(time.time()+30,))
            elif not reason:c.execute('UPDATE gateway_state SET failures=0,blocked_until=0,last_success=?',(time.time(),))
        return True

    def get(self,identifier,client):
        with closing(self.connect()) as c:
            r=c.execute('SELECT id,task,status,created,started,finished,reason,result_json,cancel_requested FROM jobs WHERE id=? AND client=?',(identifier,client)).fetchone()
            if not r:return None
            out=dict(r);out['result']=json.loads(out.pop('result_json'));out['status']='cancelled' if out['cancel_requested'] else out['status'];out['queue_seconds']=max(0,(out['started'] or time.time())-out['created']);return out

    def cancel(self,identifier,client):
        with closing(self.connect()) as c,c:
            r=c.execute('SELECT status FROM jobs WHERE id=? AND client=?',(identifier,client)).fetchone()
            if not r:return False
            if r['status']=='queued':c.execute("UPDATE jobs SET status='cancelled',input_json='',finished=? WHERE id=?",(time.time(),identifier))
            elif r['status']=='running':c.execute('UPDATE jobs SET cancel_requested=1 WHERE id=?',(identifier,))
        return True

    def status(self,client):
        with closing(self.connect()) as c:
            counts={r[0]:r[1] for r in c.execute('SELECT status,COUNT(*) FROM jobs WHERE client=? GROUP BY status',(client,))}
            active=c.execute("SELECT COUNT(*) FROM jobs WHERE status='running'").fetchone()[0]
            queued=c.execute("SELECT COUNT(*) FROM jobs WHERE status='queued'").fetchone()[0]
            state=dict(c.execute('SELECT * FROM gateway_state').fetchone())
        return {'client':client,'model':self.model,'capacity':self.capacity,'active':active,'queued':queued,'client_counts':counts,'queue_limit':self.queue_limit,'circuit_open_until':state['blocked_until'],'last_success_at':state['last_success'],**self.model_health()}

    def model_health(self):
        if self.transport!=self.infer:return {'model_reachable':None,'model_available':None,'model_loaded':None}
        with self.health_lock:
            if self.health_cache['until']>time.monotonic():return dict(self.health_cache['value'])
            value={'model_reachable':False,'model_available':False,'model_loaded':False}
            try:
                with requests.Session() as c:
                    c.trust_env=False
                    if self.provider=='deepseek':
                        r=c.get(self.url+'/v1/models',headers={'Authorization':'Bearer '+self.api_key},timeout=(2,5),allow_redirects=False)
                        if r.status_code==200:
                            value['model_reachable']=True
                            value['model_available']=any(m.get('id')==self.model for m in r.json().get('data',[]))
                            value['model_loaded']=value['model_available']
                    else:
                        r=c.get(self.url+'/api/tags',timeout=(1,1),allow_redirects=False)
                        if r.status_code==200:
                            value['model_reachable']=True;value['model_available']=any(m.get('name')==self.model for m in r.json().get('models',[]))
                            loaded=c.get(self.url+'/api/ps',timeout=(1,1),allow_redirects=False)
                            if loaded.status_code==200:value['model_loaded']=any(m.get('name')==self.model for m in loaded.json().get('models',[]))
            except (requests.RequestException,ValueError):pass
            self.health_cache={'until':time.monotonic()+5,'value':value};return dict(value)

    def infer(self,payload):
        from utils.local_ai import _read_json
        opts=payload.get('options',{});timeout=opts.get('timeout',20);deadline=time.monotonic()+timeout
        with requests.Session() as client:
            client.trust_env=False
            if self.provider=='deepseek':
                body={'model':self.model,'messages':payload['messages'],'stream':False,'temperature':.2,
                      'max_tokens':opts.get('num_predict',512),'response_format':{'type':'json_object'}}
                with client.post(self.url+'/v1/chat/completions',headers={'Authorization':'Bearer '+self.api_key},
                    json=body,timeout=(3,timeout),stream=True,allow_redirects=False) as r:
                    raw=_read_json(r,65536,deadline)
                try:
                    choice=raw['choices'][0];content=choice['message']['content']
                    if choice.get('finish_reason')=='length':raise ValueError('model_output_truncated')
                    data={'message':{'content':content},'done':True}
                except (KeyError,IndexError,TypeError):
                    raise ValueError('invalid_model_output')
            else:
                with client.post(self.url+'/api/chat',json={'model':self.model,'messages':payload['messages'],'format':payload.get('schema') or {'type':'object','properties':{'reply':{'type':'string'}},'required':['reply'],'additionalProperties':False},'stream':False,'think':opts.get('think',False),'keep_alive':'5m','options':{'num_ctx':opts.get('num_ctx',4096),'num_predict':opts.get('num_predict',512),'temperature':.2}},timeout=(3,timeout),stream=True,allow_redirects=False) as r:
                    data=_read_json(r,65536,deadline)
        return data

    def process_one(self):
        job=self.claim()
        if not job:return False
        try:data=self.transport(job['payload']);reason=''
        except requests.Timeout:data={};reason='gateway_timeout'
        except requests.RequestException:data={};reason='model_unavailable'
        except TimeoutError:data={};reason='gateway_timeout'
        except ValueError as e:data={};reason='model_http_error' if str(e)=='model_http_error' else 'invalid_model_output'
        except Exception:data={};reason='gateway_worker_error'
        self.finish(job,data,reason);return True

    def loop(self):
        while not self.stop.is_set():
            try:worked=self.process_one()
            except sqlite3.Error:worked=False
            if not worked:self.wake.wait(.2);self.wake.clear()

    def start(self):
        for n in range(self.capacity):
            t=threading.Thread(target=self.loop,name='gateway-'+str(n),daemon=True);t.start();self.threads.append(t)

    def close(self):
        self.stop.set();self.wake.set()
        for t in self.threads:t.join(35)


def create_app(gateway):
    app=Flask(__name__);app.config['MAX_CONTENT_LENGTH']=24576
    @app.before_request
    def auth():
        token=request.headers.get('Authorization','');client=gateway.authenticate(token[7:] if token.startswith('Bearer ') else '')
        if not client:return jsonify(code=1,reason='gateway_auth_failed'),401
        if request.content_length and request.content_length>24576:return jsonify(code=1,reason='input_too_large'),413
        request.gateway_client=client
    @app.after_request
    def headers(r):r.headers['Cache-Control']='no-store';return r
    @app.post('/v1/jobs')
    def submit():
        try:return jsonify(code=0,data=gateway.enqueue(request.gateway_client,request.get_json(silent=True))),202
        except PermissionError:return jsonify(code=1,reason='task_forbidden'),403
        except OverflowError as e:return jsonify(code=1,reason=str(e)),429
        except (ValueError,TypeError,RecursionError):return jsonify(code=1,reason='gateway_invalid_input'),400
        except sqlite3.Error:return jsonify(code=1,reason='gateway_storage_unavailable'),503
    @app.get('/v1/jobs/<identifier>')
    def result(identifier):
        row=gateway.get(identifier,request.gateway_client)
        return (jsonify(code=0,data=row),200) if row else (jsonify(code=1,reason='not_found'),404)
    @app.post('/v1/jobs/<identifier>/cancel')
    def cancel(identifier):return (jsonify(code=0,data={'cancelled':True}),200) if gateway.cancel(identifier,request.gateway_client) else (jsonify(code=1,reason='not_found'),404)
    @app.get('/v1/status')
    def status():return jsonify(code=0,data=gateway.status(request.gateway_client))
    return app


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--config',default='deployment/gateway/gateway.json');args=parser.parse_args()
    cfg=json.loads(Path(args.config).read_text(encoding='utf-8-sig'))
    host=cfg.get('host','127.0.0.1');addr=ipaddress.ip_address(host)
    if not (addr.is_loopback or addr.is_private) or host in ('0.0.0.0','::'):raise SystemExit('Bind a specific private or loopback address')
    service=Gateway(cfg['database'],cfg['model'],cfg['clients'],cfg.get('model_url',cfg.get('ollama_url','http://127.0.0.1:11434')),cfg.get('capacity',1),provider=cfg.get('provider','local'),api_key=cfg.get('api_key',''))
    from werkzeug.serving import make_server
    server=make_server(host,cfg.get('port',11500),create_app(service),threaded=True)
    service.start();print(f'Shared inference service: {host}:{server.server_port}',flush=True)
    try:server.serve_forever()
    except KeyboardInterrupt:pass
    finally:server.server_close();service.close()
