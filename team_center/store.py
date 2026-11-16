import hashlib
import ipaddress
import json
import re
import secrets
import sqlite3
import time
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from werkzeug.security import check_password_hash, generate_password_hash

ZONE = timezone(timedelta(hours=8))
FIELDS = {'source_id','table','record_id','timestamp','src_ip','session_id','channel','kind','rule_level','excerpt','traffic_origin'}
QUERY_FIELDS = {'sensors','start','end','ip','session','kind','term','origin'}
SECRET = re.compile(r'''(?i)(["']?(?:password|passwd|pwd|密码|口令|secret|token|access_token|refresh_token|api_key|authorization|cookie|set-cookie|session|csrf_token|phpsessid|jsessionid)["']?\s*[:=]\s*)("[^"]*"|'[^']*'|[^&,;\r\n} ]+)''')

def clean(value, limit=2000):
    if not isinstance(value,str):raise ValueError('text_required')
    text=SECRET.sub(r'\1[redacted]',re.sub(r'[\x00-\x08\x0b-\x1f\x7f]','',value))
    return re.sub(r'(https?://)[^/@\s]+:[^/@\s]+@',r'\1[redacted]@',text)[:limit]

def stamp(value):
    if not isinstance(value,str) or len(value)>40:raise ValueError('time_invalid')
    try:
        dt=datetime.fromisoformat(value)
        return (dt.replace(tzinfo=ZONE) if dt.tzinfo is None else dt.astimezone(ZONE)).strftime('%Y-%m-%d %H:%M:%S')
    except ValueError:raise ValueError('time_invalid') from None

class CenterStore:
    def __init__(self,path):
        self.path=Path(path);self.path.parent.mkdir(parents=True,exist_ok=True)
        with closing(self.connect()) as c,c:
            c.execute('PRAGMA journal_mode=WAL')
            c.executescript('''
            CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,name TEXT UNIQUE,password TEXT,role TEXT,active INTEGER);
            CREATE TABLE IF NOT EXISTS sensors(id TEXT PRIMARY KEY,name TEXT,token_hash TEXT UNIQUE,active INTEGER,last_seen REAL DEFAULT 0,health TEXT DEFAULT '{}');
            CREATE TABLE IF NOT EXISTS grants(user_id TEXT,sensor_id TEXT,PRIMARY KEY(user_id,sensor_id));
            CREATE TABLE IF NOT EXISTS evidence(id TEXT PRIMARY KEY,sensor_id TEXT,source_id TEXT,table_name TEXT,record_id INTEGER,timestamp TEXT,src_ip TEXT,session_id TEXT,kind TEXT,origin TEXT,document TEXT);
            CREATE INDEX IF NOT EXISTS evidence_scope_time ON evidence(sensor_id,timestamp,id);
            CREATE TABLE IF NOT EXISTS batches(sensor_id TEXT,id TEXT,digest TEXT,created REAL,PRIMARY KEY(sensor_id,id));
            CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY,created REAL,actor TEXT,action TEXT,target TEXT);
            CREATE TABLE IF NOT EXISTS member_metrics(id TEXT PRIMARY KEY,sensor_id TEXT,document TEXT,created REAL);
            CREATE TABLE IF NOT EXISTS center_evaluations(id TEXT PRIMARY KEY,document TEXT,created REAL);
            CREATE TABLE IF NOT EXISTS center_replays(id TEXT PRIMARY KEY,document TEXT,created REAL);
            ''')
    def connect(self):
        c=sqlite3.connect(self.path,timeout=2);c.row_factory=sqlite3.Row;c.execute('PRAGMA busy_timeout=2000');return c
    def audit(self,actor,action,target):
        with closing(self.connect()) as c,c:c.execute('INSERT INTO audit(created,actor,action,target) VALUES(?,?,?,?)',(time.time(),actor,action,target))
    def create_user(self,name,password,role,sensor_ids):
        if not isinstance(name,str) or not re.fullmatch(r'[A-Za-z0-9_-]{3,40}',name) or not isinstance(password,str) or not 12<=len(password)<=128 or role not in ('admin','analyst','readonly'):raise ValueError('user_invalid')
        identifier=secrets.token_hex(12)
        with closing(self.connect()) as c,c:
            self._validate_sensors(c,sensor_ids)
            c.execute('INSERT INTO users VALUES(?,?,?,?,1)',(identifier,name,generate_password_hash(password),role))
            c.executemany('INSERT INTO grants VALUES(?,?)',[(identifier,s) for s in set(sensor_ids)])
        return self.user(identifier)
    @staticmethod
    def _validate_sensors(c,ids):
        if not isinstance(ids,list) or len(ids)>100 or any(not isinstance(s,str) or not c.execute('SELECT 1 FROM sensors WHERE id=?',(s,)).fetchone() for s in ids):raise ValueError('sensors_invalid')
    def update_user(self,identifier,active,sensor_ids):
        if type(active) is not bool:raise ValueError('active_invalid')
        with closing(self.connect()) as c,c:
            c.execute('BEGIN IMMEDIATE');self._validate_sensors(c,sensor_ids)
            if not c.execute('SELECT 1 FROM users WHERE id=?',(identifier,)).fetchone():raise ValueError('user_missing')
            c.execute('UPDATE users SET active=? WHERE id=?',(int(active),identifier));c.execute('DELETE FROM grants WHERE user_id=?',(identifier,));c.executemany('INSERT INTO grants VALUES(?,?)',[(identifier,s) for s in set(sensor_ids)])
    def user(self,identifier):
        with closing(self.connect()) as c:r=c.execute('SELECT id,name,role,active FROM users WHERE id=? AND active=1',(identifier,)).fetchone()
        return dict(r) if r else None
    def authenticate(self,name,password):
        if not isinstance(name,str) or not isinstance(password,str) or len(password)>128:return None
        with closing(self.connect()) as c:r=c.execute('SELECT * FROM users WHERE name=? AND active=1',(name,)).fetchone()
        if r and check_password_hash(r['password'],password):return self.user(r['id'])
        return None
    def scope(self,user_id):
        user=self.user(user_id)
        if not user:raise PermissionError('user_disabled')
        with closing(self.connect()) as c:
            return [r[0] for r in c.execute('SELECT id FROM sensors' if user['role']=='admin' else 'SELECT sensor_id FROM grants WHERE user_id=?',() if user['role']=='admin' else (user_id,))]
    def issue_sensor(self,name):
        name=clean(name,80)
        if not name:raise ValueError('name_required')
        identifier=secrets.token_hex(12);token=secrets.token_urlsafe(36)
        with closing(self.connect()) as c,c:c.execute('INSERT INTO sensors(id,name,token_hash,active) VALUES(?,?,?,1)',(identifier,name,hashlib.sha256(token.encode()).hexdigest()))
        return {'id':identifier,'name':name,'token':token}
    def revoke_sensor(self,identifier):
        with closing(self.connect()) as c,c:c.execute('UPDATE sensors SET active=0 WHERE id=?',(identifier,))
    def sensor_auth(self,token):
        if not isinstance(token,str) or not re.fullmatch(r'[A-Za-z0-9_-]{32,256}',token):return None
        with closing(self.connect()) as c:r=c.execute('SELECT id,name FROM sensors WHERE token_hash=? AND active=1',(hashlib.sha256(token.encode()).hexdigest(),)).fetchone()
        return dict(r) if r else None
    def sensors(self,user_id):
        ids=self.scope(user_id)
        with closing(self.connect()) as c:
            rows=[dict(r) for r in c.execute('SELECT id,name,active,last_seen,health,(SELECT COUNT(*) FROM evidence e WHERE e.sensor_id=s.id) AS evidence_count FROM sensors s ORDER BY name') if r['id'] in ids]
        for r in rows:r['health']=json.loads(r['health'])
        return rows
    def validate_record(self,sensor_id,r):
        if not isinstance(r,dict) or set(r)!=FIELDS:raise ValueError('record_fields_invalid')
        if not isinstance(r['source_id'],str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}',r['source_id']) or r['table'] not in ('raw_request','event_log') or type(r['record_id']) is not int or not 0<r['record_id']<2**63:raise ValueError('record_identity_invalid')
        if r['traffic_origin'] not in ('synthetic','operational','unknown') or r['channel'] not in ('web','ssh','system'):raise ValueError('record_type_invalid')
        if any(not isinstance(r[k],str) or len(r[k])>2000 for k in FIELDS-{'record_id'}):raise ValueError('record_text_invalid')
        if r['src_ip']:ipaddress.ip_address(r['src_ip'])
        value=dict(r);value['timestamp']=stamp(r['timestamp'])
        if r['src_ip']:value['src_ip']=str(ipaddress.ip_address(r['src_ip']))
        for key,limit in {'session_id':128,'kind':80,'rule_level':20,'excerpt':2000}.items():value[key]=clean(value[key],limit)
        value['id']=hashlib.sha256(f'{sensor_id}|{r["source_id"]}|{r["table"]}|{r["record_id"]}'.encode()).hexdigest()[:24];value['sensor_id']=sensor_id
        return value
    def ingest(self,sensor_id,batch_id,records,health,metrics=None):
        if not isinstance(batch_id,str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,80}',batch_id) or not isinstance(records,list) or len(records)>100:raise ValueError('batch_invalid')
        if not isinstance(health,dict) or set(health)-{'pending','paused','error','cursor'} or len(json.dumps(health))>1000:raise ValueError('health_invalid')
        docs=[self.validate_record(sensor_id,r) for r in records]
        metrics=metrics or []
        if not isinstance(metrics,list) or len(metrics)+len(records)>100:raise ValueError('metrics_limit')
        for m in metrics:
            if not isinstance(m,dict) or set(m)-{'id','task','status','reason','latency_ms','origin','rule_attack','ai_attack','model','timestamp'} or not isinstance(m.get('id'),str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,80}',m['id']) or len(json.dumps(m))>2000:raise ValueError('metric_invalid')
            if not all(isinstance(m.get(k),str) and len(m[k])<=160 for k in ('task','status','reason','model','origin')) or m['origin'] not in ('synthetic','operational','unknown') or type(m.get('latency_ms')) is not int or not 0<=m['latency_ms']<=3600000 or type(m.get('timestamp')) not in (int,float) or not 0<=m['timestamp']<=time.time()+86400:raise ValueError('metric_value_invalid')
            if m.get('rule_attack') is not None and type(m['rule_attack']) is not bool or m.get('ai_attack') is not None and type(m['ai_attack']) is not bool:raise ValueError('metric_verdict_invalid')
        digest=hashlib.sha256(json.dumps([docs,metrics],sort_keys=True).encode()).hexdigest()
        with closing(self.connect()) as c,c:
            c.execute('BEGIN IMMEDIATE')
            if not c.execute('SELECT 1 FROM sensors WHERE id=? AND active=1',(sensor_id,)).fetchone():raise PermissionError('sensor_revoked')
            old=c.execute('SELECT digest FROM batches WHERE sensor_id=? AND id=?',(sensor_id,batch_id)).fetchone()
            if old and old['digest']!=digest:raise ValueError('batch_identity_conflict')
            for r in docs:
                oldrow=c.execute('SELECT document FROM evidence WHERE id=?',(r['id'],)).fetchone();document=json.dumps(r,ensure_ascii=False,sort_keys=True)
                if oldrow and oldrow['document']!=document:raise ValueError('source_generation_conflict')
                c.execute('INSERT OR IGNORE INTO evidence VALUES(?,?,?,?,?,?,?,?,?,?,?)',(r['id'],sensor_id,r['source_id'],r['table'],r['record_id'],r['timestamp'],r['src_ip'],r['session_id'],r['kind'],r['traffic_origin'],document))
            for m in metrics:
                mid=hashlib.sha256((sensor_id+'|'+m['id']).encode()).hexdigest();c.execute('INSERT OR IGNORE INTO member_metrics VALUES(?,?,?,?)',(mid,sensor_id,json.dumps(m,ensure_ascii=False),time.time()))
            c.execute('INSERT OR IGNORE INTO batches VALUES(?,?,?,?)',(sensor_id,batch_id,digest,time.time()))
            c.execute('UPDATE sensors SET last_seen=?,health=? WHERE id=?',(time.time(),json.dumps({k:clean(str(v),300) if k=='error' else v for k,v in health.items()}),sensor_id))
        return {'batch_id':batch_id,'accepted':len(docs),'duplicate':bool(old)}
    def query(self,user_id,query):
        if not isinstance(query,dict) or set(query)-QUERY_FIELDS:raise ValueError('query_invalid')
        allowed=self.scope(user_id);ids=query.get('sensors',allowed)
        if not isinstance(ids,list) or len(ids)>100 or any(not isinstance(s,str) or s not in allowed for s in ids):raise PermissionError('sensor_out_of_scope')
        cond=['sensor_id IN ('+','.join('?' for _ in ids)+')' if ids else '0'];args=list(ids)
        for key,column in {'start':'timestamp','end':'timestamp','ip':'src_ip','session':'session_id','kind':'kind','origin':'origin'}.items():
            if key not in query or query[key]=='':continue
            value=query[key]
            if not isinstance(value,str) or len(value)>128:raise ValueError('filter_invalid')
            if key in ('start','end'):value=stamp(value)
            if key=='ip':value=str(ipaddress.ip_address(value))
            cond.append(column+('>=?' if key=='start' else '<=?' if key=='end' else '=?'));args.append(value)
        if query.get('start') and query.get('end'):
            span=datetime.fromisoformat(stamp(query['end']))-datetime.fromisoformat(stamp(query['start']))
            if not timedelta(0)<=span<=timedelta(days=30):raise ValueError('time_range_limit_30_days')
        term=query.get('term','')
        if not isinstance(term,str) or len(term)>80:raise ValueError('term_invalid')
        if term:cond.append("json_extract(document,'$.excerpt') LIKE ? ESCAPE '\\'");args.append('%'+term.replace('\\','\\\\').replace('%','\\%').replace('_','\\_')+'%')
        return ' AND '.join(cond),args
    def search(self,user_id,query,limit=20,cursor=''):
        where,args=self.query(user_id,query);limit=max(1,min(100,int(limit)))
        with closing(self.connect()) as c:
            total=c.execute('SELECT COUNT(*) FROM evidence WHERE '+where,args).fetchone()[0]
            if cursor:
                if not re.fullmatch(r'[a-f0-9]{24}',cursor):raise ValueError('cursor_invalid')
                old=c.execute('SELECT timestamp,id FROM evidence WHERE '+where+' AND id=?',[*args,cursor]).fetchone()
                if not old:raise ValueError('cursor_expired')
                where+=' AND (timestamp<? OR (timestamp=? AND id<?))';args.extend((old['timestamp'],old['timestamp'],old['id']))
            rows=c.execute('SELECT document FROM evidence WHERE '+where+' ORDER BY timestamp DESC,id DESC LIMIT ?',[*args,limit+1]).fetchall()
        docs=[json.loads(r[0]) for r in rows[:limit]]
        return {'records':docs,'total':total,'next':docs[-1]['id'] if len(rows)>limit else ''}
    def evidence(self,user_id,identifier):
        allowed=self.scope(user_id)
        with closing(self.connect()) as c:r=c.execute('SELECT sensor_id,document FROM evidence WHERE id=?',(identifier,)).fetchone()
        return json.loads(r['document']) if r and r['sensor_id'] in allowed else None
