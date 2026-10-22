"""Read-only sources and a durable, acknowledged outbox; never delete source rows."""
import hashlib
import ipaddress
import json
import secrets
import sqlite3
import time
from contextlib import closing
from pathlib import Path
from urllib.parse import urlsplit
import requests
from team_center.store import clean,stamp

def endpoint_ok(endpoint,allow_lan_http=False):
    try:
        u=urlsplit(endpoint);ip=ipaddress.ip_address(u.hostname)
        private=ip.is_loopback or any(ip in ipaddress.ip_network(n) for n in (('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16') if ip.version==4 else ('fc00::/7',)))
        return bool(private and u.scheme in ('http','https') and (u.scheme=='https' or ip.is_loopback or allow_lan_http) and not u.username and not u.password and u.path in ('','/') and not u.query and not u.fragment and (u.port is None or 1<=u.port<=65535))
    except (TypeError,ValueError):return False

class Collector:
    def __init__(self,spool_path,source_paths,sensor_id,endpoint,token,max_bytes=16777216,allow_lan_http=False,origin='unknown',ai_path=None):
        if not endpoint_ok(endpoint,allow_lan_http):raise ValueError('center_endpoint_invalid')
        if origin not in ('unknown','operational','synthetic'):raise ValueError('origin_invalid')
        self.path=Path(spool_path);self.path.parent.mkdir(parents=True,exist_ok=True)
        self.sources=[Path(p).resolve() for p in source_paths];self.sensor_id=sensor_id;self.endpoint=endpoint.rstrip('/');self.token=token;self.max_bytes=max_bytes;self.origin=origin
        self.transport=self._send
        self.heartbeat_transport=self._heartbeat
        self.ai_path=Path(ai_path).resolve() if ai_path else None
        with closing(self.connect()) as c,c:
            c.executescript('''CREATE TABLE IF NOT EXISTS sources(path TEXT PRIMARY KEY,source_id TEXT,inode TEXT,anchor TEXT,raw_id INTEGER,event_id INTEGER);
            CREATE TABLE IF NOT EXISTS outbox(id TEXT PRIMARY KEY,payload TEXT,source_id TEXT,table_name TEXT,last_id INTEGER,created REAL);
            CREATE TABLE IF NOT EXISTS generations(source_id TEXT PRIMARY KEY,anchor TEXT,inode TEXT,raw_id INTEGER,event_id INTEGER);
            CREATE TABLE IF NOT EXISTS state(id INTEGER PRIMARY KEY,paused INTEGER,error TEXT);
            INSERT OR IGNORE INTO state(id,paused,error) VALUES(1,0,'');''')
            if 'anchors' not in {r[1] for r in c.execute('PRAGMA table_info(sources)')}:c.execute("ALTER TABLE sources ADD COLUMN anchors TEXT DEFAULT '{}'")
            if 'source_error' not in {r[1] for r in c.execute('PRAGMA table_info(state)')}:c.execute("ALTER TABLE state ADD COLUMN source_error TEXT DEFAULT ''")
    def connect(self):
        c=sqlite3.connect(self.path,timeout=2);c.row_factory=sqlite3.Row;return c
    def status(self):
        with closing(self.connect()) as c:
            state=dict(c.execute('SELECT paused,error,source_error FROM state').fetchone());state['pending']=c.execute('SELECT COUNT(*) FROM outbox').fetchone()[0]
            source=state.pop('source_error');state['error']='; '.join(v for v in (source,state['error']) if v)
        state['paused']=bool(state['paused']);return state
    def _state(self,paused=False,error=''):
        with closing(self.connect()) as c,c:c.execute('UPDATE state SET error=? WHERE id=1',(clean(error,300),))
    def _source_state(self,paused=False,error=''):
        with closing(self.connect()) as c,c:c.execute('UPDATE state SET paused=?,source_error=? WHERE id=1',(int(paused),clean(error,300)))
    def _registry(self,path,reader):
        names={r[0] for r in reader.execute("SELECT name FROM sqlite_master WHERE type='table'")};anchor=[]
        for table in ('raw_request','event_log','ai_calls'):
            if table in names:
                r=reader.execute('SELECT * FROM '+table+' ORDER BY '+('rowid' if table=='ai_calls' else 'id')+' LIMIT 1').fetchone()
                if r:anchor.append((table,{k:v for k,v in dict(r).items() if k not in ('status','reason','finished_at','latency_ms','response_preview','threat_score')}))
        digest=hashlib.sha256(json.dumps(anchor,sort_keys=True,default=str).encode()).hexdigest() if anchor else ''
        anchors={table:{'id':row['id'],'hash':hashlib.sha256(json.dumps(row,sort_keys=True,default=str).encode()).hexdigest()} for table,row in anchor}
        inode=str(path.stat().st_ino)
        with closing(self.connect()) as c,c:
            c.execute('INSERT OR REPLACE INTO generations SELECT source_id,anchor,inode,raw_id,event_id FROM sources')
            old=c.execute('SELECT * FROM sources WHERE path=?',(str(path),)).fetchone()
            if not old:
                moved=c.execute('SELECT * FROM sources WHERE inode=? AND anchor=?',(inode,digest)).fetchone()
                if not moved and path.parent.name=='archive' and digest:moved=c.execute('SELECT * FROM generations WHERE anchor=? OR inode=? ORDER BY raw_id DESC LIMIT 1',(digest,inode)).fetchone()
                source=moved['source_id'] if moved else secrets.token_hex(16)
                c.execute('INSERT INTO sources(path,source_id,inode,anchor,raw_id,event_id,anchors) VALUES(?,?,?,?,?,?,?)',(str(path),source,inode,digest,moved['raw_id'] if moved else 0,moved['event_id'] if moved else 0,json.dumps(anchors)))
            else:
                changed=old['inode']!=inode;previous=json.loads(old['anchors'])
                for table,a in previous.items():
                    if table not in names:changed=True;continue
                    row=reader.execute('SELECT * FROM '+table+' WHERE id=?',(a['id'],)).fetchone()
                    if row:
                        stable={k:v for k,v in dict(row).items() if k not in ('status','reason','finished_at','latency_ms','response_preview','threat_score')}
                        changed=changed or hashlib.sha256(json.dumps(stable,sort_keys=True,default=str).encode()).hexdigest()!=a['hash']
                    else:
                        high=reader.execute('SELECT MAX('+('rowid' if table=='ai_calls' else 'id')+') FROM '+table).fetchone()[0] or 0
                        cursor=old['event_id'] if table=='event_log' else old['raw_id']
                        changed=changed or high<cursor
                if changed:c.execute('UPDATE sources SET source_id=?,inode=?,anchor=?,raw_id=0,event_id=0,anchors=? WHERE path=?',(secrets.token_hex(16),inode,digest,json.dumps(anchors),str(path)))
                elif not previous and anchors:c.execute('UPDATE sources SET anchor=?,anchors=? WHERE path=?',(digest,json.dumps(anchors),str(path)))
            row=dict(c.execute('SELECT * FROM sources WHERE path=?',(str(path),)).fetchone())
            c.execute('INSERT OR REPLACE INTO generations VALUES(?,?,?,?,?)',(row['source_id'],row['anchor'],row['inode'],row['raw_id'],row['event_id']))
            return row,names
    def _record(self,source,table,row):
        if table=='raw_request':
            excerpt=f'{row.get("method","")} {row.get("path","")} query={row.get("query_string","")} body={row.get("body","")} headers={row.get("headers","")}'
            level='high' if int(row.get('threat_score') or 0)>=60 else 'medium' if int(row.get('threat_score') or 0)>=20 else 'low';channel='web';kind='http_request';ts=row.get('create_time')
        else:
            if row.get('source')=='web' and row.get('raw_request_id'):return None
            excerpt=f'{row.get("event_type","")} {row.get("payload","")}';level=row.get('severity','unknown');channel=row.get('source','system');kind=row.get('event_type','event');ts=row.get('timestamp')
        return {'source_id':source,'table':table,'record_id':row['id'],'timestamp':stamp(str(ts or '')),'src_ip':str(row.get('src_ip') or ''),'session_id':str(row.get('session_id') or '')[:128],
                'channel':channel if channel in ('web','ssh','system') else 'system','kind':str(kind)[:80],'rule_level':str(level)[:20],'excerpt':clean(excerpt,2000),'traffic_origin':self.origin}
    def stage(self):
        size=sum(p.stat().st_size for p in (self.path,Path(str(self.path)+'-wal')) if p.exists())
        if size>=self.max_bytes:self._source_state(True,'spool_disk_budget');return self.status()
        try:
            for path in self.sources:
                with closing(sqlite3.connect(path.as_uri()+'?mode=ro',uri=True,timeout=1)) as reader:
                    reader.row_factory=sqlite3.Row;registry,names=self._registry(path,reader)
                    for table,key in (('raw_request','raw_id'),('event_log','event_id')):
                        if table not in names:continue
                        with closing(self.connect()) as c:
                            if c.execute('SELECT 1 FROM outbox WHERE source_id=? AND table_name=?',(registry['source_id'],table)).fetchone():continue
                        rows=reader.execute('SELECT * FROM '+table+' WHERE id>? ORDER BY id LIMIT 100',(registry[key],)).fetchall()
                        if not rows:continue
                        bid=secrets.token_hex(16)
                        while True:
                            records=[r for row in rows if (r:=self._record(registry['source_id'],table,dict(row))) is not None]
                            text=json.dumps({'batch_id':bid,'records':records,'health':self.status()},ensure_ascii=False)
                            if len(text.encode())<=262144 or len(rows)==1:break
                            rows=rows[:max(1,len(rows)//2)]
                        if len(text.encode())>262144 or size+len(text.encode())>self.max_bytes:self._source_state(True,'spool_disk_budget');return self.status()
                        with closing(self.connect()) as c,c:c.execute('INSERT INTO outbox VALUES(?,?,?,?,?,?)',(bid,text,registry['source_id'],table,rows[-1]['id'],time.time()))
                        size+=len(text.encode())
            self._source_state()
            if self.ai_path and self.ai_path.exists():self._stage_metrics()
        except (OSError,sqlite3.Error,ValueError) as error:self._source_state(False,type(error).__name__+': '+str(error)[:150])
        return self.status()
    def _stage_metrics(self):
        with closing(sqlite3.connect(self.ai_path.as_uri()+'?mode=ro',uri=True,timeout=1)) as reader:
            reader.row_factory=sqlite3.Row;registry,names=self._registry(self.ai_path,reader)
            if 'ai_calls' not in names:return
            with closing(self.connect()) as c:
                if c.execute('SELECT 1 FROM outbox WHERE source_id=? AND table_name=?',(registry['source_id'],'ai_calls')).fetchone():return
            rows=reader.execute('SELECT rowid AS sequence,* FROM ai_calls WHERE rowid>? ORDER BY rowid LIMIT 100',(registry['raw_id'],)).fetchall();ready=[]
            for r in rows:
                if r['status']=='running':break
                if r['task']=='web_detect' and r['status']=='success' and 'ai_detections' in names:
                    detection=reader.execute('SELECT status FROM ai_detections WHERE call_id=?',(r['id'],)).fetchone()
                    if not detection and ('src_ip' not in r.keys() or r['src_ip']!='evaluation') or detection and detection['status'] not in ('completed','fallback','skipped','cancelled'):
                        self._source_state(False,'waiting_detection_save');break
                ready.append(r)
            if not ready:return
            metrics=[]
            for r in ready:
                m={'id':registry['source_id']+'-'+r['id'],'task':r['task'],'model':r['model'],'status':r['status'],'reason':clean(r['reason'],100),'latency_ms':r['latency_ms'],'origin':self.origin,'timestamp':r['created_at']}
                if 'ai_detections' in names:
                    d=reader.execute('SELECT snapshot_json,verdict,status FROM ai_detections WHERE call_id=?',(r['id'],)).fetchone()
                    if d:
                        snap=json.loads(d['snapshot_json']);m.update(rule_attack=int(snap.get('rule_score',0))>=20,ai_attack=(d['verdict']=='suspicious') if d['status']=='completed' and d['verdict']!='uncertain' else None)
                metrics.append(m)
            bid=secrets.token_hex(16);text=json.dumps({'batch_id':bid,'records':[],'metrics':metrics,'health':self.status()},ensure_ascii=False)
            if self.path.stat().st_size+len(text.encode())>=self.max_bytes:self._source_state(True,'spool_disk_budget');return
            with closing(self.connect()) as c,c:c.execute('INSERT INTO outbox VALUES(?,?,?,?,?,?)',(bid,text,registry['source_id'],'ai_calls',ready[-1]['sequence'],time.time()))
    def batch(self):
        with closing(self.connect()) as c:row=c.execute('SELECT payload FROM outbox ORDER BY created,id LIMIT 1').fetchone()
        return json.loads(row[0]) if row else None
    def _send(self,payload):
        payload=dict(payload,health=self._health())
        with requests.Session() as client:
            client.trust_env=False
            with client.post(self.endpoint+'/api/ingest',data=json.dumps(payload,ensure_ascii=False).encode(),headers={'Content-Type':'application/json','Authorization':'Bearer '+self.token},timeout=(3,10),allow_redirects=False,stream=True) as response:
                if response.status_code!=200:raise ValueError('center_http_'+str(response.status_code))
                data=bytearray();deadline=time.monotonic()+10
                for chunk in response.iter_content(chunk_size=1):
                    if time.monotonic()>deadline:raise ValueError('center_reply_deadline')
                    data.extend(chunk)
                    if len(data)>4096:raise ValueError('center_reply_too_large')
                return json.loads(data)
    def flush_once(self):
        payload=self.batch()
        if not payload:
            try:
                self.heartbeat_transport(self.status());self._state(self.status()['paused'])
            except (requests.RequestException,ValueError) as error:self._state(self.status()['paused'],type(error).__name__+': '+str(error)[:150])
            return self.status()
        try:
            ack=self.transport(payload)
            if not isinstance(ack,dict) or ack.get('batch_id')!=payload['batch_id'] or ack.get('accepted')!=len(payload['records']):raise ValueError('ack_invalid')
            with closing(self.connect()) as c,c:
                c.execute('BEGIN IMMEDIATE');row=c.execute('SELECT * FROM outbox WHERE id=?',(payload['batch_id'],)).fetchone()
                if row:
                    key='raw_id' if row['table_name'] in ('raw_request','ai_calls') else 'event_id'
                    c.execute('UPDATE sources SET '+key+'=MAX('+key+',?) WHERE source_id=?',(row['last_id'],row['source_id']));c.execute('DELETE FROM outbox WHERE id=?',(row['id'],))
                    c.execute('UPDATE generations SET '+key+'=MAX('+key+',?) WHERE source_id=?',(row['last_id'],row['source_id']))
            self._state()
            if not self.status()['pending'] and self.path.stat().st_size>self.max_bytes//2:
                with closing(self.connect()) as c:c.execute('VACUUM')
        except (requests.RequestException,ConnectionError,ValueError,sqlite3.Error) as error:self._state(False,type(error).__name__+': '+str(error)[:150])
        return self.status()
    def _heartbeat(self,state):
        state=dict(state,error=clean(state.get('error',''),100))
        with requests.Session() as client:
            client.trust_env=False
            with client.post(self.endpoint+'/api/heartbeat',json={'health':state},headers={'Authorization':'Bearer '+self.token},timeout=(3,5),allow_redirects=False,stream=True) as response:
                if response.status_code!=200:raise ValueError('heartbeat_http_'+str(response.status_code))
    def _health(self):
        state=self.status();state['error']=clean(state.get('error',''),100);return state
