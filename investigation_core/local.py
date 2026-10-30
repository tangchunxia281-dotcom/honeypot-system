"""Single-host evidence indexing. No upload listener or remote credentials."""
import hashlib
import json
import sqlite3
import threading
import time
from contextlib import closing
from pathlib import Path
from investigation_core.store import CenterStore, clean, stamp
from investigation_core.jobs import JobStore

class LocalInvestigation:
    owner='local-admin'
    sensor='0'*24

    def __init__(self,path,source):
        self.store=CenterStore(path);self.source=Path(source).resolve()
        self.lock=threading.Lock();self.start_lock=threading.Lock();self.started=False
        self.health={'indexed':0,'error':'尚未索引','updated':None}
        with closing(self.store.connect()) as c,c:
            c.execute("INSERT OR IGNORE INTO users VALUES(?,?,'!','admin',1)",(self.owner,'本机管理员'))
            c.execute("INSERT OR IGNORE INTO sensors(id,name,token_hash,active) VALUES(?,'本机日志','disabled',1)",(self.sensor,))
            c.execute('CREATE TABLE IF NOT EXISTS local_cursors(source TEXT,table_name TEXT,position INTEGER,PRIMARY KEY(source,table_name))')
            c.execute('CREATE TABLE IF NOT EXISTS local_anchors(source TEXT,table_name TEXT,fingerprint TEXT,PRIMARY KEY(source,table_name))')
        self.jobs=JobStore(self.store)

    def sync(self):
        with self.lock:
            count=0
            try:
                # mode=ro prevents a missing source from silently becoming an empty DB.
                with closing(sqlite3.connect(self.source.as_uri()+'?mode=ro',uri=True,timeout=2)) as src:
                    src.row_factory=sqlite3.Row
                    tables={r[0] for r in src.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                    if not tables.intersection({'raw_request','event_log'}):raise ValueError('source_has_no_event_tables')
                    source_id=hashlib.sha256(str(self.source).encode()).hexdigest()[:24]
                    for table in ('raw_request','event_log'):
                        if table not in tables:continue
                        first=src.execute('SELECT * FROM '+table+' ORDER BY id LIMIT 1').fetchone()
                        fields=('id','method','path','query_string','body','create_time') if table=='raw_request' else ('id','timestamp','payload')
                        fingerprint=hashlib.sha256(json.dumps({k:dict(first).get(k) for k in fields},sort_keys=True,default=str).encode()).hexdigest() if first else ''
                        with closing(self.store.connect()) as c:
                            cur=c.execute('SELECT position FROM local_cursors WHERE source=? AND table_name=?',(source_id,table)).fetchone()
                            anchor=c.execute('SELECT fingerprint FROM local_anchors WHERE source=? AND table_name=?',(source_id,table)).fetchone()
                        if anchor:
                            previous=json.loads(anchor[0])
                            old=src.execute('SELECT * FROM '+table+' WHERE id=?',(previous['id'],)).fetchone()
                            old_fingerprint=hashlib.sha256(json.dumps({k:dict(old).get(k) for k in fields},sort_keys=True,default=str).encode()).hexdigest() if old else None
                            if old and old_fingerprint!=previous['hash']:
                                raise ValueError('source_reset_detected: source changed; use a new investigation database')
                        position=cur[0] if cur else 0
                        high=src.execute('SELECT MAX(id) FROM '+table).fetchone()[0] or 0
                        if high<position:raise ValueError('source_reset_detected: use a new investigation database')
                        rows=src.execute('SELECT * FROM '+table+' WHERE id>? ORDER BY id LIMIT 100',(position,)).fetchall()
                        records=[]
                        for raw in rows:
                            r=dict(raw)
                            if table=='raw_request':
                                excerpt=f'{r.get("method","")} {r.get("path","")} query={r.get("query_string","")} body={r.get("body","")} headers={r.get("headers","")}'
                                from db.event_logs import severity_from_score
                                score=int(r.get('threat_score') or 0);level=severity_from_score(score)
                                channel='web';kind='http_request';ts=r.get('create_time')
                            else:
                                if r.get('source')=='web' and r.get('raw_request_id'):continue
                                excerpt=f'{r.get("event_type","")} {r.get("payload","")}'
                                level=r.get('severity','unknown');channel=r.get('source','system');kind=r.get('event_type','event');ts=r.get('timestamp')
                            records.append(dict(source_id=source_id,table=table,record_id=r['id'],timestamp=stamp(str(ts or '')),src_ip=str(r.get('src_ip') or ''),session_id=str(r.get('session_id') or '')[:128],channel=channel if channel in ('web','ssh','mysql','redis','ftp','telnet','system') else 'system',kind=str(kind)[:80],rule_level=str(level)[:20],excerpt=clean(excerpt,2000),traffic_origin='unknown'))
                        if rows:
                            bid=hashlib.sha256(f'{source_id}:{table}:{rows[0]["id"]}:{rows[-1]["id"]}'.encode()).hexdigest()[:32]
                            self.store.ingest(self.sensor,bid,records,{},[])
                            with closing(self.store.connect()) as c,c:
                                c.execute('INSERT OR REPLACE INTO local_cursors VALUES(?,?,?)',(source_id,table,rows[-1]['id']))
                                c.execute('INSERT OR REPLACE INTO local_anchors VALUES(?,?,?)',(source_id,table,json.dumps({'id':first['id'],'hash':fingerprint})))
                            count+=len(records)
                self.health={'indexed':count,'error':'','updated':time.time()}
            except (sqlite3.Error,ValueError,OSError) as error:
                self.health={'indexed':count,'error':str(error)[:180],'updated':time.time()}
            return dict(self.health)

    def start(self):
        with self.start_lock:
            if self.started:return
            self.started=True
            threading.Thread(target=self.work,daemon=True,name='local-investigator').start()

    def work(self):
        from utils.active_investigation import process_one
        while True:
            try:
                self.sync()
                # One lease at a time. Model-disabled jobs retain the program timeline.
                while process_one(self.store,self.jobs):pass
            except Exception as error:
                self.health={'indexed':0,'error':type(error).__name__+': '+str(error)[:120],'updated':time.time()}
            time.sleep(5)
