"""Persistent local case snapshots and independent human reviews."""
import json
import secrets
import time
from contextlib import closing
from datetime import datetime,timedelta
from investigation_core.store import clean

class Workflow:
    def __init__(self,engine):
        self.engine=engine;self.store=engine.store
        with closing(self.store.connect()) as c,c:
            c.executescript('''CREATE TABLE IF NOT EXISTS local_cases(id TEXT PRIMARY KEY,title TEXT,query_json TEXT,evidence_json TEXT,status TEXT,note TEXT,revision INTEGER,created REAL,updated REAL);
            CREATE TABLE IF NOT EXISTS local_reviews(evidence_id TEXT PRIMARY KEY,label TEXT,note TEXT,revision INTEGER,updated REAL);
            CREATE TABLE IF NOT EXISTS local_case_jobs(case_id TEXT,job_id TEXT,PRIMARY KEY(case_id,job_id));''')
    def event(self,identifier):
        row=self.store.evidence(self.engine.owner,identifier)
        if not row:raise ValueError('evidence_not_found')
        with closing(self.store.connect()) as c:r=c.execute('SELECT * FROM local_reviews WHERE evidence_id=?',(identifier,)).fetchone()
        row['review']=dict(r) if r else None
        return row
    def review_event(self,identifier,p):
        self.event(identifier)
        if not isinstance(p,dict) or p.get('label') not in ('attack','benign','uncertain') or type(p.get('revision')) is not int:raise ValueError('review_invalid')
        note=clean(p.get('note',''),500)
        with closing(self.store.connect()) as c,c:
            c.execute('BEGIN IMMEDIATE');r=c.execute('SELECT revision FROM local_reviews WHERE evidence_id=?',(identifier,)).fetchone()
            if p['revision']!=(r[0] if r else 0):raise ValueError('revision_conflict')
            c.execute('INSERT OR REPLACE INTO local_reviews VALUES(?,?,?,?,?)',(identifier,p['label'],note,p['revision']+1,time.time()))
        self.store.audit(self.engine.owner,'review_event',identifier)
        return self.event(identifier)['review']
    def create_case(self,p):
        if not isinstance(p,dict) or not isinstance(p.get('title'),str) or not p['title'].strip():raise ValueError('title_required')
        anchor=None
        if p.get('evidence_id'):
            row=self.event(p['evidence_id']);anchor=row;base=datetime.fromisoformat(row['timestamp'])
            q={'ip':row['src_ip'],'start':(base-timedelta(minutes=15)).isoformat(' '),'end':(base+timedelta(minutes=15)).isoformat(' ')}
            if row.get('session_id'):q['session']=row['session_id']
        else:q=p.get('query',{})
        self.store.query(self.engine.owner,q)
        records=self.store.search(self.engine.owner,q,60)['records']
        if not records:raise ValueError('no_evidence_in_scope')
        # A busy window must not discard the event that prompted the case.
        if anchor and not any(r['id']==anchor['id'] for r in records):
            records=records[:59]+[anchor]
            records.sort(key=lambda r:(r['timestamp'],r['id']),reverse=True)
        # Freeze the time boundaries even when the user started with an open query.
        q={**q,'start':q.get('start',min(r['timestamp'] for r in records)),'end':q.get('end',max(r['timestamp'] for r in records))}
        self.store.query(self.engine.owner,q)
        identifier=secrets.token_hex(12);now=time.time()
        with closing(self.store.connect()) as c,c:
            c.execute('INSERT INTO local_cases VALUES(?,?,?,?,?,?,?,?,?)',(identifier,clean(p['title'],100),json.dumps(q),json.dumps(records,ensure_ascii=False),'open','',0,now,now))
        self.store.audit(self.engine.owner,'create_case',identifier)
        return self.get_case(identifier)
    def get_case(self,identifier):
        with closing(self.store.connect()) as c:
            r=c.execute('SELECT * FROM local_cases WHERE id=?',(identifier,)).fetchone()
            if not r:raise ValueError('case_not_found')
            row=dict(r);row['query']=json.loads(row.pop('query_json'));row['evidence']=json.loads(row.pop('evidence_json'))
            row['job_ids']=[r[0] for r in c.execute('SELECT job_id FROM local_case_jobs WHERE case_id=? ORDER BY rowid DESC',(identifier,))]
        return row
    def listing(self,query=None):
        # Match the frozen snapshot, including after the live index is archived.
        # Filter before the limit so busy unrelated sources cannot hide a case.
        where,args=self.store.query(self.engine.owner,query or {})
        snapshot='''SELECT json_extract(value,'$.sensor_id') AS sensor_id,
            json_extract(value,'$.timestamp') AS timestamp,
            json_extract(value,'$.src_ip') AS src_ip,
            json_extract(value,'$.session_id') AS session_id,
            json_extract(value,'$.kind') AS kind,
            json_extract(value,'$.traffic_origin') AS origin,
            value AS document FROM json_each(local_cases.evidence_json)'''
        sql='SELECT id,title,status,revision,created,updated FROM local_cases WHERE EXISTS (SELECT 1 FROM ('+snapshot+') WHERE '+where+') ORDER BY updated DESC,id DESC LIMIT 100'
        with closing(self.store.connect()) as c:return [dict(r) for r in c.execute(sql,args)]
    def update_case(self,identifier,p):
        self.get_case(identifier)
        if not isinstance(p,dict) or p.get('status') not in ('open','reviewing','closed') or type(p.get('revision')) is not int:raise ValueError('case_update_invalid')
        with closing(self.store.connect()) as c,c:
            r=c.execute('UPDATE local_cases SET status=?,note=?,revision=revision+1,updated=? WHERE id=? AND revision=?',(p['status'],clean(p.get('note',''),1000),time.time(),identifier,p['revision']))
            if r.rowcount!=1:raise ValueError('revision_conflict')
        self.store.audit(self.engine.owner,'update_case',identifier)
        return self.get_case(identifier)
    def link_job(self,case_id,job_id):
        self.get_case(case_id)
        with closing(self.store.connect()) as c,c:c.execute('INSERT OR IGNORE INTO local_case_jobs VALUES(?,?)',(case_id,job_id))
