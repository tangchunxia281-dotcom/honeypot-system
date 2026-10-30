"""Durable evidence index and asynchronous analyst tasks, separate from event DB."""
import json
import secrets
import time
import sqlite3
from pathlib import Path
from contextlib import closing
from utils.ai_store import CallStore,ensure_schema


class AnalystStore(CallStore):
    def connect(self):
        conn=super().connect()
        try:
            ensure_schema(conn,self.path,'analyst-v5',self._initialize_analyst)
            return conn
        except Exception:conn.close();raise

    @staticmethod
    def _initialize_analyst(conn):
            conn.executescript('''
                CREATE TABLE IF NOT EXISTS analyst_cursors(source TEXT PRIMARY KEY, raw_id INTEGER, event_id INTEGER);
                CREATE TABLE IF NOT EXISTS analyst_evidence(id TEXT PRIMARY KEY, source TEXT, locator TEXT,
                    timestamp TEXT, src_ip TEXT, channel TEXT, session_id TEXT, kind TEXT, rule_level TEXT,
                    excerpt TEXT, indexed_at REAL);
                CREATE INDEX IF NOT EXISTS analyst_evidence_time ON analyst_evidence(timestamp);
                CREATE INDEX IF NOT EXISTS analyst_evidence_ip ON analyst_evidence(src_ip,timestamp);
                CREATE TABLE IF NOT EXISTS analyst_tasks(id TEXT PRIMARY KEY, fingerprint TEXT UNIQUE,
                    created_at REAL, updated_at REAL, expires_at REAL, task TEXT, owner TEXT, conversation TEXT,
                    question TEXT, status TEXT, reason TEXT, attempts INTEGER, context_json TEXT,
                    result_json TEXT, call_id TEXT);
                CREATE INDEX IF NOT EXISTS analyst_tasks_queue ON analyst_tasks(status,task,created_at);
                CREATE INDEX IF NOT EXISTS analyst_tasks_listing ON analyst_tasks(task,created_at,id);
                CREATE TABLE IF NOT EXISTS analyst_report_items(evidence_id TEXT PRIMARY KEY, task_id TEXT);
                CREATE TABLE IF NOT EXISTS analyst_reviews(id INTEGER PRIMARY KEY,task_id TEXT,owner TEXT,
                    verdict TEXT,human_risk TEXT,note TEXT,created_at REAL);
                CREATE INDEX IF NOT EXISTS analyst_reviews_task ON analyst_reviews(task_id,created_at);
                CREATE TABLE IF NOT EXISTS analyst_attempts(id INTEGER PRIMARY KEY,task_id TEXT,attempt INTEGER,
                    status TEXT,reason TEXT,result_json TEXT,call_id TEXT,created_at REAL);
            ''')
            columns={r[1] for r in conn.execute('PRAGMA table_info(analyst_tasks)')}
            if 'lease_token' not in columns:conn.execute("ALTER TABLE analyst_tasks ADD COLUMN lease_token TEXT DEFAULT ''")
            if not conn.execute("SELECT 1 FROM ai_migrations WHERE name='analyst-deferred-v5'").fetchone():
                conn.execute("UPDATE analyst_tasks SET status='queued',reason='waiting_recovery',attempts=0,updated_at=?,expires_at=0 WHERE status='fallback' AND reason='circuit_open'",(time.time(),))
                conn.execute("INSERT INTO ai_migrations VALUES('analyst-deferred-v5',?)",(time.time(),))

    def cursor(self,source):
        with closing(self.connect()) as c:
            r=c.execute('SELECT raw_id,event_id FROM analyst_cursors WHERE source=?',(source,)).fetchone()
        return dict(r) if r else {'raw_id':0,'event_id':0}

    def index_batch(self,source,raw_id,event_id,records):
        with closing(self.connect()) as c,c:
            c.execute('BEGIN IMMEDIATE')
            c.executemany('INSERT OR IGNORE INTO analyst_evidence VALUES(?,?,?,?,?,?,?,?,?,?,?)',
                [(r['id'],source,r['locator'],r['timestamp'],r['src_ip'],r['channel'],r['session_id'],r['kind'],r['rule_level'],r['excerpt'],time.time()) for r in records])
            c.execute('INSERT INTO analyst_cursors VALUES(?,?,?) ON CONFLICT(source) DO UPDATE SET raw_id=MAX(raw_id,excluded.raw_id),event_id=MAX(event_id,excluded.event_id)',
                      (source,raw_id,event_id))

    def enqueue(self,task,context,fingerprint,owner='',conversation='',question=''):
        now=time.time();identifier=secrets.token_hex(12)
        with closing(self.connect()) as c,c:
            c.execute('BEGIN IMMEDIATE')
            c.execute("UPDATE analyst_tasks SET status='fallback',reason='worker_interrupted',updated_at=? WHERE status='running' AND expires_at<?",(now,now))
            old=c.execute('SELECT id,status FROM analyst_tasks WHERE fingerprint=?',(fingerprint,)).fetchone()
            if old:return dict(old)
            if c.execute("SELECT COUNT(*) FROM analyst_tasks WHERE status IN ('queued','running')").fetchone()[0]>=64:
                return {'id':'','status':'rejected','reason':'analyst_queue_full'}
            if owner and c.execute('SELECT COUNT(*) FROM analyst_tasks WHERE owner=? AND task=? AND created_at>?',(owner,task,now-3600)).fetchone()[0]>=20:
                return {'id':'','status':'rejected','reason':'question_budget'}
            c.execute('''INSERT INTO analyst_tasks(id,fingerprint,created_at,updated_at,expires_at,task,owner,conversation,
                question,status,reason,attempts,context_json,result_json,call_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                (identifier,fingerprint,now,now,0,task,owner,conversation,question,'queued','',0,json.dumps(context,ensure_ascii=False),'{}',''))
            return {'id':identifier,'status':'queued'}

    def next_report_records(self,limit=12):
        with closing(self.connect()) as c:
            first=c.execute('''SELECT src_ip,session_id,timestamp FROM analyst_evidence WHERE id NOT IN
                (SELECT evidence_id FROM analyst_report_items) ORDER BY timestamp,id LIMIT 1''').fetchone()
            if not first:return []
            # Use a supplied session when present; session-less records are only
            # same-source temporal clues, never evidence of a single person.
            return [dict(r) for r in c.execute('''SELECT * FROM analyst_evidence WHERE src_ip=? AND session_id=?
                AND (julianday(?) IS NULL OR julianday(timestamp)<=julianday(?)+1.0/96) AND id NOT IN
                (SELECT evidence_id FROM analyst_report_items) ORDER BY timestamp,id LIMIT ?''',(first['src_ip'],first['session_id'],first['timestamp'],first['timestamp'],limit))]

    def link_report(self,identifier,records):
        with closing(self.connect()) as c,c:
            c.executemany('INSERT OR IGNORE INTO analyst_report_items VALUES(?,?)',[(r['id'],identifier) for r in records])

    def claim(self,timeout,chat_only=False):
        now=time.time()
        with closing(self.connect()) as c,c:
            c.execute('BEGIN IMMEDIATE')
            c.execute("UPDATE analyst_tasks SET status='fallback',reason='worker_interrupted',updated_at=? WHERE status='running' AND expires_at<?",(now,now))
            if c.execute("SELECT COUNT(*) FROM analyst_tasks WHERE status='running'").fetchone()[0]:return None
            row=c.execute("SELECT * FROM analyst_tasks WHERE status='queued' AND updated_at<=?"+(" AND task IN ('chat','general_chat')" if chat_only else '')+" ORDER BY CASE WHEN task IN ('chat','general_chat') THEN 0 ELSE 1 END,created_at LIMIT 1",(now,)).fetchone()
            if not row:return None
            lease=secrets.token_hex(12)
            c.execute("UPDATE analyst_tasks SET status='running',attempts=attempts+1,lease_token=?,expires_at=?,updated_at=? WHERE id=?",(lease,now+timeout*2+20,now,row['id']))
            result=self.decode(dict(row));result['attempts']+=1;result['lease_token']=lease;return result

    def finish_task(self,job,result):
        success=result.get('status')=='success';reason=result.get('reason','')
        transient=reason in ('capacity_limit','priority_wait','rate_limit','background_paused','gateway_queue_full','gateway_client_pending','gateway_client_budget') and job['attempts']<3
        correction=reason in ('invalid_model_output','model_output_truncated') and job['attempts']<2
        transient=transient or correction
        if reason in ('circuit_open','disabled'):transient=True
        status='completed' if success else 'queued' if transient else 'fallback'
        with closing(self.connect()) as c,c:
            c.execute('BEGIN IMMEDIATE')
            current=c.execute('SELECT status,lease_token FROM analyst_tasks WHERE id=?',(job['id'],)).fetchone()
            if not current or current['status']!='running' or current['lease_token']!=job.get('lease_token',''):return False
            c.execute('INSERT INTO analyst_attempts(task_id,attempt,status,reason,result_json,call_id,created_at) VALUES(?,?,?,?,?,?,?)',
                (job['id'],job['attempts'],result.get('status','fallback'),reason,json.dumps(result.get('data',{}) if success else {},ensure_ascii=False),result.get('call_id',''),time.time()))
            c.execute('''UPDATE analyst_tasks SET status=?,reason=?,result_json=?,call_id=?,updated_at=?,expires_at=0
                WHERE id=? AND status='running' ''',(status,reason,json.dumps(result.get('data',{}) if success else {},ensure_ascii=False),
                result.get('call_id',''),time.time()+(30 if reason=='circuit_open' else 3 if transient else 0),job['id']))
            if reason in ('capacity_limit','priority_wait','rate_limit','background_paused','circuit_open','disabled'):
                c.execute('UPDATE analyst_tasks SET attempts=MAX(0,attempts-1) WHERE id=?',(job['id'],))
            return True

    @staticmethod
    def decode(row):
        row['context']=json.loads(row.pop('context_json'));row['result']=json.loads(row.pop('result_json'))
        return row

    def get(self,identifier,owner=None):
        with closing(self.connect()) as c:
            r=c.execute('SELECT * FROM analyst_tasks WHERE id=?'+(' AND owner=?' if owner is not None else ''),
                        (identifier,owner) if owner is not None else (identifier,)).fetchone()
        return self.decode(dict(r)) if r else None

    def listing(self,limit=12,before=None,risk='',state=''):
        with closing(self.connect()) as c:
            clauses=["task='report'"];args=[]
            if before:
                if isinstance(before,tuple):clauses.append('(created_at<? OR (created_at=? AND id<?))');args.extend((before[0],before[0],before[1]))
                else:clauses.append('created_at<?');args.append(before)
            if risk:clauses.append("json_extract(result_json,'$.risk')=?");args.append(risk)
            if state:clauses.append('status=?');args.append(state)
            rows=[]
            for r in c.execute("SELECT id,created_at,updated_at,status,reason,call_id,result_json,attempts,json_array_length(context_json,'$.records') AS record_count,json_extract(context_json,'$.records[0].src_ip') AS src_ip FROM analyst_tasks WHERE "+' AND '.join(clauses)+' ORDER BY created_at DESC,id DESC LIMIT ?',[*args,limit]):
                row=dict(r);row['result']=json.loads(row.pop('result_json'));row['context']={'selected':row['record_count'],'records':[]}
                rows.append(row)
            indexed=c.execute('SELECT COUNT(*) FROM analyst_evidence').fetchone()[0]
            states={r[0]:r[1] for r in c.execute("SELECT status,COUNT(*) FROM analyst_tasks WHERE task='report' GROUP BY status")}
            risks={r[0]:r[1] for r in c.execute("SELECT json_extract(result_json,'$.risk'),COUNT(*) FROM analyst_tasks WHERE task='report' AND status='completed' GROUP BY 1")}
            covered=c.execute('SELECT COUNT(*) FROM analyst_report_items').fetchone()[0]
        return {'reports':rows,'indexed':indexed,'assigned':covered,'unassigned':indexed-covered,'states':states,'risks':risks,
            'next_before':str(rows[-1]['created_at'])+':'+rows[-1]['id'] if len(rows)==limit else None}

    def search(self,ip='',term='',limit=8):
        cond=[];args=[]
        if ip:cond.append('src_ip=?');args.append(ip)
        if term:cond.append("excerpt LIKE ? ESCAPE '\\'");args.append('%'+term.replace('\\','\\\\').replace('%','\\%').replace('_','\\_')+'%')
        where=' WHERE '+' AND '.join(cond) if cond else ''
        with closing(self.connect()) as c:
            total=c.execute('SELECT COUNT(*) FROM analyst_evidence'+where,args).fetchone()[0]
            records=[dict(r) for r in c.execute('SELECT * FROM analyst_evidence'+where+' ORDER BY timestamp DESC,id LIMIT ?',[*args,limit])]
        return {'total_matching':total,'records':records,'selected':len(records)}

    def conversations(self,owner,conversation):
        with closing(self.connect()) as c:
            rows=[self.decode(dict(r)) for r in c.execute("SELECT * FROM analyst_tasks WHERE owner=? AND conversation=? AND task IN ('chat','general_chat') ORDER BY created_at DESC LIMIT 20",(owner,conversation))]
        return list(reversed(rows))

    def retry_task(self,identifier,owner=None):
        with closing(self.connect()) as c,c:
            c.execute('BEGIN IMMEDIATE')
            row=c.execute('SELECT * FROM analyst_tasks WHERE id=?',(identifier,)).fetchone()
            if not row or (owner is not None and row['owner']!=owner):return 'not_found'
            if row['status'] in ('queued','running'):return 'active'
            if c.execute("SELECT COUNT(*) FROM analyst_tasks WHERE status IN ('queued','running')").fetchone()[0]>=64:return 'queue_full'
            c.execute("UPDATE analyst_tasks SET status='queued',reason='manual_retry',attempts=0,updated_at=?,expires_at=0,lease_token='' WHERE id=?",(time.time(),identifier))
            return 'queued'

    def cancel(self,identifier,owner=None):
        with closing(self.connect()) as c,c:
            row=c.execute('SELECT owner FROM analyst_tasks WHERE id=?',(identifier,)).fetchone()
            if not row or (owner is not None and row['owner']!=owner):return False
            c.execute("UPDATE analyst_tasks SET status='cancelled',reason='user_cancelled',updated_at=?,lease_token='' WHERE id=? AND status IN ('queued','running')",(time.time(),identifier))
            return True

    def review(self,identifier,owner,verdict,human_risk,note):
        with closing(self.connect()) as c,c:
            if not c.execute("SELECT 1 FROM analyst_tasks WHERE id=? AND task='report' AND status='completed'",(identifier,)).fetchone():return False
            c.execute('INSERT INTO analyst_reviews(task_id,owner,verdict,human_risk,note,created_at) VALUES(?,?,?,?,?,?)',
                (identifier,owner,verdict,human_risk,note[:500],time.time()));return True

    def reviews(self,identifier):
        with closing(self.connect()) as c:return [dict(r) for r in c.execute('SELECT * FROM analyst_reviews WHERE task_id=? ORDER BY created_at DESC LIMIT 10',(identifier,))]

    def archive_old(self,days=30):
        """Archive terminal AI tasks before pruning their derived index; original events untouched."""
        with closing(self.connect()) as c:
            rows=[dict(r) for r in c.execute("SELECT * FROM analyst_tasks WHERE status IN ('completed','fallback','cancelled') AND updated_at<? ORDER BY updated_at LIMIT 100",(time.time()-days*86400,))]
        moved=0;directory=self.path.parent/'ai-archives';directory.mkdir(exist_ok=True)
        for row in rows:
            month=time.strftime('%Y%m',time.gmtime(row['created_at']));target=directory/(month+'.sqlite')
            task=self.decode(row)
            # Serialize archive writers and reviews with the runtime transaction.
            # The archive commits first; a crash leaves a duplicate, not lost data.
            with closing(self.connect()) as c,c:
                c.execute('BEGIN IMMEDIATE')
                current=c.execute('SELECT status,updated_at FROM analyst_tasks WHERE id=?',(task['id'],)).fetchone()
                if not current or current['updated_at']!=task['updated_at'] or current['status'] not in ('completed','fallback','cancelled'):continue
                task['reviews']=[dict(r) for r in c.execute('SELECT * FROM analyst_reviews WHERE task_id=?',(task['id'],))]
                task['attempt_history']=[dict(r) for r in c.execute('SELECT * FROM analyst_attempts WHERE task_id=?',(task['id'],))]
                with closing(sqlite3.connect(target)) as archive,archive:
                    archive.execute('CREATE TABLE IF NOT EXISTS archived_tasks(id TEXT PRIMARY KEY,payload TEXT,archived_at REAL)')
                    archive.execute('INSERT INTO archived_tasks VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload,archived_at=excluded.archived_at',(task['id'],json.dumps(task,ensure_ascii=False),time.time()))
                c.execute('DELETE FROM analyst_evidence WHERE id IN (SELECT evidence_id FROM analyst_report_items WHERE task_id=?)',(task['id'],))
                for table,key in (('analyst_report_items','task_id'),('analyst_reviews','task_id'),('analyst_attempts','task_id'),('analyst_tasks','id')):
                    c.execute('DELETE FROM '+table+' WHERE '+key+'=?',(task['id'],))
                moved+=1
        return moved

    def archives(self):
        directory=self.path.parent/'ai-archives'
        return [{'name':p.name,'bytes':p.stat().st_size} for p in sorted(directory.glob('*.sqlite'),reverse=True) if p.name[:6].isdigit() and p.resolve().is_relative_to(directory.resolve())] if directory.exists() else []

    def archived(self,name):
        import re
        directory=(self.path.parent/'ai-archives').resolve();path=(directory/name).resolve()
        if not re.fullmatch(r'[0-9]{6}\.sqlite',name) or not path.is_relative_to(directory) or not path.exists():return None
        with closing(sqlite3.connect(path.as_uri()+'?mode=ro',uri=True)) as c:
            return [json.loads(r[0]) for r in c.execute('SELECT payload FROM archived_tasks ORDER BY archived_at DESC LIMIT 100')]

    def related_reports(self,identifiers):
        if not identifiers:return []
        slots=','.join('?' for _ in identifiers)
        with closing(self.connect()) as c:
            rows=c.execute("SELECT DISTINCT t.id,t.result_json FROM analyst_tasks t JOIN analyst_report_items i ON i.task_id=t.id WHERE t.status='completed' AND i.evidence_id IN ("+slots+") ORDER BY t.created_at DESC LIMIT 3",identifiers).fetchall()
        return [{'id':r['id'],**{k:v for k,v in json.loads(r['result_json']).items() if k in ('title','risk','risk_reason')}} for r in rows]
