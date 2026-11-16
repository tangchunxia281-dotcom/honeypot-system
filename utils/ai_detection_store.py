"""Persistent bounded detection queue, separate from original attack evidence."""
import json
import sqlite3
import time
from contextlib import closing
from utils.ai_store import CallStore


class DetectionStore(CallStore):
    def connect(self):
        conn=super().connect()
        try:
            conn.execute('''CREATE TABLE IF NOT EXISTS ai_detections (
                id TEXT PRIMARY KEY, raw_key TEXT UNIQUE NOT NULL, created_at REAL NOT NULL,
                updated_at REAL NOT NULL, expires_at REAL NOT NULL, src_ip TEXT NOT NULL,
                session_id TEXT NOT NULL, raw_request_id INTEGER NOT NULL,
                snapshot_json TEXT NOT NULL, status TEXT NOT NULL, reason TEXT NOT NULL,
                verdict TEXT NOT NULL, result_json TEXT NOT NULL, call_id TEXT NOT NULL)''')
            conn.execute('CREATE INDEX IF NOT EXISTS ai_detection_time ON ai_detections(created_at)')
            conn.execute('CREATE INDEX IF NOT EXISTS ai_detection_queue ON ai_detections(status,created_at)')
            conn.execute('CREATE INDEX IF NOT EXISTS ai_detection_ip ON ai_detections(src_ip,created_at)')
            conn.commit()
            return conn
        except Exception:
            conn.close();raise

    def enqueue(self,job,settings):
        now=time.time()
        with closing(self.connect()) as conn,conn:
            conn.execute('BEGIN IMMEDIATE')
            existing=conn.execute('SELECT id,status,reason FROM ai_detections WHERE raw_key=?',(job['raw_key'],)).fetchone()
            if existing:return dict(existing,existing=True)
            conn.execute("DELETE FROM ai_detections WHERE status NOT IN ('queued','running') AND created_at<?",(now-30*86400,))
            conn.execute("DELETE FROM ai_detections WHERE id IN (SELECT id FROM ai_detections WHERE status NOT IN ('queued','running') ORDER BY created_at DESC LIMIT -1 OFFSET 9999)")
            active=conn.execute("SELECT COUNT(*) FROM ai_detections WHERE status IN ('queued','running')").fetchone()[0]
            used=conn.execute("SELECT COUNT(*) FROM ai_detections WHERE src_ip=? AND created_at>? AND reason NOT IN ('queue_full','source_budget')",(job['src_ip'],now-3600)).fetchone()[0]
            reason='queue_full' if active>=settings['detection_queue_max'] else 'source_budget' if used>=settings['detection_per_ip_hour'] else ''
            conn.execute('INSERT INTO ai_detections VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                (job['id'],job['raw_key'],now,now,0,job['src_ip'],job['session_id'],job['raw_request_id'],
                 json.dumps(job['snapshot'],ensure_ascii=False),'skipped' if reason else 'queued',reason,'uncertain','{}',''))
            return {'id':job['id'],'status':'skipped' if reason else 'queued','reason':reason,'existing':False}

    def claim(self,timeout,delay=0):
        now=time.time()
        with closing(self.connect()) as conn,conn:
            conn.execute('BEGIN IMMEDIATE')
            conn.execute("UPDATE ai_detections SET status='fallback',reason='worker_interrupted',verdict='uncertain',updated_at=? WHERE status='running' AND expires_at<?",(now,now))
            if conn.execute("SELECT COUNT(*) FROM ai_detections WHERE status='running'").fetchone()[0]:
                return None
            row=conn.execute("SELECT * FROM ai_detections WHERE status='queued' AND updated_at<=? ORDER BY created_at LIMIT 1",(now-delay,)).fetchone()
            if not row:return None
            conn.execute("UPDATE ai_detections SET status='running',expires_at=?,updated_at=? WHERE id=?",(now+timeout*2+20,now,row['id']))
            return self.decode(dict(row))

    def requeue(self,identifier,reason):
        with closing(self.connect()) as conn,conn:
            conn.execute("UPDATE ai_detections SET status='queued',reason=?,updated_at=?,expires_at=0 WHERE id=? AND status='running'",(reason,time.time(),identifier))

    def finish(self,identifier,call):
        result=(call.get('data') or {}) if call['status']=='success' else {}
        status='completed' if call['status']=='success' else 'fallback'
        with closing(self.connect()) as conn,conn:
            conn.execute('''UPDATE ai_detections SET status=?,reason=?,verdict=?,result_json=?,call_id=?,updated_at=?,expires_at=0 WHERE id=?''',
                (status,call.get('reason',''),result.get('verdict','uncertain'),json.dumps(result,ensure_ascii=False),
                 call.get('call_id',''),time.time(),identifier))

    def retry(self,identifier,settings):
        with closing(self.connect()) as conn,conn:
            conn.execute('BEGIN IMMEDIATE')
            row=conn.execute('SELECT status FROM ai_detections WHERE id=?',(identifier,)).fetchone()
            if not row:return None
            if row['status'] in ('queued','running'):return 'already_active'
            active=conn.execute("SELECT COUNT(*) FROM ai_detections WHERE status IN ('queued','running')").fetchone()[0]
            if active>=settings['detection_queue_max']:return 'queue_full'
            conn.execute("UPDATE ai_detections SET status='queued',reason='',verdict='uncertain',result_json='{}',updated_at=? WHERE id=?",(time.time(),identifier))
            return 'queued'

    @staticmethod
    def decode(row):
        row['snapshot']=json.loads(row.pop('snapshot_json'))
        row['result']=json.loads(row.pop('result_json'))
        row['rule_ai_disagreement']=row['status']=='completed' and ((row['snapshot']['rule_score']>=20) != (row['verdict']=='suspicious'))
        return row

    def listing(self,limit=50,src_ip=''):
        with closing(self.connect()) as conn:
            if src_ip:
                rows=conn.execute('SELECT * FROM ai_detections WHERE src_ip=? ORDER BY created_at DESC LIMIT ?',(src_ip,limit)).fetchall()
            else:
                rows=conn.execute('SELECT * FROM ai_detections ORDER BY created_at DESC LIMIT ?',(limit,)).fetchall()
            counts={r[0]:r[1] for r in conn.execute('SELECT status,COUNT(*) FROM ai_detections'+(' WHERE src_ip=?' if src_ip else '')+' GROUP BY status',[src_ip] if src_ip else [])}
            return {'counts':counts,'records':[self.decode(dict(r)) for r in rows]}

    def get(self,identifier):
        with closing(self.connect()) as conn:
            row=conn.execute('SELECT * FROM ai_detections WHERE id=?',(identifier,)).fetchone()
            return self.decode(dict(row)) if row else None
