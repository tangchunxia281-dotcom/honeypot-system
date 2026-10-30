"""Process-shared leases and bounded, prompt-free AI call audit."""
import sqlite3
import time
import threading
from contextlib import closing
from pathlib import Path

_schema_guard=threading.RLock()
_schemas=set()


def ensure_schema(conn,path,name,initializer):
    stat=Path(path).stat();key=(str(Path(path).resolve()),stat.st_ino,name)
    with _schema_guard:
        if key not in _schemas:
            initializer(conn);conn.commit()
            if len(_schemas)>256:_schemas.clear()
            _schemas.add(key)


class CallStore:
    def __init__(self, path):
        self.path = Path(path)

    def connect(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.path, timeout=0.5)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute('PRAGMA busy_timeout=500')
            ensure_schema(conn,self.path,'calls-v5',self._initialize)
            return conn
        except Exception:
            conn.close()
            raise

    @staticmethod
    def _initialize(conn):
            try:conn.execute('PRAGMA journal_mode=WAL')
            except sqlite3.OperationalError:pass
            conn.execute('''CREATE TABLE IF NOT EXISTS ai_calls (
                id TEXT PRIMARY KEY, created_at REAL NOT NULL, finished_at REAL,
                task TEXT NOT NULL, model TEXT NOT NULL, src_ip TEXT NOT NULL,
                session_id TEXT NOT NULL, input_sha256 TEXT NOT NULL,
                status TEXT NOT NULL, reason TEXT NOT NULL, latency_ms INTEGER NOT NULL,
                response_preview TEXT NOT NULL)''')
            conn.execute('CREATE INDEX IF NOT EXISTS ai_calls_time ON ai_calls(created_at)')
            conn.execute('CREATE INDEX IF NOT EXISTS ai_calls_session ON ai_calls(session_id,task,created_at)')
            conn.execute('CREATE INDEX IF NOT EXISTS ai_calls_source ON ai_calls(src_ip,created_at)')
            conn.execute('CREATE TABLE IF NOT EXISTS ai_leases (id TEXT PRIMARY KEY, expires_at REAL NOT NULL)')
            conn.execute('CREATE TABLE IF NOT EXISTS ai_state (id INTEGER PRIMARY KEY, failures INTEGER, open_until REAL)')
            conn.execute('CREATE TABLE IF NOT EXISTS ai_waiters(id TEXT PRIMARY KEY,expires_at REAL)')
            conn.execute('CREATE TABLE IF NOT EXISTS ai_diagnostics(call_id TEXT PRIMARY KEY,detail TEXT)')
            conn.execute('CREATE TABLE IF NOT EXISTS ai_scheduler(id INTEGER PRIMARY KEY,pause_until REAL)')
            conn.execute('INSERT OR IGNORE INTO ai_scheduler VALUES(1,0)')
            conn.execute('INSERT OR IGNORE INTO ai_state VALUES(1,0,0)')
            conn.execute('CREATE TABLE IF NOT EXISTS ai_migrations(name TEXT PRIMARY KEY,applied_at REAL)')
            if not conn.execute("SELECT 1 FROM ai_migrations WHERE name='transport-circuit-v5'").fetchone():
                conn.execute('UPDATE ai_state SET failures=0,open_until=0 WHERE id=1')
                conn.execute("INSERT INTO ai_migrations VALUES('transport-circuit-v5',?)",(time.time(),))

    def register_waiter(self,identifier,ttl):
        with closing(self.connect()) as conn,conn:
            conn.execute('DELETE FROM ai_waiters WHERE expires_at<=?',(time.time(),))
            if conn.execute('SELECT COUNT(*) FROM ai_waiters').fetchone()[0]<16:
                conn.execute('INSERT OR REPLACE INTO ai_waiters VALUES(?,?)',(identifier,time.time()+ttl))

    def unregister_waiter(self,identifier):
        with closing(self.connect()) as conn,conn:conn.execute('DELETE FROM ai_waiters WHERE id=?',(identifier,))

    def pause_background(self,seconds):
        until=time.time()+max(0,min(600,seconds)) if seconds else 0
        with closing(self.connect()) as conn,conn:conn.execute('UPDATE ai_scheduler SET pause_until=? WHERE id=1',(until,))
        return until

    def background_paused(self):
        with closing(self.connect()) as conn:return conn.execute('SELECT pause_until FROM ai_scheduler WHERE id=1').fetchone()[0]

    def start(self, call, settings, waitable=False):
        now = time.time()
        with closing(self.connect()) as conn, conn:
            conn.execute('BEGIN IMMEDIATE')
            conn.execute('DELETE FROM ai_leases WHERE expires_at<=?', (now,))
            conn.execute("UPDATE ai_calls SET status='fallback',reason='worker_interrupted',finished_at=? WHERE status='running' AND created_at<? AND id NOT IN (SELECT id FROM ai_leases)",(now,now-60))
            conn.execute('DELETE FROM ai_waiters WHERE expires_at<=?',(now,))
            # Keep operational history bounded; never touch the original event database.
            conn.execute('DELETE FROM ai_calls WHERE created_at<? AND status!=?', (now-30*86400,'running'))
            conn.execute('''DELETE FROM ai_calls WHERE id IN (SELECT id FROM ai_calls
                WHERE status!='running' ORDER BY created_at DESC LIMIT -1 OFFSET 9999)''')
            failures, open_until = conn.execute('SELECT failures,open_until FROM ai_state WHERE id=1').fetchone()
            recent = conn.execute("SELECT COUNT(*),MAX(created_at) FROM ai_calls WHERE session_id=? AND task=? AND reason NOT IN ('rate_limit','capacity_limit','circuit_open','disabled','configuration_invalid','session_budget','source_budget','priority_wait','background_paused')",
                                  (call['session_id'],call['task'])).fetchone()
            reason = ''
            if not settings['enabled']:
                reason = 'disabled'
            elif not settings['configured']:
                reason = 'configuration_invalid'
            elif now < open_until and not (call['task']=='probe' and settings.get('bypass_circuit')):
                reason = 'circuit_open'
            elif recent[0] >= settings['max_calls_per_session']:
                reason = 'session_budget'
            elif recent[1] and now-recent[1] < settings['min_interval']:
                reason = 'rate_limit'
            elif call['task'] in ('ssh_reply','web_reply') and conn.execute("SELECT COUNT(*) FROM ai_calls WHERE src_ip=? AND task IN ('ssh_reply','web_reply') AND created_at>? AND reason NOT IN ('rate_limit','capacity_limit','circuit_open','disabled','configuration_invalid','session_budget','source_budget')",(call['src_ip'],now-3600)).fetchone()[0]>=settings.get('interaction_per_ip_hour',40):
                reason = 'source_budget'
            elif conn.execute('SELECT COUNT(*) FROM ai_leases').fetchone()[0] >= settings['concurrency']:
                reason = 'capacity_limit'
            elif call['task'] in ('web_detect','log_report') and conn.execute('SELECT pause_until FROM ai_scheduler WHERE id=1').fetchone()[0]>now:
                reason = 'background_paused'
            elif call['task'] in ('web_detect','log_report') and conn.execute('SELECT COUNT(*) FROM ai_waiters').fetchone()[0]:
                reason = 'priority_wait'
            if reason=='capacity_limit' and waitable:return reason
            conn.execute('INSERT INTO ai_calls VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
                         (call['id'],now,now if reason else None,call['task'],settings['model'],
                          call['src_ip'][:64],call['session_id'][:64],call['input_sha256'],
                          'fallback' if reason else 'running',reason,0,''))
            if not reason:
                conn.execute('INSERT INTO ai_leases VALUES(?,?)',(call['id'],now+settings['timeout']*2+15))
            return reason

    def finish(self, call_id, status, reason, latency_ms, preview='',validation_detail=''):
        now = time.time()
        with closing(self.connect()) as conn, conn:
            conn.execute('BEGIN IMMEDIATE')
            conn.execute('UPDATE ai_calls SET finished_at=?,status=?,reason=?,latency_ms=?,response_preview=? WHERE id=?',
                         (now,status,reason[:80],int(latency_ms),preview[:600],call_id))
            if validation_detail:conn.execute('INSERT OR REPLACE INTO ai_diagnostics VALUES(?,?)',(call_id,validation_detail[:80]))
            if status == 'success':
                conn.execute('UPDATE ai_state SET failures=0,open_until=0 WHERE id=1')
            elif reason in ('model_http_error','model_unavailable'):
                failures = conn.execute('SELECT failures FROM ai_state WHERE id=1').fetchone()[0]+1
                conn.execute('UPDATE ai_state SET failures=?,open_until=? WHERE id=1',
                             (failures,now+30 if failures>=3 else 0))

    def release(self, call_id):
        for attempt in range(5):
            try:
                with closing(self.connect()) as conn, conn:
                    conn.execute('DELETE FROM ai_leases WHERE id=?',(call_id,))
                return
            except sqlite3.OperationalError as error:
                if 'locked' not in str(error).lower() or attempt==4:raise
                time.sleep(.05*(attempt+1))

    def snapshot(self):
        now=time.time()
        with closing(self.connect()) as conn:
            counts={row[0]:row[1] for row in conn.execute("SELECT CASE WHEN c.status='running' AND c.created_at<? AND COALESCE(l.expires_at,0)<=? THEN 'fallback' ELSE c.status END,COUNT(*) FROM ai_calls c LEFT JOIN ai_leases l ON l.id=c.id GROUP BY 1",(now-60,now))}
            active=conn.execute('SELECT COUNT(*) FROM ai_leases WHERE expires_at>?',(now,)).fetchone()[0]
            state=dict(conn.execute('SELECT failures,open_until FROM ai_state WHERE id=1').fetchone())
            rows=[dict(row) for row in conn.execute("SELECT ai_calls.*,COALESCE(detail,'') AS validation_detail,COALESCE(ai_leases.expires_at,0) AS lease_until FROM ai_calls LEFT JOIN ai_diagnostics ON call_id=ai_calls.id LEFT JOIN ai_leases ON ai_leases.id=ai_calls.id ORDER BY created_at DESC LIMIT 30")]
            for row in rows:
                if row['status']=='running' and row['created_at']<now-60 and row['lease_until']<=now:
                    row.update(status='fallback',reason='worker_interrupted')
            last=conn.execute("SELECT MAX(finished_at) FROM ai_calls WHERE status='success'").fetchone()[0]
            return dict(counts=counts,active=active,circuit_open_until=state['open_until'],
                        background_paused_until=conn.execute('SELECT pause_until FROM ai_scheduler WHERE id=1').fetchone()[0],
                        last_success_at=last,recent=rows,history_scope='retained history, maximum 10000 rows / 30 days')
