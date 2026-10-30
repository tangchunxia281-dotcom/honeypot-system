"""Atomic interaction reservation, bounded session state and prompt-free replay."""
import json
import secrets
import time
from contextlib import closing
from utils.ai_store import CallStore


class InteractionStore(CallStore):
    @staticmethod
    def denied(reason,token,channel,ip):
        try:
            from utils.logger import get_logger
            get_logger('ai_interaction').warning('[交互拒绝] channel=%s session=%s source_ip=%s reason=%s',channel,token,ip,reason)
        except Exception:pass
        return {'reason':reason,'session_id':token}

    def connect(self):
        conn=super().connect()
        try:
            conn.execute('''CREATE TABLE IF NOT EXISTS interaction_sessions (
                id TEXT PRIMARY KEY, src_ip TEXT NOT NULL, channel TEXT NOT NULL,
                expires_at REAL NOT NULL, step INTEGER NOT NULL, busy_until REAL NOT NULL,
                state_json TEXT NOT NULL)''')
            conn.execute('''CREATE TABLE IF NOT EXISTS ai_interactions (
                id TEXT PRIMARY KEY, created_at REAL NOT NULL, finished_at REAL,
                session_id TEXT NOT NULL, channel TEXT NOT NULL, src_ip TEXT NOT NULL,
                step INTEGER NOT NULL, status TEXT NOT NULL, source TEXT NOT NULL,
                strategy TEXT NOT NULL, reason TEXT NOT NULL, call_id TEXT NOT NULL,
                input_preview TEXT NOT NULL, output_preview TEXT NOT NULL, state_json TEXT NOT NULL,
                UNIQUE(session_id,step))''')
            conn.execute('CREATE INDEX IF NOT EXISTS interactions_time ON ai_interactions(created_at)')
            conn.commit()
            return conn
        except Exception:
            conn.close();raise

    def begin(self, token, ip, channel, settings, preview):
        now=time.time()
        with closing(self.connect()) as conn, conn:
            conn.execute('BEGIN IMMEDIATE')
            conn.execute('DELETE FROM interaction_sessions WHERE expires_at<=?',(now,))
            conn.execute("UPDATE ai_interactions SET status='fallback',source='fallback',reason='worker_interrupted',finished_at=? WHERE status='running' AND created_at<?",(now,now-90))
            conn.execute("DELETE FROM ai_interactions WHERE created_at<? AND status!='running'",(now-30*86400,))
            conn.execute("DELETE FROM ai_interactions WHERE id IN (SELECT id FROM ai_interactions WHERE status!='running' ORDER BY created_at DESC LIMIT -1 OFFSET 9998)")
            row=conn.execute('SELECT * FROM interaction_sessions WHERE id=? AND src_ip=? AND channel=?',
                             (token,ip,channel)).fetchone() if token else None
            if row is None:
                if conn.execute('SELECT COUNT(*) FROM interaction_sessions').fetchone()[0]>=settings['interaction_sessions']:
                    return self.denied('session_capacity','',channel,ip)
                token=secrets.token_hex(16)
                conn.execute('INSERT INTO interaction_sessions VALUES(?,?,?,?,?,?,?)',
                             (token,ip,channel,now+settings['interaction_ttl'],0,0,'{}'))
                row=conn.execute('SELECT * FROM interaction_sessions WHERE id=?',(token,)).fetchone()
            if row['busy_until']>now:return self.denied('session_busy',token,channel,ip)
            if row['step']>=settings['interaction_steps']:return self.denied('step_budget',token,channel,ip)
            step=row['step']+1;identifier=secrets.token_hex(12)
            conn.execute('UPDATE interaction_sessions SET step=?,busy_until=? WHERE id=?',
                         (step,now+max(settings['timeout'],settings.get('gateway_wait',90) if settings.get('provider')=='gateway' else 0)*2+15,token))
            conn.execute('INSERT INTO ai_interactions VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                         (identifier,now,None,token,channel,ip,step,'running','pending','','','',preview[:800],'',row['state_json']))
            return {'id':identifier,'session_id':token,'channel':channel,'step':step,'state':json.loads(row['state_json']),'reason':''}

    def complete(self, turn, state, source, strategy, reason, output, call_id=''):
        now=time.time();state_json=json.dumps(state,ensure_ascii=False)
        if len(state_json)>2048:raise ValueError('state_too_large')
        with closing(self.connect()) as conn, conn:
            conn.execute('BEGIN IMMEDIATE')
            row=conn.execute('SELECT step,busy_until FROM interaction_sessions WHERE id=? AND expires_at>?',
                             (turn['session_id'],now)).fetchone()
            if not row or row['step']!=turn['step'] or row['busy_until']<now:raise ValueError('stale_turn')
            conn.execute('UPDATE interaction_sessions SET state_json=?,busy_until=0 WHERE id=?',
                         (state_json,turn['session_id']))
            conn.execute('''UPDATE ai_interactions SET finished_at=?,status=?,source=?,strategy=?,reason=?,
                call_id=?,output_preview=?,state_json=? WHERE id=? AND status='running' ''',
                (now,'fallback' if source=='fallback' else 'completed',source,strategy[:64],reason[:80],call_id[:32],output[:1200],state_json,turn['id']))
        try:
            from utils.logger import get_logger
            get_logger('ai_interaction').info('[交互完成] channel=%s session=%s step=%s source=%s strategy=%s reason=%s call=%s',
                turn.get('channel',''),turn['session_id'],turn['step'],source,strategy,reason,call_id)
        except Exception:
            pass  # SQLite remains authoritative; file logger failure must not undo a committed turn.

    def listing(self, limit=50, session_id='', channel='', *, src_ip='', start=None, end=None):
        conditions=[];values=[]
        if session_id:conditions.append('session_id=?');values.append(session_id)
        if channel:conditions.append('channel=?');values.append(channel)
        if src_ip:conditions.append('src_ip=?');values.append(src_ip)
        if start is not None:conditions.append('created_at>=?');values.append(start)
        if end is not None:conditions.append('created_at<?');values.append(end)
        where=' WHERE '+' AND '.join(conditions) if conditions else ''
        with closing(self.connect()) as conn:
            counts={r[0]:r[1] for r in conn.execute('SELECT source,COUNT(*) FROM ai_interactions'+where+' GROUP BY source',values)}
            rows=[dict(r) for r in conn.execute('SELECT * FROM ai_interactions'+where+' ORDER BY created_at DESC LIMIT ?',[*values,limit])]
        for row in rows:row['state']=json.loads(row.pop('state_json'))
        return {'counts':counts,'records':rows,'scope':'Retained 30 days / 10000 interactions; previews only, not full packet replay'}

