"""Cross-process notification suppression; raw evidence is never deleted."""
import hashlib
import time
from contextlib import closing
from utils.ai_store import ensure_schema


class NoiseGate:
    def __init__(self,store):self.store=store
    def connect(self):
        c=self.store.connect()
        ensure_schema(c,self.store.path,'noise-v1',lambda x:x.executescript('''
            CREATE TABLE IF NOT EXISTS alert_noise(key TEXT PRIMARY KEY,src_ip TEXT,kind TEXT,first REAL,last REAL,
                level INTEGER,observed INTEGER,admitted INTEGER,suppressed INTEGER,next_emit REAL,pending INTEGER);
        '''));return c
    def admit(self,ip,kind,subject,level,now=None):
        now=time.time() if now is None else now
        route=str(subject).split('?',1)[0][:180];key=hashlib.sha256((str(ip)+'|'+str(kind)+'|'+route).encode()).hexdigest()
        with closing(self.connect()) as c,c:
            c.execute('BEGIN IMMEDIATE');c.execute('DELETE FROM alert_noise WHERE last<?',(now-86400,))
            row=c.execute('SELECT * FROM alert_noise WHERE key=?',(key,)).fetchone()
            if not row:
                if c.execute('SELECT COUNT(*) FROM alert_noise').fetchone()[0]>=10000:
                    c.execute('DELETE FROM alert_noise WHERE key IN (SELECT key FROM alert_noise ORDER BY last LIMIT 100)')
                c.execute('INSERT INTO alert_noise VALUES(?,?,?,?,?,?,?,?,?,?,?)',(key,ip,kind,now,now,level,1,1,0,now+300,0));return {'allowed':True,'merged':0}
            allowed=now>=row['next_emit'] or level>row['level']
            merged=row['pending'] if allowed else 0
            c.execute('UPDATE alert_noise SET last=?,level=?,observed=observed+1,admitted=admitted+?,suppressed=suppressed+?,next_emit=?,pending=? WHERE key=?',
                (now,max(level,row['level']) if not allowed else level,int(allowed),int(not allowed),now+300 if allowed else row['next_emit'],0 if allowed else row['pending']+1,key))
            return {'allowed':allowed,'merged':merged}
    def snapshot(self):
        with closing(self.connect()) as c:
            row=c.execute('SELECT COALESCE(SUM(observed),0),COALESCE(SUM(admitted),0),COALESCE(SUM(suppressed),0) FROM alert_noise').fetchone()
        return dict(zip(('observed','admitted','suppressed'),row))
