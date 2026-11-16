import json
import secrets
import time
from contextlib import closing
from team_center.store import clean

class JobStore:
    def __init__(self,center):
        self.center=center
        with closing(center.connect()) as c,c:
            c.executescript('''CREATE TABLE IF NOT EXISTS center_jobs(id TEXT PRIMARY KEY,owner TEXT,request_id TEXT,question TEXT,query_json TEXT,status TEXT,reason TEXT,created REAL,deadline REAL,lease TEXT,result_json TEXT,UNIQUE(owner,request_id));
            CREATE TABLE IF NOT EXISTS center_steps(id INTEGER PRIMARY KEY,job_id TEXT,document TEXT);
            CREATE TABLE IF NOT EXISTS center_calls(id TEXT PRIMARY KEY,job_id TEXT,document TEXT);
            CREATE TABLE IF NOT EXISTS center_feedback(job_id TEXT PRIMARY KEY,revision INTEGER,verdict TEXT,note TEXT,actor TEXT,created REAL);
            CREATE TABLE IF NOT EXISTS center_feedback_audit(id INTEGER PRIMARY KEY,job_id TEXT,document TEXT,created REAL);''')
    def create(self,user_id,question,query,request_id):
        user=self.center.user(user_id)
        if not user or user['role'] not in ('admin','analyst'):raise PermissionError('role_denied')
        if not isinstance(question,str) or not 1<=len(question.strip())<=500 or not isinstance(request_id,str) or not 1<=len(request_id)<=80:raise ValueError('investigation_invalid')
        self.center.query(user_id,query);query=dict(query,sensors=query.get('sensors',self.center.scope(user_id)))
        identifier=secrets.token_hex(12);now=time.time()
        with closing(self.center.connect()) as c,c:
            c.execute('BEGIN IMMEDIATE');old=c.execute('SELECT id,question,query_json FROM center_jobs WHERE owner=? AND request_id=?',(user_id,request_id)).fetchone()
            if old:
                if old['question']!=clean(question,500) or json.loads(old['query_json'])!=query:raise ValueError('idempotency_input_conflict')
                return self.get(user_id,old['id'])
            if c.execute("SELECT COUNT(*) FROM center_jobs WHERE status IN ('queued','running')").fetchone()[0]>=64:raise ValueError('queue_full')
            if c.execute('SELECT COUNT(*) FROM center_jobs WHERE owner=? AND created>?',(user_id,now-3600)).fetchone()[0]>=20:raise ValueError('hourly_budget')
            c.execute('INSERT INTO center_jobs VALUES(?,?,?,?,?,?,?,?,?,?,?)',(identifier,user_id,request_id,clean(question,500),json.dumps(query),'queued','',now,now+90,'','{}'))
        return self.get(user_id,identifier)
    @staticmethod
    def decode(row):
        obj=dict(row);obj['query']=json.loads(obj.pop('query_json'));obj['result']=json.loads(obj.pop('result_json'));return obj
    def visible(self,user_id,row):
        return row and set(row['query']['sensors']).issubset(self.center.scope(user_id))
    def get(self,user_id,identifier):
        with closing(self.center.connect()) as c:
            raw=c.execute('SELECT * FROM center_jobs WHERE id=?',(identifier,)).fetchone();row=self.decode(raw) if raw else None
            if not self.visible(user_id,row):return None
            row['steps']=[json.loads(r[0]) for r in c.execute('SELECT document FROM center_steps WHERE job_id=? ORDER BY id',(identifier,))]
            f=c.execute('SELECT * FROM center_feedback WHERE job_id=?',(identifier,)).fetchone();row['feedback']=dict(f) if f else None
        if row['status']=='fallback' and not row['result'].get('story'):
            from utils.attack_story import build_story
            pool=self.center.search(user_id,row['query'],60)
            row['result']['story']=build_story(pool['records'])
            row['result']['story']['scope']='当前授权索引中的程序时间线；不是已完成AI调查的快照。'
        row.pop('lease',None);return row
    def listing(self,user_id):
        with closing(self.center.connect()) as c:rows=[self.decode(r) for r in c.execute('SELECT * FROM center_jobs ORDER BY created DESC LIMIT 200')]
        return [{k:v for k,v in r.items() if k not in ('lease','result','question')} for r in rows if self.visible(user_id,r)][:30]
    def claim(self):
        now=time.time()
        with closing(self.center.connect()) as c,c:
            c.execute('BEGIN IMMEDIATE');c.execute("UPDATE center_jobs SET status='fallback',reason='deadline_exceeded',lease='' WHERE status IN ('queued','running') AND deadline<=?",(now,))
            if c.execute("SELECT 1 FROM center_jobs WHERE status='running'").fetchone():return None
            r=c.execute("SELECT * FROM center_jobs WHERE status='queued' ORDER BY created LIMIT 1").fetchone()
            if not r:return None
            lease=secrets.token_hex(12);c.execute("UPDATE center_jobs SET status='running',lease=? WHERE id=?",(lease,r['id']));row=self.decode(r);row['lease']=lease;return row
    def live(self,job):
        with closing(self.center.connect()) as c:r=c.execute('SELECT status,lease,deadline FROM center_jobs WHERE id=?',(job['id'],)).fetchone()
        return bool(r and r['status']=='running' and r['lease']==job['lease'] and r['deadline']>time.time())
    def append_step(self,identifier,lease,step):
        with closing(self.center.connect()) as c,c:
            c.execute('BEGIN IMMEDIATE');r=c.execute('SELECT status,lease FROM center_jobs WHERE id=?',(identifier,)).fetchone()
            if not r or r['status']!='running' or r['lease']!=lease:return False
            c.execute('INSERT INTO center_steps(job_id,document) VALUES(?,?)',(identifier,json.dumps(step,ensure_ascii=False)));return True
    def record_call(self,job_id,call):
        with closing(self.center.connect()) as c,c:
            c.execute('INSERT OR IGNORE INTO center_calls VALUES(?,?,?)',(job_id+'|'+call.get('call_id','')+'|'+call['task'],job_id,json.dumps(call,ensure_ascii=False)))
    def finish(self,identifier,lease,result,status='completed',reason=''):
        with closing(self.center.connect()) as c,c:
            c.execute('BEGIN IMMEDIATE');row=c.execute('SELECT * FROM center_jobs WHERE id=?',(identifier,)).fetchone()
            if not row or row['status']!='running' or row['lease']!=lease:return False
            query=json.loads(row['query_json'])
            user=self.center.user(row['owner'])
            if not user or user['role'] not in ('admin','analyst') or not set(query['sensors']).issubset(self.center.scope(row['owner'])):result={};status='denied';reason='authorization_changed'
            elif row['deadline']<=time.time():
                from utils.attack_story import build_story
                facts=result.get('story',{}).get('facts',[])
                result={**result,'story':build_story(facts,None)};status='fallback';reason='deadline_exceeded'
            c.execute('UPDATE center_jobs SET status=?,reason=?,result_json=?,lease=? WHERE id=?',(status,reason,json.dumps(result,ensure_ascii=False),'',identifier));return True
    def cancel(self,user_id,identifier):
        row=self.get(user_id,identifier);user=self.center.user(user_id)
        if not row or not user or user['role'] not in ('admin','analyst') or row['owner']!=user_id and user['role']!='admin':raise PermissionError('cancel_denied')
        with closing(self.center.connect()) as c,c:c.execute("UPDATE center_jobs SET status='cancelled',reason='user_cancelled',lease='' WHERE id=? AND status IN ('queued','running')",(identifier,))
        return True
    def feedback(self,user_id,identifier,revision,verdict,note):
        row=self.get(user_id,identifier)
        if not row or self.center.user(user_id)['role'] not in ('admin','analyst'):raise PermissionError('feedback_denied')
        if row['status']!='completed':raise ValueError('job_not_completed')
        if type(revision) is not int or verdict not in ('accepted','incorrect','uncertain') or not isinstance(note,str) or len(note)>500:raise ValueError('feedback_invalid')
        with closing(self.center.connect()) as c,c:
            c.execute('BEGIN IMMEDIATE');r=c.execute('SELECT revision FROM center_feedback WHERE job_id=?',(identifier,)).fetchone()
            if revision!=(r[0] if r else 0):raise ValueError('revision_conflict')
            row={'job_id':identifier,'revision':revision+1,'verdict':verdict,'note':clean(note,500),'actor':user_id,'created':time.time()}
            c.execute('INSERT OR REPLACE INTO center_feedback VALUES(?,?,?,?,?,?)',tuple(row.values()));c.execute('INSERT INTO center_feedback_audit(job_id,document,created) VALUES(?,?,?)',(identifier,json.dumps(row,ensure_ascii=False),time.time()))
        return row
