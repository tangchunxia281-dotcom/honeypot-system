"""Independent human reviews, scheduled summaries, and evaluation provenance."""
import json
import secrets
import time
from contextlib import closing
from utils.ai_store import ensure_schema
from utils.ai_detection import ATTACK_TYPES


class TeamStore:
    def __init__(self,analyst):self.analyst=analyst
    def connect(self):
        c=self.analyst.connect()
        try:ensure_schema(c,self.analyst.path,'team-v1',self.schema);return c
        except Exception:c.close();raise
    @staticmethod
    def schema(c):
        c.executescript('''
            CREATE TABLE IF NOT EXISTS detection_reviews(id TEXT PRIMARY KEY,revision INTEGER,label TEXT,attack_type TEXT,note TEXT,actor TEXT,updated REAL,sample_json TEXT);
            CREATE TABLE IF NOT EXISTS review_audit(id INTEGER PRIMARY KEY,detection_id TEXT,revision INTEGER,label TEXT,attack_type TEXT,note TEXT,actor TEXT,created REAL);
            CREATE TABLE IF NOT EXISTS period_reports(id TEXT PRIMARY KEY,kind TEXT,start REAL,end REAL,task_id TEXT,metrics_json TEXT,created REAL,UNIQUE(kind,start,end));
            CREATE TABLE IF NOT EXISTS period_settings(id INTEGER PRIMARY KEY,enabled INTEGER,period TEXT);
            INSERT OR IGNORE INTO period_settings VALUES(1,1,'hour');
            CREATE TABLE IF NOT EXISTS evaluation_runs(id TEXT PRIMARY KEY,created REAL,mode TEXT,dataset_sha TEXT,metrics_json TEXT);
        ''')
    def disagreements(self,limit=30,before='',view='pending',src_ip=''):
        from utils.ai_detection_store import DetectionStore
        store=DetectionStore(self.analyst.path);store.connect().close()
        with closing(self.connect()) as c:
            clauses=["d.status='completed'", "(d.verdict='uncertain' OR (CAST(json_extract(d.snapshot_json,'$.rule_score') AS INTEGER)>=20)!=(d.verdict='suspicious'))"]
            args=[]
            if src_ip:clauses.append('d.src_ip=?');args.append(src_ip)
            if view=='pending':clauses.append('r.id IS NULL')
            elif view=='reviewed':clauses.append('r.id IS NOT NULL')
            elif view!='all':raise ValueError('view_invalid')
            total=c.execute('SELECT COUNT(*) FROM ai_detections d LEFT JOIN detection_reviews r ON r.id=d.id WHERE '+' AND '.join(clauses),args).fetchone()[0]
            if before:
                stamp,identifier=before.split(':',1);clauses.append('(d.created_at<? OR (d.created_at=? AND d.id<?))');args.extend((float(stamp),float(stamp),identifier))
            rows=c.execute('SELECT d.*,r.label AS human_label,r.attack_type AS human_type,r.note AS human_note,r.revision AS review_revision FROM ai_detections d LEFT JOIN detection_reviews r ON r.id=d.id WHERE '+' AND '.join(clauses)+' ORDER BY d.created_at DESC,d.id DESC LIMIT ?',(*args,limit+1)).fetchall()
        more=len(rows)>limit;out=[]
        for row in rows[:limit]:
            r=store.decode(dict(row));r['disagreement_kind']='insufficient_evidence' if r['verdict']=='uncertain' else 'rule_only' if r['snapshot']['rule_score']>=20 else 'ai_only';out.append(r)
        return {'records':out,'total':total,'next_before':str(out[-1]['created_at'])+':'+out[-1]['id'] if more else ''}
    def review(self,identifier,revision,label,kind,note,actor):
        if not all(isinstance(v,str) for v in (label,kind,note)) or label not in ('attack','benign','uncertain') or kind and kind not in ATTACK_TYPES or not isinstance(note,str) or len(note)>500 or type(revision) is not int:raise ValueError('review_invalid')
        if label=='attack' and not kind:raise ValueError('attack_type_required')
        if label!='attack':kind=''
        from utils.ai_analyst import _clean
        from utils.investigations import Conflict
        note=_clean(note,500)
        with closing(self.connect()) as c,c:
            c.execute('BEGIN IMMEDIATE');row=c.execute('SELECT status,snapshot_json,raw_key FROM ai_detections WHERE id=?',(identifier,)).fetchone()
            if not row or row['status']!='completed':raise ValueError('detection_not_completed')
            old=c.execute('SELECT revision FROM detection_reviews WHERE id=?',(identifier,)).fetchone();expected=old['revision'] if old else 0
            if revision!=expected:raise Conflict('review_version_conflict')
            revision+=1;c.execute('INSERT INTO detection_reviews VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET revision=excluded.revision,label=excluded.label,attack_type=excluded.attack_type,note=excluded.note,actor=excluded.actor,updated=excluded.updated',(identifier,revision,label,kind,note,actor,time.time(),json.dumps({'fields':json.loads(row['snapshot_json'])['fields'],'group':row['raw_key']},ensure_ascii=False)))
            c.execute('INSERT INTO review_audit(detection_id,revision,label,attack_type,note,actor,created) VALUES(?,?,?,?,?,?,?)',(identifier,revision,label,kind,note,actor,time.time()))
        return {'revision':revision,'label':label,'attack_type':kind,'note':note}
    def export_reviews(self):
        with closing(self.connect()) as c:
            rows=c.execute("SELECT * FROM detection_reviews WHERE label!='uncertain' ORDER BY updated DESC LIMIT 500").fetchall()
        return [{'id':r['id'],'label':r['label'],'attack_type':r['attack_type'],**json.loads(r['sample_json']),
            'review_note':r['note'],'review_revision':r['revision'],'reviewed_at':r['updated'],'source':'human_review','split':'unassigned'} for r in rows]
    def period_config(self,enabled=None,period=None):
        with closing(self.connect()) as c,c:
            if enabled is not None:
                if type(enabled) is not bool or period not in ('hour','day'):raise ValueError('schedule_invalid')
                c.execute('UPDATE period_settings SET enabled=?,period=? WHERE id=1',(int(enabled),period))
            r=dict(c.execute('SELECT * FROM period_settings').fetchone());r['enabled']=bool(r['enabled']);return r
    def periods(self):
        with closing(self.connect()) as c:rows=[dict(r) for r in c.execute('SELECT * FROM period_reports ORDER BY end DESC LIMIT 30')]
        for r in rows:
            r['metrics']=json.loads(r.pop('metrics_json'));job=self.analyst.get(r['task_id']) if r['task_id'] else None
            r['ai_status']=job['status'] if job else 'waiting_index' if r['metrics'].get('index_lag') or r['metrics'].get('scan_error') else 'waiting_capacity' if r['metrics']['total_indexed'] else 'no_evidence';r['ai_result']=job['result'] if job else {};r['ai_call_id']=job['call_id'] if job else ''
        return {'settings':self.period_config(),'reports':rows}
    def reserve_period(self,kind,start,end,metrics):
        identifier=secrets.token_hex(12)
        with closing(self.connect()) as c,c:
            c.execute('BEGIN IMMEDIATE')
            old=c.execute('SELECT id FROM period_reports WHERE kind=? AND start=? AND end=?',(kind,start,end)).fetchone()
            if old:return None
            c.execute('INSERT INTO period_reports VALUES(?,?,?,?,?,?,?)',(identifier,kind,start,end,'',json.dumps(metrics,ensure_ascii=False),time.time()))
        return identifier
    def period_task(self,identifier,task_id):
        with closing(self.connect()) as c,c:c.execute('UPDATE period_reports SET task_id=? WHERE id=?',(task_id,identifier))
    def record_evaluation(self,run):
        identifier=run['run_id']
        with closing(self.connect()) as c,c:c.execute('INSERT OR REPLACE INTO evaluation_runs VALUES(?,?,?,?,?)',(identifier,time.time(),run['mode'],run['dataset_sha256'],json.dumps(run,ensure_ascii=False)))
        return identifier
    def evaluations(self):
        with closing(self.connect()) as c:rows=[json.loads(r[0]) for r in c.execute('SELECT metrics_json FROM evaluation_runs ORDER BY created DESC LIMIT 12')]
        return rows
