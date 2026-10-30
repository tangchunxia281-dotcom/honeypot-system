"""Five-entry analyst workspace; local evidence is the canonical navigation anchor."""
import hashlib
import json
import re
import sqlite3
import threading
from contextlib import closing
from pathlib import Path
from flask import request,jsonify,render_template
from investigation_core.workflow import Workflow
from investigation_core.store import clean,stamp

def register(app,login,csrf):
    state={};guard=threading.Lock()
    def flow():
        with guard:
            if not state:state['flow']=Workflow(app.local_engine())
            return state['flow']
    def route(path,methods=('GET',)):
        from functools import wraps
        def decorate(fn):
            @wraps(fn)
            def safe(*args,**kwargs):
                try:return fn(*args,**kwargs)
                except (ValueError,TypeError) as error:
                    code=409 if str(error)=='revision_conflict' else 400
                    return jsonify(error=str(error)[:160]),code
                except PermissionError:return jsonify(error='scope_denied'),403
                except sqlite3.Error:return jsonify(error='storage_unavailable'),503
            app.add_url_rule(path,'workspace_'+fn.__name__,login(csrf(safe)),methods=list(methods));return fn
        return decorate
    def body():
        p=request.get_json(silent=True)
        if not isinstance(p,dict):raise ValueError('json_object_required')
        return p
    def query():return {k:request.args[k] for k in ('ip','session','term','start','end','kind','origin','channel') if request.args.get(k)}
    @app.get('/workspace/<view>')
    @login
    def workspace_page(view):
        if view not in ('overview','events','sessions','investigate','settings'):return '页面不存在',404
        return render_template('workspace.html',workspace_view=view)
    @route('/api/workspace/overview')
    def overview():
        f=flow();q=query();where,args=f.store.query(f.engine.owner,q)
        with closing(f.store.connect()) as c:
            total=c.execute('SELECT COUNT(*) FROM evidence WHERE '+where,args).fetchone()[0]
            channels={r[0]:r[1] for r in c.execute("SELECT json_extract(document,'$.channel'),COUNT(*) FROM evidence WHERE "+where+" GROUP BY json_extract(document,'$.channel')",args)}
        return jsonify(total=total,channels=channels,recent=f.store.search(f.engine.owner,q,8)['records'],cases=f.listing(q)[:5],index=f.engine.health,scope='本机已索引记录数，不等于攻击次数')
    @route('/api/workspace/events')
    def events():
        f=flow();r=f.store.search(f.engine.owner,query(),30,request.args.get('cursor',''))
        with closing(f.store.connect()) as c:reviews={r['evidence_id']:dict(r) for r in c.execute('SELECT * FROM local_reviews')}
        for row in r['records']:row['review']=reviews.get(row['id'])
        return jsonify(r)
    @route('/api/workspace/events/<identifier>')
    def event(identifier):
        f=flow();r=f.event(identifier);r['rule']={'level':r['rule_level'],'score':None,'signals':[]};r['ai']=None
        if r['table']=='raw_request' and f.engine.source.exists():
            with closing(sqlite3.connect(f.engine.source.as_uri()+'?mode=ro',uri=True,timeout=2)) as c:
                c.row_factory=sqlite3.Row;raw=c.execute('SELECT * FROM raw_request WHERE id=?',(r['record_id'],)).fetchone()
            if raw and stamp(str(raw['create_time']))==r['timestamp']:
                raw=dict(raw);r['rule']['score']=int(raw.get('threat_score') or 0)
                from db.http_requests import calculate_threat_score
                try:headers=json.loads(raw.get('headers') or '{}')
                except (ValueError,TypeError):headers={}
                _,_,signals=calculate_threat_score(raw.get('method',''),raw.get('path',''),raw.get('query_string',''),headers if isinstance(headers,dict) else {},raw.get('body',''))
                r['rule']['signals']=[clean(str(v),160) for v in signals[:8]];r['rule']['signals_source']='current_rule_replay'

        if r['table']=='raw_request':
            # Detection snapshots outlive the active raw table after archival.
            # Verify source, row identity and the original timestamp together.
            from utils import ai_detection
            with closing(ai_detection.STORE.connect()) as c:
                candidates=c.execute('SELECT * FROM ai_detections WHERE raw_request_id=? AND src_ip=? AND session_id=? ORDER BY created_at DESC LIMIT 100',(r['record_id'],r['src_ip'],r['session_id'])).fetchall()
            for candidate in candidates:
                found=ai_detection.STORE.decode(dict(candidate));request_time=found['snapshot'].get('request_time','')
                try:matches=stamp(request_time)==r['timestamp']
                except ValueError:matches=False
                key=hashlib.sha256(f'{f.engine.source}|{r["record_id"]}|{request_time}'.encode()).hexdigest()
                if not matches or key!=found['raw_key']:continue
                r['ai']=found
                r['rule'].update(score=found['snapshot']['rule_score'],signals=found['snapshot'].get('rule_signals',[]),signals_source='captured_snapshot')
                break
        if r['table']=='raw_request':
            from utils.classifier import client
            from db.connection import _config,USE_MYSQL
            source=str(getattr(_config,'DB_PATH',''))if not USE_MYSQL else str(getattr(_config,'DB_HOST',''))+'|'+str(getattr(_config,'DB_NAME',''))
            r['classification']=client().get(dict(source=source,raw_request_id=r['record_id'],request_time=r['timestamp'],ip=r['src_ip'],session_id=r['session_id']))
        return jsonify(r)
    @route('/api/workspace/events/<identifier>/review',('POST',))
    def review(identifier):return jsonify(flow().review_event(identifier,body()))
    @route('/api/workspace/sessions')
    def sessions():
        f=flow();q=query();records=f.store.search(f.engine.owner,q,60)
        from utils.ai_interaction import get_store
        turn_sid=request.args.get('turn_session','')
        if turn_sid and not re.fullmatch(r'[a-f0-9]{32}',turn_sid):raise ValueError('interaction_session_invalid')
        # Apply source and time conditions in SQLite before limiting candidates.
        from datetime import datetime
        from investigation_core.store import ZONE
        bounds={key:datetime.fromisoformat(stamp(q[key])).replace(tzinfo=ZONE).timestamp() for key in ('start','end') if q.get(key)}
        if 'end' in bounds:bounds['end']+=1  # UI timestamps have second precision.
        turns=get_store().listing(100 if turn_sid else 50,turn_sid,src_ip=q.get('ip',''),start=bounds.get('start'),end=bounds.get('end'))
        return jsonify(**records,turns=turns['records'],interaction_scope='交互按独立交互会话、来源与时间先筛选，再显示最近50条（指定交互会话最多100条）。采集会话和交互会话编号不同；采集关键词不用于筛选交互，同IP/同时段不证明同一会话。')
    @route('/api/workspace/cases',('GET','POST'))
    def cases():
        f=flow()
        if request.method=='GET':return jsonify(records=f.listing(query()))
        return jsonify(f.create_case(body())),201
    @route('/api/workspace/cases/<identifier>',('GET','POST'))
    def case(identifier):
        f=flow();return jsonify(f.update_case(identifier,body()) if request.method=='POST' else f.get_case(identifier))
    @route('/api/workspace/cases/<identifier>/ask',('POST',))
    def ask(identifier):
        f=flow();case=f.get_case(identifier);p=body()
        if case['status']=='closed':raise ValueError('case_closed_reopen_first')
        job=f.engine.jobs.create(f.engine.owner,p.get('question'),case['query'],p.get('request_id'))
        f.link_job(identifier,job['id']);f.engine.start();return jsonify(job),202
    @route('/api/workspace/cases/<identifier>/export')
    def export(identifier):
        f=flow();case=f.get_case(identifier);case['jobs']=[f.engine.jobs.get(f.engine.owner,j) for j in case['job_ids']]
        case['scope_note']='evidence为建案时快照；补查任务可在固定范围读取启动时当前索引，引用归任务结果。'
        f.store.audit(f.engine.owner,'export_case',identifier)
        return app.response_class(json.dumps(case,ensure_ascii=False,indent=2),mimetype='application/json',headers={'Content-Disposition':'attachment; filename="case.json"'})
