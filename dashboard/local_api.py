"""Local investigation routes, using the dashboard login and CSRF boundary."""
import json
import os
import sqlite3
import threading
from pathlib import Path
from flask import request,jsonify,render_template
from investigation_core.local import LocalInvestigation
from utils.attack_story import build_story
from utils.ai_effectiveness import snapshot

def register(app,login,csrf):
    lock=threading.Lock();state={}
    @app.before_request
    def local_body_limit():
        if request.path.startswith(('/api/local/','/api/workspace/')) and request.content_length and request.content_length>262144:
            return jsonify(error='request_too_large'),413
    def engine():
        with lock:
            if not state:
                from app_config import config
                root=Path(__file__).resolve().parents[1]
                state['engine']=LocalInvestigation(os.environ.get('HONEYPOT_LOCAL_INDEX',root/'database/investigation.sqlite'),config['default'].DB_PATH)
            return state['engine']
    def query():return {k:request.args[k] for k in ('ip','session','term','start','end','kind','origin','channel') if request.args.get(k)}
    def body():
        p=request.get_json(silent=True)
        if not isinstance(p,dict):raise ValueError('json_object_required')
        return p
    def safe(fn):
        from functools import wraps
        @wraps(fn)
        def wrapped(*a,**kw):
            try:return fn(*a,**kw)
            except PermissionError:return jsonify(error='scope_denied'),403
            except (ValueError,TypeError) as e:return jsonify(error=str(e)[:160]),400
            except sqlite3.Error:return jsonify(error='storage_unavailable'),503
        return wrapped
    def route(path,methods=('GET',)):
        def wrap(fn):
            app.add_url_rule(path,'local_'+fn.__name__,login(csrf(safe(fn))),methods=list(methods));return fn
        return wrap
    @route('/ai/local')
    def page():return render_template('local_investigation.html')
    @route('/api/local/status')
    def status():
        e=engine();return jsonify(e.health)
    @route('/api/local/sync',('POST',))
    def sync():return jsonify(engine().sync())
    @route('/api/local/evidence')
    def evidence():
        e=engine();return jsonify(e.store.search(e.owner,query(),min(60,max(1,int(request.args.get('limit',20)))),request.args.get('cursor','')))
    @route('/api/local/evidence/<identifier>')
    def detail(identifier):
        e=engine();r=e.store.evidence(e.owner,identifier);return (jsonify(r),200) if r else (jsonify(error='not_found'),404)
    @route('/api/local/story')
    def story():
        e=engine();r=e.store.search(e.owner,query(),60);s=build_story(r['records']);s['total_matching']=r['total'];return jsonify(s)
    @route('/api/local/jobs',('GET','POST'))
    def jobs():
        e=engine()
        if request.method=='GET':return jsonify(records=e.jobs.listing(e.owner))
        p=body()
        if set(p)-{'question','query','request_id'}:raise ValueError('unknown_fields')
        r=e.jobs.create(e.owner,p.get('question'),p.get('query',{}),p.get('request_id'));e.start();return jsonify(r),202
    @route('/api/local/jobs/<identifier>')
    def job(identifier):
        e=engine();r=e.jobs.get(e.owner,identifier);return (jsonify(r),200) if r else (jsonify(error='not_found'),404)
    @route('/api/local/jobs/<identifier>/cancel',('POST',))
    def cancel(identifier):
        e=engine();e.jobs.cancel(e.owner,identifier);return jsonify(ok=True)
    @route('/api/local/jobs/<identifier>/feedback',('POST',))
    def feedback(identifier):
        e=engine();p=body();return jsonify(e.jobs.feedback(e.owner,identifier,p.get('revision'),p.get('verdict'),p.get('note','')))
    @route('/api/local/jobs/<identifier>/export')
    def export(identifier):
        e=engine();r=e.jobs.get(e.owner,identifier)
        if not r:return jsonify(error='not_found'),404
        r.pop('owner',None);e.store.audit(e.owner,'export_investigation',identifier)
        return app.response_class(json.dumps(r,ensure_ascii=False,indent=2),mimetype='application/json',headers={'Content-Disposition':'attachment; filename="investigation.json"'})
    @route('/api/local/effects')
    def effects():
        e=engine();return jsonify(snapshot(e.store,e.jobs,e.owner,query()))
    app.start_local_investigation=lambda:engine().start()
    app.local_engine=engine
