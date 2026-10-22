import json
from flask import g,jsonify,request,render_template
from team_center.jobs import JobStore
from utils.attack_story import build_story
from utils.ai_effectiveness import snapshot

def register(app,store):
    login,role=app.center_guards;jobs=JobStore(store);app.center_jobs=jobs
    def body():
        p=request.get_json(silent=True)
        if not isinstance(p,dict):raise ValueError('json_object_required')
        return p
    @app.get('/')
    def home():return render_template('center.html')
    @app.get('/api/story')
    @login
    def story():
        pool=store.search(g.user['id'],app.center_query(),60);r=build_story(pool['records']);r['total_matching']=pool['total'];return jsonify(r)
    @app.get('/api/investigations')
    @login
    def investigations():return jsonify(records=jobs.listing(g.user['id']))
    @app.post('/api/investigations')
    @role('admin','analyst')
    def create():
        p=body();return jsonify(jobs.create(g.user['id'],p.get('question'),p.get('query',{}),p.get('request_id'))),202
    @app.get('/api/investigations/<identifier>')
    @login
    def investigation(identifier):
        row=jobs.get(g.user['id'],identifier);return (jsonify(row),200) if row else (jsonify(error='not_found'),404)
    @app.post('/api/investigations/<identifier>/cancel')
    @role('admin','analyst')
    def cancel(identifier):jobs.cancel(g.user['id'],identifier);return jsonify(ok=True)
    @app.post('/api/investigations/<identifier>/feedback')
    @role('admin','analyst')
    def feedback(identifier):
        p=body()
        try:return jsonify(jobs.feedback(g.user['id'],identifier,p.get('revision'),p.get('verdict'),p.get('note','')))
        except ValueError as error:
            if str(error)=='revision_conflict':return jsonify(error='revision_conflict'),409
            raise
    @app.get('/api/investigations/<identifier>/export')
    @login
    def export(identifier):
        row=jobs.get(g.user['id'],identifier)
        if not row:return jsonify(error='not_found'),404
        row.pop('owner',None);store.audit(g.user['id'],'export_investigation',identifier)
        return app.response_class(json.dumps(row,ensure_ascii=False,indent=2),mimetype='application/json',headers={'Content-Disposition':'attachment; filename="investigation.json"'})
    @app.get('/api/effectiveness')
    @login
    def effects():
        filters=app.center_query();filters.update({k:request.args[k] for k in ('model','version') if request.args.get(k)})
        return jsonify(snapshot(store,jobs,g.user['id'],filters))
    @app.get('/api/evaluations')
    @role('admin')
    def evaluations():
        from contextlib import closing
        with closing(store.connect()) as c:return jsonify(records=[json.loads(r[0]) for r in c.execute('SELECT document FROM center_evaluations ORDER BY created DESC LIMIT 12')])
    @app.get('/api/replays')
    @role('admin')
    def replays():
        from contextlib import closing
        with closing(store.connect()) as c:return jsonify(records=[json.loads(r[0]) for r in c.execute('SELECT document FROM center_replays ORDER BY created DESC LIMIT 12')])
    @app.post('/api/replays')
    @role('admin')
    def import_replay():
        from contextlib import closing
        from utils.ai_effectiveness import validate_replay
        import time
        obj=validate_replay(body())
        with closing(store.connect()) as c,c:c.execute('INSERT OR IGNORE INTO center_replays VALUES(?,?,?)',(obj['run_id'],json.dumps(obj,ensure_ascii=False),time.time()))
        store.audit(g.user['id'],'import_replay',obj['run_id']);return jsonify(ok=True)
    return jobs
