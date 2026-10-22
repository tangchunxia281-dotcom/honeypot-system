import secrets
import json
import sqlite3
import time
from datetime import timedelta
from contextlib import closing
from flask import Flask,g,jsonify,request,session
from team_center.auth import guards

def create_app(store,secret):
    app=Flask(__name__);app.secret_key=secret
    app.config.update(MAX_CONTENT_LENGTH=262144,SESSION_COOKIE_NAME='honeypot_center',SESSION_COOKIE_HTTPONLY=True,SESSION_COOKIE_SAMESITE='Strict',PERMANENT_SESSION_LIFETIME=timedelta(minutes=30))
    login,role=guards(store);attempts={}
    @app.before_request
    def body_limit():
        if request.content_length is not None and request.content_length>262144:return jsonify(error='request_too_large'),413
        if request.is_json and request.method=='POST' and not isinstance(request.get_json(silent=True),dict):return jsonify(error='json_object_required'),400
    @app.errorhandler(ValueError)
    def invalid(e):return jsonify(error=str(e)[:100]),400
    @app.errorhandler(PermissionError)
    def denied(e):return jsonify(error='scope_denied'),403
    @app.errorhandler(sqlite3.Error)
    def unavailable(e):return jsonify(error='storage_unavailable'),503
    @app.after_request
    def headers(response):
        response.headers['Cache-Control']='no-store';response.headers['X-Content-Type-Options']='nosniff';response.headers['X-Frame-Options']='DENY';return response
    @app.get('/api/session')
    def identity():
        if not session.get('csrf'):session['csrf']=secrets.token_urlsafe(32)
        return jsonify(user=store.user(session.get('uid','')),csrf=session['csrf'])
    @app.post('/login')
    def authenticate():
        p=request.get_json(silent=True) or {};addr=request.remote_addr;now=time.time()
        for k in list(attempts):
            if now-attempts[k][0]>300:attempts.pop(k)
        if len(attempts)>2048:attempts.clear()
        old,count=attempts.get(addr,(now,0))
        if count>=10:return jsonify(error='login_rate_limit'),429
        if not session.get('csrf') or request.headers.get('X-CSRF-Token')!=session['csrf']:return jsonify(error='csrf_invalid'),403
        user=store.authenticate(p.get('name'),p.get('password'))
        if not user:attempts[addr]=(old,count+1);return jsonify(error='invalid_credentials'),401
        session.clear();session['uid']=user['id'];session['csrf']=secrets.token_urlsafe(32);session.permanent=True;attempts.pop(addr,None);store.audit(user['id'],'login','');return jsonify(user=user,csrf=session['csrf'])
    @app.post('/logout')
    @login
    def logout():session.clear();return jsonify(ok=True)
    @app.get('/api/sensors')
    @login
    def sensors():return jsonify(records=store.sensors(g.user['id']))
    @app.post('/api/sensors')
    @role('admin')
    def issue_sensor():
        p=request.get_json(silent=True) or {};r=store.issue_sensor(p.get('name',''));store.audit(g.user['id'],'issue_sensor',r['id']);return jsonify(r),201
    @app.post('/api/sensors/<identifier>/revoke')
    @role('admin')
    def revoke_sensor(identifier):store.revoke_sensor(identifier);store.audit(g.user['id'],'revoke_sensor',identifier);return jsonify(ok=True)
    @app.get('/api/users')
    @role('admin')
    def users():
        with closing(store.connect()) as c:return jsonify(records=[dict(r) for r in c.execute('SELECT id,name,role,active FROM users')])
    @app.post('/api/users')
    @role('admin')
    def create_user():
        p=request.get_json(silent=True) or {};r=store.create_user(p.get('name'),p.get('password'),p.get('role'),p.get('sensors',[]));store.audit(g.user['id'],'create_user',r['id']);return jsonify(r),201
    @app.post('/api/users/<identifier>')
    @role('admin')
    def update_user(identifier):
        if identifier==g.user['id']:raise ValueError('cannot_disable_self')
        p=request.get_json(silent=True) or {};store.update_user(identifier,p.get('active'),p.get('sensors',[]));store.audit(g.user['id'],'update_user',identifier);return jsonify(ok=True)
    @app.post('/api/ingest')
    def ingest():
        sensor=store.sensor_auth(request.headers.get('Authorization','').removeprefix('Bearer '))
        if not sensor:return jsonify(error='sensor_auth_failed'),401
        p=request.get_json(silent=True)
        if not isinstance(p,dict) or set(p)-{'batch_id','records','health','metrics'}:raise ValueError('ingest_invalid')
        return jsonify(store.ingest(sensor['id'],p.get('batch_id'),p.get('records'),p.get('health',{}),p.get('metrics',[])))
    @app.post('/api/heartbeat')
    def heartbeat():
        sensor=store.sensor_auth(request.headers.get('Authorization','').removeprefix('Bearer '))
        if not sensor:return jsonify(error='sensor_auth_failed'),401
        p=request.get_json(silent=True) or {};health=p.get('health')
        if not isinstance(health,dict) or set(health)-{'pending','paused','error','cursor'} or len(jsonify(health).get_data())>1000:raise ValueError('health_invalid')
        from team_center.store import clean
        with closing(store.connect()) as c,c:c.execute('UPDATE sensors SET last_seen=?,health=? WHERE id=?',(time.time(),json.dumps({k:clean(str(v),300) if k=='error' else v for k,v in health.items()}),sensor['id']))
        return jsonify(ok=True)
    def query_args():
        q={k:request.args[k] for k in ('start','end','ip','session','kind','term','origin') if k in request.args}
        if 'sensor' in request.args:q['sensors']=[request.args['sensor']]
        return q
    @app.get('/api/evidence')
    @login
    def evidence():return jsonify(store.search(g.user['id'],query_args(),int(request.args.get('limit',20)),request.args.get('cursor','')))
    @app.get('/api/evidence/<identifier>')
    @login
    def detail(identifier):
        row=store.evidence(g.user['id'],identifier)
        return (jsonify(row),200) if row else (jsonify(error='not_found'),404)
    app.center_store=store;app.center_guards=(login,role);app.center_query=query_args
    from team_center.api import register
    register(app,store)
    return app
