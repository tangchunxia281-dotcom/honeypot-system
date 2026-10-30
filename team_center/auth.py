import functools
import hmac
from flask import g,jsonify,request,session

def guards(store):
    def login(fn):
        @functools.wraps(fn)
        def wrapped(*a,**kw):
            g.user=store.user(session.get('uid',''))
            if not g.user:return jsonify(error='login_required'),401
            if request.method!='GET' and (not session.get('csrf') or not hmac.compare_digest(str(session['csrf']),request.headers.get('X-CSRF-Token',''))):return jsonify(error='csrf_invalid'),403
            return fn(*a,**kw)
        return wrapped
    def role(*roles):
        def decorate(fn):
            @login
            @functools.wraps(fn)
            def wrapped(*a,**kw):
                if g.user['role'] not in roles:return jsonify(error='role_denied'),403
                return fn(*a,**kw)
            return wrapped
        return decorate
    return login,role
