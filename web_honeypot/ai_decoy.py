"""A stateful preview bait. Never fetch URLs, run commands or expose model APIs."""
import json
import hashlib
import re
import secrets
from flask import request, jsonify, make_response
from utils import local_ai
from utils.ai_detection import sanitize
from utils.ai_interaction import get_store,choose,WEB_STRATEGIES

COOKIE='preview_sid'


def register(app,get_ip):
    @app.route('/api/preview',methods=['GET','POST'])
    @app.route('/api/preview/jobs/<job_id>',methods=['GET'])
    def ai_preview(job_id=None):
        if not local_ai.SETTINGS.get('web_interaction_enabled',False):return jsonify(error='Not Found'),404
        if request.content_length and request.content_length>4096:return jsonify(error='Payload Too Large'),413
        if len(request.query_string)>4096:return jsonify(error='URI Too Long'),414
        token=request.cookies.get(COOKIE,'')
        if not re.fullmatch(r'[0-9a-f]{32}',token):token=''
        url=request.args.get('url') or request.args.get('target') or ''
        if request.method=='POST':
            data=request.get_json(silent=True) if request.is_json else request.form
            if isinstance(data,dict) or hasattr(data,'get'):url=data.get('url') or data.get('target') or url
        if not isinstance(url,str):return jsonify(error='Invalid URL'),400
        if len(url)>1000:return jsonify(error='Invalid URL'),400
        preview=sanitize(request.method+' '+request.path+' '+url,800)[0]
        try:
            store=get_store();turn=store.begin(token,get_ip(),'web',local_ai.SETTINGS,preview)
            if turn['reason']:return jsonify(error='Service Busy',reason=turn['reason']),429
            state=dict(turn['state']);call={};source='program';reason='';strategy='job_lookup'
            if job_id is not None:
                if not re.fullmatch(r'[0-9a-f]{24}',job_id) or state.get('job_id')!=job_id:
                    payload={'error':'Job Not Found'};code=404
                else:
                    # Deterministic transition: the same session always observes the same job.
                    state['job_status']='ready'
                    payload={'job_id':job_id,'status':'ready','title':'Preview cache','content':'Preview generated from cache.'};code=200
            else:
                call=choose('web_reply',{'method':request.method,'target':sanitize(url,1000)[0],
                                        'prior_job_status':state.get('job_status','none')},
                            WEB_STRATEGIES if url.strip() else ('format_error',),turn['session_id'],get_ip())
                source='model' if call['status']=='success' else 'fallback';reason=call.get('reason','')
                strategy=call.get('data',{}).get('strategy','preview_pending' if url.strip() else 'format_error') if source=='model' else ('preview_pending' if url.strip() else 'format_error')
                if strategy=='preview_pending':
                    # Idempotent per-session job; no target content or real secrets enter state.
                    target_hash=hashlib.sha256(url.encode()).hexdigest()
                    if state.get('target_hash')!=target_hash:
                        state.update(job_id=secrets.token_hex(12),job_status='queued',target_hash=target_hash)
                    payload={'job_id':state['job_id'],'status':state['job_status'],'poll':'/api/preview/jobs/'+state['job_id']};code=202 if state['job_status']=='queued' else 200
                elif strategy=='format_error':payload={'error':'Invalid preview URL'};code=400
                else:payload={'error':'Preview service temporarily busy'};code=503
            store.complete(turn,state,source,strategy,reason,json.dumps(payload,ensure_ascii=False),call.get('call_id',''))
            response=make_response(jsonify(payload),code)
            response.set_cookie(COOKIE,turn['session_id'],max_age=local_ai.SETTINGS['interaction_ttl'],httponly=True,
                                samesite='Strict',secure=request.is_secure,path='/api/preview')
            response.headers['Cache-Control']='no-store'
            return response
        except Exception:
            # A failed audit or stale reservation may not deliver an uncommitted AI decision.
            return jsonify(error='Preview service temporarily unavailable'),503
