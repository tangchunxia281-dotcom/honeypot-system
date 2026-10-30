"""Finite ERP bait with isolated cookie and protected per-session task IDs."""
import json
import re
import secrets
from flask import request,jsonify,make_response
from utils import local_ai
from utils.ai_detection import sanitize
from utils.ai_interaction import get_store,choose
from utils.decoy_profiles import business_payload


def register(app,get_ip):
    @app.route('/api/erp/<resource>',methods=['GET','POST'])
    @app.route('/api/erp/jobs/<job_id>',methods=['GET'])
    def business(resource='job',job_id=None):
        if not local_ai.SETTINGS.get('web_interaction_enabled',False):return jsonify(error='Not Found'),404
        if request.content_length and request.content_length>4096:return jsonify(error='Payload Too Large'),413
        if len(request.query_string)>4096:return jsonify(error='URI Too Long'),414
        if resource not in ('status','catalog','login','orders','export','job'):return jsonify(error='Not Found'),404
        if resource in ('login','export') and request.method!='POST':return jsonify(error='Method Not Allowed'),405
        if resource=='login':
            payload=request.get_json(silent=True)
            if not isinstance(payload,dict) or not isinstance(payload.get('username'),str) or not 1<=len(payload['username'])<=80 or not isinstance(payload.get('password',''),str) or len(payload.get('password',''))>200:return jsonify(error='Invalid login format'),400
        token=request.cookies.get('erp_sid','');token=token if re.fullmatch(r'[a-f0-9]{32}',token) else ''
        try:
            store=get_store();turn=store.begin(token,get_ip(),'web',local_ai.SETTINGS,sanitize(request.method+' '+request.path,800)[0])
            if turn['reason']:return jsonify(error='Service Busy',reason=turn['reason']),429
            state=dict(turn['state']);state.setdefault('persona_seed',secrets.token_hex(12));call={};source='program';reason='';strategy=resource
            if resource=='job':
                if not re.fullmatch(r'[a-f0-9]{24}',job_id or '') or state.get('export_id')!=job_id:payload={'error':'Job Not Found'};code=404
                else:state['export_status']='ready';payload,code=business_payload(state,resource,resource)
            else:
                action='business_'+resource;call=choose('web_reply',{'resource':resource,'method':request.method,'virtual_profile':state.get('profile_id','new'),'authenticated':bool(state.get('business_authenticated'))},(action,'service_busy'),turn['session_id'],get_ip())
                source='model' if call['status']=='success' else 'fallback';reason=call.get('reason','');strategy=call.get('data',{}).get('strategy',action) if source=='model' else action
                if strategy=='service_busy':payload={'error':'Service Busy'};code=503
                else:payload,code=business_payload(state,resource,strategy)
            store.complete(turn,state,source,strategy,reason,json.dumps(payload,ensure_ascii=False),call.get('call_id',''))
            response=make_response(jsonify(payload),code);response.set_cookie('erp_sid',turn['session_id'],max_age=local_ai.SETTINGS['interaction_ttl'],httponly=True,samesite='Strict',secure=request.is_secure,path='/api/erp');response.headers['Cache-Control']='no-store';return response
        except Exception:return jsonify(error='Service Unavailable'),503
