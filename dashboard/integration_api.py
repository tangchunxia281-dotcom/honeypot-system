"""Optional services and source labels inside the existing five-entry workspace."""
import json
import os
import socket
import sqlite3
from functools import wraps
from pathlib import Path
from flask import jsonify,request
from utils.integration_settings import ROOT,LOCK,parser,write,cloud_public,save_cloud,protocol_settings,save_protocols
from utils.source_targets import Targets

def register(app,login,csrf):
    def rootconfig():return Path(app.config.get('INTEGRATION_CONFIG')or os.environ.get('HONEYPOT_CONFIG',ROOT/'honeypot.ini'))
    def aiconfig():return Path(app.config.get('AI_SETUP_CONFIG')or os.environ.get('HONEYPOT_AI_CONFIG',ROOT/'ai.local.ini'))
    def targetstore():return Targets(app.local_engine().store.path)
    def body():
        if request.content_length is not None and request.content_length>8192:raise ValueError('request_too_large')
        raw=request.stream.read(8193)
        if len(raw)>8192 or request.mimetype!='application/json':raise ValueError('json_object_required')
        p=json.loads(raw)
        if not isinstance(p,dict):raise ValueError('json_object_required')
        return p
    def route(path,methods=('GET',)):
        def decorate(fn):
            @wraps(fn)
            def safe(*args,**kwargs):
                try:return fn(*args,**kwargs)
                except (ValueError,TypeError)as error:return jsonify(error=str(error)[:100]),409 if str(error)=='revision_conflict'else 400
                except (OSError,sqlite3.Error):return jsonify(error='storage_or_service_unavailable'),503
            protected=csrf(safe)
            @wraps(fn)
            def bounded(*args,**kwargs):
                if request.method=='POST'and (not request.headers.get('X-CSRF-Token')or (request.content_length or 0)>8192):return jsonify(error='csrf_or_body_limit'),403
                return protected(*args,**kwargs)
            app.add_url_rule(path,'integrations_'+fn.__name__,login(bounded),methods=list(methods));return fn
        return decorate
    @route('/api/integrations/targets',('GET','POST'))
    def targets():
        store=targetstore()
        if request.method=='POST':
            row=store.save(body());app.local_engine().store.audit(app.local_engine().owner,'source_target_save',row['ip']);return jsonify(row)
        return jsonify(records=store.listing(request.args.get('q','')[:80]),note='来源标签仅用于复核，不改变网络或防火墙策略。')
    @route('/api/integrations/targets/delete',('POST',))
    def delete():
        p=body();targetstore().delete(p.get('ip',''),p.get('revision'));app.local_engine().store.audit(app.local_engine().owner,'source_target_delete',p['ip']);return jsonify(deleted=True)
    @route('/api/integrations/targets/suggest')
    def suggest():
        e=app.local_engine();q={k:request.args[k]for k in ('ip','session','term','start','end','channel')if request.args.get(k)}
        result=e.store.search(e.owner,q,100);group={}
        for row in result['records']:
            if not row['src_ip']or row['rule_level']not in('medium','high','critical'):continue
            g=group.setdefault(row['src_ip'],{'ip':row['src_ip'],'count':0,'channels':set()});g['count']+=1;g['channels'].add(row['channel'])
        return jsonify(records=[{**g,'channels':sorted(g['channels'])}for g in group.values()],sampled=len(result['records']),total=result['total'],note='只从当前范围最近100条已索引证据提取候选，不自动标注或封禁。')
    @route('/api/integrations/protocols',('GET','POST'))
    def protocols():
        if request.method=='POST':return jsonify(save_protocols(rootconfig(),body().get('services')))
        rows=protocol_settings(rootconfig())
        for row in rows:
            with socket.socket()as s:
                s.settimeout(.1);row['listening']=s.connect_ex(('127.0.0.1',row['port']))==0
        return jsonify(services=rows,restart_required=True,note='端口有监听不等于已完成协议验收；设置保存后重启全部服务生效。')
    @route('/api/integrations/classifier',('GET','POST'))
    def classifier():
        from utils.classifier import client,endpoint,config
        if request.method=='POST':
            p=body()
            if set(p)!={'enabled','url','timeout'}or type(p['enabled'])is not bool or type(p['timeout'])not in(int,float)or not .1<=p['timeout']<=5:raise ValueError('classifier_config_invalid')
            endpoint(p['url'])
            with LOCK:
                path=Path(os.environ.get('HONEYPOT_CLASSIFIER_CONFIG',ROOT/'classifier.ini'));conf=parser(path)
                if not conf.has_section('classifier'):conf.add_section('classifier')
                for k,v in p.items():conf.set('classifier',k,str(v).lower()if k=='enabled'else str(v))
                write(path,conf)
            return jsonify(saved=True,**config())
        return jsonify(client().status())
    @route('/api/integrations/cloud',('GET','POST'))
    def cloud():
        if request.method=='POST':return jsonify(save_cloud(aiconfig(),body()))
        from utils import local_ai
        return jsonify(saved=cloud_public(aiconfig()),running={'provider':local_ai.SETTINGS.get('provider','local'),'model':local_ai.SETTINGS['model'],'enabled':local_ai.SETTINGS['enabled']})
    @route('/api/integrations/cloud/probe',('POST',))
    def probe():
        p=body()
        if p.get('confirm')is not True:raise ValueError('explicit_probe_confirmation_required')
        from utils import local_ai
        result=local_ai.call_model('probe',[{'role':'system','content':'Return JSON only: {"reply":"connection verified"}.'},{'role':'user','content':'Connection test, no evidence attached.'}],'integration-probe')
        return jsonify({**result,'provider':local_ai.SETTINGS.get('provider','local'),'model':local_ai.SETTINGS['model']})
