"""Authenticated workbench endpoints; no arbitrary commands or model endpoints."""
import ipaddress
import json
import re
from pathlib import Path
from flask import request,jsonify,render_template
from utils import ai_analyst,local_ai
from utils.workbench_store import WorkbenchStore
from utils.investigations import Conflict
from utils.evidence_selection import graph


def register(app,login,csrf,safe,owner):
    def team():return WorkbenchStore(ai_analyst.get_store())
    @app.route('/ai/workbench')
    @login
    def ai_workbench_page():return render_template('ai_workbench.html')
    @app.get('/api/workbench/graph')
    @login
    @safe
    def api_team_graph():
        ip=request.args.get('ip','');term=request.args.get('term','')
        if len(term)>80:return jsonify(code=1,msg='关键词过长'),400
        try:ip=str(ipaddress.ip_address(ip)) if ip else ''
        except ValueError:return jsonify(code=1,msg='来源IP无效'),400
        store=ai_analyst.get_store();pool=store.search(ip,term,200);reports=store.related_reports([r['id'] for r in pool['records']])
        for p in reports:
            row=store.get(p['id']);p['record_ids']=[r['id'] for r in row['context']['records']]
        data=graph(pool['records'],reports);data['total_matching']=pool['total_matching'];data['reports']=reports
        return jsonify(code=0,data=data)
    @app.get('/api/workbench/evidence/<identifier>')
    @login
    @safe
    def api_team_evidence(identifier):
        if not re.fullmatch(r'[a-f0-9]{24}',identifier):return jsonify(code=1,msg='编号无效'),400
        from contextlib import closing
        with closing(ai_analyst.get_store().connect()) as c:row=c.execute('SELECT * FROM analyst_evidence WHERE id=?',(identifier,)).fetchone()
        return (jsonify(code=0,data=dict(row)),200) if row else (jsonify(code=1,msg='证据不存在或已经归档，请刷新关联图'),404)
    @app.get('/api/workbench/disagreements')
    @login
    @safe
    def api_team_disagreements():
        try:
            before=request.args.get('before','')
            if before and not re.fullmatch(r'[0-9]{1,12}(?:\.[0-9]{1,10})?:[a-f0-9]{24}',before):raise ValueError()
            ip=request.args.get('ip','');ip=str(ipaddress.ip_address(ip)) if ip else ''
            return jsonify(code=0,data=team().disagreements(before=before,view=request.args.get('view','pending'),src_ip=ip))
        except ValueError:return jsonify(code=1,msg='筛选参数无效'),400
    @app.post('/api/workbench/disagreements/<identifier>')
    @login
    @csrf
    @safe
    def api_team_disagreement_review(identifier):
        if not re.fullmatch(r'[a-f0-9]{24}',identifier):return jsonify(code=1,msg='编号无效'),400
        p=request.get_json(silent=True)
        if not isinstance(p,dict):return jsonify(code=1,msg='内容无效'),400
        try:return jsonify(code=0,data=team().review(identifier,p.get('revision',0),p.get('label'),p.get('attack_type',''),p.get('note',''),owner()))
        except Conflict:return jsonify(code=1,msg='其他人已经复核，请刷新后再保存'),409
        except (ValueError,TypeError):return jsonify(code=1,msg='复核内容无效'),400
    @app.get('/api/workbench/review-samples')
    @login
    @safe
    def api_team_review_export():
        text='\n'.join(json.dumps(r,ensure_ascii=False) for r in team().export_reviews())+'\n'
        return app.response_class(text,mimetype='application/x-ndjson',headers={'Content-Disposition':'attachment; filename="reviewed-samples.jsonl"'})
    @app.get('/api/workbench/periods')
    @login
    @safe
    def api_team_periods():return jsonify(code=0,data=team().periods())
    @app.post('/api/workbench/periods/config')
    @login
    @csrf
    @safe
    def api_team_period_config():
        p=request.get_json(silent=True)
        if not isinstance(p,dict) or type(p.get('enabled')) is not bool or p.get('period') not in ('hour','day'):return jsonify(code=1,msg='配置无效'),400
        try:return jsonify(code=0,data=team().period_config(p.get('enabled'),p.get('period')))
        except ValueError:return jsonify(code=1,msg='配置无效'),400
    @app.post('/api/workbench/periods/run')
    @login
    @csrf
    @safe
    def api_team_period_run():
        from utils.periodic_analysis import make_period
        p=request.get_json(silent=True)
        if not isinstance(p,dict) or p.get('period') not in ('hour','day'):return jsonify(code=1,msg='周期无效'),400
        ai_analyst.ingest_once();result=make_period(ai_analyst.get_store(),p['period'],manual=True);ai_analyst.start_worker();ai_analyst._wake.set();return jsonify(code=0,data=result)
    @app.get('/api/workbench/noise')
    @login
    @safe
    def api_team_noise():
        from utils.alert_noise import NoiseGate
        return jsonify(code=0,data=NoiseGate(ai_analyst.get_store()).snapshot())
    @app.get('/api/workbench/evaluations')
    @login
    @safe
    def api_team_evaluations():
        data=team().evaluations()
        return jsonify(code=0,data=[{k:v for k,v in r.items() if k!='cases'} for r in data])
    @app.post('/api/workbench/evaluate-rules')
    @login
    @csrf
    @safe
    def api_team_evaluate_rules():
        from utils.evaluation import run
        result=run(Path(__file__).resolve().parents[1]/'evaluation/fixtures.jsonl');team().record_evaluation(result)
        return jsonify(code=0,data={k:v for k,v in result.items() if k!='cases'})
    @app.get('/api/workbench/evaluations/<identifier>')
    @login
    @safe
    def api_team_evaluation_detail(identifier):
        for row in team().evaluations():
            if row['run_id']==identifier:return jsonify(code=0,data=row)
        return jsonify(code=1,msg='评测不存在'),404
    @app.get('/api/workbench/decoys')
    @login
    @safe
    def api_team_decoys():
        from utils.decoy_profiles import PROFILES,profile
        import os
        active=profile(os.environ.get('HONEYPOT_PERSONA_SEED','team-sensor'))
        service=next((name for name,state in active['services'].items() if state=='running'),next(iter(active['services'])))
        return jsonify(code=0,data={'profiles':PROFILES,'active':active,'ssh_commands':['diag','appctl status','appctl stop '+service,'systemctl status '+service,'appctl start '+service,'appctl logs','dbdiag'],
            'web_routes':['GET /api/erp/status','GET /api/erp/catalog','POST /api/erp/login','GET /api/erp/orders','POST /api/erp/export','GET /api/erp/jobs/<id>'],'scope':'全部是合成数据和虚拟状态，不执行主机命令或真实登录。'})
