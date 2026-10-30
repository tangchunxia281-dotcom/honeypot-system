"""Real Ollama acceptance with fail-fast, isolated data and honest provenance."""
import argparse
import hashlib
import json
import os
import sys
import time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))

def main():
    p=argparse.ArgumentParser();p.add_argument('--skip-prewarm',action='store_true');p.add_argument('--output',default=str(ROOT/'demo-results/active-acceptance'));p.add_argument('--mode',choices=['baseline','active','all'],default='all');p.add_argument('--model',required=True);p.add_argument('--index-db');args=p.parse_args();out=Path(args.output).resolve();out.mkdir(parents=True,exist_ok=True)
    os.environ.update(HONEYPOT_AI_ENABLED='true',HONEYPOT_AI_PROVIDER='local',HONEYPOT_AI_MODEL=args.model,HONEYPOT_AI_DB=str(out/'ai.sqlite'),HONEYPOT_AI_ANALYSIS_TIMEOUT='30',DB_TYPE='sqlite',DB_PATH=str(out/'events.sqlite'),PYTHONUTF8='1')
    import app_config
    app_config.Config.LOG_DIR=str(out/'logs')
    from utils import local_ai
    report={'model':args.model,'created':time.time(),'scope':'真实模型调用，数据为项目自编合成验收；不是外部真实流量准确率。','code_sha256':hashlib.sha256((ROOT/'utils/active_investigation.py').read_bytes()).hexdigest()}
    import requests
    client=requests.Session();client.trust_env=False;start=time.monotonic()
    try:
        if not args.skip_prewarm:
            response=client.post(local_ai.SETTINGS['base_url']+'/api/generate',json={'model':args.model,'prompt':'','stream':False,'keep_alive':'10m','options':{'num_ctx':4096}},timeout=(3,120));response.raise_for_status();data=response.json();report['prewarm']={'done':data.get('done') is True,'seconds':round(time.monotonic()-start,3)}
            if not report['prewarm']['done']:raise ValueError('prewarm_not_ready')
        else:report['prewarm']={'requested':False}
        probe=local_ai.probe('acceptance-probe');report['probe']=probe;print('probe: '+probe['status'],flush=True)
        if probe['status']!='success':raise ValueError('structured_probe_failed:'+probe.get('reason',''))
        if args.mode in ('baseline','all'):
            from utils.evaluation import run
            failures=[0]
            partial=[]
            def progress(i,n,r):
                partial.append(r);report['baseline_partial']=partial
                failures[0]=failures[0]+1 if r['status']!='success' else 0;print(f'{i}/{n}: {r["status"]} {r["prediction"]} {r["reason"]}',flush=True)
                if failures[0]>=3:raise ValueError('three_consecutive_failures_stop')
            report['baseline']=run(ROOT/'evaluation/fixtures.jsonl','ai',progress=progress)
            report.pop('baseline_partial',None)
        if args.mode in ('active','all'):
            from investigation_core.store import CenterStore
            from investigation_core.jobs import JobStore
            from utils.active_investigation import process_one
            center=CenterStore(out/'center.sqlite');sensor=center.issue_sensor('验收合成设备');user=center.create_user('accept-'+str(int(time.time())),os.urandom(24).hex(),'analyst',[sensor['id']]);jobs=JobStore(center)
            texts=['GET /admin User-Agent=sqlmap','GET /products?id=1 UNION SELECT username,password FROM users','POST /api/preview url=http://169.254.169.254/latest/meta-data/']+['GET /news page='+str(i) for i in range(27)]
            records=[dict(source_id='acceptance',table='raw_request',record_id=i+1,timestamp=f'2026-10-11 10:{i:02d}:00',src_ip='127.0.0.1',session_id='accept',channel='web',kind='http_request',rule_level='unknown',excerpt=t,traffic_origin='synthetic') for i,t in enumerate(texts)]
            frozen=json.dumps(records,ensure_ascii=False,sort_keys=True);(out/'frozen-active-fixture.json').write_text(frozen,encoding='utf-8');report['active_dataset_sha256']=hashlib.sha256(frozen.encode()).hexdigest()
            center.ingest(sensor['id'],'acceptance',records,{})
            job=jobs.create(user['id'],'请补查这些最近正常浏览请求前是否存在注入或管理探测，按时间整理过程，缺证据时明确说明。',{'sensors':[sensor['id']],'ip':'127.0.0.1','origin':'synthetic'},'acceptance')
            process_one(center,jobs);report['active']=jobs.get(user['id'],job['id']);print('active: '+report['active']['status']+' '+report['active']['reason'],flush=True)
    except Exception as error:report['error']=type(error).__name__+': '+str(error)[:240];print(report['error'],flush=True)
    finally:
        if args.index_db and report.get('baseline'):
            import sqlite3
            from contextlib import closing
            from investigation_core.store import CenterStore
            if not Path(args.index_db).exists():report['center_import_error']='指定中心数据库不存在，未创建新库。'
            else:
                center=CenterStore(args.index_db);evaluation=report['baseline']
                with closing(center.connect()) as c,c:c.execute('INSERT OR IGNORE INTO center_evaluations VALUES(?,?,?)',(evaluation['run_id'],json.dumps(evaluation,ensure_ascii=False),time.time()))
        client.close();target=out/'real-ai-acceptance.json';target.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8');print(str(target),flush=True);local_ai._pool.shutdown(wait=True)
    return 1 if report.get('error') else 0

if __name__=='__main__':
    if hasattr(sys.stdout,'reconfigure'):sys.stdout.reconfigure(encoding='utf-8',errors='replace')
    raise SystemExit(main())
