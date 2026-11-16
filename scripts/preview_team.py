"""Temporary UI acceptance. Explicit mock classifications; never production data."""
import hashlib,json,logging,os,sys,tempfile,threading,time
from datetime import datetime,timedelta
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
if __name__=='__main__':
    for s in (sys.stdout,sys.stderr):
        if hasattr(s,'reconfigure'):s.reconfigure(encoding='utf-8',errors='replace')
    with tempfile.TemporaryDirectory(prefix='team-ui-') as folder:
        temp=Path(folder);ini=temp/'project.ini';ini.write_text('[app]\nproduction_mode=false\n[admin]\nuser=team-preview\npassword=preview-only\n[services.dashboard]\nhost=127.0.0.1\nport=5168\n',encoding='utf-8')
        os.environ.update(HONEYPOT_CONFIG=str(ini),PRODUCTION_MODE='false',ADMIN_USER='team-preview',ADMIN_PASS='preview-only',SECRET_KEY='team-preview-key',DB_TYPE='sqlite',DB_PATH=str(temp/'events.db'),HONEYPOT_AI_DB=str(temp/'ai.db'),ALERT_ENABLED='false',HONEYPOT_AI_ANALYSIS_ENABLED='false',HONEYPOT_AI_DETECTION_ENABLED='false')
        import app_config
        app_config.Config.LOG_DIR=str(temp/'logs')
        from utils import ai_analyst,local_ai,ai_detection
        from utils.team_store import TeamStore
        from utils.evaluation import run
        from utils.periodic_analysis import make_period
        from utils.ai_detection_store import DetectionStore
        from dashboard import server as dashboard
        app=dashboard.app;store=ai_analyst.get_store();team=TeamStore(store)
        base=(datetime.now().replace(minute=0,second=0,microsecond=0)-timedelta(minutes=45))
        examples=['GET /admin','GET /products id=1 UNION SELECT password FROM users','GET /download file=../../etc/passwd','ssh_exec whoami; cat /etc/passwd','GET /api/preview url=http://169.254.169.254/','GET /search name={{7*7}}']
        rows=[{'id':hashlib.sha256(str(i).encode()).hexdigest()[:24],'source':'fixture','locator':'fixture/raw_request:'+str(i),'timestamp':(base+timedelta(minutes=i)).strftime('%Y-%m-%d %H:%M:%S'),'src_ip':'192.0.2.90','channel':'ssh' if i==3 else 'web','session_id':'fixture-session','kind':'http_request' if i!=3 else 'ssh_command','rule_level':'medium','excerpt':text} for i,text in enumerate(examples)]
        store.index_batch('fixture',6,0,rows);make_period(store,'hour')
        detector=DetectionStore(store.path)
        for i in range(3):
            identifier=f'{i+1:024x}';snapshot=ai_detection.make_snapshot('GET','/search','q=fixture','',{'User-Agent':'Mozilla/5.0'},30 if i!=1 else 5,[],str(datetime.now()))
            detector.enqueue({'id':identifier,'raw_key':identifier,'raw_request_id':i+1,'src_ip':'192.0.2.90','session_id':'fixture-session','snapshot':snapshot},local_ai.SETTINGS)
            verdict=['no_clear_attack','suspicious','uncertain'][i];detector.finish(identifier,{'status':'success','data':{'verdict':verdict,'attack_types':['xss'] if verdict=='suspicious' else [],'summary':'自动化界面测试桩：用于验证分歧复核，非实际模型推理。','evidence':[]},'call_id':'ui-test-double'})
        team.record_evaluation(run(ROOT/'evaluation/fixtures.jsonl'))
        @app.context_processor
        def fixture_banner():return {'ACCEPTANCE_FIXTURE':True}
        from werkzeug.serving import make_server
        server=make_server('127.0.0.1',5168,app,threaded=True);timer=threading.Timer(1200,server.shutdown);timer.daemon=True;timer.start()
        @app.post('/__preview_stop')
        @dashboard.enhanced_login_required
        @dashboard.csrf_protect_api
        def stop():threading.Thread(target=server.shutdown,daemon=True).start();return {'code':0}
        print('Temporary team UI: 5168 (explicit fixture classifications)',flush=True)
        try:server.serve_forever()
        except KeyboardInterrupt:pass
        finally:timer.cancel();server.server_close();local_ai._pool.shutdown(wait=True);logging.shutdown()
