"""Isolated UI acceptance; source data and real configuration remain untouched."""
import logging,os,sys,tempfile,time,threading
from unittest.mock import patch
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'scripts'))
if __name__=='__main__':
    with tempfile.TemporaryDirectory(prefix='Project-preview-') as folder:
        temp=Path(folder);ini=temp/'preview.ini';ini.write_text('[app]\nproduction_mode=false\n[admin]\nuser=studio-preview\npassword=preview-local-only\n[services.dashboard]\nhost=127.0.0.1\nport=5167\n',encoding='utf-8')
        os.environ.update(HONEYPOT_CONFIG=str(ini),PRODUCTION_MODE='false',ADMIN_USER='studio-preview',ADMIN_PASS='preview-local-only',SECRET_KEY='studio-preview-only',
            DB_TYPE='sqlite',DB_PATH=str(temp/'events.db'),ALERT_ENABLED='false',HONEYPOT_AI_DB=str(temp/'ai.db'),HONEYPOT_AI_DETECTION_ENABLED='false',ALLOW_DASHBOARD_MOCK_DATA='false')
        import app_config
        app_config.Config.LOG_DIR=str(temp/'logs')
        from db import archive
        archive._ARCHIVE_DIR=str(temp/'archive')
        from test_analyst import seed_events
        from utils import ai_analyst,local_ai,ai_detection
        from dashboard import server as dashboard
        app=dashboard.app
        from werkzeug.serving import make_server
        seed_events();ai_analyst.ingest_once();ai_analyst.queue_report(force=True);ai_analyst.start_worker()
        def create_case():
            from utils.investigations import InvestigationStore
            for _ in range(90):
                reports=ai_analyst.get_store().listing()['reports']
                ready=[r for r in reports if r['status']=='completed']
                if ready:
                    book=InvestigationStore(ai_analyst.get_store());case=book.create('多阶段输入探测 · 演示调查','192.0.2.90','preview',ready[0]['id'])
                    book.update(case['id'],1,'preview','investigating','medium','核对虚拟回应与原始输入，尚无真实入侵成功证据。');return
                time.sleep(2)
        threading.Thread(target=create_case,daemon=True).start()
        server=make_server('127.0.0.1',5167,app,threaded=True);print('Studio temporary preview: 5167',flush=True)
        # Only this isolated preview uses reserved/documentation coordinates.
        positions=[{'src_ip':'192.0.2.90','longitude':-74,'latitude':40.7,'event_count':3,'location':'美国/纽约'},
                   {'src_ip':'198.51.100.20','longitude':2.35,'latitude':48.8,'event_count':6,'location':'法国/巴黎'}]
        timer=threading.Timer(1200,server.shutdown);timer.daemon=True;timer.start()
        @app.route('/__preview_stop',methods=['POST'])
        @dashboard.enhanced_login_required
        @dashboard.csrf_protect_api
        def preview_stop():
            threading.Thread(target=server.shutdown,daemon=True).start()
            return {'code':0,'data':'stopping'}
        try:
            with patch.object(dashboard,'get_server_info',return_value={'server':{'public_ip':'127.0.0.1'},'location':{'country':'中国','city':'本地测试','longitude':120,'latitude':30}}),patch.object(dashboard,'get_event_geo_data',return_value=positions):server.serve_forever()
        except KeyboardInterrupt:pass
        finally:timer.cancel();server.server_close();ai_analyst.stop_worker();ai_detection.stop_worker();local_ai._pool.shutdown(wait=True);logging.shutdown()
