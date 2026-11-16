"""Small actual-model acceptance with temporary evidence and audited compact outputs."""
import json,logging,os,sys,tempfile,time
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'scripts'))
if __name__=='__main__':
    for stream in (sys.stdout,sys.stderr):
        if hasattr(stream,'reconfigure'):stream.reconfigure(encoding='utf-8',errors='replace')
    with tempfile.TemporaryDirectory(prefix='Project-live-') as folder:
        temp=Path(folder);ini=temp/'test.ini';ini.write_text('[app]\nproduction_mode=false\n[admin]\npassword=test-only\n',encoding='utf-8')
        os.environ.update(HONEYPOT_CONFIG=str(ini),PRODUCTION_MODE='false',ADMIN_PASS='test-only',SECRET_KEY='test-only',DB_TYPE='sqlite',DB_PATH=str(temp/'events.db'),ALERT_ENABLED='false',HONEYPOT_AI_DB=str(temp/'ai.db'),HONEYPOT_AI_DETECTION_ENABLED='false')
        import app_config
        app_config.Config.LOG_DIR=str(temp/'logs')
        from db import archive
        archive._ARCHIVE_DIR=str(temp/'archive')
        from test_analyst import seed_events
        from utils import ai_analyst,local_ai
        seed_events();ai_analyst.ingest_once();report=ai_analyst.queue_report(force=True)
        def complete(identifier):
            for _ in range(3):
                ai_analyst.process_one();row=ai_analyst.get_store().get(identifier)
                if row['status']!='queued':return row
                time.sleep(3.1)
            return row
        with patch.object(ai_analyst,'start_worker'):
            report=complete(report['id']);chat=ai_analyst.ask('live','a'*32,'这些日志体现什么攻击目的？哪些结论不能确认？','192.0.2.90');chat=complete(chat['id'])
            general=ai_analyst.ask('live','b'*32,'请用一句话说明你是本地运行的聊天助手。',mode='general');general=complete(general['id'])
            from utils.investigations import InvestigationStore
            book=InvestigationStore(ai_analyst.get_store());case=book.create('多阶段输入调查','192.0.2.90','live',report['id'])
            case_chat=ai_analyst.ask('live','c'*32,'根据这份调查证据说明下一步优先复核什么？',case_id=case['id']);case_chat=complete(case_chat['id'])
        result={'model':local_ai.SETTINGS['model'],'report':report,'chat':chat,'general':general,'investigation_chat':case_chat,'case':case,'calls':local_ai.STORE.snapshot(),
                'scope':'Four small functional tasks; not an accuracy or hardware throughput benchmark.'}
        Path(os.environ.get('MIMO_ACCEPTANCE_OUTPUT',str(temp/'live.json'))).write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
        for key in ('report','chat','general','investigation_chat'):print(key,result[key]['status'],result[key].get('reason'),flush=True)
        local_ai._pool.shutdown(wait=True);logging.shutdown()
        raise SystemExit(0 if all(result[k]['status']=='completed' for k in ('report','chat','general','investigation_chat')) else 1)
