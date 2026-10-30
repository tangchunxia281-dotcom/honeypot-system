"""Project: grounded reports, Q&A isolation, scheduling, coverage and regressions."""
import hashlib
import json
import logging
import os
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'scripts'))
from test_runtime import Checks
from test_detection import DetectionChecks
from test_interaction import InteractionChecks


class AnalystChecks(unittest.TestCase):
    def setUp(self):
        Checks.setUp(self)
        from utils import ai_analyst
        from db import connection
        from db import archive
        self.analyst=ai_analyst;self.root=Path(self.folder.name)
        self.ai.SETTINGS.update(analysis_enabled=True,analysis_timeout=2)
        self.extra=[patch.object(ai_analyst,'start_worker'),patch.object(connection._config,'DB_PATH',str(self.root/'events.db')),
                    patch.object(archive,'_ARCHIVE_DIR',str(self.root/'archive'))]
        for p in self.extra:p.start()
        with closing(connection.get_connection()):pass
        self.store=self.analyst.get_store()

    def tearDown(self):
        for p in reversed(self.extra):p.stop()
        Checks.tearDown(self)

    def evidence(self,index=1):
        return {'id':hashlib.sha256(str(index).encode()).hexdigest()[:24],'locator':'fixture/raw_request:'+str(index),
                'timestamp':'2026-10-09 10:00:00','src_ip':'192.0.2.90','channel':'web','session_id':'session',
                'kind':'http_request','rule_level':'medium','excerpt':'GET /admin q=<script>alert(1)</script>'}

    def context(self):return {'records':[self.evidence()],'selected':1}

    def report(self):
        r=self.evidence()
        return {'title':'同来源的探测尝试','risk':'high','summary':'记录显示可疑输入，建议核对。','intent':'可能探测输入处理。',
                'risk_reason':'输入含可执行浏览器片段。','timeline':[{'evidence_id':r['id'],'description':'提交可疑脚本输入。'}],
                'evidence':[{'id':r['id'],'quote':'<script>'}],'recommendations':['核对相邻请求。'],
                'limitations':'只有一条可见证据，不能认定真实入侵成功。'}

    def test_index_full_batches_resume_and_linked_web_events_deduplicated(self):
        with closing(sqlite3.connect(self.root/'events.db')) as c,c:
            for i in range(70):c.execute("INSERT INTO raw_request(src_ip,method,path,create_time) VALUES('192.0.2.1','GET','/admin','2026-10-09 10:00:00')")
            c.execute("INSERT INTO event_log(source,severity,event_type,src_ip,raw_request_id) VALUES('web','medium','path_probe','192.0.2.1',1)")
            c.execute("INSERT INTO event_log(source,severity,event_type,src_ip,payload) VALUES('ssh','medium','ssh_command','192.0.2.1','whoami')")
        self.analyst.ingest_once();self.assertEqual(self.store.listing()['indexed'],65)
        self.assertEqual(self.analyst._state['lag'],6)
        self.analyst.ingest_once();self.analyst.ingest_once()
        self.assertEqual(self.store.listing()['indexed'],71);self.assertEqual(self.analyst._state['lag'],0)

    def test_sqlite_archive_is_included(self):
        archive=self.root/'archive';archive.mkdir();target=archive/'archive_20261008.sqlite'
        with closing(sqlite3.connect(self.root/'events.db')) as source,closing(sqlite3.connect(target)) as dst:
            source.backup(dst)
        with closing(sqlite3.connect(target)) as c,c:c.execute("INSERT INTO event_log(source,severity,event_type,payload) VALUES('ssh','high','ssh_command','cat /etc/passwd')")
        self.analyst.ingest_once();self.assertEqual(self.store.listing()['indexed'],1)

    def test_passwords_redacted_before_index(self):
        records=self.analyst._records_from_rows('s','event_log',[{'id':1,'source':'ssh','payload':'password=private-value, 密码：another-private','event_type':'login_failed'}])
        text=json.dumps(records,ensure_ascii=False)
        self.assertNotIn('private-value',text);self.assertNotIn('another-private',text)

    def test_report_grounding_and_independent_risk(self):
        result=self.analyst.validate(self.report(),self.context())
        self.assertEqual(result['risk'],'high');self.assertEqual(self.context()['records'][0]['rule_level'],'medium')

    def test_fabricated_reference_or_quote_rejected(self):
        for change in ({'evidence':[{'id':'fake','quote':'<script>'}]},{'evidence':[{'id':self.evidence()['id'],'quote':'invented'}]},
                       {'timeline':[{'evidence_id':'fake','description':'fabricated'}]}):
            with self.assertRaises(ValueError):self.analyst.validate({**self.report(),**change},self.context())

    def test_real_compromise_claim_and_claim_all_logs_rejected(self):
        for summary in ('目标已经攻破。','我已检查全部日志。'):
            with self.assertRaises(ValueError):self.analyst.validate({**self.report(),'summary':summary},self.context())

    def test_chat_empty_context_can_explain_missing_evidence(self):
        reply={'answer':'没有检索到相关证据，无法判断。','evidence':[],'limitations':'没有可见记录。'}
        self.assertEqual(self.analyst.validate(reply,{'records':[]},True),reply)

    def test_report_job_linking_survives_restart_without_duplicates(self):
        record=self.evidence();self.store.index_batch('fixture',1,0,[record])
        first=self.analyst.queue_report(force=True);second=self.analyst.queue_report(force=True)
        self.assertTrue(first['id']);self.assertIsNone(second);self.assertEqual(self.store.listing()['assigned'],1)

    def test_chat_prioritized_over_report_and_claim_exclusive(self):
        report=self.store.enqueue('report',self.context(),'report1')
        chat=self.store.enqueue('chat',self.context(),'chat1','owner','conversation','question')
        job=self.store.claim(2);self.assertEqual(job['id'],chat['id']);self.assertIsNone(self.store.claim(2))

    def test_owner_isolation_and_conversation_history(self):
        job=self.store.enqueue('chat',self.context(),'chat1','owner1','conversation','question')
        self.assertIsNone(self.store.get(job['id'],'owner2'))
        self.assertEqual(len(self.store.conversations('owner1','conversation')),1)
        self.assertEqual(self.store.conversations('owner2','conversation'),[])

    def test_chat_retrieves_saved_risk_without_overwriting_it(self):
        record=self.evidence();self.store.index_batch('fixture',1,0,[record])
        job=self.analyst.queue_report(force=True)
        claimed=self.store.claim(2)
        self.store.finish_task(claimed,{'status':'success','data':self.report(),'call_id':'fixture'})
        chat=self.analyst.ask('owner','a'*32,'为什么风险较高？')
        context=self.store.get(chat['id'])['context']
        self.assertEqual(context['related_reports'][0]['risk'],'high')
        self.assertEqual(self.store.get(job['id'])['result']['risk'],'high')

    def test_parameterized_search_filters(self):
        self.store.index_batch('fixture',1,0,[self.evidence()])
        self.assertEqual(self.store.search(term='<script>')['selected'],1)
        self.assertEqual(self.store.search(term="' OR 1=1 --")['selected'],0)
        self.assertEqual(self.store.search(ip='192.0.2.91')['selected'],0)

    def test_chat_hourly_budget_and_input_limit(self):
        for i in range(20):self.store.enqueue('chat',{'records':[]},'chat'+str(i),'owner','conversation','question')
        self.assertEqual(self.store.enqueue('chat',{'records':[]},'last','owner','conversation','question')['reason'],'question_budget')
        with self.assertRaises(ValueError):self.analyst.ask('owner','c','q'*501)

    def test_processing_requires_validated_data(self):
        self.store.enqueue('report',self.context(),'report1')
        with patch.object(self.ai,'_transport',return_value=self.report()):self.assertTrue(self.analyst.process_one())
        self.assertEqual(self.store.listing()['reports'][0]['status'],'completed')

    def test_failed_report_does_not_invent_ai_risk(self):
        self.store.enqueue('report',self.context(),'report1')
        with patch.object(self.ai,'_transport',return_value={'risk':'high'}):self.analyst.process_one()
        row=self.store.listing()['reports'][0]
        self.assertEqual(row['status'],'queued');self.assertEqual(row['result'],{})

    def test_invalid_output_correction_is_bounded(self):
        job=self.store.enqueue('report',self.context(),'report1')
        for _ in range(2):
            with closing(self.store.connect()) as c,c:c.execute('UPDATE analyst_tasks SET updated_at=0')
            with patch.object(self.ai,'_transport',return_value={'risk':'high'}):self.analyst.process_one()
        row=self.store.get(job['id']);self.assertEqual(row['status'],'fallback');self.assertEqual(row['attempts'],2)

    def test_background_waits_for_foreground_waiter(self):
        self.ai.STORE.register_waiter('foreground',5)
        with patch.object(self.ai,'_transport') as model:
            result=self.ai.call_model('log_report',[],'report',schema={},validator=lambda x:x)
        self.assertEqual(result['reason'],'priority_wait');model.assert_not_called()

    def test_demo_mode_pauses_reports_but_question_remains_eligible(self):
        self.ai.STORE.pause_background(600)
        self.store.enqueue('report',self.context(),'report1')
        question=self.store.enqueue('chat',self.context(),'chat1','owner','conversation','question')
        job=self.store.claim(2,chat_only=True);self.assertEqual(job['id'],question['id'])
        with patch.object(self.ai,'_transport') as model:result=self.ai.call_model('log_report',[],'report')
        self.assertEqual(result['reason'],'background_paused');model.assert_not_called()

    def test_foreground_can_wait_briefly_for_capacity(self):
        call={'id':'occupied','task':'web_detect','session_id':'bg','src_ip':'','input_sha256':'x'}
        self.assertEqual(self.ai.STORE.start(call,self.ai.SETTINGS),'')
        thread=threading.Thread(target=lambda:(time.sleep(.12),self.ai.STORE.release('occupied')));thread.start()
        with patch.dict(self.ai.SETTINGS,interactive_wait=1),patch.object(self.ai,'_transport',return_value='ok'):
            result=self.ai.probe('foreground')
        thread.join();self.assertEqual(result['status'],'success')

    def test_truncated_output_reason_and_diagnostic_persisted(self):
        from utils.ai_detection import EvidenceValidationError
        def bad(_):raise EvidenceValidationError('evidence_quote_mismatch')
        with patch.object(self.ai,'_transport',return_value={}):result=self.ai.call_model('test',[],'invalid',schema={},validator=bad)
        self.assertEqual(result['validation_detail'],'evidence_quote_mismatch')
        self.assertEqual(self.ai.STORE.snapshot()['recent'][0]['validation_detail'],'evidence_quote_mismatch')

    def test_analysis_api_login_csrf_and_chat_owner(self):
        from dashboard.server import app
        base='http://127.0.0.1:5001';client=app.test_client();other=app.test_client()
        self.assertEqual(client.get('/api/ai/analysis',base_url=base).status_code,401)
        for c in (client,other):
            with c.session_transaction(base_url=base) as session:session.update(is_admin=True,username='test',csrf_token='fixture')
        headers={'Origin':base,'X-CSRF-Token':'fixture'}
        self.assertEqual(client.get('/ai/analysis',base_url=base).status_code,200)
        payload={'conversation':'a'*32,'question':'总结日志'}
        self.assertEqual(client.post('/api/ai/chat',base_url=base,json=payload,headers={'Origin':base}).status_code,403)
        response=client.post('/api/ai/chat',base_url=base,json=payload,headers=headers)
        self.assertEqual(response.status_code,202);identifier=response.json['data']['id']
        self.assertEqual(other.get('/api/ai/chat/'+identifier,base_url=base,headers={'Origin':base}).status_code,404)
        self.assertEqual(client.get('/api/ai/chat/'+identifier,base_url=base,headers={'Origin':base}).status_code,200)

    def test_demo_mode_api_requires_login_and_csrf(self):
        from dashboard.server import app
        client=app.test_client();base='http://127.0.0.1:5001'
        self.assertEqual(client.post('/api/ai/analysis/mode',base_url=base,json={'mode':'interactive'}).status_code,401)
        with client.session_transaction(base_url=base) as s:s.update(is_admin=True,username='test',csrf_token='fixture')
        self.assertEqual(client.post('/api/ai/analysis/mode',base_url=base,json={'mode':'interactive'},headers={'Origin':base}).status_code,403)
        response=client.post('/api/ai/analysis/mode',base_url=base,json={'mode':'interactive'},headers={'Origin':base,'X-CSRF-Token':'fixture'})
        self.assertEqual(response.status_code,200);self.assertGreater(self.ai.STORE.background_paused(),time.time())

    def test_report_export_requires_completed_task_and_escapes_html(self):
        from dashboard.server import app
        job=self.store.enqueue('report',self.context(),'export')
        client=app.test_client();base='http://127.0.0.1:5001';path='/api/ai/analysis/'+job['id']+'/export'
        self.assertEqual(client.get(path,base_url=base).status_code,401)
        with client.session_transaction(base_url=base) as s:s.update(is_admin=True,username='test')
        self.assertEqual(client.get(path,base_url=base,headers={'Origin':base}).status_code,409)
        claimed=self.store.claim(2);self.store.finish_task(claimed,{'status':'success','data':self.report(),'call_id':'fixture'})
        response=client.get(path,base_url=base,headers={'Origin':base})
        self.assertEqual(response.status_code,200);self.assertIn('attachment;',response.headers['Content-Disposition'])
        self.assertNotIn('<script>',response.text);self.assertIn('&lt;script&gt;',response.text)


def seed_events():
    from db.connection import get_connection
    with closing(get_connection()) as c,c:
        for path,query,score in [('/admin','',20),('/products','id=1 UNION SELECT username,password FROM users',45),
                                ('/download','file=../../etc/passwd',35)]:
            c.execute('INSERT INTO raw_request(src_ip,method,path,query_string,threat_score,create_time) VALUES(?,?,?,?,?,?)',
                      ('192.0.2.90','GET',path,query,score,'2026-10-09 10:00:00'))
        c.execute("INSERT INTO event_log(source,severity,event_type,src_ip,payload,timestamp) VALUES('ssh','medium','ssh_exec','192.0.2.90','whoami; cat /etc/passwd','2026-10-09 10:01:00')")


def live(output):
    from utils import ai_analyst,local_ai
    seed_events();ai_analyst.ingest_once();report=ai_analyst.queue_report(force=True)
    ai_analyst.process_one();store=ai_analyst.get_store();report=store.get(report['id'])
    question=ai_analyst.ask('live','a'*32,'这些记录反映什么攻击目的？请给出证据。','192.0.2.90')
    ai_analyst.process_one();chat=store.get(question['id'])
    data={'model':local_ai.SETTINGS['model'],'report':report,'chat':chat,'scope':'Synthetic multistep fixtures; functional acceptance, not accuracy benchmark.'}
    Path(output).write_text(json.dumps(data,ensure_ascii=False,indent=2),encoding='utf-8')
    print('LIVE_REPORT',report['status'],report['reason'],report['result'].get('risk'),flush=True)
    print('LIVE_CHAT',chat['status'],chat['reason'],flush=True)
    return report['status']=='completed' and chat['status']=='completed'


if __name__=='__main__':
    with tempfile.TemporaryDirectory(prefix='Project-') as folder:
        temp=Path(folder);ini=temp/'test.ini';ini.write_text('[app]\nproduction_mode=false\n[admin]\npassword=test-only\n',encoding='utf-8')
        os.environ.update(HONEYPOT_CONFIG=str(ini),PRODUCTION_MODE='false',ADMIN_PASS='test-only',SECRET_KEY='test-only',
            DB_TYPE='sqlite',DB_PATH=str(temp/'events.db'),ALERT_ENABLED='false',HONEYPOT_AI_DB=str(temp/'ai.db'),HONEYPOT_AI_DETECTION_ENABLED='false')
        import app_config
        app_config.Config.LOG_DIR=str(temp/'logs')
        suite=unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(c) for c in (Checks,DetectionChecks,InteractionChecks,AnalystChecks))
        result=unittest.TextTestRunner(verbosity=2).run(suite);passed=result.wasSuccessful()
        from utils import ai_detection,ai_analyst,local_ai
        if '--live' in sys.argv and passed:
            from db import archive
            with patch.object(ai_analyst,'start_worker'),patch.object(archive,'_ARCHIVE_DIR',str(temp/'archive')):
                passed=live(os.environ.get('MIMO_ACCEPTANCE_OUTPUT',str(temp/'live.json')))
        ai_analyst.stop_worker();ai_detection.stop_worker();local_ai._pool.shutdown(wait=True);logging.shutdown()
        raise SystemExit(0 if passed else 1)
