"""Project: regression, burst, multiple processes, restart and recovery."""
import json
import logging
import multiprocessing
import os
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'scripts'))
from test_runtime import Checks
from test_detection import DetectionChecks
from test_interaction import InteractionChecks
from test_analyst import AnalystChecks
from test_demo import DemoChecks
from test_investigations import InvestigationChecks
from test_team import TeamChecks


def lease_process(path,settings,worker):
    from utils.ai_store import CallStore
    store=CallStore(path)
    for index in range(10):
        call={'id':f'process-{worker}-{index}','task':'probe','session_id':f'worker-{worker}-{index}','src_ip':'fixture','input_sha256':'fixture'}
        reason=store.start(call,settings)
        if not reason:
            with closing(store.connect()) as c,c:
                active=c.execute('SELECT COUNT(*) FROM ai_leases WHERE expires_at>?',(time.time(),)).fetchone()[0]
                c.execute('INSERT INTO pressure_samples VALUES(?)',(active,))
            time.sleep(.01);store.finish(call['id'],'success','',10);store.release(call['id'])
        else:time.sleep(.005)


class FinalChecks(unittest.TestCase):
    def setUp(self):
        AnalystChecks.setUp(self)
    def tearDown(self):AnalystChecks.tearDown(self)
    evidence=AnalystChecks.evidence
    context=AnalystChecks.context
    report=AnalystChecks.report

    def test_semantic_failures_never_disable_healthy_service(self):
        with patch.object(self.ai,'_transport',return_value={}):
            for i in range(5):self.ai.call_model('log_report',[],'bad'+str(i),schema={},validator=lambda o:(_ for _ in ()).throw(ValueError('invalid_model_output')))
        self.assertEqual(self.ai.STORE.snapshot()['circuit_open_until'],0)
        with patch.object(self.ai,'_transport',return_value='healthy'):self.assertEqual(self.ai.probe('after-semantic')['status'],'success')

    def test_network_outage_holds_jobs_and_actual_probe_recovers(self):
        import requests
        with patch.object(self.ai,'_transport',side_effect=requests.ConnectionError()):
            for i in range(3):self.ai.probe('outage'+str(i))
        job=self.store.enqueue('report',self.context(),'held')
        for _ in range(5):self.assertFalse(self.analyst.process_one())
        self.assertEqual(self.store.get(job['id'])['status'],'queued')
        with patch.object(self.ai,'_transport',return_value='recovered'):
            result=self.ai.call_model('probe',[],'recovery',options={'bypass_circuit':True})
        self.assertEqual(result['status'],'success');self.assertEqual(self.ai.STORE.snapshot()['circuit_open_until'],0)

    def test_short_references_are_materialized_from_true_evidence(self):
        obj={**self.report()};obj.pop('evidence');obj['refs']=['E1'];obj['timeline']=[{'evidence_id':'E1','description':'观察到输入。'}]
        job=self.store.enqueue('report',self.context(),'compact')
        with patch.object(self.ai,'_transport',return_value=obj):self.analyst.process_one()
        row=self.store.get(job['id']);self.assertEqual(row['status'],'completed')
        self.assertEqual(row['result']['evidence'][0]['quote'],self.evidence()['excerpt'][:180])
        self.assertEqual(row['result']['evidence'][0]['id'],self.evidence()['id'])

    def test_fabricated_short_reference_is_rejected_without_cooldown(self):
        obj={**self.report()};obj.pop('evidence');obj['refs']=['E99']
        job=self.store.enqueue('report',self.context(),'fake')
        with patch.object(self.ai,'_transport',return_value=obj):self.analyst.process_one()
        self.assertEqual(self.store.get(job['id'])['status'],'queued')
        self.assertEqual(self.ai.STORE.snapshot()['circuit_open_until'],0)

    def test_stale_worker_cannot_overwrite_restarted_job(self):
        job=self.store.enqueue('report',self.context(),'stale');old=self.store.claim(2)
        with closing(self.store.connect()) as c,c:c.execute('UPDATE analyst_tasks SET expires_at=0')
        self.store.claim(2);self.store.retry_task(job['id']);new=self.store.claim(2)
        self.assertNotEqual(old['lease_token'],new['lease_token'])
        self.assertFalse(self.store.finish_task(old,{'status':'success','data':self.report()}))
        self.assertTrue(self.store.finish_task(new,{'status':'success','data':self.report()}))

    def test_cancel_drops_late_result_and_owner_isolation(self):
        job=self.store.enqueue('chat',self.context(),'cancel','owner','conv','question');claimed=self.store.claim(2)
        self.assertFalse(self.store.cancel(job['id'],'another'))
        self.assertTrue(self.store.cancel(job['id'],'owner'))
        self.assertFalse(self.store.finish_task(claimed,{'status':'success','data':{'answer':'late'}}))
        self.assertEqual(self.store.get(job['id'])['status'],'cancelled')

    def test_plain_chat_reads_no_log_evidence_or_log_history(self):
        item=self.store.enqueue('chat',self.context(),'log','owner','conv','question');claimed=self.store.claim(2)
        self.store.finish_task(claimed,{'status':'success','data':{'answer':'sensitive-log-fixture'}})
        job=self.analyst.ask('owner','conv','你好',mode='general')
        context=self.store.get(job['id'])['context']
        self.assertEqual(context['records'],[]);self.assertEqual(context['history'],[])
        with patch.object(self.ai,'_transport',return_value='你好，本地聊天。'):self.analyst.process_one()
        self.assertEqual(self.store.get(job['id'])['status'],'completed')

    def test_manual_review_preserves_original_ai_result(self):
        job=self.store.enqueue('report',self.context(),'review');claimed=self.store.claim(2)
        self.store.finish_task(claimed,{'status':'success','data':self.report()})
        self.assertTrue(self.store.review(job['id'],'owner','false_positive','low','需要复核'))
        self.assertEqual(self.store.get(job['id'])['result']['risk'],'high')
        self.assertEqual(self.store.reviews(job['id'])[0]['human_risk'],'low')

    def test_pagination_same_timestamp_does_not_skip_reports(self):
        for i in range(25):self.store.enqueue('report',self.context(),'page'+str(i))
        with closing(self.store.connect()) as c,c:c.execute('UPDATE analyst_tasks SET created_at=123')
        found=[];cursor=None
        for _ in range(3):
            page=self.store.listing(12,cursor);found.extend(r['id'] for r in page['reports'])
            value=page['next_before'];cursor=(float(value.split(':')[0]),value.split(':')[1]) if value else None
        self.assertEqual(len(set(found)),25)

    def test_list_payload_is_small_and_excludes_raw_log_bodies(self):
        for i in range(12):self.store.enqueue('report',{'records':[dict(self.evidence(j),excerpt='raw-fixture-'+'x'*490) for j in range(24)]},'slim'+str(i))
        text=json.dumps(self.store.listing());self.assertNotIn('raw-fixture',text);self.assertLess(len(text),25000)

    def test_history_archives_before_pruning_derived_index(self):
        r=self.evidence();self.store.index_batch('archivefixture',1,0,[r]);job=self.analyst.queue_report(force=True);claimed=self.store.claim(2)
        self.store.finish_task(claimed,{'status':'success','data':self.report()});self.store.review(job['id'],'owner','agree','high','保留复核')
        with closing(self.store.connect()) as c,c:c.execute('UPDATE analyst_tasks SET created_at=?,updated_at=?',(time.time()-40*86400,time.time()-40*86400))
        self.assertEqual(self.store.archive_old(30),1)
        files=self.store.archives();archived=self.store.archived(files[0]['name'])
        self.assertEqual(archived[0]['result']['risk'],'high');self.assertEqual(len(archived[0]['reviews']),1)
        self.assertIsNone(self.store.get(job['id']));self.assertIsNone(self.store.archived('../ai.db'))

    def test_threaded_model_burst_never_exceeds_configured_capacity(self):
        entered=0;peak=0;guard=threading.Lock()
        def transport(_):
            nonlocal entered,peak
            with guard:entered+=1;peak=max(peak,entered)
            time.sleep(.02)
            with guard:entered-=1
            return 'ok'
        with patch.object(self.ai,'_transport',side_effect=transport),ThreadPoolExecutor(max_workers=12) as clients:
            results=list(clients.map(lambda i:self.ai.probe('burst'+str(i)),range(40)))
        self.assertLessEqual(peak,1);self.assertTrue(any(r['status']=='success' for r in results))
        # A soft caller deadline may precede completion/lease cleanup. Wait for
        # bounded cleanup rather than demanding that it release a running job.
        deadline=time.monotonic()+4
        while self.ai.STORE.snapshot()['active'] and time.monotonic()<deadline:time.sleep(.05)
        self.assertEqual(self.ai.STORE.snapshot()['active'],0)

    def test_multiple_os_processes_share_capacity(self):
        with closing(self.ai.STORE.connect()) as c,c:c.execute('CREATE TABLE pressure_samples(active INTEGER)')
        settings=dict(self.ai.SETTINGS,concurrency=2)
        context=multiprocessing.get_context('spawn')
        workers=[context.Process(target=lease_process,args=(str(self.ai.STORE.path),settings,i)) for i in range(4)]
        for worker in workers:worker.start()
        for worker in workers:worker.join(20)
        for worker in workers:
            if worker.is_alive():worker.terminate();worker.join(2)
            self.assertEqual(worker.exitcode,0)
        with closing(self.ai.STORE.connect()) as c:
            peak=c.execute('SELECT MAX(active) FROM pressure_samples').fetchone()[0]
        self.assertIsNotNone(peak);self.assertLessEqual(peak,2)

    def test_web_traffic_burst_is_bounded_and_recovers(self):
        from web_honeypot.server import app
        from werkzeug.serving import make_server
        import requests
        server=make_server('127.0.0.1',0,app,threaded=True);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        def request(i):
            with requests.Session() as client:
                client.trust_env=False
                return client.get('http://127.0.0.1:'+str(server.server_port)+'/search',params={'q':'fixture-'+str(i)},timeout=10).status_code
        try:
            with patch.dict(self.ai.SETTINGS,enabled=False),ThreadPoolExecutor(max_workers=12) as clients:codes=list(clients.map(request,range(60)))
            self.assertTrue(all(code in (200,429) for code in codes));self.assertIn(200,codes)
            from db.connection import get_connection
            with closing(get_connection()) as c:
                captured=c.execute("SELECT COUNT(*) FROM raw_request WHERE query_string LIKE '%fixture-%'").fetchone()[0]
            self.assertEqual(captured,60)
        finally:server.shutdown();server.server_close();thread.join(2)


if __name__=='__main__':
    for stream in (sys.stdout,sys.stderr):
        if hasattr(stream,'reconfigure'):stream.reconfigure(encoding='utf-8',errors='replace')
    multiprocessing.freeze_support()
    with tempfile.TemporaryDirectory(prefix='Project-') as folder:
        temp=Path(folder);ini=temp/'test.ini';ini.write_text('[app]\nproduction_mode=false\n[admin]\npassword=test-only\n',encoding='utf-8')
        os.environ.update(HONEYPOT_CONFIG=str(ini),PRODUCTION_MODE='false',ADMIN_PASS='test-only',SECRET_KEY='test-only',
            DB_TYPE='sqlite',DB_PATH=str(temp/'events.db'),ALERT_ENABLED='false',HONEYPOT_AI_DB=str(temp/'ai.db'),
            HONEYPOT_AI_DETECTION_ENABLED='false',HONEYPOT_AI_ANALYSIS_ENABLED='false')
        import app_config
        app_config.Config.LOG_DIR=str(temp/'logs')
        from utils import ai_detection,ai_analyst,local_ai
        suite=unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(c) for c in (Checks,DetectionChecks,InteractionChecks,AnalystChecks,DemoChecks,FinalChecks,InvestigationChecks,TeamChecks))
        result=unittest.TextTestRunner(verbosity=2).run(suite)
        ai_analyst.stop_worker();ai_detection.stop_worker();local_ai._pool.shutdown(wait=True);logging.shutdown()
        raise SystemExit(0 if result.wasSuccessful() else 1)
