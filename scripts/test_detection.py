"""Project guards and optional real-model review in disposable databases."""
import json
import logging
import os
import sys
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))


class DetectionChecks(unittest.TestCase):
    def setUp(self):
        from utils import local_ai,ai_detection
        from utils.ai_store import CallStore
        from utils.ai_detection_store import DetectionStore
        self.ai=local_ai;self.detect=ai_detection
        self.folder=tempfile.TemporaryDirectory();self.root=Path(self.folder.name)
        self.pool=ThreadPoolExecutor(max_workers=1)
        self.settings=dict(local_ai.SETTINGS,enabled=True,configured=True,detection_enabled=True,
                           min_interval=0,timeout=2,detection_queue_max=32,detection_per_ip_hour=20,normal_sample_every=1,detection_delay=0,interactive_wait=0,analysis_enabled=False)
        self.patches=[patch.object(local_ai,'SETTINGS',self.settings),
            patch.object(local_ai,'STORE',CallStore(self.root/'ai.db')),
            patch.object(local_ai,'_pool',self.pool),patch.object(ai_detection,'STORE',DetectionStore(self.root/'ai.db')),
            patch.object(ai_detection,'start_worker')]
        for p in self.patches:p.start()

    def tearDown(self):
        self.pool.shutdown(wait=True)
        for p in reversed(self.patches):p.stop()
        self.folder.cleanup()

    def submit(self,index=1,query='q=<script>alert(1)</script>',score=22):
        return self.detect.submit(index,'192.0.2.1','session-test','GET','/search',query,
            {'User-Agent':'fixture'},'',score,['疑似XSS特征'],'2026-10-09 01:00:00','fixture',force=True)

    def decision(self,kind='xss'):
        return {'verdict':'suspicious','attack_types':[kind],'summary':'疑似攻击输入，需核对上下文。',
                'evidence':[{'field':'query','quote':'<script>'}]}

    def test_supported_types_and_exact_evidence(self):
        snapshot=self.detect.make_snapshot('GET','/','<script>','','',22,[],'now')
        for kind in self.detect.ATTACK_TYPES:
            self.assertEqual(self.detect.validate_result(self.decision(kind),snapshot)['attack_types'],[kind])

    def test_invented_evidence_unknown_type_and_success_claim_rejected(self):
        snapshot=self.detect.make_snapshot('GET','/','<script>',{}, {},22,[],'now')
        for change in ({'attack_types':['host_execute']},{'summary':'攻击已成功'},
                       {'evidence':[{'field':'headers','quote':'x'}]},
                       {'evidence':[{'field':'query','quote':'not-in-input'}]}):
            with self.assertRaises(ValueError):self.detect.validate_result({**self.decision(),**change},snapshot)

    def test_cautious_negation_is_allowed(self):
        snapshot=self.detect.make_snapshot('GET','/','<script>','',{},22,[],'now')
        obj={**self.decision(),'summary':'疑似攻击，不能确认攻击成功。'}
        self.assertEqual(self.detect.validate_result(obj,snapshot)['verdict'],'suspicious')

    def test_truncated_no_attack_is_uncertain(self):
        snapshot=self.detect.make_snapshot('GET','/','a'*1300,'',{},0,[],'now')
        obj={'verdict':'no_clear_attack','attack_types':[],'summary':'没有明确攻击。','evidence':[]}
        self.assertEqual(self.detect.validate_result(obj,snapshot)['verdict'],'uncertain')

    def test_credentials_are_not_sent_to_model(self):
        snapshot=self.detect.make_snapshot('POST','/','password%3Dsecret&url=http://user:pass@host/',
            '{"api_key":"private-value"}',{'Cookie':'cookie-secret','Authorization':'Bearer secret'},0,[],'now')
        text=json.dumps(snapshot)
        for value in ('private-value','cookie-secret','Bearer secret','user:pass','password=secret'):
            self.assertNotIn(value,text)

    def test_encoded_multiword_password_and_session_tokens_are_removed(self):
        snapshot=self.detect.make_snapshot('GET','/','password=super%20secret&PHPSESSID=session-private&csrf_token=csrf-private','',{},0,[],'now')
        text=json.dumps(snapshot)
        for value in ('super secret','session-private','csrf-private'):self.assertNotIn(value,text)

    def test_queue_bound_and_duplicate_request(self):
        self.settings['detection_queue_max']=1
        first=self.submit()
        self.assertEqual(self.submit()['id'],first['id'])
        second=self.submit(2)
        self.assertEqual(second['reason'],'queue_full')
        self.assertEqual(self.detect.STORE.get(second['id'])['verdict'],'uncertain')

    def test_per_source_budget(self):
        self.settings['detection_per_ip_hour']=1
        self.assertEqual(self.submit()['status'],'queued')
        self.assertEqual(self.submit(2)['reason'],'source_budget')

    def test_single_detection_claim_across_stores(self):
        from utils.ai_detection_store import DetectionStore
        self.submit();self.submit(2)
        first=self.detect.STORE.claim(2)
        self.assertIsNotNone(first)
        self.assertIsNone(DetectionStore(self.root/'ai.db').claim(2))

    def test_background_result_links_request_and_does_not_replace_rule(self):
        record=self.submit()
        with patch.object(self.ai,'_transport',return_value=self.decision()):
            self.assertTrue(self.detect.process_one())
        result=self.detect.STORE.get(record['id'])
        self.assertEqual(result['raw_request_id'],1)
        self.assertEqual(result['snapshot']['rule_score'],22)
        self.assertEqual(result['status'],'completed')
        self.assertTrue(result['call_id'])

    def test_failure_and_invalid_output_remain_uncertain(self):
        import requests
        first=self.submit()
        with patch.object(self.ai,'_transport',side_effect=requests.ConnectionError('fixture')):
            self.detect.process_one()
        row=self.detect.STORE.get(first['id'])
        self.assertEqual((row['status'],row['verdict']),('fallback','uncertain'))
        self.assertEqual(row['reason'],'model_unavailable')
        second=self.submit(2)
        with patch.object(self.ai,'_transport',return_value={**self.decision(),'evidence':[]}):self.detect.process_one()
        self.assertEqual(self.detect.STORE.get(second['id'])['verdict'],'uncertain')

    def test_rule_ai_disagreement_is_visible(self):
        record=self.submit(query='q=hello',score=0)
        obj={**self.decision(),'evidence':[{'field':'query','quote':'hello'}]}
        with patch.object(self.ai,'_transport',return_value=obj):self.detect.process_one()
        self.assertTrue(self.detect.STORE.get(record['id'])['rule_ai_disagreement'])

    def test_request_capture_returns_without_waiting_for_model(self):
        from db.http_requests import log_raw_request
        from db import connection
        with patch.object(connection._config,'DB_PATH',str(self.root/'events.db')),patch.object(self.ai,'_transport') as model:
            score,signals=log_raw_request('captured','192.0.2.2','GET','/search','q=<script>alert(1)</script>',{'User-Agent':'fixture'},'')
            conn=connection.get_connection()
            try:before=tuple(conn.execute('SELECT threat_score,is_suspicious FROM raw_request ORDER BY id DESC LIMIT 1').fetchone())
            finally:conn.close()
            model.assert_not_called()
            self.assertEqual(len(self.detect.STORE.listing()['records']),1)
            with patch.object(self.ai,'_transport',return_value=self.decision()):self.detect.process_one()
            conn=connection.get_connection()
            try:after=tuple(conn.execute('SELECT threat_score,is_suspicious FROM raw_request ORDER BY id DESC LIMIT 1').fetchone())
            finally:conn.close()
            self.assertEqual(before,after)
            self.assertEqual(before[0],score)

    def test_new_api_auth_csrf_and_detail(self):
        from dashboard.server import app
        client=app.test_client();base='http://127.0.0.1:5001'
        record=self.submit()
        self.assertEqual(client.get('/api/ai/detections',base_url=base).status_code,401)
        with client.session_transaction(base_url=base) as session:
            session.update(is_admin=True,username='test',csrf_token='fixture')
        headers={'Origin':base}
        self.assertEqual(client.post('/api/ai/detections/'+record['id']+'/retry',base_url=base,headers=headers).status_code,403)
        self.assertEqual(client.get('/api/ai/detections',base_url=base,headers={'Origin':'http://evil.test'}).status_code,403)
        response=client.get('/api/ai/detections/'+record['id'],base_url=base,headers=headers)
        self.assertEqual(response.json['data']['raw_request_id'],1)
        self.assertEqual(client.get('/api/ai/detections?src_ip=invalid',base_url=base,headers=headers).status_code,400)

    def test_fast_rules_cover_ssrf_ssti_xxe_and_technique_precedes_path(self):
        from db.http_requests import calculate_threat_score,_classify_web_event_type
        fixtures=[('/api/preview','url=http://169.254.169.254/latest/meta-data/','','ssrf_probe'),
                  ('/admin','name={{7*7}}','','ssti_probe'),
                  ('/api/preview','','<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>','xxe_probe'),
                  ('/admin','q=<script>alert(1)</script>','','xss_probe')]
        for path,query,body,expected in fixtures:
            score,suspicious,signals=calculate_threat_score('POST' if body else 'GET',path,query,{'User-Agent':'fixture'},body)
            self.assertTrue(suspicious)
            self.assertEqual(_classify_web_event_type('GET',path,query,body,signals),expected)

    def test_fast_rules_do_not_flag_public_preview_or_plain_template_name(self):
        from db.http_requests import calculate_threat_score
        for query in ('url=https://example.com/image.png','name={{username}}','q=说明 http://169.254.169.254 地址'):
            _,_,signals=calculate_threat_score('GET','/search',query,{'User-Agent':'fixture'},'')
            self.assertFalse(any('SSRF' in signal or 'SSTI' in signal for signal in signals))

    def test_rule_score_is_bounded(self):
        from db.http_requests import calculate_threat_score
        score,_,_=calculate_threat_score('POST','/admin/backup/config/.env/.git','q=<script>alert(1)</script>&id=1 union select x',
                                        {},'<!DOCTYPE x [<!ENTITY x SYSTEM "file:///etc/passwd">]>{{7*7}}')
        self.assertEqual(score,100)


def live_review(output):
    from utils import ai_detection,local_ai
    from db.http_requests import log_raw_request
    fixtures=[
        ('normal','GET','/search','q=python教程&page=1','',{'User-Agent':'Mozilla/5.0'}),
        ('xss','GET','/search','q=<script>alert(1)</script>','',{'User-Agent':'Mozilla/5.0'}),
        ('sqli','GET','/products','id=1 UNION SELECT username,password FROM users','',{}),
        ('path_traversal','GET','/download','file=../../etc/passwd','',{}),
        ('command_injection','POST','/tools','cmd=whoami;cat /etc/passwd','',{}),
        ('ssrf','GET','/api/preview','url=http://169.254.169.254/latest/meta-data/','',{}),
        ('ssti','GET','/search','name={{7*7}}','',{}),
        ('xxe','POST','/api/preview','', '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',{'Content-Type':'application/xml'}),
        ('scanner','GET','/admin','', '',{'User-Agent':'sqlmap/1.8'})]
    records=[]
    with patch.dict(local_ai.SETTINGS,enabled=True,detection_enabled=True,detection_per_ip_hour=20,normal_sample_every=1),patch.object(ai_detection,'start_worker'):
        for index,(expected,method,path,query,body,headers) in enumerate(fixtures,1):
            score,signals=log_raw_request('live-detect','192.0.2.50',method,path,query,headers,body)
            ai_detection.process_one()
            row=ai_detection.STORE.listing(limit=1)['records'][0]
            records.append({'expected_fixture':expected,'rule_score':score,'record':row})
            print('LIVE_REVIEW',expected,row['status'],row['verdict'],row['result'].get('attack_types'),flush=True)
        with patch.dict(local_ai.SETTINGS,base_url='http://127.0.0.1:59999'):
            score,signals=log_raw_request('offline-detect','192.0.2.51','GET','/search','q=hello',{},'')
            ai_detection.process_one()
            offline=ai_detection.STORE.listing(limit=1)['records'][0]
    result={'model':local_ai.SETTINGS['model'],'fixtures':records,'unavailable_endpoint':offline,
            'scope':'9 synthetic functional fixtures, not a real-world accuracy benchmark; source labels are test expectations'}
    Path(output).write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    return all(r['record']['status']=='completed' for r in records) and offline['verdict']=='uncertain' and offline['status']=='fallback'


if __name__=='__main__':
    with tempfile.TemporaryDirectory(prefix='Project-') as folder:
        temp=Path(folder);ini=temp/'test.ini'
        ini.write_text('[app]\nproduction_mode=false\n[admin]\npassword=test-only\n',encoding='utf-8')
        os.environ.update(HONEYPOT_CONFIG=str(ini),PRODUCTION_MODE='false',ADMIN_PASS='test-only',SECRET_KEY='test-only',
            DB_TYPE='sqlite',DB_PATH=str(temp/'events.db'),ALERT_ENABLED='false',HONEYPOT_AI_DB=str(temp/'ai.db'),
            HONEYPOT_AI_DETECTION_ENABLED='false')
        import app_config
        app_config.Config.LOG_DIR=str(temp/'logs')
        from test_runtime import Checks
        suite=unittest.TestSuite([unittest.defaultTestLoader.loadTestsFromTestCase(Checks),
                                 unittest.defaultTestLoader.loadTestsFromTestCase(DetectionChecks)])
        result=unittest.TextTestRunner(verbosity=2).run(suite)
        passed=result.wasSuccessful()
        if '--live' in sys.argv and passed:
            passed=live_review(os.environ.get('MIMO_ACCEPTANCE_OUTPUT',str(temp/'live.json')))
        from utils import ai_detection,local_ai
        ai_detection.stop_worker();local_ai._pool.shutdown(wait=True);logging.shutdown()
        raise SystemExit(0 if passed else 1)
