"""Project regression checks, isolated from original data and real credentials."""
import json
import logging
import os
import sys
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))


class Checks(unittest.TestCase):
    def setUp(self):
        from utils import local_ai
        self.ai=local_ai
        self.folder=tempfile.TemporaryDirectory()
        self.pool=ThreadPoolExecutor(max_workers=1)
        from utils.ai_store import CallStore
        settings=dict(local_ai.SETTINGS,enabled=True,configured=True,ssh_enabled=True,
                      timeout=2,min_interval=0,max_calls_per_session=10,concurrency=1,interactive_wait=0,detection_delay=0,analysis_enabled=False)
        self.patches=[patch.object(local_ai,'STORE',CallStore(Path(self.folder.name)/'audit.db')),
                      patch.object(local_ai,'_pool',self.pool),
                      patch.object(local_ai,'SETTINGS',settings)]
        for item in self.patches:item.start()

    def tearDown(self):
        self.pool.shutdown(wait=True)
        for item in reversed(self.patches):item.stop()
        self.folder.cleanup()

    def test_actual_success_is_audited_without_prompt(self):
        with patch.object(self.ai,'_transport',return_value='本地模型验收成功'):
            result=self.ai.probe('probe-1')
        self.assertEqual(result['status'],'success')
        data=self.ai.STORE.snapshot()
        self.assertEqual(data['counts']['success'],1)
        self.assertEqual(data['active'],0)
        self.assertEqual(data['recent'][0]['response_preview'],'本地模型验收成功')
        self.assertNotIn('messages',data['recent'][0])

    def test_unavailable_model_falls_back(self):
        import requests
        with patch.object(self.ai,'_transport',side_effect=requests.ConnectionError('test')):
            result=self.ai.probe('probe-2')
        self.assertEqual(result['status'],'fallback')
        self.assertEqual(result['reason'],'model_unavailable')
        self.assertEqual(self.ai.STORE.snapshot()['active'],0)

    def test_timeout_keeps_slot_until_worker_finishes(self):
        def slow(_):time.sleep(.15);return 'late'
        pool=ThreadPoolExecutor(max_workers=1)
        try:
            with patch.object(self.ai,'_pool',pool),patch.dict(self.ai.SETTINGS,timeout=.03),patch.object(self.ai,'_transport',side_effect=slow):
                result=self.ai.probe('slow')
                self.assertEqual(result['reason'],'deadline_exceeded')
                self.assertEqual(self.ai.STORE.snapshot()['active'],1)
        finally:pool.shutdown(wait=True)
        data=self.ai.STORE.snapshot()
        self.assertEqual(data['active'],0)
        self.assertEqual(data['recent'][0]['status'],'fallback')
        self.assertEqual(data['recent'][0]['response_preview'],'')

    def test_leases_are_shared_between_process_stores(self):
        from utils.ai_store import CallStore
        first={'id':'a','task':'probe','session_id':'first','src_ip':'127.0.0.1','input_sha256':'x'}
        second=dict(first,id='b',session_id='second')
        self.assertEqual(self.ai.STORE.start(first,self.ai.SETTINGS),'')
        other=CallStore(self.ai.STORE.path)
        self.assertEqual(other.start(second,self.ai.SETTINGS),'capacity_limit')
        self.ai.STORE.release('a')

    def test_disabled_model_never_calls_transport(self):
        with patch.dict(self.ai.SETTINGS,enabled=False),patch.object(self.ai,'_transport') as transport:
            self.assertEqual(self.ai.probe('off')['reason'],'disabled')
            transport.assert_not_called()

    def test_repeated_failures_open_circuit_and_expiry_allows_recovery(self):
        import requests
        with patch.object(self.ai,'_transport',side_effect=requests.ConnectionError('test')):
            for i in range(3):self.ai.probe('failure-'+str(i))
        self.assertEqual(self.ai.probe('blocked')['reason'],'circuit_open')
        from contextlib import closing
        with closing(self.ai.STORE.connect()) as conn,conn:
            conn.execute('UPDATE ai_state SET open_until=0 WHERE id=1')
        with patch.object(self.ai,'_transport',return_value='recovered'):
            self.assertEqual(self.ai.probe('recovery')['status'],'success')

    def test_session_budget_is_enforced(self):
        with patch.dict(self.ai.SETTINGS,max_calls_per_session=1),patch.object(self.ai,'_transport',return_value='ok'):
            self.assertEqual(self.ai.probe('budget')['status'],'success')
            self.assertEqual(self.ai.probe('budget')['reason'],'session_budget')

    def test_output_rejects_tool_calls_and_invalid_json(self):
        response=MagicMock()
        response.__enter__.return_value=response
        response.status_code=200
        client=MagicMock()
        client.__enter__.return_value=client
        client.post.return_value=response
        for data in ([],{'done':True,'message':None},{'done':True,'message':{'content':'not json'}},
                     {'done':True,'message':{'content':'{"reply":"ok"}','tool_calls':[{}]}},
                     {'done':True,'message':{'content':'{"reply":"ok","execute":"x"}'}}):
            response.iter_content.return_value=[json.dumps(data).encode()]
            with patch.object(self.ai.requests,'Session',return_value=client):
                with self.assertRaises(ValueError):self.ai._transport([])

    def test_output_controls_and_secret_fields_are_removed(self):
        text=self.ai.safe_text('\x1b[31mhello\x1b[0m password=secret '+ 'x'*2000)
        self.assertNotIn('\x1b',text)
        self.assertNotIn('secret',text)
        self.assertLessEqual(len(text),1200)

    def test_ssh_contexts_do_not_mix(self):
        first=SimpleNamespace(session_key='one',client_ip='127.0.0.1',current_path='/one')
        second=SimpleNamespace(session_key='two',client_ip='127.0.0.1',current_path='/two')
        seen=[]
        def reply(messages,schema=None):seen.append(messages);return {'strategy':'not_found'}
        with patch.object(self.ai,'_transport',side_effect=reply):
            self.assertIsNotNone(self.ai.ssh_reply(first,'probe_first'))
            self.assertIsNotNone(self.ai.ssh_reply(second,'probe_second'))
        self.assertNotIn('probe_first',json.dumps(seen[1]))
        self.assertEqual(first._local_ai_turns,[])
        self.assertEqual(second._local_ai_turns,[])
        self.assertNotEqual(first._interaction_session,second._interaction_session)

    def test_unknown_ssh_command_retains_original_response_on_failure(self):
        from ssh_honeypot.commands import execute_single_command
        shell=SimpleNamespace(_expand_variables=lambda args:args,_expand_wildcards=lambda args:args,fs_state={},session_key='fallback')
        with patch.object(self.ai,'ssh_reply',return_value=None):
            self.assertEqual(execute_single_command(shell,'probe_missing'),'probe_missing: command not found\n')

    def test_admin_api_auth_origin_and_csrf(self):
        from dashboard.server import app
        client=app.test_client()
        url='http://127.0.0.1:5001'
        self.assertEqual(client.get('/api/ai/status',base_url=url).status_code,401)
        with client.session_transaction(base_url=url) as session:
            session['is_admin']=True;session['username']='test';session['csrf_token']='test-token'
        self.assertEqual(client.get('/api/ai/status',base_url=url,headers={'Origin':'http://evil.test'}).status_code,403)
        headers={'Origin':url}
        self.assertEqual(client.post('/api/ai/probe',base_url=url,headers=headers).status_code,403)
        with patch.object(self.ai,'probe',return_value={'status':'fallback','reason':'model_unavailable'}):
            response=client.post('/api/ai/probe',base_url=url,headers={**headers,'X-CSRF-Token':'test-token'})
            self.assertEqual(response.status_code,200)
            self.assertEqual(response.json['data']['status'],'fallback')

    def test_web_still_responds_without_model(self):
        from web_honeypot.server import app
        with patch.dict(self.ai.SETTINGS,web_interaction_enabled=False),patch.object(self.ai,'_transport',side_effect=AssertionError('not required')):
            response=app.test_client().get('/api/preview?url=http://example.test/')
        self.assertEqual(response.status_code,202)
        self.assertEqual(response.get_json()['strategy'],'preview_pending')

    def test_audit_failure_does_not_call_model(self):
        with patch.object(self.ai.STORE,'start',side_effect=OSError('test')),patch.object(self.ai,'_transport') as transport:
            self.assertEqual(self.ai.probe('storage')['reason'],'audit_storage_unavailable')
            transport.assert_not_called()

    def test_remote_model_endpoint_is_rejected(self):
        from utils.ai_settings import load_settings
        # 显式指定 local provider：否则真实配置里的 deepseek 分支会忽略 base_url，
        # 测试就会因“没有 Key”而假性通过。
        with patch.dict(os.environ,HONEYPOT_AI_PROVIDER='local',HONEYPOT_AI_BASE_URL='http://192.0.2.10:11434',HONEYPOT_AI_MODEL='qwen2.5:7b'):
            self.assertFalse(load_settings()['configured'])
        with patch.dict(os.environ,HONEYPOT_AI_PROVIDER='local',HONEYPOT_AI_BASE_URL='http://127.0.0.1:11434',HONEYPOT_AI_MODEL='qwen2.5:7b'):
            self.assertTrue(load_settings()['configured'])

    def test_model_response_byte_limit(self):
        response=MagicMock(status_code=200)
        response.iter_content.return_value=[b'x'*65537]
        with self.assertRaises(ValueError):self.ai._read_json(response,65536,time.monotonic()+2)

    def test_same_ssh_session_reentrant_call_falls_back(self):
        entered=threading.Event();release=threading.Event()
        shell=SimpleNamespace(session_key='shared',client_ip='127.0.0.1')
        def reply(_,schema=None):entered.set();release.wait(2);return {'strategy':'not_found'}
        outputs=[]
        with patch.object(self.ai,'_transport',side_effect=reply) as transport:
            worker=threading.Thread(target=lambda:outputs.append(self.ai.ssh_reply(shell,'first')))
            worker.start()
            try:
                self.assertTrue(entered.wait(1))
                self.assertIsNone(self.ai.ssh_reply(shell,'second'))
            finally:release.set();worker.join(3)
            self.assertEqual(transport.call_count,1)
            self.assertEqual(outputs,['first: command not found\n'])


if __name__=='__main__':
    with tempfile.TemporaryDirectory(prefix='Project-') as folder:
        temp=Path(folder)
        config=temp/'test.ini'
        config.write_text('[app]\nproduction_mode=false\n[admin]\npassword=test-only\n',encoding='utf-8')
        os.environ.update(HONEYPOT_CONFIG=str(config),DB_PATH=str(temp/'events.db'),DB_TYPE='sqlite',
                          ALERT_ENABLED='false',SECRET_KEY='test-only-secret',ADMIN_PASS='test-only',
                          PRODUCTION_MODE='false',HONEYPOT_AI_DB=str(temp/'ai.db'),HONEYPOT_AI_DETECTION_ENABLED='false')
        import app_config
        app_config.Config.LOG_DIR=str(temp/'logs')
        suite=unittest.defaultTestLoader.loadTestsFromTestCase(Checks)
        result=unittest.TextTestRunner(verbosity=2).run(suite)
        live_success=True
        if '--live' in sys.argv and result.wasSuccessful():
            from utils import local_ai
            live={'health':local_ai.health(force=True),'probe':local_ai.probe('live-'+str(time.time()))}
            from ssh_honeypot.commands import execute_single_command
            shell=SimpleNamespace(_expand_variables=lambda args:args,_expand_wildcards=lambda args:args,
                                  fs_state={},session_key='live-ssh-'+str(time.time()),client_ip='127.0.0.1')
            live['ssh_simulated_reply']=execute_single_command(shell,'Project_model_probe')
            with patch.dict(local_ai.SETTINGS,base_url='http://127.0.0.1:59999'):
                unavailable=local_ai.probe('offline-'+str(time.time()))
                fallback_shell=SimpleNamespace(_expand_variables=lambda args:args,_expand_wildcards=lambda args:args,
                    fs_state={},session_key='offline-ssh-'+str(time.time()),client_ip='127.0.0.1')
                fallback=execute_single_command(fallback_shell,'Project_offline_probe')
            live['unavailable_endpoint_test']={'method':'unreachable loopback address; user Ollama was not stopped',
                                              'probe':unavailable,'ssh_fallback':fallback}
            live['audit']=local_ai.STORE.snapshot()
            live_success=(live['probe']['status']=='success' and unavailable['reason']=='model_unavailable'
                          and fallback=='Project_offline_probe: command not found\n')
            Path(os.environ.get('MIMO_ACCEPTANCE_OUTPUT',str(temp/'live.json'))).write_text(json.dumps(live,ensure_ascii=False,indent=2),encoding='utf-8')
            print('LIVE_RESULT',json.dumps(live,ensure_ascii=False))
        from utils import local_ai
        local_ai._pool.shutdown(wait=True)
        logging.shutdown()
        raise SystemExit(0 if result.wasSuccessful() and live_success else 1)
