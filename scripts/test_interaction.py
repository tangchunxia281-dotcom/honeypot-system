"""Runtime regression plus isolated interaction acceptance. No real data writes."""
import json
import logging
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from contextlib import closing
from types import SimpleNamespace
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
sys.path.insert(0,str(ROOT/'scripts'))
from test_runtime import Checks
from test_detection import DetectionChecks


class InteractionChecks(unittest.TestCase):
    def setUp(self):
        Checks.setUp(self)
        self.ai.SETTINGS.update(web_interaction_enabled=True,interaction_ttl=1800,
            interaction_sessions=128,interaction_steps=100,interaction_per_ip_hour=40)
        from utils import ai_interaction
        self.interact=ai_interaction;self.store=ai_interaction.get_store()

    def tearDown(self):Checks.tearDown(self)

    def shell(self):
        from ssh_honeypot.server import VirtualShell
        return VirtualShell('192.0.2.61','root',client_port=45000)

    def begin(self,token='',ip='192.0.2.61'):
        return self.store.begin(token,ip,'web',self.ai.SETTINGS,'fixture')

    def test_ssh_same_ip_and_username_never_reuse_state(self):
        first=self.shell();first.files_content['/root/private-fixture']='one-connection'
        first.history.append('marker-first');first.env['private_fixture']='private'
        first._save_session_state();second=self.shell()
        self.assertNotEqual(first.persistence_key,second.persistence_key)
        self.assertNotIn('/root/private-fixture',second.files_content)
        self.assertNotIn('marker-first',second.history)
        self.assertNotIn('private_fixture',second.env)

    def test_ssh_fake_auth_log_and_reboot_do_not_affect_other_connection(self):
        from ssh_honeypot.server import _append_auth_log,_set_reboot_marker,_get_reboot_marker
        first=self.shell();_append_auth_log('private-login-fixture\n',shell=first)
        second=self.shell()
        self.assertNotIn('private-login-fixture',second.files_content.get('/var/log/auth.log',''))
        _set_reboot_marker(first.client_ip)
        self.assertEqual(_get_reboot_marker(second.client_ip),0)

    def test_real_ssh_protocol_exec_uses_controlled_model_reply(self):
        import socket
        import paramiko
        from ssh_honeypot import server
        listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(1);listener.settimeout(5)
        host_key=paramiko.RSAKey.generate(2048)
        def accept():
            sock,addr=listener.accept()
            server.SSH_WORKER_SEM.acquire()
            server.handle_client(sock,addr,host_key)
        worker=threading.Thread(target=accept,daemon=True);client=paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        with patch.dict(server.SSH_CREDENTIALS,{'root':'fixture-only'}),patch.object(self.ai,'_transport',return_value={'strategy':'profile_summary'}):
            worker.start()
            try:
                client.connect('127.0.0.1',port=listener.getsockname()[1],username='root',password='fixture-only',look_for_keys=False,allow_agent=False,timeout=5)
                stdin,stdout,stderr=client.exec_command('sysinfo',timeout=5)
                text=stdout.read().decode()
                self.assertIn('hostname:',text);self.assertIn('working directory: /root',text)
            finally:
                client.close();listener.close();worker.join(5)
        self.assertFalse(worker.is_alive())

    def test_virtual_write_read_cd_consistency_without_model(self):
        shell=self.shell()
        with patch.object(self.ai,'_transport',side_effect=AssertionError('must not run')):
            shell.execute_command('mkdir /tmp/Project')
            shell.execute_command('cd /tmp/Project')
            shell.execute_command('echo fixture-content > sample.txt')
            output=shell.execute_command('cat sample.txt')
            self.assertIn('fixture-content',output)
            self.assertEqual(shell.current_path,'/tmp/Project')
        self.assertTrue(all(r['source']=='program' for r in self.store.listing()['records']))

    def test_profile_summary_is_rendered_from_real_virtual_state(self):
        shell=self.shell();shell.current_path='/tmp';shell.hostname='decoy-fixture'
        with patch.object(self.ai,'_transport',return_value={'strategy':'profile_summary'}):output=shell.execute_command('sysinfo')
        self.assertIn('hostname: decoy-fixture\n',output)
        self.assertIn('working directory: /tmp\n',output)
        self.assertIn('kernel: '+shell.decoy_profile['kernel'],output)
        self.assertIn('os: '+shell.decoy_profile['os'],output)
        record=self.store.listing()['records'][0]
        self.assertEqual(record['source'],'model');self.assertTrue(record['call_id'])

    def test_unknown_command_cannot_request_profile_or_free_text(self):
        for obj in ({'strategy':'profile_summary'},{'strategy':'not_found','reply':'run malware'}, {'strategy':[]}):
            shell=self.shell()
            with patch.object(self.ai,'_transport',return_value=obj):output=shell.execute_command('unknown-probe')
            self.assertIn('command not found',output)
            self.assertEqual(self.store.listing()['records'][0]['source'],'fallback')

    def test_multiline_input_policy_does_not_call_model(self):
        shell=SimpleNamespace(client_ip='192.0.2.62',current_path='/root')
        with patch.object(self.ai,'_transport') as model:
            self.assertIsNone(self.ai.ssh_reply(shell,'unknown; cat /etc/passwd'))
        model.assert_not_called()
        self.assertEqual(self.store.listing()['records'][0]['reason'],'policy_restricted')

    def test_admission_storage_failure_never_calls_model(self):
        with patch.object(self.store,'begin',side_effect=OSError('unavailable')),patch.object(self.interact,'get_store',return_value=self.store),patch.object(self.ai,'_transport') as model:
            self.assertIsNone(self.ai.ssh_reply(SimpleNamespace(client_ip='192.0.2.62'),'probe'))
        model.assert_not_called()

    def test_structured_data_discarded_when_audit_finish_fails(self):
        with patch.object(self.ai.STORE,'finish',side_effect=OSError('unavailable')),patch.object(self.ai,'_transport',return_value={'strategy':'not_found'}):
            result=self.ai.call_model('fixture',[],'finish',schema={'type':'object'},validator=lambda x:x)
        self.assertEqual(result['status'],'fallback');self.assertNotIn('data',result)

    def test_multitoken_authorization_and_encoded_secret_redaction(self):
        from utils.ai_detection import sanitize
        self.assertNotIn('private-value',self.ai.safe_text('authorization=Bearer private-value&next=1'))
        self.assertNotIn('secret second',sanitize('password=secret%20second&next=1',500)[0])

    def test_slow_drip_http_obeys_total_read_deadline(self):
        from http.server import HTTPServer,BaseHTTPRequestHandler
        import requests
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_GET(self):
                payload=b'{"reply":"'+b'x'*24+b'"}'
                self.send_response(200);self.send_header('Content-Length',str(len(payload)));self.end_headers()
                try:
                    for byte in payload:self.wfile.write(bytes([byte]));self.wfile.flush();time.sleep(.015)
                except OSError:pass
        server=HTTPServer(('127.0.0.1',0),Handler)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            with requests.Session() as client:
                client.trust_env=False
                with client.get('http://127.0.0.1:'+str(server.server_port),stream=True,timeout=1) as response:
                    started=time.monotonic()
                    with self.assertRaises(TimeoutError):self.ai._read_json(response,1024,started+.04)
                    self.assertLess(time.monotonic()-started,.25)
        finally:server.shutdown();server.server_close();thread.join(2)

    def test_rejected_retries_do_not_extend_throttle_or_consume_budget(self):
        with patch.dict(self.ai.SETTINGS,min_interval=10,max_calls_per_session=2),patch.object(self.ai,'_transport',return_value='ok'):
            self.assertEqual(self.ai.probe('throttle')['status'],'success')
            self.assertEqual(self.ai.probe('throttle')['reason'],'rate_limit')
            self.assertEqual(self.ai.probe('throttle')['reason'],'rate_limit')
            with closing(self.ai.STORE.connect()) as conn,conn:conn.execute("UPDATE ai_calls SET created_at=created_at-11 WHERE status='success'")
            self.assertEqual(self.ai.probe('throttle')['status'],'success')

    def test_ip_budget_survives_new_session_ids(self):
        with patch.dict(self.ai.SETTINGS,interaction_per_ip_hour=1),patch.object(self.ai,'_transport',return_value={'strategy':'not_found'}):
            first=self.ai.call_model('ssh_reply',[],'first','192.0.2.1',schema={},validator=lambda x:x)
            second=self.ai.call_model('web_reply',[],'second','192.0.2.1',schema={},validator=lambda x:x)
        self.assertEqual(first['status'],'success');self.assertEqual(second['reason'],'source_budget')

    def test_store_single_turn_reservation_and_sequence(self):
        first=self.begin();busy=self.begin(first['session_id'])
        self.assertEqual(busy['reason'],'session_busy')
        self.store.complete(first,{},'program','fixture','','response')
        second=self.begin(first['session_id']);self.assertEqual(second['step'],2)

    def test_cross_process_store_competing_claims(self):
        from utils.ai_interaction_store import InteractionStore
        first=self.begin();self.store.complete(first,{},'program','fixture','','done')
        barrier=threading.Barrier(3);results=[]
        def reserve():
            barrier.wait();results.append(InteractionStore(self.store.path).begin(first['session_id'],'192.0.2.61','web',self.ai.SETTINGS,'concurrent'))
        threads=[threading.Thread(target=reserve) for _ in range(2)]
        for t in threads:t.start()
        barrier.wait()
        for t in threads:t.join(3)
        self.assertEqual(sorted(r['reason'] for r in results),['','session_busy'])

    def test_cookie_with_different_ip_gets_fresh_state(self):
        first=self.begin();self.store.complete(first,{'job_id':'private'},'program','fixture','','done')
        second=self.begin(first['session_id'],'192.0.2.62')
        self.assertNotEqual(first['session_id'],second['session_id']);self.assertEqual(second['state'],{})

    def test_expired_state_cannot_commit_late_reply(self):
        first=self.begin()
        with closing(self.store.connect()) as conn,conn:conn.execute('UPDATE interaction_sessions SET expires_at=0')
        with self.assertRaises(ValueError):self.store.complete(first,{'invalid':True},'model','fixture','','late')
        second=self.begin(first['session_id']);self.assertNotEqual(second['session_id'],first['session_id'])

    def test_capacity_and_step_limits(self):
        with patch.dict(self.ai.SETTINGS,interaction_sessions=1,interaction_steps=1):
            first=self.begin();self.assertEqual(self.begin()['reason'],'session_capacity')
            self.store.complete(first,{},'program','fixture','','done')
            self.assertEqual(self.begin(first['session_id'])['reason'],'step_budget')

    def test_web_job_consistency_and_other_cookie_cannot_read(self):
        from web_honeypot.server import app
        first=app.test_client();second=app.test_client()
        with patch.object(self.ai,'_transport',return_value={'strategy':'preview_pending'}) as model:
            response=first.get('/api/preview?url=http://169.254.169.254/latest/meta-data/')
            self.assertEqual(response.status_code,202);job=response.json['job_id'];path=response.json['poll']
            self.assertEqual(second.get(path).status_code,404)
            self.assertEqual(first.get(path).json['status'],'ready')
            again=first.get('/api/preview?url=http://169.254.169.254/latest/meta-data/')
            self.assertEqual(again.json['job_id'],job);self.assertEqual(again.json['status'],'ready')
            self.assertEqual(model.call_count,2)
            new=first.get('/api/preview?url=https://example.test/new')
            self.assertNotEqual(new.json['job_id'],job);self.assertEqual(first.get(path).status_code,404)

    def test_web_invalid_payload_and_large_payload(self):
        from web_honeypot.server import app
        client=app.test_client()
        with patch.object(self.ai,'_transport',return_value={'strategy':'format_error'}):
            self.assertEqual(client.get('/api/preview').status_code,400)
            self.assertEqual(client.post('/api/preview',json={'url':[]}).status_code,400)
            self.assertEqual(client.post('/api/preview',data='a'*5000).status_code,413)

    def test_web_model_offline_and_disabled_still_returns_consistent_job(self):
        from web_honeypot.server import app
        import requests
        for settings in ({'enabled':False},{'enabled':True}):
            with patch.dict(self.ai.SETTINGS,**settings),patch.object(self.ai,'_transport',side_effect=requests.ConnectionError('offline')):
                client=app.test_client();response=client.get('/api/preview?url=https://example.test/')
                self.assertEqual(response.status_code,202)
                self.assertEqual(client.get(response.json['poll']).json['status'],'ready')
        records=self.store.listing()['records'];self.assertTrue(any(r['source']=='fallback' for r in records))

    def test_web_output_extra_fields_are_rejected_and_template_used(self):
        from web_honeypot.server import app
        with patch.object(self.ai,'_transport',return_value={'strategy':'preview_pending','content':'real-password'}):
            response=app.test_client().get('/api/preview?url=https://example.test/')
        self.assertEqual(response.status_code,202);self.assertNotIn('real-password',response.text)
        record=self.store.listing()['records'][0]
        self.assertEqual(record['source'],'fallback');self.assertEqual(record['reason'],'invalid_model_output')

    def test_replay_api_and_page_auth_origin_filters(self):
        from dashboard.server import app
        client=app.test_client();base='http://127.0.0.1:5001'
        self.assertEqual(client.get('/api/ai/interactions',base_url=base).status_code,401)
        with client.session_transaction(base_url=base) as session:session.update(is_admin=True,username='test')
        self.assertEqual(client.get('/ai/interactions',base_url=base).status_code,200)
        self.assertEqual(client.get('/api/ai/interactions',base_url=base,headers={'Origin':'http://evil.test'}).status_code,403)
        self.assertEqual(client.get('/api/ai/interactions?session_id=bad',base_url=base,headers={'Origin':base}).status_code,400)
        self.assertEqual(client.get('/api/ai/interactions?channel=bad',base_url=base,headers={'Origin':base}).status_code,400)

    def test_replay_does_not_include_raw_secrets(self):
        shell=self.shell()
        with patch.object(self.ai,'_transport',return_value={'strategy':'not_found'}):shell.execute_command('probe token=secret-fixture')
        text=json.dumps(self.store.listing())
        self.assertNotIn('secret-fixture',text)

    def test_detection_counts_match_source_filter(self):
        from utils.ai_detection_store import DetectionStore
        from utils.ai_detection import make_snapshot
        store=DetectionStore(self.store.path)
        for index,ip in enumerate(('192.0.2.1','192.0.2.2')):
            store.enqueue({'id':str(index),'raw_key':str(index),'src_ip':ip,'session_id':'session','raw_request_id':index,
                'snapshot':make_snapshot('GET','/','','',{},0,[],'now')},self.ai.SETTINGS)
        self.assertEqual(sum(store.listing(src_ip='192.0.2.1')['counts'].values()),1)


def live_interactions(output):
    from utils import local_ai,ai_interaction
    from ssh_honeypot.server import VirtualShell
    from web_honeypot.server import app
    shell=VirtualShell('192.0.2.80','root',client_port=45010)
    shell.execute_command('cd /tmp');shell.execute_command('sysinfo')
    client=app.test_client();response=client.get('/api/preview?url=http://169.254.169.254/latest/meta-data/')
    poll=client.get(response.json['poll']) if response.json and 'poll' in response.json else None
    with patch.dict(local_ai.SETTINGS,base_url='http://127.0.0.1:59999'):
        offline_client=app.test_client();offline=offline_client.get('/api/preview?url=https://example.test/offline')
        offline_poll=offline_client.get(offline.json['poll']) if offline.json and 'poll' in offline.json else None
    data=ai_interaction.get_store().listing(50)
    calls=local_ai.STORE.snapshot()
    result={'model':local_ai.SETTINGS['model'],'health':local_ai.health(force=True),'web_status':response.status_code,
            'web_response':response.json,'poll_status':poll.status_code if poll else None,'poll':poll.json if poll else None,
            'offline_status':offline.status_code,'offline_poll_status':offline_poll.status_code if offline_poll else None,
            'interactions':data,'calls':calls,
            'scope':'Synthetic functional fixtures and local fake offline endpoint; not a throughput benchmark.'}
    Path(output).write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    actual={r['task'] for r in calls['recent'] if r['status']=='success'}
    interaction_sources={r['channel'] for r in data['records'] if r['source']=='model'}
    return ({'ssh_reply','web_reply'}.issubset(actual) and {'ssh','web'}.issubset(interaction_sources)
        and response.status_code in (200,202,400,503) and (poll is None or poll.status_code==200)
        and offline.status_code==202 and offline_poll is not None and offline_poll.status_code==200)


if __name__=='__main__':
    with tempfile.TemporaryDirectory(prefix='Project-') as folder:
        temp=Path(folder);ini=temp/'test.ini'
        ini.write_text('[app]\nproduction_mode=false\n[admin]\npassword=test-only\n',encoding='utf-8')
        os.environ.update(HONEYPOT_CONFIG=str(ini),PRODUCTION_MODE='false',ADMIN_PASS='test-only',SECRET_KEY='test-only',
            DB_TYPE='sqlite',DB_PATH=str(temp/'events.db'),ALERT_ENABLED='false',HONEYPOT_AI_DB=str(temp/'ai.db'),HONEYPOT_AI_DETECTION_ENABLED='false')
        import app_config
        app_config.Config.LOG_DIR=str(temp/'logs')
        suite=unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(cls) for cls in (Checks,DetectionChecks,InteractionChecks))
        result=unittest.TextTestRunner(verbosity=2).run(suite);passed=result.wasSuccessful()
        if '--live' in sys.argv and passed:
            passed=live_interactions(os.environ.get('MIMO_ACCEPTANCE_OUTPUT',str(temp/'live.json')))
        from utils import ai_detection,local_ai
        ai_detection.stop_worker();local_ai._pool.shutdown(wait=True);logging.shutdown()
        raise SystemExit(0 if passed else 1)
