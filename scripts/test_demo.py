"""Validate the demo driver using disposable Web/SSH services, no real model."""
import json
import logging
import os
import socket
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'scripts'))
from mixed_attack_demo import Demo,scenarios,trusted_poll_path,parse_args


class DemoChecks(unittest.TestCase):
    def test_bounded_case_set_and_marker(self):
        for quick in (True,False):
            cases=scenarios('hp_demo_fixture',quick)
            self.assertLessEqual(len(cases),12)
            self.assertTrue(all(v[4]['demo_run']=='hp_demo_fixture' for v in cases))
        self.assertEqual({r[-1] for r in scenarios('run')} - {'normal','recon','preview'},
            {'scanner','xss','sqli','path_traversal','command_injection','ssti','xxe','ssrf'})

    def test_untrusted_poll_addresses_rejected(self):
        for path in ('http://example.test/','//example.test/','/api/preview/jobs/'+'a'*24+'?url=evil','/api/preview/jobs/../secret'):
            self.assertIsNone(trusted_poll_path(path))
        self.assertEqual(trusted_poll_path('/api/preview/jobs/'+'a'*24),'/api/preview/jobs/'+'a'*24)

    def test_driver_refuses_absolute_request_path(self):
        demo=Demo(run_id='fixture')
        try:
            for path in ('//outside.test/','http://outside.test/'):
                with self.assertRaises(ValueError):demo.request('invalid',path=path)
        finally:demo.client.close()

    def test_cli_does_not_accept_remote_hosts_or_unbounded_speed(self):
        for args in (['--host','192.0.2.1'],['--gap','0'],['--timeout','1000'],['--auth-failure-demo']):
            with self.assertRaises(SystemExit):parse_args(args)

    def test_network_failure_saved_as_transport_failure(self):
        import requests
        demo=Demo(run_id='fixture')
        try:
            with patch.object(demo.client,'request',side_effect=requests.ConnectionError()):demo.request('offline')
            with tempfile.TemporaryDirectory() as folder:
                path,_=demo.save(folder);data=json.loads(path.read_text(encoding='utf-8'))
                self.assertEqual(data['records'][0]['status'],'transport_error')
        finally:demo.client.close()

    def test_real_web_and_same_ssh_channel_in_temporary_services(self):
        from web_honeypot.server import app
        from ssh_honeypot import server
        from utils import local_ai
        from werkzeug.serving import make_server
        import paramiko
        web=make_server('127.0.0.1',0,app,threaded=True)
        wt=threading.Thread(target=web.serve_forever,daemon=True);wt.start()
        listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(2);listener.settimeout(10)
        key=paramiko.RSAKey.generate(2048)
        workers=[]
        def accept():
            for _ in range(2):
                sock,addr=listener.accept();server.SSH_WORKER_SEM.acquire()
                worker=threading.Thread(target=server.handle_client,args=(sock,addr,key),daemon=True)
                workers.append(worker);worker.start()
        st=threading.Thread(target=accept,daemon=True)
        demo=Demo(web.server_port,listener.getsockname()[1],gap=.01,timeout=8,run_id='hp_demo_fixture')
        try:
            with patch.dict(server.SSH_CREDENTIALS,{'root':'fixture-private-credential'}),patch.dict(local_ai.SETTINGS,enabled=False,web_interaction_enabled=True),patch.object(local_ai,'_transport') as model:
                st.start();demo.web();demo.ssh('root','fixture-private-credential',failure_demo=True)
                model.assert_not_called()
            self.assertFalse(any(r['status'] in ('transport_error','auth_failed') for r in demo.records))
            read=next(r for r in demo.records if r['label']=='读回虚拟文件')
            self.assertIn('hp_demo_fixture',read['response_preview'])
            # Identity and virtual filesystem operations happen over one channel.
            self.assertEqual(sum(r['status']=='virtual_login_accepted' for r in demo.records),1)
            self.assertEqual(sum(r['status']=='expected_auth_rejection' for r in demo.records),1)
            self.assertNotIn('fixture-private-credential',json.dumps(demo.records))
            from db.connection import get_connection
            from contextlib import closing
            with closing(get_connection()) as connection:
                query=connection.execute("SELECT query_string FROM raw_request WHERE path='/products' ORDER BY id DESC LIMIT 1").fetchone()[0]
                self.assertIn('UNION%20SELECT',query)
        finally:
            demo.client.close();web.shutdown();web.server_close();listener.close();st.join(5);wt.join(2)
            for worker in workers:worker.join(5)


if __name__=='__main__':
    with tempfile.TemporaryDirectory(prefix='mixed-demo-verify-') as folder:
        temp=Path(folder);ini=temp/'test.ini';ini.write_text('[app]\nproduction_mode=false\n[admin]\npassword=test-only\n',encoding='utf-8')
        os.environ.update(HONEYPOT_CONFIG=str(ini),PRODUCTION_MODE='false',ADMIN_PASS='test-only',SECRET_KEY='test-only',
            DB_TYPE='sqlite',DB_PATH=str(temp/'events.db'),ALERT_ENABLED='false',HONEYPOT_AI_DB=str(temp/'ai.db'),
            HONEYPOT_AI_ENABLED='false',HONEYPOT_AI_DETECTION_ENABLED='false',HONEYPOT_AI_ANALYSIS_ENABLED='false')
        import app_config
        app_config.Config.LOG_DIR=str(temp/'logs')
        result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(DemoChecks))
        from utils import local_ai
        local_ai._pool.shutdown(wait=True);logging.shutdown()
        raise SystemExit(0 if result.wasSuccessful() else 1)
