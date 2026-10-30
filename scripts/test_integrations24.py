"""Integration contracts: six protocols, independent classification and source review."""
import tempfile
import unittest
import json
import time
from pathlib import Path

class ProtocolContracts(unittest.TestCase):
    def test_windows_permissions_preserve_inherited_service_access(self):
        from utils import logger
        from unittest.mock import patch
        import types
        calls=[]
        with patch.object(logger.os,'name','nt'),patch.object(logger.subprocess,'run',side_effect=lambda args,**kwargs:(calls.append(args)or types.SimpleNamespace(stdout='"runtime","S-1-5-21-123"',returncode=0))):
            logger._harden_permissions('synthetic-path',True)
        self.assertFalse(any('/inheritance:r'in args for args in calls))
    def test_mysql_never_requests_client_files(self):
        from db_honeypot.mysql_handler import _query_response
        packet=_query_response("LOAD DATA LOCAL INFILE '/etc/passwd' INTO TABLE x",'demo')
        self.assertEqual(packet[4],0xff)
    def test_event_protocol_names_are_preserved(self):
        from db.event_logs import _normalize_source
        for source in ('mysql','redis','ftp','telnet'):
            self.assertEqual(_normalize_source(source),source)
    def test_six_channels_survive_index_and_case(self):
        from investigation_core.local import LocalInvestigation
        from investigation_core.workflow import Workflow
        with tempfile.TemporaryDirectory() as tmp:
            engine=LocalInvestigation(Path(tmp)/'i.db',Path(tmp)/'e.db')
            rows=[dict(source_id='test24',table='event_log',record_id=i+1,timestamp='2026-10-30 12:00:00',src_ip='127.0.0.1',session_id='protocol-'+p,channel=p,kind='protocol_probe',rule_level='medium',excerpt='synthetic '+p,traffic_origin='synthetic')for i,p in enumerate(('web','ssh','mysql','redis','ftp','telnet'))]
            engine.store.ingest(engine.sensor,'batch24',rows,{},[])
            self.assertEqual({r['channel']for r in engine.store.search(engine.owner,{},20)['records']},{r['channel']for r in rows})
            case=Workflow(engine).create_case({'title':'六协议证据','query':{}})
            self.assertEqual(len(case['evidence']),6)

class TargetContracts(unittest.TestCase):
    def test_revision_and_labels_do_not_imply_firewall(self):
        from utils.source_targets import Targets
        with tempfile.TemporaryDirectory() as tmp:
            store=Targets(Path(tmp)/'targets.db')
            row=store.save({'ip':'127.0.0.1','level':'medium','status':'watching','note':'checked','tags':['测试'],'revision':0})
            self.assertEqual(row['revision'],1)
            with self.assertRaisesRegex(ValueError,'revision_conflict'):
                store.save({'ip':'127.0.0.1','level':'low','status':'handled','revision':0})
            with self.assertRaises(ValueError):store.save({'ip':'invalid','revision':0})
            self.assertEqual(len(store.listing()),1)

class ClassifierContracts(unittest.TestCase):
    def test_storage_failure_does_not_kill_worker(self):
        from utils.classifier import Classifier
        from unittest.mock import patch
        import sqlite3
        class Response:
            status_code=200
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def iter_content(self,*args):yield b'{"attack_type":"normal","is_attack":false,"attack_prob":0.9,"ai_points":0}'
        class Session:
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def post(self,*args,**kwargs):return Response()
        with tempfile.TemporaryDirectory()as tmp:
            worker=Classifier(Path(tmp)/'c.db',lambda:{'enabled':True,'url':'http://127.0.0.1:8003/api/v1/detect','timeout':1});original=worker.connect
            attempts=[0]
            def connect():
                attempts[0]+=1
                if attempts[0]==1:raise sqlite3.OperationalError('synthetic locked database')
                return original()
            row=dict(source='test',raw_request_id=1,request_time='2026-10-30 12:00:00',ip='127.0.0.1',session_id='s',rule_score=0)
            with patch('utils.classifier.requests.Session',Session),patch.object(worker,'connect',side_effect=connect):
                worker.submit(row);worker.queue.join()
                second={**row,'raw_request_id':2};worker.submit(second)
                deadline=time.monotonic()+1;found=None
                while time.monotonic()<deadline:
                    found=worker.get(second)
                    if found and found['status']=='completed':break
                    time.sleep(.02)
                self.assertIsNotNone(found);self.assertEqual(found['status'],'completed')
    def test_endpoint_is_local_and_outputs_are_bounded(self):
        from utils.classifier import endpoint,normalize_result
        with self.assertRaises(ValueError):endpoint('http://example.com/api/v1/detect')
        with self.assertRaises(ValueError):endpoint('http://127.0.0.1:8003/api/v1/detect?x=1')
        r=normalize_result({'attack_type':'normal','is_attack':False,'attack_prob':.99,'ai_points':25})
        self.assertEqual(r['effective_points'],0)
        with self.assertRaises(ValueError):normalize_result({'attack_type':'xss','is_attack':'false','attack_prob':.5,'ai_points':10})
    def test_slow_model_is_async_and_cannot_change_another_identity(self):
        from utils.classifier import Classifier
        from unittest.mock import patch
        class Response:
            status_code=200
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def iter_content(self,*args):
                time.sleep(.15)
                yield json.dumps({'attack_type':'xss','is_attack':True,'attack_prob':.9,'ai_points':20}).encode()
        class Session:
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def post(self,*args,**kwargs):return Response()
        with tempfile.TemporaryDirectory()as tmp:
            worker=Classifier(Path(tmp)/'classifier.db',lambda:{'enabled':True,'url':'http://127.0.0.1:8003/api/v1/detect','timeout':1})
            snapshot=dict(source='fixture',raw_request_id=1,request_time='2026-10-30 12:00:00',ip='127.0.0.1',session_id='A',rule_score=12)
            with patch('utils.classifier.requests.Session',Session):
                start=time.monotonic();self.assertEqual(worker.submit(snapshot),'queued');self.assertLess(time.monotonic()-start,.1)
                worker.queue.join()
            row=worker.get(snapshot);self.assertEqual(row['result']['suggested_score'],32)
            self.assertIsNone(worker.get({**snapshot,'request_time':'2026-10-30 12:00:01'}))
            self.assertEqual(snapshot['rule_score'],12)

class CloudContracts(unittest.TestCase):
    def test_https_explicit_consent_and_key_never_returned(self):
        from utils.integration_settings import save_cloud,cloud_public
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'ai.ini'
            data={'provider':'deepseek','base_url':'https://api.deepseek.com','model':'deepseek-chat','api_key':'sample-secret-123456','enabled':True,'consent':False}
            with self.assertRaises(ValueError):save_cloud(path,data)
            data['consent']=True;data['base_url']='http://api.deepseek.com'
            with self.assertRaises(ValueError):save_cloud(path,data)
            data['base_url']='https://api.deepseek.com';save_cloud(path,data)
            public=cloud_public(path)
            self.assertTrue(public['key_configured']);self.assertNotIn('sample-secret',str(public))
            self.assertTrue(public['restart_required'])
    def test_cloud_transport_uses_schema_and_auth_without_mutating_messages(self):
        from utils import local_ai
        from unittest.mock import patch
        calls=[]
        class Response:
            status_code=200
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def iter_content(self,*args,**kwargs):yield json.dumps({'choices':[{'message':{'content':'{"reply":"verified"}'},'finish_reason':'stop'}]}).encode()
        class Session:
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def post(self,*args,**kwargs):calls.append((args,kwargs));return Response()
        messages=[{'role':'user','content':'fixed test'}]
        with patch.dict(local_ai.SETTINGS,provider='deepseek',base_url='https://api.deepseek.com',api_key='sample-key',model='deepseek-chat'),patch('utils.local_ai.requests.Session',Session):
            r=local_ai._transport(messages)
        self.assertEqual(r,'verified');self.assertEqual(len(messages),1)
        self.assertEqual(calls[0][1]['headers']['Authorization'],'Bearer sample-key')
        self.assertFalse(calls[0][1]['allow_redirects'])

class InputBoundaryContracts(unittest.TestCase):
    def test_redis_rejects_oversized_bulk_before_reading(self):
        import io
        from db_honeypot.redis_handler import RedisHoneypot
        with self.assertRaises(ValueError):RedisHoneypot(None,None,None)._read_command(io.BytesIO(b'*1\r\n$999999999\r\n'))
    def test_ftp_rejects_oversized_lines_and_active_connections(self):
        import io
        from file_honeypot.ftp_handler import FTPHoneypot
        handler=FTPHoneypot(None,None,None)
        with self.assertRaises(ValueError):handler._read_command(io.BytesIO(b'A'*5000))
        messages=[];handler._send=messages.append
        handler._cmd_port('127,0,0,1,0,22',False)
        self.assertIsNone(handler._active_addr);self.assertTrue(messages[0].startswith('502'))
        self.assertEqual(handler._local_ipv4('127.0.0.1'),'127.0.0.1')
    def test_telnet_caps_line_and_subnegotiation(self):
        from remote_honeypot.telnet_handler import TelnetHoneypot
        from unittest.mock import Mock
        handler=TelnetHoneypot(None,None,None);handler._next_byte=Mock(side_effect=[97]*5000+[None])
        with self.assertRaises(ValueError):handler._read_line(echo=False)
        handler._iac_state='subneg'
        with self.assertRaises(ValueError):
            for _ in range(2000):handler._feed_byte(97,False)

class ApiContracts(unittest.TestCase):
    def test_target_and_protocol_settings_are_validated(self):
        from flask import Flask
        from dashboard.integration_api import register
        from investigation_core.local import LocalInvestigation
        with tempfile.TemporaryDirectory()as tmp:
            root=Path(tmp);app=Flask('integration-test');app.secret_key='synthetic-test-session'
            app.local_engine=lambda:engine
            engine=LocalInvestigation(root/'index.db',root/'source.db')
            app.config['INTEGRATION_CONFIG']=str(root/'honeypot.ini');app.config['AI_SETUP_CONFIG']=str(root/'ai.ini')
            register(app,lambda f:f,lambda f:f);client=app.test_client()
            p=dict(ip='127.0.0.1',level='high',status='reviewing',note='synthetic',tags=['test'],revision=0)
            self.assertEqual(client.post('/api/integrations/targets',json=p).status_code,403)
            h={'X-CSRF-Token':'test'}
            self.assertEqual(client.post('/api/integrations/targets',json=p,headers=h).status_code,200)
            self.assertEqual(client.post('/api/integrations/targets',json=p,headers=h).status_code,409)
            rows=[dict(protocol=x,enabled=True,host='127.0.0.1',port=22000+i)for i,x in enumerate(('mysql','redis','ftp','telnet'))]
            self.assertEqual(client.post('/api/integrations/protocols',json={'services':rows},headers=h).status_code,200)
            rows[1]['port']=rows[0]['port']
            self.assertEqual(client.post('/api/integrations/protocols',json={'services':rows},headers=h).status_code,400)
            self.assertEqual(len(client.get('/api/integrations/targets').get_json()['records']),1)

if __name__=='__main__':unittest.main()
