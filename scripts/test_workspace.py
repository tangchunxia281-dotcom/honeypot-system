import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

class WorkflowChecks(unittest.TestCase):
    def setUp(self):
        from investigation_core.local import LocalInvestigation
        from investigation_core.workflow import Workflow
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);root=Path(self.tmp.name)
        self.engine=LocalInvestigation(root/'index.sqlite',root/'events.sqlite');self.flow=Workflow(self.engine)
        row=dict(source_id='fixture',table='raw_request',record_id=1,timestamp='2026-10-29 12:00:00',src_ip='127.0.0.1',session_id='session-A',channel='web',kind='http_request',rule_level='medium',excerpt='GET /products?id=UNION SELECT',traffic_origin='synthetic')
        self.engine.store.ingest(self.engine.sensor,'fixture',[row],{},[])
        self.identifier=self.engine.store.search(self.engine.owner,{},20)['records'][0]['id']
    def test_case_snapshot_and_scope_survive_new_records(self):
        case=self.flow.create_case({'evidence_id':self.identifier,'title':'注入调查'})
        self.assertEqual(case['query']['session'],'session-A');self.assertEqual(len(case['evidence']),1)
        self.assertEqual(self.flow.get_case(case['id'])['evidence'][0]['id'],self.identifier)
        row=self.flow.review_event(self.identifier,{'revision':0,'label':'attack','note':'检查了请求'})
        self.assertEqual(row['revision'],1)
        with self.assertRaises(ValueError):self.flow.review_event(self.identifier,{'revision':0,'label':'benign'})
        row=self.flow.update_case(case['id'],{'revision':0,'status':'closed','note':'已复核'})
        self.assertEqual(row['status'],'closed')
    def test_unknown_evidence_never_creates_a_case(self):
        with self.assertRaises(ValueError):self.flow.create_case({'evidence_id':'a'*24,'title':'missing'})
    def test_selected_event_remains_in_bounded_busy_case_snapshot(self):
        rows=[dict(source_id='fixture',table='raw_request',record_id=n+2,timestamp='2026-10-29 12:01:00',src_ip='127.0.0.1',session_id='session-A',channel='web',kind='http_request',rule_level='low',excerpt='GET /news',traffic_origin='synthetic') for n in range(75)]
        self.engine.store.ingest(self.engine.sensor,'fixture-busy',rows,{},[])
        case=self.flow.create_case({'evidence_id':self.identifier,'title':'繁忙会话调查'})
        self.assertLessEqual(len(case['evidence']),60)
        self.assertIn(self.identifier,[r['id'] for r in case['evidence']])
    def test_open_case_scope_is_validated_after_time_boundaries_freeze(self):
        row=dict(source_id='fixture',table='raw_request',record_id=99,timestamp='2026-09-01 12:00:00',src_ip='127.0.0.1',session_id='session-A',channel='web',kind='http_request',rule_level='low',excerpt='GET /news',traffic_origin='synthetic')
        self.engine.store.ingest(self.engine.sensor,'fixture-old',[row],{},[])
        with self.assertRaisesRegex(ValueError,'time_range_limit_30_days'):
            self.flow.create_case({'query':{},'title':'范围过长不应建案成功'})

class WizardChecks(unittest.TestCase):
    def test_local_only_and_curated_downloads(self):
        from utils.ai_setup import AISetup
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):AISetup(Path(tmp)/'ai.ini',base_url='http://example.com')
            wizard=AISetup(Path(tmp)/'ai.ini')
            with self.assertRaises(ValueError):wizard.start('download','attacker/unknown-model')
    def test_configuration_preserves_values_and_is_not_live_activation(self):
        from utils.ai_setup import AISetup
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'ai.ini';path.write_text('[ai]\nenabled=false\nmodel=old\nanalysis_batch=24\n',encoding='utf-8')
            w=AISetup(path)
            with patch.object(w,'installed',return_value=[{'name':'fixture:small','size':1}]):
                r=w.configure({'enabled':True,'model':'fixture:small'})
            self.assertTrue(r['restart_required']);self.assertIn('analysis_batch = 24',path.read_text(encoding='utf-8'))
            self.assertFalse(list(Path(tmp).glob('*.tmp')))
    def test_download_progress_with_fake_ollama(self):
        from utils.ai_setup import AISetup
        from unittest.mock import patch
        class Response:
            status_code=200
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def iter_lines(self,**kwargs):
                yield b'{"status":"pulling","digest":"sha256:x","total":100,"completed":50}'
                yield b'{"status":"success"}'
        class Client:
            trust_env=False
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def post(self,*args,**kwargs):return Response()
        with tempfile.TemporaryDirectory() as tmp:
            w=AISetup(Path(tmp)/'ai.ini')
            with patch('utils.ai_setup.requests.Session',Client):
                w._download('qwen3:1.7b')
            self.assertEqual(w.status()['status'],'completed')
            self.assertNotIn('passed',w.status())

class NavigationChecks(unittest.TestCase):
    def test_five_primary_entries(self):
        root=Path(__file__).resolve().parents[1]
        text=(root/'dashboard/templates/ai_sidebar.html').read_text(encoding='utf-8')
        for label in ('安全概览','攻击事件','会话分析','证据调查','系统与评测'):self.assertIn(label,text)
        for label in ('本机研判工作台','本机证据调查','调查效果统计'):self.assertNotIn(label,text)

class PortalApiChecks(WorkflowChecks):
    def test_archived_raw_request_keeps_matching_ai_result(self):
        import hashlib
        from flask import Flask
        from unittest.mock import patch
        from dashboard.workspace_api import register
        from utils.ai_detection_store import DetectionStore
        from utils import ai_detection
        with closing(sqlite3.connect(self.engine.source)) as c,c:c.execute('CREATE TABLE raw_request(id INTEGER,create_time TEXT)')
        store=DetectionStore(Path(self.tmp.name)/'ai.sqlite')
        snap={'request_time':'2026-10-29 12:00:00','rule_score':25,'rule_signals':['SQL联合查询'],'fields':{},'truncated_fields':[]}
        for identifier,source in [('f'*24,'other-source'),('e'*24,str(self.engine.source))]:
            key=hashlib.sha256(f'{source}|1|2026-10-29 12:00:00'.encode()).hexdigest()
            store.enqueue({'id':identifier,'raw_key':key,'raw_request_id':1,'src_ip':'127.0.0.1','session_id':'session-A','snapshot':snap},{'detection_queue_max':32,'detection_per_ip_hour':20})
            store.finish(identifier,{'status':'success','data':{'verdict':'suspicious','summary':'合成注入请求','attack_types':['sqli'],'evidence':[]}})
        app=Flask(__name__);app.local_engine=lambda:self.engine
        register(app,lambda fn:fn,lambda fn:fn)
        with patch.object(ai_detection,'STORE',store):r=app.test_client().get('/api/workspace/events/'+self.identifier)
        self.assertEqual(r.status_code,200)
        value=r.get_json();self.assertIsNotNone(value['ai'])
        self.assertEqual(value['ai']['id'],'e'*24)
        self.assertEqual(value['rule']['score'],25)
        self.assertEqual(value['rule']['signals_source'],'captured_snapshot')
    def test_scope_case_link_and_closed_state(self):
        from flask import Flask,session,jsonify,request
        from functools import wraps
        from unittest.mock import patch
        from dashboard.workspace_api import register
        app=Flask(__name__);app.secret_key='fixture';app.local_engine=lambda:self.engine
        def login(fn):
            @wraps(fn)
            def inner(*a,**k):return fn(*a,**k) if session.get('is_admin') else (jsonify(error='login_required'),401)
            return inner
        def csrf(fn):
            @wraps(fn)
            def inner(*a,**k):return fn(*a,**k) if request.method!='POST' or request.headers.get('X-CSRF-Token')=='fixture' else (jsonify(error='csrf'),403)
            return inner
        register(app,login,csrf);c=app.test_client()
        self.assertEqual(c.get('/api/workspace/events').status_code,401)
        with c.session_transaction() as s:s['is_admin']=True
        self.assertEqual(c.post('/api/workspace/cases',json={}).status_code,403)
        headers={'X-CSRF-Token':'fixture'}
        case=c.post('/api/workspace/cases',json={'title':'API调查','evidence_id':self.identifier},headers=headers).get_json()
        self.assertEqual(case['query']['session'],'session-A')
        with patch.object(self.engine,'start'):
            r=c.post('/api/workspace/cases/'+case['id']+'/ask',json={'question':'解释这些请求','request_id':'test-request'},headers=headers)
        self.assertEqual(r.status_code,202)
        export=c.get('/api/workspace/cases/'+case['id']+'/export').get_json()
        self.assertEqual(export['jobs'][0]['query']['session'],'session-A')
        self.assertEqual(export['evidence'][0]['id'],self.identifier)
        self.assertEqual(c.get('/api/workspace/events?ip=not-an-ip').status_code,400)

if __name__=='__main__':unittest.main(verbosity=2)

