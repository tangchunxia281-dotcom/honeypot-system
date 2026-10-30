import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

class LocalIndexChecks(unittest.TestCase):
    def test_incremental_restart_and_no_source_mutation(self):
        from investigation_core.local import LocalInvestigation
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); source=root/'source.sqlite'
            with closing(sqlite3.connect(source)) as c, c:
                c.execute('CREATE TABLE raw_request(id INTEGER PRIMARY KEY,create_time TEXT,src_ip TEXT,session_id TEXT,method TEXT,path TEXT,query_string TEXT,body TEXT,headers TEXT,threat_score INTEGER)')
                c.execute("INSERT INTO raw_request VALUES(1,'2026-10-29 12:00:00','127.0.0.1','session','GET','/search','q=test','password=hidden','',34)")
            before=source.read_bytes()
            engine=LocalInvestigation(root/'index.sqlite',source)
            self.assertEqual(engine.sync()['indexed'],1)
            engine=LocalInvestigation(root/'index.sqlite',source)
            self.assertEqual(engine.sync()['indexed'],0)
            rows=engine.store.search(engine.owner,{},20)['records']
            self.assertEqual(len(rows),1)
            self.assertNotIn('hidden',rows[0]['excerpt'])
            self.assertEqual(source.read_bytes(),before)
            with closing(sqlite3.connect(source)) as c,c:c.execute("UPDATE raw_request SET path='/changed' WHERE id=1")
            self.assertIn('source_reset_detected',engine.sync()['error'])

    def test_missing_source_is_visible(self):
        from investigation_core.local import LocalInvestigation
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);e=LocalInvestigation(root/'index.sqlite',root/'absent.sqlite')
            self.assertTrue(e.sync()['error'])
            self.assertFalse((root/'absent.sqlite').exists())

    def test_archived_first_record_does_not_stop_new_records(self):
        from investigation_core.local import LocalInvestigation
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);source=root/'events.sqlite'
            with closing(sqlite3.connect(source)) as c,c:
                c.execute('CREATE TABLE raw_request(id INTEGER PRIMARY KEY,create_time TEXT,path TEXT)')
                c.executemany('INSERT INTO raw_request VALUES(?,?,?)',[(1,'2026-10-29 12:00:00','/a'),(2,'2026-10-29 12:01:00','/b')])
            e=LocalInvestigation(root/'index.sqlite',source);self.assertEqual(e.sync()['indexed'],2)
            with closing(sqlite3.connect(source)) as c,c:
                c.execute('DELETE FROM raw_request WHERE id=1');c.execute("INSERT INTO raw_request VALUES(3,'2026-10-29 12:02:00','/c')")
            result=e.sync();self.assertFalse(result['error']);self.assertEqual(result['indexed'],1)

class LauncherChecks(unittest.TestCase):
    def test_first_run_and_idempotence(self):
        import competition
        from unittest.mock import patch
        import configparser
        original=competition.ROOT
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            for name in ('honeypot.ini.example','ai.local.ini.example'):(root/name).write_bytes((original/name).read_bytes())
            with patch.object(competition,'ROOT',root):
                with self.assertRaises(ValueError):competition.initialize('short')
                self.assertTrue(competition.initialize('a-long-test-password'))
                before=(root/'honeypot.ini').read_bytes()
                self.assertFalse(competition.initialize('different-password'))
                self.assertEqual(before,(root/'honeypot.ini').read_bytes())
            p=configparser.ConfigParser();p.read(root/'honeypot.ini',encoding='utf-8')
            self.assertEqual(p['services.web']['host'],'127.0.0.1');self.assertTrue(p['app']['secret_key'])

    def test_disabled_model_keeps_program_timeline(self):
        from investigation_core.local import LocalInvestigation
        from utils.active_investigation import process_one
        from datetime import datetime
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);e=LocalInvestigation(root/'index.sqlite',root/'unused.sqlite')
            record=dict(source_id='fixture',table='raw_request',record_id=1,timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),src_ip='127.0.0.1',session_id='fixture',channel='web',kind='http_request',rule_level='medium',excerpt='GET /admin',traffic_origin='synthetic')
            e.store.ingest(e.sensor,'fixture',[record],{},[])
            job=e.jobs.create(e.owner,'解释请求并指出证据不足',{},'fixture-request')
            def disabled(*args,**kwargs):return {'status':'fallback','reason':'disabled','call_id':'fixture-disabled'}
            self.assertTrue(process_one(e.store,e.jobs,model_call=disabled))
            result=e.jobs.get(e.owner,job['id'])
            self.assertEqual(result['status'],'fallback')
            self.assertEqual(len(result['result']['story']['facts']),1)
            self.assertFalse(result['result']['story']['inferences'])

class ApiChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import os
        cls.tmp=tempfile.TemporaryDirectory();root=Path(cls.tmp.name)
        os.environ.update(HONEYPOT_LOCAL_INDEX=str(root/'investigation.sqlite'),HONEYPOT_AI_DB=str(root/'ai.sqlite'),DB_PATH=str(root/'events.sqlite'),HONEYPOT_AI_ENABLED='false')
        from dashboard.server import app
        app.config['TESTING']=True;cls.app=app
    @classmethod
    def tearDownClass(cls):cls.tmp.cleanup()
    def test_login_and_csrf(self):
        c=self.app.test_client();c.environ_base['HTTP_ORIGIN']='http://127.0.0.1:5001'
        self.assertEqual(c.get('/api/local/evidence').status_code,401)
        with c.session_transaction() as s:s.update(is_admin=True,csrf_token='test-token')
        self.assertEqual(c.post('/api/local/sync',json={}).status_code,403)
        self.assertEqual(c.post('/api/local/sync',json={},headers={'X-CSRF-Token':'test-token','Origin':'http://127.0.0.1:5001'}).status_code,200)
        self.assertEqual(c.get('/api/local/story').status_code,200)
        self.assertEqual(c.get('/api/local/effects').status_code,200)
        self.assertEqual(c.post('/api/local/jobs',json=[],headers={'X-CSRF-Token':'test-token'}).status_code,400)
        for route in ('/api/ingest','/api/users','/api/sensors','/api/local/users','/api/local/ingest'):
            self.assertEqual(c.post(route,json={}).status_code,404)
    def test_single_site_navigation(self):
        c=self.app.test_client();c.environ_base['HTTP_ORIGIN']='http://127.0.0.1:5001'
        with c.session_transaction() as s:s.update(is_admin=True,csrf_token='test-token')
        for path in ('/ai/local','/ai/workbench','/ai/analysis'):
            r=c.get(path);self.assertEqual(r.status_code,200)
            text=r.get_data(as_text=True)
            for forbidden in ('团队数据中心','团队研判工作台','127.0.0.1:5169','共享 AI'):
                self.assertNotIn(forbidden,text)

if __name__=='__main__':unittest.main(verbosity=2)
