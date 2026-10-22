import json
import sqlite3
import tempfile
import threading
import unittest
import sys
from contextlib import closing
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import requests
from werkzeug.serving import make_server
from team_center.store import CenterStore
from team_center.server import create_app
from utils.team_collector import Collector

class HTTPChecks(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.store=CenterStore(self.root/'center.db');self.a=self.store.issue_sensor('a');self.b=self.store.issue_sensor('b');self.user=self.store.create_user('reader','reader-test-123','readonly',[self.a['id']]);self.admin=self.store.create_user('admin','admin-test-1234','admin',[])
        self.app=create_app(self.store,'test-secret-long-12345678901234567890');self.server=make_server('127.0.0.1',0,self.app,threaded=True);self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start();self.url='http://127.0.0.1:'+str(self.server.server_port);self.c=requests.Session();self.c.trust_env=False
        csrf=self.c.get(self.url+'/api/session',timeout=2).json()['csrf'];r=self.c.post(self.url+'/login',json={'name':'reader','password':'reader-test-123'},headers={'X-CSRF-Token':csrf},timeout=2);self.csrf=r.json()['csrf']
    def tearDown(self):self.c.close();self.server.shutdown();self.server.server_close();self.thread.join(2);self.temp.cleanup()
    def seed(self,path,text):
        with closing(sqlite3.connect(path)) as c,c:
            c.execute('CREATE TABLE raw_request(id INTEGER PRIMARY KEY,create_time TEXT,src_ip TEXT,method TEXT,path TEXT,query_string TEXT,body TEXT,threat_score INTEGER,session_id TEXT)');c.execute('INSERT INTO raw_request VALUES(?,?,?,?,?,?,?,?,?)',(1,'2026-10-11 10:00:00','127.0.0.1','GET','/search',text,'',30,'same'))
    def test_two_real_http_collectors_replay_and_scope(self):
        for i,sensor in enumerate((self.a,self.b)):
            source=self.root/f'source{i}.db';self.seed(source,'<script>alert(1)</script>');col=Collector(self.root/f'spool{i}.db',[source],sensor['id'],self.url,sensor['token'],origin='synthetic');col.stage();payload=col.batch();self.assertFalse(col.flush_once()['error']);self.assertEqual(self.c.post(self.url+'/api/ingest',json=payload,headers={'Authorization':'Bearer '+sensor['token']},timeout=2).status_code,200)
        rows=self.c.get(self.url+'/api/evidence',timeout=2).json();self.assertEqual(rows['total'],1)
        self.assertEqual(self.c.get(self.url+'/api/evidence?sensor='+self.b['id'],timeout=2).status_code,403)
        other=self.store.search(self.admin['id'],{'sensors':[self.b['id']]})['records'][0]['id'];self.assertEqual(self.c.get(self.url+'/api/evidence/'+other,timeout=2).status_code,404)
        self.assertEqual(self.c.post(self.url+'/api/investigations',json={'question':'q','query':{},'request_id':'r'},headers={'X-CSRF-Token':self.csrf},timeout=2).status_code,403)
    def test_malformed_json_arrays_and_scope_on_effects(self):
        for endpoint in ('/login','/api/ingest','/api/users','/api/investigations'):
            self.assertEqual(self.c.post(self.url+endpoint,json=[],headers={'X-CSRF-Token':self.csrf},timeout=2).status_code,400)
        self.assertEqual(self.c.get(self.url+'/api/effectiveness?sensor='+self.b['id'],timeout=2).status_code,403)
    def test_idle_sensor_heartbeat_without_batch_growth(self):
        r=self.c.post(self.url+'/api/heartbeat',json={'health':{'pending':0,'paused':False,'error':''}},headers={'Authorization':'Bearer '+self.a['token']},timeout=2)
        self.assertEqual(r.status_code,200)
        self.assertGreater(self.store.sensors(self.user['id'])[0]['last_seen'],0)
        with closing(self.store.connect()) as c:self.assertEqual(c.execute('SELECT COUNT(*) FROM batches').fetchone()[0],0)

if __name__=='__main__':unittest.main()
