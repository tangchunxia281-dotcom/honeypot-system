import importlib.util
import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

class CollectorChecks(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('utils.team_collector'),'collector required')
        from utils.team_collector import Collector
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name);self.db=self.root/'events.db'
        self.seed('first password=secret')
        self.col=Collector(self.root/'spool.db',[self.db],'sensor','http://127.0.0.1:1','x'*48,16*1024*1024)
    def seed(self,text):
        with closing(sqlite3.connect(self.db)) as c,c:
            c.execute('CREATE TABLE IF NOT EXISTS raw_request(id INTEGER PRIMARY KEY,create_time TEXT,src_ip TEXT,method TEXT,path TEXT,query_string TEXT,body TEXT,threat_score INTEGER,session_id TEXT)')
            c.execute('INSERT OR REPLACE INTO raw_request VALUES(1,?,?,?,?,?,?,?,?)',('2026-10-11 10:00:00','127.0.0.1','GET','/search',text,'',30,'s'))
    def test_restart_keeps_pending(self):
        self.col.stage();self.assertEqual(self.col.status()['pending'],1)
        self.assertEqual(type(self.col)(self.root/'spool.db',[self.db],'sensor','http://127.0.0.1:1','x'*48,1000000).status()['pending'],1)
    def test_ack_lost_replay_once_and_invalid_no_commit(self):
        self.col.stage();first=self.col.batch();self.col.transport=lambda p:(_ for _ in ()).throw(ConnectionError())
        self.col.flush_once();self.assertEqual(self.col.batch()['batch_id'],first['batch_id'])
        self.col.transport=lambda p:{'batch_id':'wrong','accepted':1};self.col.flush_once();self.assertEqual(self.col.status()['pending'],1)
        self.col.transport=lambda p:{'batch_id':p['batch_id'],'accepted':len(p['records'])};self.col.flush_once();self.assertEqual(self.col.status()['pending'],0);self.col.stage();self.assertEqual(self.col.status()['pending'],0)
    def test_replaced_database_new_generation(self):
        self.col.stage();old=self.col.batch()['records'][0]['source_id'];self.col.transport=lambda p:{'batch_id':p['batch_id'],'accepted':len(p['records'])};self.col.flush_once()
        self.seed('different generation');self.col.stage();self.assertNotEqual(self.col.batch()['records'][0]['source_id'],old)
    def test_disk_budget_pauses_without_source_loss(self):
        self.col.max_bytes=1;self.col.stage();self.assertTrue(self.col.status()['paused'])
        with closing(sqlite3.connect(self.db)) as c:self.assertEqual(c.execute('SELECT COUNT(*) FROM raw_request').fetchone()[0],1)
    def test_redaction_before_spooling(self):
        self.col.stage();self.assertNotIn('password=secret',json.dumps(self.col.batch()))
    def test_unicode_batches_shrink_to_wire_limit(self):
        with closing(sqlite3.connect(self.db)) as c,c:
            for i in range(2,102):c.execute('INSERT INTO raw_request VALUES(?,?,?,?,?,?,?,?,?)',(i,'2026-10-11 10:00:00','127.0.0.1','GET','/search','中'*2000,'',30,'s'))
        self.col.stage();batch=self.col.batch();self.assertIsNotNone(batch);self.assertLess(len(batch['records']),100);self.assertLessEqual(len(json.dumps(batch,ensure_ascii=False).encode()),262144);self.assertFalse(self.col.status()['paused'])
    def metrics_seed(self,identifier):
        self.col.ai_path=self.root/'ai.db'
        with closing(sqlite3.connect(self.col.ai_path)) as c,c:
            c.execute('CREATE TABLE IF NOT EXISTS ai_calls(id TEXT,task TEXT,model TEXT,status TEXT,reason TEXT,latency_ms INTEGER,created_at REAL)')
            c.execute('INSERT INTO ai_calls VALUES(?,?,?,?,?,?,?)',(identifier,'web_detect','fixture','success','',12,1))
    def test_descending_random_ids_do_not_rotate_metrics(self):
        self.metrics_seed('z'*24);self.col._stage_metrics();first=self.col.batch()['metrics'][0]['id']
        self.col.transport=lambda p:{'batch_id':p['batch_id'],'accepted':len(p['records'])};self.col.flush_once()
        self.metrics_seed('a'*24);self.col._stage_metrics();batch=self.col.batch()
        self.assertEqual(len(batch['metrics']),1);self.assertEqual(batch['metrics'][0]['id'].split('-')[0],first.split('-')[0])
    def test_detection_verdict_save_race_defers_metric(self):
        self.metrics_seed('z'*24)
        with closing(sqlite3.connect(self.col.ai_path)) as c,c:c.execute('CREATE TABLE ai_detections(call_id TEXT,status TEXT,verdict TEXT,snapshot_json TEXT)')
        self.col._stage_metrics();self.assertIsNone(self.col.batch())
        with closing(sqlite3.connect(self.col.ai_path)) as c,c:c.execute('INSERT INTO ai_detections VALUES(?,?,?,?)',('z'*24,'completed','suspicious','{"rule_score":0}'))
        self.col._stage_metrics();self.assertTrue(self.col.batch()['metrics'][0]['ai_attack'])
    def test_metric_retention_does_not_replay_generation(self):
        self.metrics_seed('z'*24);self.col._stage_metrics();old=self.col.batch()['metrics'][0]['id'].split('-')[0]
        self.col.transport=lambda p:{'batch_id':p['batch_id'],'accepted':len(p['records'])};self.col.flush_once();self.metrics_seed('a'*24)
        with closing(sqlite3.connect(self.col.ai_path)) as c,c:c.execute('DELETE FROM ai_calls WHERE id=?',('z'*24,))
        self.col._stage_metrics();self.assertEqual(self.col.batch()['metrics'][0]['id'].split('-')[0],old)
    def test_source_failure_not_erased_by_successful_heartbeat(self):
        with closing(sqlite3.connect(self.db)) as c,c:c.execute("UPDATE raw_request SET create_time='invalid-date'")
        self.col.stage();self.col.heartbeat_transport=lambda state:None;self.col.flush_once()
        self.assertIn('time_invalid',self.col.status()['error'])
    def test_known_archive_snapshot_keeps_original_generation(self):
        import shutil
        self.col.stage();self.col.transport=lambda p:{'batch_id':p['batch_id'],'accepted':len(p['records'])};self.col.flush_once()
        archive=self.root/'archive';archive.mkdir();snapshot=archive/'snapshot.db';shutil.copy2(self.db,snapshot)
        self.seed('new generation');self.col.sources=[self.db,snapshot];self.col.stage()
        self.assertEqual(self.col.status()['pending'],1,'already acknowledged archive must not be replayed as a new source')

if __name__=='__main__':unittest.main()
