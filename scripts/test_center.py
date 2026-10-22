import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))

class CenterChecks(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('team_center'),'center package required')
        from team_center.store import CenterStore
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.store=CenterStore(Path(self.tmp.name)/'center.db')
        self.a=self.store.issue_sensor('a');self.b=self.store.issue_sensor('b')
        self.admin=self.store.create_user('admin','a-long-pass-123','admin',[])
        self.member=self.store.create_user('member','a-long-pass-123','readonly',[self.a['id']])
    def record(self,**kw):
        return dict(source_id='source1',table='raw_request',record_id=1,timestamp='2026-10-11 10:00:00',src_ip='127.0.0.1',session_id='same',channel='web',kind='http_request',rule_level='medium',excerpt='GET /search q=<script>alert(1)</script>',traffic_origin='synthetic',**kw)
    def test_same_ids_different_sensors(self):
        for s in (self.a,self.b):self.store.ingest(s['id'],'batch1',[self.record()],{})
        rows=self.store.search(self.admin['id'],{},20)['records'];self.assertEqual(len(rows),2);self.assertNotEqual(rows[0]['id'],rows[1]['id'])
        self.store.ingest(self.a['id'],'batch1',[self.record()],{});self.assertEqual(self.store.search(self.admin['id'],{},20)['total'],2)
    def test_member_scope_all_read_paths(self):
        self.store.ingest(self.b['id'],'batch1',[self.record()],{})
        row=self.store.search(self.admin['id'],{},20)['records'][0]
        self.assertEqual(self.store.search(self.member['id'],{},20)['total'],0)
        self.assertIsNone(self.store.evidence(self.member['id'],row['id']))
        with self.assertRaises(PermissionError):self.store.search(self.member['id'],{'sensors':[self.b['id']]},20)
    def test_revoked_token_denied(self):
        self.assertEqual(self.store.sensor_auth(self.a['token'])['id'],self.a['id'])
        self.store.revoke_sensor(self.a['id']);self.assertIsNone(self.store.sensor_auth(self.a['token']))
    def test_invalid_batch_atomic(self):
        bad=self.record();bad['table']='users'
        with self.assertRaises(ValueError):self.store.ingest(self.a['id'],'batch2',[self.record(),bad],{})
        self.assertEqual(self.store.search(self.admin['id'],{},20)['total'],0)
    def test_redaction_and_scope_count(self):
        row=self.record();row['excerpt']='password=superSecret token=abcdef 密码=中文机密 口令=anotherSecret'
        self.store.ingest(self.a['id'],'batch1',[row],{})
        self.assertNotIn('superSecret',self.store.search(self.member['id'],{},20)['records'][0]['excerpt'])
        self.assertNotIn('中文机密',self.store.search(self.member['id'],{},20)['records'][0]['excerpt'])
        self.assertNotIn('anotherSecret',self.store.search(self.member['id'],{},20)['records'][0]['excerpt'])
    def test_readonly_cannot_write_and_disabled_session(self):
        from team_center.server import create_app
        app=create_app(self.store,'test-secret-long-12345678901234567890');app.testing=True;c=app.test_client()
        with c.session_transaction() as s:s['uid']=self.member['id'];s['csrf']='fixture'
        self.assertEqual(c.post('/api/users',json={},headers={'X-CSRF-Token':'fixture'}).status_code,403)
        self.store.update_user(self.member['id'],False,[])
        self.assertEqual(c.get('/api/evidence').status_code,401)
    def test_ingest_body_limit(self):
        from team_center.server import create_app
        c=create_app(self.store,'test-secret-long-12345678901234567890').test_client()
        self.assertEqual(c.post('/api/ingest',data='x'*262145,headers={'Authorization':'Bearer '+self.a['token']}).status_code,413)

if __name__=='__main__':unittest.main()
