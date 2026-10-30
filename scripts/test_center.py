import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))

class CenterChecks(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('investigation_core'),'center package required')
        from investigation_core.store import CenterStore
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.store=CenterStore(Path(self.tmp.name)/'center.db')
        self.a=self.store.issue_sensor('a');self.b=self.store.issue_sensor('b')
        self.admin=self.store.create_user('admin','a-long-pass-123','admin',[])
        self.member=self.store.create_user('member','a-long-pass-123','readonly',[self.a['id']])
    def record(self,**kw):
        return dict(source_id='source1',table='raw_request',record_id=1,timestamp='2026-10-11 10:00:00',src_ip='127.0.0.1',session_id='same',channel='web',kind='http_request',rule_level='medium',excerpt='GET /search q=<script>alert(1)</script>',traffic_origin='synthetic',**kw)
