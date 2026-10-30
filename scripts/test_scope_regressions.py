"""Regressions reproduced during the product audit, with real SQLite queries."""
import tempfile
import time
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch
from flask import Flask
from investigation_core.local import LocalInvestigation
from investigation_core.workflow import Workflow
from dashboard.workspace_api import register
from utils.ai_interaction_store import InteractionStore


class ScopeRegressions(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.engine = LocalInvestigation(Path(self.tmp.name)/'index.sqlite', Path(self.tmp.name)/'events.sqlite')
        self.flow = Workflow(self.engine)
        self.app = Flask(__name__)
        self.app.local_engine = lambda: self.engine
        register(self.app, lambda fn: fn, lambda fn: fn)
        self.client = self.app.test_client()
        rows = [dict(source_id='audit-fixture', table='raw_request', record_id=i,
                     timestamp='2026-10-30 12:00:00', src_ip=ip, session_id='session-'+str(i),
                     channel='web', kind='http_request', rule_level='low',
                     excerpt='GET /fixture-'+str(i), traffic_origin='synthetic')
                for i, ip in [(1, '192.0.2.11'), (2, '192.0.2.22')]]
        self.engine.store.ingest(self.engine.sensor, 'batch', rows, {}, [])
        self.a = self.flow.create_case({'title':'A', 'query':{'ip':'192.0.2.11'}})
        self.b = self.flow.create_case({'title':'B', 'query':{'ip':'192.0.2.22'}})

    def test_overview_cases_match_the_same_source_scope_as_records(self):
        result = self.client.get('/api/workspace/overview?ip=192.0.2.11').get_json()
        self.assertEqual(result['total'], 1)
        self.assertEqual([c['id'] for c in result['cases']], [self.a['id']])

    def test_case_filter_uses_snapshot_before_limit_even_if_live_index_is_gone(self):
        with closing(self.engine.store.connect()) as c, c:
            for i in range(105):
                c.execute('INSERT INTO local_cases SELECT ?,title,query_json,evidence_json,status,note,revision,created,updated+? FROM local_cases WHERE id=?', ('new-'+str(i), i+1, self.b['id']))
            c.execute('DELETE FROM evidence')
        result = self.client.get('/api/workspace/cases?ip=192.0.2.11&term=fixture-1').get_json()
        self.assertEqual([c['id'] for c in result['records']], [self.a['id']])

    def test_interaction_source_and_time_are_filtered_before_newest_limit(self):
        store = InteractionStore(Path(self.tmp.name)/'ai.sqlite')
        now = time.time()
        with closing(store.connect()) as c, c:
            for i in range(55):
                ip = '192.0.2.11' if i == 0 else '192.0.2.22'
                c.execute('INSERT INTO ai_interactions VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                          (str(i), now-100+i, now-99+i, ('a' if i == 0 else 'b')*32,
                           'web', ip, i+1, 'completed', 'program', 'fixture', '', '',
                           'GET /fixture', '{}', '{}'))
        with patch('utils.ai_interaction.get_store', return_value=store):
            result = self.client.get('/api/workspace/sessions?ip=192.0.2.11').get_json()
            self.assertEqual([t['src_ip'] for t in result['turns']], ['192.0.2.11'])
            self.assertEqual(self.client.get('/api/workspace/sessions?ip=invalid').status_code, 400)

    def test_interaction_end_time_includes_the_whole_displayed_second(self):
        from datetime import datetime, timezone, timedelta
        store = InteractionStore(Path(self.tmp.name)/'ai.sqlite')
        when = datetime(2026,10,30,12,tzinfo=timezone(timedelta(hours=8))).timestamp()+0.5
        with closing(store.connect()) as c, c:
            c.execute('INSERT INTO ai_interactions VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                      ('at-end',when,when,'a'*32,'web','192.0.2.11',1,'completed','program','fixture','','','GET /fixture','{}','{}'))
        with patch('utils.ai_interaction.get_store', return_value=store):
            result = self.client.get('/api/workspace/sessions',query_string={'ip':'192.0.2.11','start':'2026-10-30 12:00:00','end':'2026-10-30 12:00:00'}).get_json()
        self.assertEqual([t['id'] for t in result['turns']], ['at-end'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
