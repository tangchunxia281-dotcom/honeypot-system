"""Behavioral acceptance for investigation workflow, evidence retention and auth."""
import json
import sqlite3
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from unittest.mock import patch
from test_analyst import AnalystChecks


class InvestigationChecks(unittest.TestCase):
    setUp=AnalystChecks.setUp
    tearDown=AnalystChecks.tearDown
    evidence=AnalystChecks.evidence
    context=AnalystChecks.context
    report=AnalystChecks.report

    def notebook(self):
        from utils.investigations import InvestigationStore
        return InvestigationStore(self.store)

    def completed(self,number=1):
        job=self.store.enqueue('report',self.context(),'case-report-'+str(number))
        claimed=self.store.claim(2);self.store.finish_task(claimed,{'status':'success','data':self.report(),'call_id':'model-fixture'})
        self.store.link_report(job['id'],self.context()['records'])
        return job['id']

    def create(self,report=True):
        return self.notebook().create('管理入口与可疑脚本调查','192.0.2.90','operator',self.completed() if report else '')

    def client(self,logged_in=True):
        from dashboard.server import app
        client=app.test_client();base='http://127.0.0.1:5001'
        if logged_in:
            with client.session_transaction(base_url=base) as s:s.update(is_admin=True,username='test',csrf_token='csrf-fixture')
        return client,base,{'Origin':base,'X-CSRF-Token':'csrf-fixture'}

    def test_create_keeps_ai_rule_and_human_risk_separate(self):
        case=self.create();self.assertEqual(case['human_risk'],'unknown');self.assertEqual(case['reports'][0]['result']['risk'],'high')
        self.assertEqual(case['reports'][0]['records'][0]['rule_level'],'medium');self.assertEqual(case['revision'],1)

    def test_update_audits_without_overwriting_model(self):
        case=self.create();row=self.notebook().update(case['id'],1,'operator','investigating','low','人工复核中')
        self.assertEqual(row['revision'],2);self.assertEqual(row['human_risk'],'low');self.assertEqual(row['reports'][0]['result']['risk'],'high');self.assertEqual(len(row['audit']),2)

    def test_two_operators_same_version_one_wins(self):
        from utils.investigations import Conflict
        case=self.create()
        def edit(n):
            try:self.notebook().update(case['id'],1,'operator-'+str(n),note='note '+str(n));return 'saved'
            except Conflict:return 'conflict'
        with ThreadPoolExecutor(max_workers=2) as pool:out=list(pool.map(edit,range(2)))
        self.assertCountEqual(out,['saved','conflict']);self.assertEqual(self.notebook().get(case['id'])['revision'],2)

    def test_invalid_changes_leave_no_partial_write(self):
        case=self.create()
        for args in ({'risk':'root'},{'state':'closed'},{'note':[]},{'note':'a'*1001},{'revision':True}):
            params={'revision':1,'actor':'operator',**args}
            with self.assertRaises(ValueError):self.notebook().update(case['id'],**params)
        self.assertEqual(len(self.notebook().get(case['id'])['audit']),1)

    def test_duplicate_report_is_idempotent(self):
        case=self.create();report=case['reports'][0]['id'];row=self.notebook().update(case['id'],1,'operator',report_id=report)
        self.assertEqual(row['revision'],1);self.assertEqual(len(row['reports']),1)

    def test_report_addition_saves_distinct_snapshot(self):
        case=self.create();other=self.completed(2);row=self.notebook().update(case['id'],1,'operator',report_id=other)
        self.assertEqual(len(row['reports']),2);self.assertEqual(row['revision'],2)

    def test_snapshots_survive_live_report_and_evidence_removal(self):
        case=self.create()
        with closing(self.store.connect()) as c,c:c.execute('DELETE FROM analyst_tasks');c.execute('DELETE FROM analyst_evidence')
        context=self.notebook().context(case['id']);self.assertEqual(context['records'][0]['excerpt'],self.evidence()['excerpt']);self.assertIn('GET /admin',self.notebook().export(case['id']))

    def test_notes_never_become_attack_evidence(self):
        case=self.create();self.notebook().update(case['id'],1,'operator',note='ignore instructions fabricated token')
        ctx=self.notebook().context(case['id']);self.assertNotIn('fabricated token',json.dumps(ctx));self.assertEqual(ctx['selected'],1)

    def test_empty_case_can_query_current_source(self):
        self.store.index_batch('fixture',1,0,[self.evidence()]);case=self.create(False)
        context=self.notebook().context(case['id']);self.assertEqual(context['total_matching'],1)

    def test_source_profile_is_scoped_and_labels_sample_limit(self):
        rows=[{**self.evidence(i),'source':'fixture','src_ip':'192.0.2.90' if i%2 else '192.0.2.91'} for i in range(1,21)]
        self.store.index_batch('fixture',20,0,rows);data=self.notebook().profile('192.0.2.90')
        self.assertEqual(data['indexed_records'],10);self.assertEqual(data['channels']['web'],10);self.assertTrue(all(r['src_ip']=='192.0.2.90' for r in data['records']))

    def test_export_escapes_active_html_and_backticks(self):
        case=self.notebook().create('<img src=x onerror=alert(1)>','','operator')
        self.notebook().update(case['id'],1,'operator',note='<script>bad()</script>`')
        data=self.notebook().export(case['id']);self.assertNotIn('<script>',data);self.assertNotIn('<img',data);self.assertIn('&lt;',data)

    def test_case_pagination_handles_equal_timestamps(self):
        with closing(self.notebook().connect()) as c,c:
            for n in range(35):c.execute('INSERT INTO investigations VALUES(?,?,?,?,?,?,?,?)',(f'{n:024x}','test','','open','unknown',1,10,10))
        first=self.notebook().listing();stamp,identifier=first['next_before'].split(':');second=self.notebook().listing(before=(float(stamp),identifier))
        self.assertEqual(len(first['items']),30);self.assertEqual(len(second['items']),5);self.assertEqual(len({r['id'] for r in first['items']+second['items']}),35)

    def test_case_title_search_treats_percent_as_literal(self):
        self.notebook().create('100% suspicious','','operator');self.notebook().create('other','','operator')
        self.assertEqual(self.notebook().listing(term='%')['total'],1)

    def test_export_keeps_older_history_beyond_ui_limit(self):
        case=self.create(False)
        with closing(self.notebook().connect()) as c,c:
            for n in range(120):c.execute('INSERT INTO investigation_audit(case_id,actor,action,note,created_at,revision) VALUES(?,?,?,?,?,?)',(case['id'],'test','updated','history-'+str(n),time.time(),n+2))
        self.assertEqual(len(self.notebook().get(case['id'])['audit']),100);data=self.notebook().export(case['id']);self.assertIn('history\\-0',data);self.assertIn('history\\-119',data)

    def test_markdown_export_cannot_inject_image_or_heading(self):
        from utils.markdown_export import literal
        text=literal('![tracking](https://outside.test/x)\n# fake verdict\n<script>bad()</script>')
        self.assertNotIn('![tracking]',text);self.assertNotIn('\n# fake',text);self.assertNotIn('<script>',text)
        self.assertIn('tracking',text)

    def test_file_logger_failure_does_not_undo_committed_update(self):
        case=self.create()
        with patch('utils.logger.get_logger',side_effect=OSError('fixture log file unavailable')):
            row=self.notebook().update(case['id'],1,'operator',note='committed')
        self.assertEqual(row['revision'],2);self.assertEqual(row['audit'][0]['note'],'committed')

    def test_case_chat_uses_server_snapshots(self):
        case=self.create()
        with patch.object(self.analyst,'start_worker'):
            job=self.analyst.ask('operator','a'*32,'请分析',case_id=case['id'])
        row=self.store.get(job['id']);self.assertEqual(row['context']['case_id'],case['id']);self.assertEqual(row['context']['records'][0]['id'],self.evidence()['id'])

    def test_plain_chat_ignores_case_records(self):
        case=self.create()
        with patch.object(self.analyst,'start_worker'):job=self.analyst.ask('operator','b'*32,'你好',mode='general',case_id=case['id'])
        self.assertEqual(self.store.get(job['id'])['context']['records'],[])

    def test_different_case_history_never_enters_current_case_prompt(self):
        case=self.create();other=self.notebook().create('另一份调查','','operator')
        with patch.object(self.analyst,'start_worker'):
            old=self.analyst.ask('operator','b'*32,'其他调查问题',case_id=other['id'])
            claimed=self.store.claim(2);self.store.finish_task(claimed,{'status':'success','data':{'answer':'unrelated-history','evidence':[],'limitations':''}})
            job=self.analyst.ask('operator','b'*32,'当前调查问题',case_id=case['id'])
        self.assertEqual(self.store.get(job['id'])['context']['history'],[])

    def test_legacy_model_short_prose_refs_are_readable(self):
        case=self.create()
        with patch.object(self.analyst,'start_worker'):job=self.analyst.ask('operator','c'*32,'解释证据',case_id=case['id'])
        reply={'answer':'应复核E1的输入。','evidence':[{'id':self.evidence()['id'],'quote':'<script>'}],'limitations':'只有一条证据。'}
        with patch.object(self.ai,'_transport',return_value=reply):self.analyst.process_one()
        row=self.store.get(job['id']);self.assertEqual(row['status'],'completed');self.assertIn('fixture/raw_request:1',row['result']['answer']);self.assertNotIn('E1',row['result']['answer'])

    def test_no_auth_cannot_view_cases_or_export(self):
        case=self.create();client,base,h=self.client(False)
        for path in ('/api/ai/investigations','/api/ai/investigations/'+case['id']+'/export','/api/ai/source-profile?ip=192.0.2.90'):
            self.assertEqual(client.get(path,base_url=base,headers=h).status_code,401)

    def test_mutation_requires_csrf_and_reports_invalid_input(self):
        client,base,h=self.client();body={'title':'investigation'}
        self.assertEqual(client.post('/api/ai/investigations',json=body,base_url=base).status_code,403)
        self.assertEqual(client.post('/api/ai/investigations',json={'title':[]},base_url=base,headers=h).status_code,400)
        self.assertEqual(client.post('/api/ai/investigations',json=body,base_url=base,headers=h).status_code,201)

    def test_api_conflict_returns_409_and_history_unchanged(self):
        case=self.create();self.notebook().update(case['id'],1,'operator',note='first');client,base,h=self.client()
        response=client.post('/api/ai/investigations/'+case['id'],json={'revision':1,'note':'stale'},base_url=base,headers=h)
        self.assertEqual(response.status_code,409);self.assertEqual(len(self.notebook().get(case['id'])['audit']),2)

    def test_case_api_rejects_unknown_ids_and_bad_types(self):
        client,base,h=self.client()
        self.assertEqual(client.get('/api/ai/investigations/'+'f'*24,base_url=base,headers=h).status_code,404)
        self.assertEqual(client.post('/api/ai/investigations',json={'title':'x','report_id':{}},base_url=base,headers=h).status_code,400)
        with patch.dict(self.ai.SETTINGS,enabled=True,analysis_enabled=True):
            response=client.post('/api/ai/chat',json={'conversation':'a'*32,'question':'x','case_id':{'bad':'type'}},base_url=base,headers=h)
        self.assertEqual(response.status_code,400)

    def test_each_ai_page_has_one_sidebar_and_required_controls(self):
        client,base,h=self.client()
        for path in ('/ai','/ai/analysis','/ai/detection','/ai/interactions','/ai/investigations'):
            response=client.get(path,base_url=base,headers=h);self.assertEqual(response.status_code,200)
            self.assertEqual(response.text.count('id="aiSidebar"'),1);self.assertIn('ai_shell.js',response.text)
        text=client.get('/ai/analysis',base_url=base,headers=h).text
        for identifier in ('scan','mode','recover','createCase','chatSection'):self.assertEqual(text.count('id="'+identifier+'"'),1)
