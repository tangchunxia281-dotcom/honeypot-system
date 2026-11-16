"""Shared queue isolation, retrieval coverage, graph and review workflows."""
import hashlib
import json
import os
import secrets
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
from unittest.mock import patch
from test_analyst import AnalystChecks


class TeamChecks(unittest.TestCase):
    tearDown=AnalystChecks.tearDown;evidence=AnalystChecks.evidence;context=AnalystChecks.context;report=AnalystChecks.report
    def setUp(self):
        AnalystChecks.setUp(self)
        state=patch.dict(self.analyst._state,{'lag':0,'scan_error':''});state.start();self.extra.append(state)

    def team(self):
        from utils.team_store import TeamStore
        return TeamStore(self.store)

    def detection(self,score=30,verdict='no_clear_attack',identifier='a'*24):
        from utils.ai_detection_store import DetectionStore
        store=DetectionStore(self.store.path)
        snap={'fields':{'method':'GET','path':'/search','query':'q=normal','body':'','user_agent':'Mozilla/5.0','referer':'','content_type':''},'rule_score':score,'rule_signals':[],'truncated_fields':[],'request_time':'fixture'}
        store.enqueue({'id':identifier,'raw_key':identifier,'raw_request_id':1,'src_ip':'192.0.2.90','session_id':'fixture','snapshot':snap},self.ai.SETTINGS)
        store.finish(identifier,{'status':'success','data':{'verdict':verdict,'summary':'fixture','attack_types':[],'evidence':[]},'call_id':'fixture'})
        return store

    def test_evidence_selection_preserves_rare_tail_after_repetitive_requests(self):
        from utils.evidence_selection import select
        rows=[{**self.evidence(i),'excerpt':'GET /search q=normal','rule_level':'low'} for i in range(1,31)]
        rare={**self.evidence(40),'excerpt':'GET /api/preview url=http://169.254.169.254/','rule_level':'low'};rows.append(rare)
        out=select(rows,6);self.assertIn(rare['id'],[r['id'] for r in out['records']]);self.assertEqual(out['distinct'],2)

    def test_long_body_keeps_attack_window_and_marks_omission(self):
        from utils.evidence_selection import clip
        text='benign '*300+'<script>alert(1)</script>'+' harmless'*200
        out=clip(text,500);self.assertIn('<script>',out);self.assertIn('[中间省略]',out);self.assertLessEqual(len(out),500)

    def test_partitions_cover_every_distinct_behavior(self):
        from utils.evidence_selection import partitions
        rows=[{**self.evidence(i),'excerpt':'GET /search q=normal-'+str(i)} for i in range(1,25)]
        parts=partitions(rows,6);self.assertEqual(len(parts),4);self.assertCountEqual([r['id'] for part in parts for r in part],[r['id'] for r in rows]);self.assertTrue(all(len(p)<=6 for p in parts))

    def test_question_retrieval_prioritizes_requested_type(self):
        from utils.evidence_selection import select
        x={**self.evidence(1),'excerpt':'q=<script>alert(1)</script>'};sql={**self.evidence(2),'excerpt':'id=1 UNION SELECT password FROM users'}
        self.assertEqual(select([x,sql],1,'请分析SQL输入')['records'][0]['id'],sql['id'])

    def test_graph_does_not_connect_different_sources_or_assert_same_time_order(self):
        from utils.evidence_selection import graph
        a=self.evidence(1);b={**self.evidence(2),'src_ip':'192.0.2.91'};c=self.evidence(3)
        g=graph([a,b,c]);self.assertTrue(g['edges']);self.assertTrue(all(not e['ordered'] for e in g['edges']))
        self.assertTrue(all(e['from']!=b['id'] and e['to']!=b['id'] for e in g['edges']))

    def test_old_timezone_is_normalized_before_window_queries(self):
        self.assertEqual(self.analyst.normalize_timestamp('2026-10-09T02:00:00+00:00'),'2026-10-09 10:00:00')

    def test_disagreement_uncertainty_is_not_called_normal(self):
        self.detection(5,'uncertain');d=self.team().disagreements();self.assertEqual(d['records'][0]['disagreement_kind'],'insufficient_evidence')

    def test_review_snapshot_survives_detection_retention(self):
        detector=self.detection();self.team().review('a'*24,0,'benign','','说明','operator')
        with closing(detector.connect()) as c,c:c.execute('DELETE FROM ai_detections')
        out=self.team().export_reviews();self.assertEqual(out[0]['label'],'benign');self.assertEqual(out[0]['fields']['query'],'q=normal')

    def test_review_does_not_replace_rule_or_ai_and_conflicting_edits_fail(self):
        from utils.investigations import Conflict
        detector=self.detection();self.team().review('a'*24,0,'attack','xss','人工观察','operator')
        row=detector.get('a'*24);self.assertEqual(row['snapshot']['rule_score'],30);self.assertEqual(row['verdict'],'no_clear_attack')
        with self.assertRaises(Conflict):self.team().review('a'*24,0,'benign','','stale','other')

    def test_unconfirmed_samples_are_not_exported(self):
        self.detection();self.team().review('a'*24,0,'uncertain','','不足','operator');self.assertEqual(self.team().export_reviews(),[])

    def test_review_types_rejected(self):
        self.detection()
        for label,kind,note in [('attack','','x'),('benign',[],''),([], '', ''),('benign','','x'*501)]:
            with self.assertRaises(ValueError):self.team().review('a'*24,0,label,kind,note,'operator')

    def test_noise_suppression_shared_and_escalation_bypasses_window(self):
        from utils.alert_noise import NoiseGate
        a=NoiseGate(self.store);b=NoiseGate(self.store)
        self.assertTrue(a.admit('fixture','web','/search',2,100)['allowed']);self.assertFalse(b.admit('fixture','web','/search',2,101)['allowed']);self.assertTrue(b.admit('fixture','web','/search',4,102)['allowed'])
        self.assertEqual(a.snapshot(),{'observed':3,'admitted':2,'suppressed':1})

    def test_noise_window_reports_only_new_suppressed_events(self):
        from utils.alert_noise import NoiseGate
        g=NoiseGate(self.store);g.admit('x','web','/p',2,100);g.admit('x','web','/p',2,101)
        self.assertEqual(g.admit('x','web','/p',2,401)['merged'],1);self.assertEqual(g.admit('x','web','/p',2,702)['merged'],0)

    def test_noise_distinct_routes_and_sources_not_merged(self):
        from utils.alert_noise import NoiseGate
        g=NoiseGate(self.store)
        for ip,path in [('a','/p'),('a','/q'),('b','/p')]:self.assertTrue(g.admit(ip,'web',path,2,100)['allowed'])

    def test_period_window_idempotence_and_bounded_ai_sampling(self):
        from utils.periodic_analysis import make_period
        from datetime import datetime,timezone,timedelta
        records=[{**self.evidence(i),'timestamp':'2026-10-09 10:30:00','source':'fixture'} for i in range(1,31)]
        self.store.index_batch('fixture',30,0,records);now=datetime(2026,10,9,11,1,tzinfo=timezone(timedelta(hours=8))).timestamp()
        a=make_period(self.store,'hour',now);b=make_period(self.store,'hour',now);self.assertEqual(a['status'],'created');self.assertEqual(b['status'],'already_exists');row=self.team().periods()['reports'][0];self.assertEqual(row['metrics']['total_indexed'],30);self.assertLessEqual(self.store.get(row['task_id'])['context']['selected'],24)

    def test_period_grouping_preserves_important_distinct_features(self):
        from utils.periodic_analysis import metrics
        rows=[self.evidence(1),self.evidence(2),{**self.evidence(3),'excerpt':'GET /api/preview url=http://169.254.169.254/'}]
        out=metrics(rows,3,0,1,0);self.assertEqual(out['alert_occurrences_sampled'],3);self.assertEqual(out['alert_groups_sampled'],2)

    def test_period_waits_for_index_and_retries_after_capacity_returns(self):
        from utils.periodic_analysis import make_period
        from datetime import datetime,timezone,timedelta
        self.store.index_batch('fixture',1,0,[{**self.evidence(),'source':'fixture','timestamp':'2026-10-09 10:30:00'}])
        now=datetime(2026,10,9,11,1,tzinfo=timezone(timedelta(hours=8))).timestamp()
        with patch.dict(self.analyst._state,lag=10):self.assertEqual(make_period(self.store,'hour',now)['status'],'waiting_index')
        for i in range(64):self.store.enqueue('report',self.context(),'filler-'+str(i))
        make_period(self.store,'hour',now);self.assertEqual(self.team().periods()['reports'][0]['task_id'],'')
        with closing(self.store.connect()) as c,c:c.execute("UPDATE analyst_tasks SET status='cancelled'")
        make_period(self.store,'hour',now);self.assertTrue(self.team().periods()['reports'][0]['task_id'])

    def test_exact_graph_node_context_excludes_other_evidence(self):
        rows=[{**self.evidence(i),'source':'fixture'} for i in (1,2)];self.store.index_batch('fixture',2,0,rows)
        with patch.object(self.analyst,'start_worker'):job=self.analyst.ask('operator','b'*32,'解释此节点',evidence_id=rows[1]['id'])
        self.assertEqual([r['id'] for r in self.store.get(job['id'])['context']['records']],[rows[1]['id']])

    def test_synthetic_dataset_has_no_group_or_normalized_split_leakage(self):
        from utils.evaluation import load
        rows,digest=load(Path(__file__).resolve().parents[1]/'evaluation/fixtures.jsonl');self.assertEqual(len(rows),84);self.assertEqual(len(digest),64)

    def test_dataset_loader_rejects_family_leakage(self):
        from utils.evaluation import load
        row={'id':'first','group':'one','label':'benign','attack_type':'','split':'test','fields':{'method':'GET','path':'/','query':'','body':'','user_agent':'Mozilla','referer':'','content_type':''}}
        path=Path(self.folder.name)/'bad.jsonl';path.write_text(json.dumps(row)+'\n'+json.dumps({**row,'id':'second','split':'calibration'}),encoding='utf-8')
        with self.assertRaisesRegex(ValueError,'leakage'):load(path)

    def test_failed_ai_call_is_not_true_negative(self):
        from utils.evaluation import summarize
        rows=[{'status':'fallback','expected':'benign','prediction':'uncertain','attack_type':'','predicted_types':[],'latency_ms':1}]
        m=summarize(rows);self.assertEqual(m['tn'],0);self.assertEqual(m['negative_abstentions'],1);self.assertEqual(m['coverage'],0)

    def test_failed_attack_call_counts_against_system_recall(self):
        from utils.evaluation import summarize
        rows=[{'status':'fallback','expected':'attack','prediction':'uncertain','attack_type':'xss','predicted_types':[],'latency_ms':1}]
        m=summarize(rows);self.assertEqual(m['fn_including_abstained_attacks'],1);self.assertEqual(m['system_recall'],0)

    def test_business_sessions_and_jobs_do_not_leak(self):
        from web_honeypot.server import app
        a=app.test_client();b=app.test_client();a.environ_base['REMOTE_ADDR']='192.0.2.201';b.environ_base['REMOTE_ADDR']='192.0.2.201'
        with patch.object(self.ai,'_transport',side_effect=lambda messages,schema=None,options=None:{'strategy':json.loads(messages[1]['content'])['allowed_strategies'][0]}):
            self.assertEqual(a.get('/api/erp/orders').status_code,401);self.assertEqual(a.post('/api/erp/login',json={'username':'guest','password':'fixture'}).status_code,200)
            self.assertEqual(a.get('/api/erp/orders').status_code,200);self.assertEqual(b.get('/api/erp/orders').status_code,401)
            response=a.post('/api/erp/export');self.assertEqual(response.status_code,202);job=response.json['job_id'];self.assertEqual(b.get('/api/erp/jobs/'+job).status_code,404);self.assertEqual(a.get('/api/erp/jobs/'+job).json['status'],'ready')

    def test_persona_native_commands_and_file_metadata_agree(self):
        from ssh_honeypot.server import VirtualShell
        shell=VirtualShell('192.0.2.1');self.assertEqual(shell.execute_command('hostname').strip(),shell.hostname);self.assertEqual(shell.execute_command('cat /etc/hostname').strip(),shell.hostname)
        self.assertIn(shell.decoy_profile['kernel'],shell.execute_command('uname -a'))

    def test_virtual_service_changes_match_systemctl_and_are_isolated(self):
        from ssh_honeypot.server import VirtualShell
        from utils.decoy_profiles import render
        a=VirtualShell('192.0.2.1');b=VirtualShell('192.0.2.1');service=next(iter(a.decoy_profile['services']))
        b_initial=b.services_state[service]['running'];render(a,'service_stop',service)
        self.assertIn('inactive',a.execute_command('systemctl status '+service));self.assertEqual(b.services_state[service]['running'],b_initial)

    def test_virtual_profile_is_stable_between_connections(self):
        from ssh_honeypot.server import VirtualShell
        a=VirtualShell('192.0.2.1');b=VirtualShell('192.0.2.1');self.assertEqual(a.hostname,b.hostname);self.assertIsNot(a.decoy_profile['services'],b.decoy_profile['services'])

    def test_fresh_deployment_creates_host_key_directory_and_keeps_identity(self):
        from ssh_honeypot import server
        target=Path(self.folder.name)/'fresh/state/host_key'
        with patch.object(server,'HOST_KEY_FILE_ED25519',str(target)):
            a=server.generate_host_key();before=target.read_bytes();b=server.generate_host_key()
        self.assertEqual(a.get_fingerprint(),b.get_fingerprint());self.assertEqual(target.read_bytes(),before)

    def test_completed_lease_cleanup_retries_a_transient_write_lock(self):
        import sqlite3
        call={'id':'cleanup-test','task':'probe','session_id':'cleanup','src_ip':'fixture','input_sha256':'fixture'}
        self.assertEqual(self.ai.STORE.start(call,self.ai.SETTINGS),'')
        original=self.ai.STORE.connect;calls=0
        def connect():
            nonlocal calls
            calls+=1
            if calls==1:raise sqlite3.OperationalError('database is locked')
            return original()
        with patch.object(self.ai.STORE,'connect',side_effect=connect):self.ai.STORE.release(call['id'])
        self.assertEqual(self.ai.STORE.snapshot()['active'],0);self.assertEqual(calls,2)

    def test_shared_endpoint_settings_require_explicit_lan_http_and_token(self):
        from utils.ai_settings import load_settings
        config=Path(self.folder.name)/'client.ini';config.write_text('[ai]\nenabled=true\nprovider=gateway\nmodel=fixture\ngateway_url=http://192.168.1.10:11500\nclient_token='+'t'*40+'\n',encoding='utf-8')
        with patch.dict(os.environ,{'HONEYPOT_AI_CONFIG':str(config)},clear=False):
            self.assertFalse(load_settings()['configured'])
            with patch.dict(os.environ,{'HONEYPOT_AI_ALLOW_INSECURE_LAN':'true'}):self.assertTrue(load_settings()['configured'])

    def test_gateway_connection_failure_is_not_misreported_as_bad_output(self):
        with patch.object(self.ai,'_transport',side_effect=ValueError('model_unavailable')):
            result=self.ai.probe('gateway-outage')
        self.assertEqual(result['reason'],'model_unavailable')

    def test_team_endpoints_require_login_and_mutation_csrf(self):
        from dashboard.server import app
        c=app.test_client();base='http://127.0.0.1:5001'
        self.assertEqual(c.get('/api/team/graph',base_url=base).status_code,401)
        with c.session_transaction(base_url=base) as s:s.update(is_admin=True,username='fixture',csrf_token='fixture')
        self.assertEqual(c.post('/api/team/evaluate-rules',json={},base_url=base,headers={'Origin':base}).status_code,403)
        self.assertEqual(c.get('/ai/team',base_url=base).status_code,200)


class GatewayChecks(unittest.TestCase):
    def setUp(self):
        from ai_gateway.server import Gateway,create_app
        self.folder=tempfile.TemporaryDirectory();self.tokens={'a':'a'*40,'b':'b'*40};clients={name:{'token_hash':hashlib.sha256(token.encode()).hexdigest(),'max_pending':10,'per_minute':50} for name,token in self.tokens.items()}
        self.gateway=Gateway(Path(self.folder.name)/'gateway.db','fixture',clients,transport=lambda p:{'done':True,'message':{'content':'{"reply":"ok"}'}});self.app=create_app(self.gateway);self.client=self.app.test_client()
    def tearDown(self):self.gateway.close();self.folder.cleanup()
    def payload(self,task='log_report'):return {'request_id':secrets.token_hex(12),'task':task,'messages':[{'role':'user','content':'fixture'}],'schema':None,'options':{}}
    def headers(self,client='a'):return {'Authorization':'Bearer '+self.tokens[client]}
    def test_auth_required_and_no_tokens_in_status(self):
        self.assertEqual(self.client.get('/v1/status').status_code,401);r=self.client.get('/v1/status',headers=self.headers());self.assertEqual(r.status_code,200);self.assertNotIn(self.tokens['a'],r.text)
    def test_jobs_and_replies_are_client_isolated(self):
        r=self.client.post('/v1/jobs',json=self.payload(),headers=self.headers());identifier=r.json['data']['id'];self.assertEqual(self.client.get('/v1/jobs/'+identifier,headers=self.headers('b')).status_code,404);self.gateway.process_one();self.assertEqual(self.client.get('/v1/jobs/'+identifier,headers=self.headers()).json['data']['status'],'completed')
    def test_idempotent_submission_does_not_duplicate_work(self):
        payload=self.payload();a=self.gateway.enqueue('a',payload);b=self.gateway.enqueue('a',payload);self.assertEqual(a['id'],b['id'])
    def test_queue_capacity_is_global(self):
        self.gateway.queue_limit=4
        for i in range(4):self.gateway.enqueue('a' if i%2 else 'b',self.payload())
        with self.assertRaises(OverflowError):self.gateway.enqueue('b',self.payload())
    def test_foreground_priority_and_global_capacity(self):
        self.gateway.enqueue('a',self.payload('log_report'));high=self.gateway.enqueue('b',self.payload('ssh_reply'));job=self.gateway.claim();self.assertEqual(job['id'],high['id']);self.assertIsNone(self.gateway.claim())
    def test_cancelled_running_job_retains_capacity_until_inference_finishes(self):
        j=self.gateway.enqueue('a',self.payload());job=self.gateway.claim();self.gateway.cancel(j['id'],'a');self.gateway.enqueue('b',self.payload());self.assertIsNone(self.gateway.claim());self.gateway.finish(job,{'reply':'late'});self.assertEqual(self.gateway.get(j['id'],'a')['status'],'cancelled');self.assertIsNotNone(self.gateway.claim())
    def test_restart_stale_lease_cannot_publish_old_output(self):
        j=self.gateway.enqueue('a',self.payload());job=self.gateway.claim()
        with closing(self.gateway.connect()) as c,c:c.execute('UPDATE jobs SET lease=? WHERE id=?',('new',j['id']))
        self.assertFalse(self.gateway.finish(job,{'reply':'stale'}))
    def test_round_robin_fairness_between_members(self):
        for _ in range(3):self.gateway.enqueue('a',self.payload())
        b=self.gateway.enqueue('b',self.payload());first=self.gateway.claim();self.gateway.finish(first,{'ok':1});second=self.gateway.claim();self.assertEqual(second['client'],'b')
    def test_member_quota_cannot_consume_every_slot(self):
        self.gateway.clients['a']['max_pending']=1;self.gateway.enqueue('a',self.payload())
        with self.assertRaises(OverflowError):self.gateway.enqueue('a',self.payload())
        self.assertTrue(self.gateway.enqueue('b',self.payload())['id'])
    def test_http_rejects_invalid_tasks_tool_roles_and_oversized_data(self):
        for p in ({**self.payload(),'task':'run_shell'},{**self.payload(),'messages':[{'role':'tool','content':'x'}]},{**self.payload(),'options':{'endpoint':'http://outside.test'}}):self.assertEqual(self.client.post('/v1/jobs',json=p,headers=self.headers()).status_code,400)
        self.assertEqual(self.client.post('/v1/jobs',data='x'*30000,headers=self.headers()).status_code,413)
    def test_global_model_circuit_does_not_drop_queue(self):
        for _ in range(3):
            self.gateway.enqueue('a',self.payload('probe'));job=self.gateway.claim();self.gateway.finish(job,{},'model_unavailable')
        ordinary=self.gateway.enqueue('b',self.payload());self.assertIsNone(self.gateway.claim());self.assertEqual(self.gateway.get(ordinary['id'],'b')['status'],'queued')
        self.gateway.enqueue('a',self.payload('probe'));probe=self.gateway.claim();self.gateway.finish(probe,{'ok':1});self.assertIsNotNone(self.gateway.claim())
    def test_semantic_transport_failure_does_not_open_global_network_circuit(self):
        self.gateway.transport=lambda p:(_ for _ in ()).throw(ValueError('invalid_model_output'))
        for _ in range(4):self.gateway.enqueue('a',self.payload());self.gateway.process_one()
        self.assertEqual(self.gateway.status('a')['circuit_open_until'],0)
    def test_real_http_adapter_consumes_shared_queue_and_cancels_timeout(self):
        from werkzeug.serving import make_server
        from utils.gateway_client import transport
        server=make_server('127.0.0.1',0,self.app,threaded=True);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start();self.gateway.start()
        settings={'gateway_url':'http://127.0.0.1:'+str(server.server_port),'client_token':self.tokens['a'],'timeout':5,'gateway_wait':5,'context_length':1024,'think':False}
        try:
            data=transport(settings,[{'role':'user','content':'fixture'}],None,{'request_id':secrets.token_hex(12),'task':'probe','timeout':5});self.assertTrue(data['done'])
        finally:server.shutdown();server.server_close();thread.join(2)
