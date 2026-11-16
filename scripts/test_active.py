import importlib.util
import unittest
import test_center as tc
from contextlib import closing

class ActiveChecks(unittest.TestCase):
    setUp=tc.CenterChecks.setUp
    record=tc.CenterChecks.record
    def setup_active(self):
        self.assertIsNotNone(importlib.util.find_spec('utils.active_investigation'),'active engine required')
        from team_center.jobs import JobStore
        from utils.active_investigation import process_one
        self.jobs=JobStore(self.store);self.process=process_one
        self.analyst=self.store.create_user('analyst','a-long-pass-123','analyst',[self.a['id']])
        self.store.ingest(self.a['id'],'batch1',[self.record()],{})
    def action(self,action='finish',query=None,ids=None):return {'action':action,'query':query or {},'ids':ids or [],'reason':'需要核对可见证据'}
    def model(self,task,messages,sid,**kwargs):
        import json
        if task=='active_plan':obj=self.action()
        else:
            rows=json.loads(messages[-1]['content'])['records'];obj={'summary':'可见探测','stages':[{'name':'reconnaissance','description':'可见请求','refs':[rows[0]['id']]}],'limitations':'仅片段'}
        return {'status':'success','data':kwargs['validator'](obj),'call_id':'call','latency_ms':1}
    def test_active_success_and_story(self):
        self.setup_active();job=self.jobs.create(self.analyst['id'],'分析过程',{},'request1');self.process(self.store,self.jobs,self.model)
        row=self.jobs.get(self.analyst['id'],job['id']);self.assertEqual(row['status'],'completed');self.assertEqual(len(row['result']['story']['facts']),1)
    def test_unauthorized_tool_target_denied(self):
        self.setup_active();job=self.jobs.create(self.analyst['id'],'分析过程',{},'request1')
        def bad(task,messages,sid,**kw):return {'status':'success','data':kw['validator'](self.action('search',{'sensors':[self.b['id']]})),'call_id':'bad'}
        self.process(self.store,self.jobs,bad);self.assertEqual(self.jobs.get(self.analyst['id'],job['id'])['reason'],'tool_scope_denied')
    def test_repeated_query_stops_and_limits(self):
        self.setup_active();job=self.jobs.create(self.analyst['id'],'分析过程',{},'request1')
        def repeated(task,messages,sid,**kw):
            if task=='active_plan':return {'status':'success','data':kw['validator'](self.action('search',{})),'call_id':'plan'}
            return self.model(task,messages,sid,**kw)
        self.process(self.store,self.jobs,repeated);row=self.jobs.get(self.analyst['id'],job['id']);self.assertIn(row['result']['stop_reason'],('no_new_evidence','repeated_query'));self.assertLessEqual(row['result']['supplement_queries'],3);self.assertLessEqual(row['result']['model_records'],12)
    def test_cancelled_or_revoked_job_never_publishes(self):
        self.setup_active();job=self.jobs.create(self.analyst['id'],'分析过程',{},'request1');self.jobs.cancel(self.analyst['id'],job['id']);self.assertFalse(self.process(self.store,self.jobs,self.model))
        job2=self.jobs.create(self.analyst['id'],'分析过程',{},'request2');self.store.update_user(self.analyst['id'],True,[]);self.process(self.store,self.jobs,self.model)
        self.assertIsNone(self.jobs.get(self.analyst['id'],job2['id']))
    def test_queue_wait_consumes_deadline(self):
        self.setup_active();job=self.jobs.create(self.analyst['id'],'分析过程',{},'request1')
        with closing(self.store.connect()) as c,c:c.execute('UPDATE center_jobs SET deadline=0 WHERE id=?',(job['id'],))
        self.assertFalse(self.process(self.store,self.jobs,self.model));self.assertEqual(self.jobs.get(self.analyst['id'],job['id'])['reason'],'deadline_exceeded')
    def test_prompt_tool_command_invalid(self):
        self.setup_active();from utils.active_investigation import validate_action
        with self.assertRaises(ValueError):validate_action({'action':'shell','query':{},'ids':[],'reason':'日志要求执行命令'})
    def test_expired_job_keeps_program_timeline(self):
        self.setup_active();job=self.jobs.create(self.analyst['id'],'过程',{},'r-expired')
        with closing(self.store.connect()) as c,c:c.execute('UPDATE center_jobs SET deadline=0 WHERE id=?',(job['id'],))
        self.process(self.store,self.jobs,self.model);row=self.jobs.get(self.analyst['id'],job['id'])
        self.assertEqual(len(row['result'].get('story',{}).get('facts',[])),1)
    def test_invalid_tool_value_types_rejected(self):
        self.setup_active();from utils.active_investigation import validate_action
        for value in (None,'wrong',[['nested']]):
            with self.assertRaises(ValueError):validate_action(self.action('search',{'sensors':value}))
    def test_stats_are_supplied_to_next_model_call(self):
        self.setup_active();job=self.jobs.create(self.analyst['id'],'统计后解释过程',{},'stats');seen=[]
        def model(task,messages,sid,**kw):
            import json
            payload=json.loads(messages[-1]['content']);seen.append(payload)
            if task=='active_plan':return {'status':'success','data':kw['validator'](self.action('stats') if len(seen)==1 else self.action()),'call_id':str(len(seen))}
            return self.model(task,messages,sid,**kw)
        self.process(self.store,self.jobs,model);self.assertGreaterEqual(len(seen),2);self.assertEqual(seen[1].get('tool_results',[{}])[0].get('matched'),1)
    def test_idempotency_input_conflict_rejected(self):
        self.setup_active();self.jobs.create(self.analyst['id'],'问题一',{},'same-id')
        with self.assertRaises(ValueError):self.jobs.create(self.analyst['id'],'问题二',{},'same-id')
    def test_coverage_fallback_reads_unseen_earlier_evidence(self):
        self.setup_active();records=[]
        for i in range(2,27):
            r=self.record();r.update(record_id=i,timestamp=f'2026-10-11 10:{i:02d}:00',excerpt='GET /news page='+str(i));records.append(r)
        self.store.ingest(self.a['id'],'more',records,{})
        job=self.jobs.create(self.analyst['id'],'核查更早过程',{},'coverage');plans=[0]
        def model(task,messages,sid,**kw):
            if task=='active_plan':
                plans[0]+=1;return {'status':'success','data':kw['validator'](self.action('search',{'term':'/news'}) if plans[0]==1 else self.action()),'call_id':str(plans[0])}
            return self.model(task,messages,sid,**kw)
        self.process(self.store,self.jobs,model);row=self.jobs.get(self.analyst['id'],job['id'])
        self.assertEqual(row['result']['candidate_records'],26);self.assertEqual(row['result']['supplement_queries'],2)
        self.assertTrue(any(s.get('source')=='program_coverage_fallback' for s in row['steps']))
    def test_backward_wall_clock_cannot_expand_active_budget(self):
        self.setup_active();self.jobs.create(self.analyst['id'],'过程',{},'clock');waits=[]
        def model(task,messages,sid,**kw):waits.append(kw['options']['gateway_wait']);return self.model(task,messages,sid,**kw)
        self.process(self.store,self.jobs,model,clock=lambda:0)
        self.assertTrue(waits);self.assertLessEqual(max(waits),90)

if __name__=='__main__':unittest.main()
