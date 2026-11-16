import importlib.util
import unittest
import test_active as ta

class EffectChecks(unittest.TestCase):
    setUp=ta.ActiveChecks.setUp
    record=ta.ActiveChecks.record
    setup_active=ta.ActiveChecks.setup_active
    action=ta.ActiveChecks.action
    model=ta.ActiveChecks.model
    def effect(self):
        self.assertIsNotNone(importlib.util.find_spec('utils.ai_effectiveness'),'effects required')
        from utils.ai_effectiveness import snapshot
        return snapshot(self.store,self.jobs,self.analyst['id'],{})
    def test_zero_reviews_no_accuracy(self):
        self.setup_active();self.assertIsNone(self.effect()['human_acceptance']['rate'])
    def test_failures_not_benign_and_feedback_revision(self):
        self.setup_active();job=self.jobs.create(self.analyst['id'],'过程',{},'r1');self.process(self.store,self.jobs,self.model)
        self.jobs.feedback(self.analyst['id'],job['id'],0,'accepted','已核对原文')
        with self.assertRaises(ValueError):self.jobs.feedback(self.analyst['id'],job['id'],0,'incorrect','旧版本')
        r=self.effect();self.assertEqual(r['human_acceptance']['reviewed'],1);self.assertEqual(r['human_acceptance']['rate'],1)
    def test_scope_and_synthetic_separated(self):
        self.setup_active();self.store.ingest(self.b['id'],'b1',[self.record()],{})
        self.assertEqual(self.effect()['evidence']['total'],1);self.assertEqual(self.effect()['evidence']['origins']['synthetic'],1)
    def test_member_replay_not_double_counted_or_accuracy(self):
        self.setup_active();m={'id':'call-1','task':'web_detect','status':'success','reason':'','latency_ms':10,'origin':'synthetic','ai_attack':True,'rule_attack':False,'model':'fixture','timestamp':1}
        self.store.ingest(self.a['id'],'m1',[],{},[m]);self.store.ingest(self.a['id'],'m2',[],{},[m])
        r=self.effect();self.assertEqual(r['member_declared']['total'],1);self.assertIsNone(r['human_acceptance']['rate'])
    def test_replay_requires_real_denominators(self):
        self.setup_active();from utils import ai_effectiveness as effects
        self.assertTrue(hasattr(effects,'validate_replay'))
        obj={'run_id':'a'*24,'dataset_sha256':'b'*64,'model':'fixture','origin':'synthetic','arms':{'fixed':{'steps':2,'valid_steps':2,'latency_ms':0},'ai':{'steps':2,'valid_steps':1,'latency_ms':10}},'scope':'合成有限策略回放，不证明延长真实攻击会话。'}
        self.assertEqual(effects.validate_replay(obj)['arms']['ai']['valid_steps'],1)
        obj['arms']['ai']['valid_steps']=3
        with self.assertRaises(ValueError):effects.validate_replay(obj)

if __name__=='__main__':unittest.main()
