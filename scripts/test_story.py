import importlib.util
import unittest

class StoryChecks(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('utils.attack_story'),'story required')
        from utils.attack_story import build_story,validate_interpretation
        self.build=build_story;self.validate=validate_interpretation
        self.rows=[{'id':'a'*24,'sensor_id':'a','timestamp':'2026-10-11 10:00:00','session_id':'s','src_ip':'127.0.0.1','channel':'web','kind':'login','excerpt':'virtual login success'},
                   {'id':'b'*24,'sensor_id':'b','timestamp':'2026-10-11 10:00:00','session_id':'s','src_ip':'127.0.0.1','channel':'ssh','kind':'command','excerpt':'whoami'}]
    def test_equal_time_and_multi_sensor_not_identity(self):
        story=self.build(self.rows,None)
        self.assertTrue(all(r['simultaneous'] for r in story['facts']));self.assertFalse(story['same_session']);self.assertIn('不证明',story['limitations'])
    def test_unknown_reference_rejected(self):
        with self.assertRaises(ValueError):self.validate({'summary':'x','stages':[{'name':'probe','description':'x','refs':['c'*24]}],'limitations':'x'},self.rows)
    def test_no_model_timeline_still_visible(self):
        story=self.build(self.rows,None);self.assertEqual(len(story['facts']),2);self.assertEqual(story['ai_status'],'not_completed');self.assertEqual(story['inferences'],[])
    def test_virtual_success_not_host_compromise(self):
        story=self.build(self.rows,{'summary':'虚拟登录','stages':[{'name':'access_attempt','description':'观察到虚拟登录回应','refs':['a'*24]}],'limitations':'虚拟数据'})
        self.assertEqual(story['inferences'][0]['certainty'],'ai_inference');self.assertFalse(story['host_compromise_confirmed'])

if __name__=='__main__':unittest.main()
