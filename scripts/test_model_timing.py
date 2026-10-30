import unittest
class TimingChecks(unittest.TestCase):
    def test_native_timing_units_and_unavailable_values(self):
        from utils import local_ai
        self.assertTrue(hasattr(local_ai,'model_timing'))
        result=local_ai.model_timing({'eval_duration':2000000,'prompt_eval_duration':1000000,'load_duration':0,'total_duration':4000000})
        self.assertEqual(result['generation_ms'],2);self.assertEqual(result['prompt_ms'],1)
        self.assertIsNone(local_ai.model_timing({'eval_duration':True})['generation_ms'])
        self.assertIsNone(local_ai.model_timing({})['generation_ms'])
if __name__=='__main__':unittest.main()
