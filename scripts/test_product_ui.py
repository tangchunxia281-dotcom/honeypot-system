import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
class ProductUiChecks(unittest.TestCase):
 def test_real_panels_replace_anchors_and_legacy_cross_routes(self):
  s=(ROOT/'dashboard/templates/workspace.html').read_text(encoding='utf-8')
  self.assertNotIn('href="#model"',s)
  self.assertNotIn('/ai/workbench?tab=graph',s)
  for key in ('timeline','graph','replay','model','effects','calls'): self.assertIn('data-tab="'+key+'"',s)
 def test_no_recording_coaching_inside_product(self):
  for name in ('workspace.html','ai_sidebar.html'):
   s=(ROOT/'dashboard/templates'/name).read_text(encoding='utf-8')
   for label in ('演示指引','6～8分钟演示','演示路线','单机参赛版'):self.assertNotIn(label,s)
if __name__=='__main__': unittest.main(verbosity=2)
