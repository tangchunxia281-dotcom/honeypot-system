import unittest
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))

class BindChecks(unittest.TestCase):
    def test_lan_requires_explicit_opt_in(self):
        from scripts import team_center as cli
        self.assertTrue(hasattr(cli,'validate_bind'),'bind validator required')
        with self.assertRaises(ValueError):cli.validate_bind('192.168.1.10',5169,False)
        cli.validate_bind('192.168.1.10',5169,True);cli.validate_bind('127.0.0.1',5169,False)
        with self.assertRaises(ValueError):cli.validate_bind('0.0.0.0',5169,True)

if __name__=='__main__':unittest.main()
