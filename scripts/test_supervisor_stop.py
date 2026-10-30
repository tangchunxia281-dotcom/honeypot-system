import os,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
class StopChecks(unittest.TestCase):
    def test_explicit_operator_stop_precedes_restart_checks(self):
        import main
        case=self
        class Process:
            def poll(self):case.fail('stop sentinel must be checked before service restart logic')
        with tempfile.TemporaryDirectory() as folder:
            sentinel=Path(folder)/'STOP';sentinel.touch()
            with patch.dict(os.environ,{'HONEYPOT_STOP_FILE':str(sentinel)}),patch.object(main.time,'sleep'),patch.object(main,'processes',{'fixture':Process()}):main.monitor_processes()
if __name__=='__main__':unittest.main()
