"""Isolated correctness and local HTTP checks; does not call a real model."""
import sys
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT));sys.path.insert(1,str(ROOT/'scripts'))
if __name__=='__main__':
    if hasattr(sys.stdout,'reconfigure'):sys.stdout.reconfigure(encoding='utf-8',errors='replace')
    loader=unittest.TestLoader();suite=unittest.TestSuite()
    for module in ('test_center','test_collector','test_story','test_active','test_effectiveness','test_gateway_deadline','test_center_deploy','test_center_http','test_model_timing','test_supervisor_stop'):suite.addTests(loader.loadTestsFromName(module))
    result=unittest.TextTestRunner(verbosity=2).run(suite);raise SystemExit(0 if result.wasSuccessful() else 1)
