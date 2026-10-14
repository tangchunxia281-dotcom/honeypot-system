# -*- coding: utf-8 -*-
"""pytest 全局夹具与测试环境隔离。

关键：必须在导入 app_config / db 之前，把 SQLite 指向临时文件，
否则测试会读写真实 database/event_logs.db。
"""
import os
import sys
import tempfile

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

_TEST_DIR = tempfile.mkdtemp(prefix='honeypot-test-')
os.environ['DB_TYPE'] = 'sqlite'
os.environ['DB_PATH'] = os.path.join(_TEST_DIR, 'test_event_logs.db')

# RFC 5737 文档专用网段，供各测试文件使用，避免与真实数据混淆
TEST_IP_A = '203.0.113.10'
TEST_IP_B = '203.0.113.11'
TEST_IP_MARK = '203.0.113.199'
