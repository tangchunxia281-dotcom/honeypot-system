# -*- coding: utf-8 -*-
"""db.event_logs 核心写入/查询路径测试。"""
from db.event_logs import get_event_logs, log_event, severity_from_score

from conftest import TEST_IP_A, TEST_IP_B


def test_log_event_and_query():
    new_id = log_event(source='web', severity='high', event_type='path_probe',
                       src_ip=TEST_IP_A, payload='pytest 写入')
    assert isinstance(new_id, int) and new_id > 0
    rows = get_event_logs(limit=20, source='web')
    assert any(r.get('id') == new_id for r in rows)


def test_log_event_normalization():
    """source/severity/event_type 应统一归一化为小写标准值。"""
    new_id = log_event(source='WEB', severity='HIGH', event_type='SQL_Injection',
                       src_ip=TEST_IP_B)
    assert new_id
    rows = get_event_logs(limit=20, source='web', severity='high')
    hit = [r for r in rows if r.get('id') == new_id]
    assert hit and hit[0].get('event_type') == 'sql_injection'


def test_severity_from_score():
    # 阈值来自 utils/alerting.py：risk=40 / high=60 / critical=80
    assert severity_from_score(90) == 'critical'
    assert severity_from_score(70) == 'high'
    assert severity_from_score(50) == 'medium'
    assert severity_from_score(10) == 'low'
    assert severity_from_score('bad') == 'low'


def test_log_event_does_not_raise_on_odd_input():
    """异常输入应静默降级返回 None 或正常写入，绝不抛异常影响蜜罐主流程。"""
    log_event(source=None, severity=None, event_type=None, src_ip=None, payload=object())
