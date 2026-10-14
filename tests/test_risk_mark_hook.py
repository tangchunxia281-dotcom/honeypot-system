# -*- coding: utf-8 -*-
"""[risk-mark] db.event_logs -> risk_mark.service.on_event 闭环测试。"""
from db.event_logs import log_event
from risk_mark import config as mark_config
from risk_mark import service
from risk_mark.constants import TARGET_IP

from conftest import TEST_IP_MARK


def _cleanup():
    try:
        service.unmark(target_type=TARGET_IP, target_value=TEST_IP_MARK)
    except Exception:
        pass


def test_log_event_triggers_risk_mark(monkeypatch):
    """打开总开关后，log_event 落库应自动触发识别并落标。"""
    monkeypatch.setattr(mark_config, 'AUTO_DETECT_ENABLED', True)
    monkeypatch.setattr(mark_config, 'AUTO_DETECT_APPLY', True)
    _cleanup()
    try:
        new_id = log_event(source='web', severity='critical', event_type='sql_injection',
                           src_ip=TEST_IP_MARK, payload='pytest 闭环')
        assert new_id
        mark = service.get_mark(TARGET_IP, TEST_IP_MARK)
        assert mark is not None, '闭环未产生密标'
        assert str(mark.get('source', '')).startswith('detector:')
    finally:
        _cleanup()


def test_hook_disabled_by_default(monkeypatch):
    """总开关关闭时，钩子静默跳过，不产生任何密标。"""
    monkeypatch.setattr(mark_config, 'AUTO_DETECT_ENABLED', False)
    _cleanup()
    new_id = log_event(source='web', severity='critical', event_type='sql_injection',
                       src_ip=TEST_IP_MARK)
    assert new_id
    assert service.get_mark(TARGET_IP, TEST_IP_MARK) is None
