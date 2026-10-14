# -*- coding: utf-8 -*-
"""utils/alerting 告警去重与限频逻辑测试（不触发真实网络发送）。"""
import time

from utils import alerting


def _reset_state(monkeypatch):
    monkeypatch.setattr(alerting, 'ALERT_ENABLED', True)
    monkeypatch.setattr(alerting, 'ALERT_MIN_INTERVAL', 0.0)
    monkeypatch.setattr(alerting, 'ALERT_DEDUP_WINDOW', 60)
    alerting._dedup.clear()
    alerting._dedup_count.clear()
    alerting._last_send_by_type.clear()


def test_dedup_window(monkeypatch):
    _reset_state(monkeypatch)
    assert alerting._should_send('k1') is True
    assert alerting._should_send('k1') is False, '去重窗口内同 key 不应重复发送'
    assert alerting._should_send('k2') is True, '不同 key 互不影响'
    assert alerting._dedup_count.get('k1') == 1, '被去重的次数应累计'


def test_disabled_switch(monkeypatch):
    _reset_state(monkeypatch)
    monkeypatch.setattr(alerting, 'ALERT_ENABLED', False)
    assert alerting._should_send('k3') is False


def test_dedup_window_expiry(monkeypatch):
    _reset_state(monkeypatch)
    monkeypatch.setattr(alerting, 'ALERT_DEDUP_WINDOW', 1)
    assert alerting._should_send('k4') is True
    alerting._dedup['k4'] = time.time() - 5  # 模拟窗口已过
    assert alerting._should_send('k4') is True


def test_min_interval_per_category(monkeypatch):
    _reset_state(monkeypatch)
    monkeypatch.setattr(alerting, 'ALERT_MIN_INTERVAL', 3600.0)
    assert alerting._should_send('k5', category='ssh') is True
    assert alerting._should_send('k6', category='ssh') is False, '同类别最小间隔内应限频'
    assert alerting._should_send('k7', category='web') is True, '不同类别互不影响'
