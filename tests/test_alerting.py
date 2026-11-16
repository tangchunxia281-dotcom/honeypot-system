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


# ---------- [alert-channels] 多渠道 ----------

def test_channel_formatters():
    wecom = alerting._format_wecom('内容', True)
    assert wecom['msgtype'] == 'text' and wecom['text']['mentioned_list'] == ['@all']
    ding = alerting._format_dingtalk('内容', True)
    assert ding['at']['isAtAll'] is True
    feishu = alerting._format_feishu('内容', True)
    assert feishu['msg_type'] == 'text' and 'user_id="all"' in feishu['content']['text']
    generic = alerting._format_generic('内容', False)
    assert generic['source'] == 'honeypot-system' and generic['mention_all'] is False
    # 不 @all 时不应带 at 字段
    assert 'at' not in alerting._format_dingtalk('内容', False)


def test_deliver_multi_channel(monkeypatch):
    """任一渠道成功即送达；单渠道异常不影响其余渠道。"""
    calls = []

    class _Resp:
        status_code = 200

    def _fake_post(url, json=None, timeout=None):
        calls.append((url, json))
        return _Resp()

    def _boom(content):
        raise RuntimeError('smtp down')

    monkeypatch.setattr(alerting.requests, 'post', _fake_post)
    monkeypatch.setattr(alerting, '_CHANNELS', [
        {'name': 'wecom', 'kind': 'json', 'url': 'http://a', 'formatter': alerting._format_wecom},
        {'name': 'generic', 'kind': 'json', 'url': 'http://b', 'formatter': alerting._format_generic},
        {'name': 'smtp', 'kind': 'smtp'},
    ])
    monkeypatch.setattr(alerting, '_send_smtp', _boom)
    assert alerting._deliver('内容', False) is True
    assert [u for u, _ in calls] == ['http://a', 'http://b'], '两个 JSON 渠道都应被投递'


def test_deliver_all_fail_returns_false(monkeypatch):
    def _fail_post(url, json=None, timeout=None):
        raise RuntimeError('network down')

    monkeypatch.setattr(alerting.requests, 'post', _fail_post)
    monkeypatch.setattr(alerting, '_CHANNELS', [
        {'name': 'wecom', 'kind': 'json', 'url': 'http://a', 'formatter': alerting._format_wecom},
    ])
    assert alerting._deliver('内容', False) is False
