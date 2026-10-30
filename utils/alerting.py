# -*- coding: utf-8 -*-
"""
告警通知模块（企业微信机器人）
"""
import os
import time
import threading
import hashlib
import logging
import re
import json
import queue
from utils.logger import setup_logger
import requests
from urllib.parse import quote
from env_utils import env_bool as _env_bool, env_float as _env_float, env_int as _env_int, env_str as _env_str

_logger = setup_logger('alert', 'alert.log', console_output=False)

ALERT_WEBHOOK_URL = _env_str('ALERT_WEBHOOK_URL', '')
ALERT_ENABLED = _env_bool('ALERT_ENABLED', True) and bool(ALERT_WEBHOOK_URL)
ALERT_TIMEOUT = _env_float('ALERT_TIMEOUT', 3.0, 0.1, 60.0)
ALERT_MIN_INTERVAL = _env_float('ALERT_MIN_INTERVAL', 3.0, 0.0, 3600.0)
ALERT_DEDUP_WINDOW = _env_int('ALERT_DEDUP_WINDOW', 60, 0, 86400)
ALERT_RISK_THRESHOLD = _env_int('ALERT_RISK_THRESHOLD', 40, 0, 100)
ALERT_HIGH_THRESHOLD = _env_int('ALERT_HIGH_THRESHOLD', 60, 0, 100)
ALERT_CRITICAL_THRESHOLD = _env_int('ALERT_CRITICAL_THRESHOLD', 80, 0, 100)
ALERT_MENTION_ALL = _env_bool('ALERT_MENTION_ALL', False)
ALERT_RETRY = _env_int('ALERT_RETRY', 1, 0, 5)
ALERT_DETAIL_URL = _env_str('ALERT_DETAIL_URL', '')
ALERT_DETAIL_URL_ENABLED = _env_bool('ALERT_DETAIL_URL_ENABLED', False)
ALERT_MSG_MAX_BYTES = _env_int('ALERT_MSG_MAX_BYTES', 3900, 256, 12000)
ALERT_ASYNC_ENABLED = _env_bool('ALERT_ASYNC_ENABLED', True)
ALERT_QUEUE_MAX = _env_int('ALERT_QUEUE_MAX', 1000, 50, 50000)
ALERT_QUEUE_DROP_OLDEST = _env_bool('ALERT_QUEUE_DROP_OLDEST', True)
ALERT_WORKERS = _env_int('ALERT_WORKERS', 1, 1, 8)

_lock = threading.Lock()
_last_send_ts = 0.0
_last_send_by_type = {}
_dedup = {}
_dedup_count = {}
_alert_queue = queue.Queue(maxsize=ALERT_QUEUE_MAX)
_alert_worker_lock = threading.Lock()
_alert_workers_started = False
_alert_metrics_lock = threading.Lock()
_alert_metrics = {
    'queued': 0,
    'sent_ok': 0,
    'sent_fail': 0,
    'queue_full': 0,
    'drop_oldest': 0,
    'drop_current': 0,
}
_ANSI_ESCAPE_RE = re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]')
_CTRL_STRIP_RE = re.compile(r'[\x00-\x08\x0b-\x1f\x7f]')
_ALERT_TITLE_TEMPLATES = {
    'ssh_login_success': 'SSH 登录成功',
    'scp_upload': 'SCP 文件上传',
    'web_high_risk': 'Web 高危请求',
    'web_upload': 'Web 配置包上传',
}


def _hash_key(text: str) -> str:
    return hashlib.sha1((text or '').encode('utf-8', errors='ignore')).hexdigest()[:12]


def _should_send(dedup_key: str, category: str = 'general') -> bool:
    if not ALERT_ENABLED:
        return False
    now = time.time()
    global _last_send_ts
    with _lock:
        last_type_ts = _last_send_by_type.get(category, 0.0)
        if ALERT_MIN_INTERVAL > 0 and (now - last_type_ts) < ALERT_MIN_INTERVAL:
            return False
        last = _dedup.get(dedup_key)
        if last and (now - last) < ALERT_DEDUP_WINDOW:
            _dedup_count[dedup_key] = _dedup_count.get(dedup_key, 0) + 1
            return False
        _dedup[dedup_key] = now
        _last_send_ts = now
        _last_send_by_type[category] = now
    return True


def _inc_alert_metric(name: str, delta: int = 1) -> None:
    with _alert_metrics_lock:
        _alert_metrics[name] = int(_alert_metrics.get(name, 0)) + int(delta)


def _post_text_payload(payload: dict) -> bool:
    try:
        for _ in range(max(1, ALERT_RETRY + 1)):
            resp = requests.post(ALERT_WEBHOOK_URL, json=payload, timeout=ALERT_TIMEOUT)
            if 200 <= resp.status_code < 300:
                return True
        return False
    except Exception as e:
        _logger.debug(f"alert send failed: {e}")
        return False


def _alert_worker_loop(worker_id: int) -> None:
    while True:
        try:
            payload = _alert_queue.get(timeout=0.5)
        except queue.Empty:
            continue
        try:
            ok = _post_text_payload(payload)
            if ok:
                _inc_alert_metric('sent_ok')
            else:
                _inc_alert_metric('sent_fail')
        except Exception:
            _inc_alert_metric('sent_fail')
        finally:
            _alert_queue.task_done()


def _ensure_alert_workers_started() -> None:
    global _alert_workers_started
    if not ALERT_ENABLED or not ALERT_ASYNC_ENABLED:
        return
    if _alert_workers_started:
        return
    with _alert_worker_lock:
        if _alert_workers_started:
            return
        for i in range(ALERT_WORKERS):
            t = threading.Thread(target=_alert_worker_loop, args=(i,), daemon=True, name=f"alert-worker-{i+1}")
            t.start()
        _alert_workers_started = True


def _enqueue_alert_payload(payload: dict) -> bool:
    _ensure_alert_workers_started()
    try:
        _alert_queue.put_nowait(payload)
        _inc_alert_metric('queued')
        return True
    except queue.Full:
        _inc_alert_metric('queue_full')
        if not ALERT_QUEUE_DROP_OLDEST:
            _inc_alert_metric('drop_current')
            return False
        try:
            _alert_queue.get_nowait()
            _alert_queue.task_done()
            _inc_alert_metric('drop_oldest')
        except queue.Empty:
            pass
        try:
            _alert_queue.put_nowait(payload)
            _inc_alert_metric('queued')
            return True
        except queue.Full:
            _inc_alert_metric('drop_current')
            return False


def _send_text(content: str, mention_all: bool = False) -> bool:
    if not ALERT_ENABLED:
        return False
    payload = {"msgtype": "text", "text": {"content": content}}
    if mention_all:
        payload["text"]["mentioned_list"] = ["@all"]
    if ALERT_ASYNC_ENABLED:
        return _enqueue_alert_payload(payload)
    return _post_text_payload(payload)


def _level_from_score(score: int) -> str:
    if score >= ALERT_CRITICAL_THRESHOLD:
        return '严重'
    if score >= ALERT_HIGH_THRESHOLD:
        return '高危'
    if score >= ALERT_RISK_THRESHOLD:
        return '警告'
    return '提示'


def _normalize_level(level: str) -> str:
    if not level:
        return ''
    lv = str(level).strip()
    mapping = {
        'CRITICAL': '严重',
        'HIGH': '高危',
        'WARN': '警告',
        'WARNING': '警告',
        'INFO': '提示',
    }
    return mapping.get(lv.upper(), lv)


def _level_icon(level: str) -> str:
    mapping = {
        '严重': '🔴',
        '高危': '🟠',
        '警告': '🟡',
        '提示': '🔵',
    }
    return mapping.get(level or '', '')


def _append_bullets(lines: list, text: str) -> None:
    if not text:
        return
    safe_block = _sanitize_block(text, max_len=1600)
    for raw in safe_block.splitlines():
        item = _sanitize_inline(raw, max_len=260)
        if not item:
            continue
        lines.append(f"- {item}")


def _sanitize_inline(value: str, max_len: int = 240) -> str:
    s = str(value or '')
    s = _ANSI_ESCAPE_RE.sub('', s)
    s = s.replace('\r', ' ').replace('\n', ' ').replace('\t', ' ')
    s = _CTRL_STRIP_RE.sub('', s)
    s = ' '.join(s.split())
    if max_len > 0 and len(s) > max_len:
        s = s[:max_len]
    return s


def _sanitize_block(value: str, max_len: int = 1600) -> str:
    s = str(value or '')
    s = _ANSI_ESCAPE_RE.sub('', s)
    s = s.replace('\r\n', '\n').replace('\r', '\n')
    s = _CTRL_STRIP_RE.sub('', s)
    if max_len > 0 and len(s) > max_len:
        s = s[:max_len]
    return s


def _title_for(event_type: str, fallback: str) -> str:
    key = str(event_type or '').strip().lower()
    if key and key in _ALERT_TITLE_TEMPLATES:
        return _ALERT_TITLE_TEMPLATES[key]
    return fallback


def alert_event(title: str, src_ip: str = '', summary: str = '', extra: str = '',
                dedup_key: str = '', category: str = 'general', level: str = '', score: int = -1,
                subject: str = '', layout: str = 'single', subject_label: str = '',
                event_type: str = '', tags: list = None) -> bool:
    if not ALERT_ENABLED:
        return False
    title = _sanitize_inline(_title_for(event_type, title), max_len=120)
    src_ip = _sanitize_inline(src_ip, max_len=80)
    subject = _sanitize_inline(subject, max_len=180)
    subject_label = _sanitize_inline(subject_label, max_len=20)
    summary = _sanitize_block(summary, max_len=1200)
    extra = _sanitize_block(extra, max_len=1200)
    event_type = _sanitize_inline(event_type, max_len=64)
    safe_tags = []
    for t in (tags or []):
        x = _sanitize_inline(t, max_len=24)
        if x and x not in safe_tags:
            safe_tags.append(x)
    now_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
    key = dedup_key or _hash_key(f"{title}|{src_ip}|{summary}")
    try:
        from utils.alert_noise import NoiseGate
        from utils import local_ai
        weight=4 if score>=60 or level=='严重' else 3 if score>=40 or level in ('高危','critical','high') else 2
        decision=NoiseGate(local_ai.STORE).admit(src_ip,event_type or category,subject,weight)
        if not decision['allowed']:return False
    except Exception:
        # Preserve the original notifier on storage failure; never alter capture.
        decision={'allowed':True,'merged':0}
    if not _should_send(key, category=category):
        return False
    if not level and score >= 0:
        level = _level_from_score(score)
    if not level:
        level = '提示'
    level = _normalize_level(level)
    merged = _dedup_count.pop(key, 0)+decision.get('merged',0)
    lines = []
    if layout == 'multi':
        icon = _level_icon(level)
        level_tag = f"【{icon}{level}】" if level else ""
        lines.append(f"{level_tag}{title}".strip())
        if subject:
            if subject_label:
                lines.append(f"- {subject_label}: {subject}")
            else:
                lines.append(f"- 对象: {subject}")
        if src_ip:
            lines.append(f"- IP: {src_ip}")
        lines.append(f"- 时间: {now_str}")
    else:
        headline_parts = [f"{title}", level]
        if subject:
            headline_parts.append(subject)
        if src_ip:
            headline_parts.append(src_ip)
        headline_parts.append(now_str)
        lines.append(" | ".join(headline_parts))
    if summary:
        if layout == 'multi':
            _append_bullets(lines, summary)
        else:
            lines.append(summary)
    if extra:
        if layout == 'multi':
            _append_bullets(lines, extra)
        else:
            lines.append(f"详情: {extra}")
    if merged:
        if layout == 'multi':
            lines.append(f"- 合并: 最近 {merged} 条同类告警")
        else:
            lines.append(f"合并: 最近 {merged} 条同类告警")

    if ALERT_DETAIL_URL_ENABLED and ALERT_DETAIL_URL:
        url = ALERT_DETAIL_URL
        try:
            q = f"title={quote(title)}&level={quote(level)}&ip={quote(src_ip or '')}&ts={quote(now_str)}"
            url = url + ("&" if "?" in url else "?") + q
        except Exception:
            pass
        lines.append(f"详情链接: {url}")

    content = "\n".join(lines)
    try:
        if len(content.encode("utf-8")) > ALERT_MSG_MAX_BYTES:
            # 截断，保留首行与最后一行（通常是详情链接）
            first = lines[0]
            tail = lines[-1] if len(lines) > 1 else ""
            content = first
            if tail:
                content += "\n" + tail
    except Exception:
        pass
    mention_all = ALERT_MENTION_ALL and (level == '严重')
    sent = _send_text(content, mention_all=mention_all)
    try:
        event = {
            'ts': int(time.time() * 1000),
            'src_ip': src_ip,
            'sensor': _sanitize_inline(category, max_len=24) or 'general',
            'event_type': event_type or 'alert',
            'severity': level,
            'title': title,
            'summary': _sanitize_inline(summary, max_len=220),
            'detail': _sanitize_block((summary + ("\n" + extra if extra else "")).strip(), max_len=1600),
            'tags': safe_tags,
            'merged': int(merged),
            'sent': bool(sent),
            'async_mode': bool(ALERT_ASYNC_ENABLED),
        }
        _logger.info("event " + json.dumps(event, ensure_ascii=False))
    except Exception:
        _logger.debug("alert event log failed", exc_info=True)
    return sent


def alert_ssh_login_success(src_ip: str, username: str) -> bool:
    return alert_event(_title_for('ssh_login_success', "SSH 登录成功"), src_ip=src_ip, summary='', subject=username, layout='multi', subject_label='用户',
                       dedup_key=_hash_key(f"ssh_ok|{src_ip}|{username}"), category='ssh', level='高危',
                       event_type='ssh_login_success', tags=['auth', 'login_success'])


def alert_scp_capture(src_ip: str, filename: str, size: int) -> bool:
    safe_name = _sanitize_inline(filename, max_len=180)
    summary = f"大小: {size} bytes"
    return alert_event(_title_for('scp_upload', "SCP 文件上传"), src_ip=src_ip, summary=summary, subject=safe_name, layout='multi', subject_label='文件名',
                       dedup_key=_hash_key(f"scp|{src_ip}|{safe_name}"), category='ssh', level='警告',
                       event_type='scp_upload', tags=['file_upload', 'scp'])


def alert_web_high_risk(src_ip: str, method: str, path: str, score: int, signals: list, user_agent: str = '') -> bool:
    safe_method = _sanitize_inline(method, max_len=12)
    safe_path = _sanitize_inline(path, max_len=180)
    sig = ','.join(_sanitize_inline(s, max_len=30) for s in (signals or [])[:3] if s)
    summary = f"请求: {safe_method} {safe_path} (score={score})"
    extra_lines = []
    if sig:
        extra_lines.append(f"判定: {sig}")
    if user_agent:
        extra_lines.append(f"UA: {_sanitize_inline(user_agent, max_len=120)}")
    extra = "\n".join(extra_lines)
    tags = ['web', 'high_risk']
    for s in (signals or [])[:3]:
        tag = _sanitize_inline(s, max_len=24)
        if tag:
            tags.append(tag)
    return alert_event(_title_for('web_high_risk', "Web 高危请求"), src_ip=src_ip, summary=summary, extra=extra, subject=safe_path, layout='multi', subject_label='路径',
                       dedup_key=_hash_key(f"web|{src_ip}|{safe_path}|{score}"), category='web', score=score,
                       event_type='web_high_risk', tags=tags)


def alert_web_upload(src_ip: str, filename: str, size: int, result: str = '') -> bool:
    name = _sanitize_inline(filename or '(empty)', max_len=180)
    summary = f"大小: {size} bytes"
    extra = f"结果: {_sanitize_inline(result, max_len=80)}" if result else ''
    return alert_event(_title_for('web_upload', "Web 配置包上传"), src_ip=src_ip, summary=summary, extra=extra, subject=name, layout='multi', subject_label='文件名',
                       dedup_key=_hash_key(f"upload|{src_ip}|{name}"), category='web', level='警告',
                       event_type='web_upload', tags=['web', 'upload'])
