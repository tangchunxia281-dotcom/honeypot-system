# -*- coding: utf-8 -*-
"""密标数据模型与字段规范化。

包含两类对象：
- RiskMark      : 落库的一条密标记录（密级 + 原因 + 有效期 + 来源）
- MarkProposal  : 风险识别器输出的"标注建议"，尚未落库

所有外部输入都会先经过本模块的规范化函数，保证入库数据干净、可控。
"""
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

from .constants import (
    LEVEL_CRITICAL,
    LEVEL_HIGH,
    LEVEL_LABELS,
    LEVEL_LOW,
    LEVEL_MEDIUM,
    LEVEL_ORDER,
    LEVELS,
    MAX_EXTRA_JSON,
    MAX_MARK_CODE,
    MAX_OPERATOR,
    MAX_REASON,
    MAX_TARGET_VALUE,
    SOURCE_MANUAL,
    STATUS_ACTIVE,
    STATUS_LABELS,
    STATUSES,
    TARGET_IP,
    TARGET_TYPES,
)

TIME_FMT = '%Y-%m-%d %H:%M:%S'

_LEVEL_ALIAS = {
    '低': LEVEL_LOW, '低危': LEVEL_LOW, '提示': LEVEL_LOW, 'info': LEVEL_LOW,
    '中': LEVEL_MEDIUM, '中危': LEVEL_MEDIUM, '关注': LEVEL_MEDIUM,
    'warn': LEVEL_MEDIUM, 'warning': LEVEL_MEDIUM, 'med': LEVEL_MEDIUM,
    '高': LEVEL_HIGH, '高危': LEVEL_HIGH, '机密': LEVEL_HIGH,
    '严重': LEVEL_CRITICAL, '紧急': LEVEL_CRITICAL, '绝密': LEVEL_CRITICAL, 'crit': LEVEL_CRITICAL,
}

_TARGET_ALIAS = {
    'ip': 'ip', '来源ip': 'ip', '地址': 'ip',
    'session': 'session', '会话': 'session', '会话id': 'session',
    'account': 'account', '账号': 'account', '用户名': 'account', 'user': 'account',
}


def now_text() -> str:
    """当前时间文本（与 event_log 口径一致，统一按北京时间落库）。"""
    try:
        from zoneinfo import ZoneInfo
        return datetime.now(ZoneInfo('Asia/Shanghai')).strftime(TIME_FMT)
    except Exception:
        return datetime.now().strftime(TIME_FMT)


def _clip(value, max_len: int) -> str:
    text = str(value or '').strip()
    return text if len(text) <= max_len else text[:max_len]


def normalize_target_type(value) -> str:
    text = str(value or '').strip().lower()
    if text in TARGET_TYPES:
        return text
    return _TARGET_ALIAS.get(text, TARGET_IP)


def normalize_level(value) -> str:
    text = str(value or '').strip().lower()
    if text in LEVELS:
        return text
    return _LEVEL_ALIAS.get(text, LEVEL_MEDIUM)


def normalize_status(value) -> str:
    text = str(value or '').strip().lower()
    return text if text in STATUSES else STATUS_ACTIVE


def normalize_target_value(value, target_type: str = TARGET_IP) -> str:
    text = str(value or '').strip()
    if normalize_target_type(target_type) == TARGET_IP:
        # 兼容 [::1] / :port 等写法
        text = text.strip('[]').strip()
    return _clip(text, MAX_TARGET_VALUE)


def parse_expires(value) -> str:
    """把多种时间输入规范为 'YYYY-MM-DD HH:MM:SS'；无法识别则返回空串（表示长期有效）。"""
    if value in (None, ''):
        return ''
    if isinstance(value, datetime):
        return value.strftime(TIME_FMT)
    text = str(value).strip()
    if not text:
        return ''
    for fmt in (TIME_FMT, '%Y-%m-%dT%H:%M:%S', '%Y-%m-%d %H:%M', '%Y-%m-%d'):
        try:
            return datetime.strptime(text, fmt).strftime(TIME_FMT)
        except ValueError:
            continue
    return ''


def default_expires_at(days) -> str:
    """按天数生成有效期；days <= 0 表示长期有效。"""
    try:
        days_v = int(days)
    except (TypeError, ValueError):
        days_v = 0
    if days_v <= 0:
        return ''
    return (datetime.now() + timedelta(days=days_v)).strftime(TIME_FMT)


def is_expired(expires_at: str, now: Optional[str] = None) -> bool:
    text = str(expires_at or '').strip()
    if not text:
        return False
    current = str(now or now_text())
    return text <= current


def dump_extra(extra) -> str:
    if not extra:
        return ''
    if isinstance(extra, str):
        text = extra.strip()
    else:
        try:
            text = json.dumps(extra, ensure_ascii=False)
        except (TypeError, ValueError):
            text = str(extra)
    return _clip(text, MAX_EXTRA_JSON)


def load_extra(raw) -> Dict[str, Any]:
    if isinstance(raw, dict):
        return dict(raw)
    text = str(raw or '').strip()
    if not text:
        return {}
    try:
        parsed = json.loads(text)
    except (TypeError, ValueError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


@dataclass
class RiskMark:
    """一条密标记录。

    target_type + target_value 唯一确定标注对象（数据库层有唯一索引），
    重复标注同一对象时执行覆盖更新，不会产生多条记录。
    """

    target_type: str = TARGET_IP
    target_value: str = ''
    level: str = LEVEL_MEDIUM
    reason: str = ''
    source: str = SOURCE_MANUAL
    status: str = STATUS_ACTIVE
    mark_code: str = ''
    created_by: str = ''
    created_at: str = ''
    updated_at: str = ''
    expires_at: str = ''
    extra: Dict[str, Any] = field(default_factory=dict)
    mark_id: Optional[int] = None

    def __post_init__(self) -> None:
        self.target_type = normalize_target_type(self.target_type)
        self.target_value = normalize_target_value(self.target_value, self.target_type)
        self.level = normalize_level(self.level)
        self.status = normalize_status(self.status)
        self.reason = _clip(self.reason, MAX_REASON)
        self.mark_code = _clip(self.mark_code, MAX_MARK_CODE)
        self.created_by = _clip(self.created_by, MAX_OPERATOR)
        self.source = _clip(self.source, 64).lower() or SOURCE_MANUAL
        self.created_at = str(self.created_at or '').strip() or now_text()
        self.updated_at = str(self.updated_at or '').strip() or self.created_at
        self.expires_at = parse_expires(self.expires_at)
        if not isinstance(self.extra, dict):
            self.extra = load_extra(self.extra)

    # ---------- 校验 ----------
    def validate(self) -> None:
        """校验必填项，非法时抛出 ValueError（由上层转成 4xx 提示）。"""
        if not str(self.target_value or '').strip():
            raise ValueError('标注对象不能为空')
        if self.target_type not in TARGET_TYPES:
            raise ValueError('不支持的对象类型: %s' % self.target_type)
        if self.level not in LEVELS:
            raise ValueError('不支持的密级: %s' % self.level)

    # ---------- 序列化 ----------
    def to_dict(self) -> Dict[str, Any]:
        payload = {
            'id': self.mark_id,
            'target_type': self.target_type,
            'target_value': self.target_value,
            'level': self.level,
            'level_label': LEVEL_LABELS.get(self.level, self.level),
            'mark_code': self.mark_code,
            'reason': self.reason,
            'source': self.source,
            'status': self.status,
            'status_label': STATUS_LABELS.get(self.status, self.status),
            'created_by': self.created_by,
            'created_at': self.created_at,
            'updated_at': self.updated_at,
            'expires_at': self.expires_at,
            'expired': is_expired(self.expires_at),
            'extra': dict(self.extra or {}),
        }
        return payload


@dataclass
class MarkProposal:
    """风险识别器给出的标注建议（未落库）。"""

    target_type: str = TARGET_IP
    target_value: str = ''
    level: str = LEVEL_MEDIUM
    reason: str = ''
    detector: str = ''
    extra: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.target_type = normalize_target_type(self.target_type)
        self.target_value = normalize_target_value(self.target_value, self.target_type)
        self.level = normalize_level(self.level)
        self.reason = _clip(self.reason, MAX_REASON)
        self.detector = _clip(self.detector, 64)
        if not isinstance(self.extra, dict):
            self.extra = load_extra(self.extra)

    @property
    def key(self) -> str:
        return '%s:%s' % (self.target_type, self.target_value)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'target_type': self.target_type,
            'target_value': self.target_value,
            'level': self.level,
            'level_label': LEVEL_LABELS.get(self.level, self.level),
            'reason': self.reason,
            'detector': self.detector,
            'extra': dict(self.extra or {}),
        }


def row_to_dict(row) -> Optional[Dict[str, Any]]:
    """把数据库行统一转成对外的密标字典。"""
    if not row:
        return None
    if not isinstance(row, dict):
        return None
    item = dict(row)
    try:
        item['id'] = int(item.get('id')) if item.get('id') is not None else None
    except (TypeError, ValueError):
        item['id'] = None
    item['target_type'] = normalize_target_type(item.get('target_type'))
    item['target_value'] = str(item.get('target_value') or '')
    item['level'] = normalize_level(item.get('level'))
    item['level_label'] = LEVEL_LABELS.get(item['level'], item['level'])
    item['status'] = normalize_status(item.get('status'))
    item['status_label'] = STATUS_LABELS.get(item['status'], item['status'])
    item['mark_code'] = str(item.get('mark_code') or '')
    item['reason'] = str(item.get('reason') or '')
    item['source'] = str(item.get('source') or SOURCE_MANUAL)
    item['created_by'] = str(item.get('created_by') or '')
    item['created_at'] = str(item.get('created_at') or '')
    item['updated_at'] = str(item.get('updated_at') or '')
    item['expires_at'] = str(item.get('expires_at') or '')
    item['expired'] = is_expired(item['expires_at'])
    item['extra'] = load_extra(item.get('extra'))
    return item


def sort_key(item: Dict[str, Any]):
    """列表排序：先按密级高低，再按更新时间倒序。"""
    data = item if isinstance(item, dict) else {}
    level_rank = LEVEL_ORDER.get(normalize_level(data.get('level')), 0)
    return (level_rank, str(data.get('updated_at') or ''))


__all__ = [
    'TIME_FMT',
    'RiskMark',
    'MarkProposal',
    'now_text',
    'normalize_target_type',
    'normalize_level',
    'normalize_status',
    'normalize_target_value',
    'parse_expires',
    'default_expires_at',
    'is_expired',
    'dump_extra',
    'load_extra',
    'row_to_dict',
    'sort_key',
]
