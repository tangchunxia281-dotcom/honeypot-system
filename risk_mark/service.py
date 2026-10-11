# -*- coding: utf-8 -*-
"""密标业务门面。

对上层（Dashboard API、其他蜜罐模块）暴露稳定的高层接口，
屏蔽 store（持久化）与 detectors（识别器）的实现细节。
"""
import json
from typing import Any, Dict, List, Optional

from . import config as mark_config
from .constants import (
    LEVEL_LABELS,
    LEVEL_ORDER,
    LEVELS,
    SOURCE_DETECTOR_PREFIX,
    SOURCE_MANUAL,
    STATUS_ACTIVE,
    STATUS_LABELS,
    STATUSES,
    TARGET_IP,
    TARGET_TYPE_LABELS,
    TARGET_TYPES,
)
from .detectors import DetectionContext, detector_registry_info, run_detectors
from .log import logger
from .models import (
    MarkProposal,
    RiskMark,
    default_expires_at,
    normalize_level,
    row_to_dict,
    sort_key,
)
from .store import (
    count_by_level,
    count_total,
    delete_mark,
    expire_due_marks,
    get_mark as _store_get_mark,
    get_marks_map as _store_get_marks_map,
    list_marks as _store_list_marks,
    upsert_mark,
)

# ============================================
# 密标增删查
# ============================================
def mark(
    target_type: str = TARGET_IP,
    target_value: str = '',
    level: str = 'medium',
    reason: str = '',
    *,
    created_by: str = '',
    mark_code: str = '',
    expires_at: str = '',
    ttl_days: Optional[int] = None,
    source: str = SOURCE_MANUAL,
    extra=None,
) -> Dict[str, Any]:
    """新增或覆盖一条密标。

    Raises:
        ValueError: 入参非法（如标注对象为空）。
        RuntimeError: 持久化失败。
    """
    ttl = mark_config.DEFAULT_TTL_DAYS if ttl_days is None else ttl_days
    record = RiskMark(
        target_type=target_type,
        target_value=target_value,
        level=level,
        reason=reason,
        source=source,
        mark_code=mark_code,
        created_by=created_by,
        expires_at=str(expires_at or '').strip() or default_expires_at(ttl),
        extra=extra or {},
    )
    record.validate()
    mark_id = upsert_mark(record)
    if mark_id is None:
        raise RuntimeError('密标写入失败')
    record.mark_id = mark_id
    return record.to_dict()


def unmark(mark_id=None, target_type: str = '', target_value: str = '') -> int:
    """移除密标，返回删除行数。"""
    return delete_mark(mark_id=mark_id, target_type=target_type, target_value=target_value)


def get_mark(target_type: str, target_value: str) -> Optional[Dict[str, Any]]:
    return row_to_dict(_store_get_mark(str(target_type or '').strip().lower(), str(target_value or '').strip()))


def marks_for_ips(ips) -> Dict[str, Dict[str, Any]]:
    """批量获取多个 IP 的密标，供事件列表快速打标。"""
    rows = _store_get_marks_map(TARGET_IP, ips)
    out: Dict[str, Dict[str, Any]] = {}
    for key, row in (rows or {}).items():
        item = row_to_dict(row)
        if item:
            out[key] = item
    return out


def list_marks(
    target_type: str = '',
    level: str = '',
    status: str = STATUS_ACTIVE,
    keyword: str = '',
    limit: int = 200,
    offset: int = 0,
) -> Dict[str, Any]:
    """分页查询密标，附带密级统计。"""
    expire_due_marks()  # 懒过期：查询前先结算已到期的密标
    rows, total = _store_list_marks(
        target_type=target_type, level=level, status=status,
        keyword=keyword, limit=limit, offset=offset,
    )
    items = [row_to_dict(r) for r in (rows or [])]
    items = [i for i in items if i]
    items.sort(key=sort_key, reverse=True)
    return {
        'items': items,
        'total': int(total or 0),
        'stats': count_by_level(STATUS_ACTIVE),
    }


def summary() -> Dict[str, Any]:
    """密标总览：数量、密级分布、识别器清单与配置，用于面板头部。"""
    return {
        'total': count_total(STATUS_ACTIVE),
        'by_level': count_by_level(STATUS_ACTIVE),
        'detectors': detector_registry_info(),
        'config': {
            'auto_detect_enabled': bool(mark_config.AUTO_DETECT_ENABLED),
            'auto_detect_apply': bool(mark_config.AUTO_DETECT_APPLY),
            'repeat_window_hours': int(mark_config.REPEAT_WINDOW_HOURS),
            'repeat_threshold': int(mark_config.REPEAT_THRESHOLD),
            'default_ttl_days': int(mark_config.DEFAULT_TTL_DAYS),
        },
    }


def meta() -> Dict[str, Any]:
    """枚举元数据，供前端渲染下拉项。"""
    return {
        'target_types': [{'value': t, 'label': TARGET_TYPE_LABELS.get(t, t)} for t in TARGET_TYPES],
        'levels': [{'value': lv, 'label': LEVEL_LABELS.get(lv, lv)} for lv in LEVELS],
        'statuses': [{'value': s, 'label': STATUS_LABELS.get(s, s)} for s in STATUSES],
        'detectors': detector_registry_info(),
        'config': summary()['config'],
    }


# ============================================
# 风险识别
# ============================================
def _coerce_context(context) -> DetectionContext:
    if isinstance(context, DetectionContext):
        return context
    data = context if isinstance(context, dict) else {}
    extra = data.get('extra')
    if isinstance(extra, str):
        try:
            extra = json.loads(extra)
        except (TypeError, ValueError):
            extra = {}
    return DetectionContext(
        source=data.get('source', ''),
        event_type=data.get('event_type', ''),
        src_ip=data.get('src_ip', ''),
        session_id=data.get('session_id', ''),
        severity=data.get('severity', ''),
        payload=data.get('payload', ''),
        extra=extra if isinstance(extra, dict) else {},
        now=data.get('timestamp', ''),
    )


def _coerce_proposals(proposals) -> List[MarkProposal]:
    out: List[MarkProposal] = []
    for item in proposals or []:
        if isinstance(item, MarkProposal):
            out.append(item)
        elif isinstance(item, dict):
            out.append(MarkProposal(
                target_type=item.get('target_type', TARGET_IP),
                target_value=item.get('target_value', ''),
                level=item.get('level', 'medium'),
                reason=item.get('reason', ''),
                detector=item.get('detector', ''),
                extra=item.get('extra') or {},
            ))
    return [p for p in out if p.target_value]


def evaluate(context) -> List[Dict[str, Any]]:
    """运行全部识别器，返回标注建议（不落库）。"""
    ctx = _coerce_context(context)
    return [p.to_dict() for p in run_detectors(ctx)]


def evaluate_event(
    source: str = '',
    event_type: str = '',
    src_ip: str = '',
    severity: str = '',
    session_id: str = '',
    payload: str = '',
    extra=None,
) -> List[Dict[str, Any]]:
    """按单条事件要素运行识别器，返回标注建议。"""
    return evaluate(DetectionContext(
        source=source, event_type=event_type, src_ip=src_ip,
        severity=severity, session_id=session_id, payload=payload, extra=extra or {},
    ))


def apply_proposals(proposals, created_by: str = 'auto') -> List[Dict[str, Any]]:
    """把识别建议落库；同对象取最高密级，且不覆盖级别更高的已有密标。"""
    merged: Dict[str, MarkProposal] = {}
    for proposal in _coerce_proposals(proposals):
        current = merged.get(proposal.key)
        if current is None or LEVEL_ORDER.get(proposal.level, 0) >= LEVEL_ORDER.get(current.level, 0):
            merged[proposal.key] = proposal

    applied: List[Dict[str, Any]] = []
    for proposal in merged.values():
        existing = _store_get_mark(proposal.target_type, proposal.target_value)
        if existing and str(existing.get('status') or '').lower() == STATUS_ACTIVE:
            existing_level = normalize_level(existing.get('level'))
            # 已有不低于当前级别的密标（含人工标注）时，保留原结论
            if LEVEL_ORDER.get(existing_level, 0) >= LEVEL_ORDER.get(proposal.level, 0):
                continue
        try:
            applied.append(mark(
                target_type=proposal.target_type,
                target_value=proposal.target_value,
                level=proposal.level,
                reason=proposal.reason,
                source=f"{SOURCE_DETECTOR_PREFIX}{proposal.detector}" if proposal.detector else SOURCE_DETECTOR_PREFIX,
                created_by=created_by,
                extra=proposal.extra,
            ))
        except ValueError as e:
            logger.debug(f"跳过非法识别结果 {proposal.key}: {e}")
        except Exception as e:
            logger.debug(f"识别结果落标失败 {proposal.key}: {e}")
    return applied


def _iter_recent_events(hours: int, limit: int) -> List[Dict[str, Any]]:
    try:
        from db import get_event_logs
    except Exception as e:  # 数据库层不可用时不影响密标本身
        logger.error(f"加载事件日志失败: {e}")
        return []
    try:
        rows = get_event_logs(limit=limit, offset=0, hours=hours) or []
    except Exception as e:
        logger.error(f"查询事件日志失败: {e}")
        return []
    return [r for r in rows if isinstance(r, dict)]


def auto_scan(hours: int = 24, limit: Optional[int] = None, apply: Optional[bool] = None,
              created_by: str = 'auto') -> Dict[str, Any]:
    """对最近事件批量运行识别器。

    Args:
        hours: 事件时间窗口（小时）。
        limit: 最多扫描的事件条数。
        apply: 是否落库；None 时取配置 [risk_mark] auto_detect_apply。
        created_by: 落标操作者标识。
    """
    try:
        hours_v = max(1, min(int(hours), 24 * 30))
    except (TypeError, ValueError):
        hours_v = 24
    try:
        limit_v = int(limit) if limit else mark_config.SCAN_EVENT_LIMIT
    except (TypeError, ValueError):
        limit_v = mark_config.SCAN_EVENT_LIMIT
    limit_v = max(1, min(limit_v, mark_config.SCAN_EVENT_LIMIT))

    events = _iter_recent_events(hours_v, limit_v)
    proposals: List[Dict[str, Any]] = []
    for event in events:
        for proposal in evaluate(event):
            proposals.append(proposal)

    apply_enabled = bool(mark_config.AUTO_DETECT_APPLY) if apply is None else bool(apply)
    applied = apply_proposals(proposals, created_by=created_by) if (apply_enabled and proposals) else []
    return {
        'scanned': len(events),
        'proposals': proposals,
        'applied': applied,
        'apply_enabled': apply_enabled,
        'auto_detect_enabled': bool(mark_config.AUTO_DETECT_ENABLED),
        'hours': hours_v,
    }


def on_event(
    source: str = '',
    event_type: str = '',
    src_ip: str = '',
    severity: str = '',
    session_id: str = '',
    payload: str = '',
    extra=None,
    apply: Optional[bool] = None,
) -> Dict[str, Any]:
    """事件写入后的可选钩子。

    设计为异常安全：任何异常都会被吞掉并降级为空结果，
    因此可以放心在蜜罐事件链路中调用而不影响主流程。

    Returns:
        {'proposals': [...], 'applied': [...]}
    """
    empty = {'proposals': [], 'applied': []}
    try:
        if not mark_config.AUTO_DETECT_ENABLED:
            return empty
        proposals = evaluate_event(
            source=source, event_type=event_type, src_ip=src_ip, severity=severity,
            session_id=session_id, payload=payload, extra=extra,
        )
        if not proposals:
            return empty
        apply_enabled = bool(mark_config.AUTO_DETECT_APPLY) if apply is None else bool(apply)
        applied = apply_proposals(proposals) if apply_enabled else []
        return {'proposals': proposals, 'applied': applied}
    except Exception as e:
        logger.debug(f"密标事件钩子执行失败: {e}")
        return empty


__all__ = [
    'mark',
    'unmark',
    'get_mark',
    'marks_for_ips',
    'list_marks',
    'summary',
    'meta',
    'evaluate',
    'evaluate_event',
    'apply_proposals',
    'auto_scan',
    'on_event',
]
