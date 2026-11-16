# -*- coding: utf-8 -*-
"""风险识别扩展点（密标自动标注引擎）。

扩展方式（后续新增风险识别只需两步）：
    1. 继承 BaseDetector，实现 detect(context) -> Optional[MarkProposal]
    2. 调用 register_detector(MyDetector()) 注册（可放在本模块末尾或独立模块）

示例：
    from risk_mark.detectors import BaseDetector, DetectionContext, MarkProposal, register_detector

    class SqlInjectionDetector(BaseDetector):
        name = 'sql_injection'
        description = '检测 SQL 注入特征并建议密标'
        default_level = 'high'

        def detect(self, context):
            if 'union select' in str(context.payload or '').lower() and context.src_ip:
                return MarkProposal(target_type='ip', target_value=context.src_ip,
                                    level='high', reason='命中 SQL 注入特征', detector=self.name)
            return None

    register_detector(SqlInjectionDetector())

内置识别器默认开启，但"自动识别"总开关 [risk_mark] auto_detect_enabled 默认关闭，
因此默认不会在后台产生任何密标，行为完全可控。
"""
from abc import ABC, abstractmethod
from collections import OrderedDict
from dataclasses import dataclass, field
from threading import Lock
from typing import Any, Dict, List, Optional

from . import config as mark_config
from .constants import (
    LEVEL_CRITICAL,
    LEVEL_HIGH,
    LEVEL_LABELS,
    LEVEL_MEDIUM,
    TARGET_IP,
)
from .log import logger
from .models import MarkProposal, normalize_level, now_text
from .store import count_recent_high_events


@dataclass
class DetectionContext:
    """一次识别上下文：既可以来自单条事件，也可以来自批量扫描。"""

    source: str = ''
    event_type: str = ''
    src_ip: str = ''
    session_id: str = ''
    severity: str = ''
    payload: str = ''
    extra: Dict[str, Any] = field(default_factory=dict)
    now: str = ''

    def __post_init__(self) -> None:
        self.source = str(self.source or '').strip().lower()
        self.event_type = str(self.event_type or '').strip().lower()
        self.src_ip = str(self.src_ip or '').strip()
        self.session_id = str(self.session_id or '').strip()
        self.severity = str(self.severity or '').strip().lower()
        self.payload = str(self.payload or '')
        if not isinstance(self.extra, dict):
            self.extra = {}
        self.now = str(self.now or '').strip() or now_text()


class BaseDetector(ABC):
    """风险识别器基类：所有自动标注策略的统一入口。"""

    name: str = 'base'
    description: str = ''
    default_level: str = LEVEL_MEDIUM
    enabled: bool = True

    @abstractmethod
    def detect(self, context: DetectionContext) -> Optional[MarkProposal]:
        """返回标注建议；不命中返回 None。"""
        raise NotImplementedError

    def info(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'description': self.description,
            'default_level': self.default_level,
            'default_level_label': LEVEL_LABELS.get(self.default_level, self.default_level),
            'enabled': bool(self.enabled),
        }


_DETECTORS: "OrderedDict[str, BaseDetector]" = OrderedDict()
_DETECTOR_LOCK = Lock()


def register_detector(detector: BaseDetector, override: bool = False) -> BaseDetector:
    """注册识别器；同名且 override=False 时保留已有实现。"""
    if not isinstance(detector, BaseDetector):
        raise TypeError('detector 必须是 BaseDetector 的子类实例')
    name = str(getattr(detector, 'name', '') or '').strip()
    if not name:
        raise ValueError('detector.name 不能为空')
    with _DETECTOR_LOCK:
        if name in _DETECTORS and not override:
            return _DETECTORS[name]
        _DETECTORS[name] = detector
    return detector


def unregister_detector(name: str) -> bool:
    with _DETECTOR_LOCK:
        return _DETECTORS.pop(str(name or '').strip(), None) is not None


def get_detectors(only_enabled: bool = True) -> List[BaseDetector]:
    with _DETECTOR_LOCK:
        items = list(_DETECTORS.values())
    return [d for d in items if d.enabled] if only_enabled else items


def detector_registry_info() -> List[Dict[str, Any]]:
    return [d.info() for d in get_detectors(only_enabled=False)]


def run_detectors(context: DetectionContext) -> List[MarkProposal]:
    """依次运行全部启用的识别器；单个识别器异常不影响其余识别器。"""
    proposals: List[MarkProposal] = []
    for detector in get_detectors():
        try:
            proposal = detector.detect(context)
        except Exception as e:  # 单个策略失败不阻断整体识别
            logger.debug(f"识别器 {detector.name} 执行失败: {e}")
            continue
        if isinstance(proposal, MarkProposal) and proposal.target_value:
            proposals.append(proposal)
    return proposals


# ============================================
# 内置识别器
# ============================================
class SeverityDetector(BaseDetector):
    """单条高危事件即建议密标（无状态、开销极低）。"""

    name = 'severity'
    description = '单条 high/critical 事件即建议密标该来源 IP'
    default_level = LEVEL_HIGH

    def detect(self, context: DetectionContext) -> Optional[MarkProposal]:
        severity = normalize_level(context.severity) if context.severity else ''
        if severity not in (LEVEL_HIGH, LEVEL_CRITICAL):
            return None
        if not context.src_ip:
            return None
        return MarkProposal(
            target_type=TARGET_IP,
            target_value=context.src_ip,
            level=severity,
            reason=f"命中 {severity} 级事件：{context.event_type or 'unknown'}",
            detector=self.name,
        )


class RepeatOffenderDetector(BaseDetector):
    """统计窗口内同一 IP 的高危事件累计次数，达到阈值即建议密标。"""

    name = 'repeat_offender'
    description = '窗口内同一来源 IP 高危事件累计达到阈值'
    default_level = LEVEL_HIGH

    def __init__(self, window_hours: Optional[int] = None, threshold: Optional[int] = None):
        try:
            self.window_hours = int(window_hours) if window_hours else int(mark_config.REPEAT_WINDOW_HOURS)
        except (TypeError, ValueError):
            self.window_hours = 24
        try:
            self.threshold = int(threshold) if threshold else int(mark_config.REPEAT_THRESHOLD)
        except (TypeError, ValueError):
            self.threshold = 5

    def detect(self, context: DetectionContext) -> Optional[MarkProposal]:
        if not context.src_ip:
            return None
        count = count_recent_high_events(context.src_ip, self.window_hours)
        if count < self.threshold:
            return None
        return MarkProposal(
            target_type=TARGET_IP,
            target_value=context.src_ip,
            level=self.default_level,
            reason=f"近 {self.window_hours} 小时高危事件 {count} 次（阈值 {self.threshold}）",
            detector=self.name,
            extra={'window_hours': self.window_hours, 'threshold': self.threshold, 'count': count},
        )


def register_builtin_detectors() -> None:
    """注册内置识别器（幂等）。"""
    register_detector(SeverityDetector())
    register_detector(RepeatOffenderDetector())


register_builtin_detectors()

__all__ = [
    'DetectionContext',
    'BaseDetector',
    'SeverityDetector',
    'RepeatOffenderDetector',
    'register_detector',
    'unregister_detector',
    'get_detectors',
    'detector_registry_info',
    'run_detectors',
    'register_builtin_detectors',
]
