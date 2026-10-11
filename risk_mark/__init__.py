# -*- coding: utf-8 -*-
"""密标（Risk Mark）模块：风险对象标注 + 可扩展风险识别。

密标 = 对风险对象（来源 IP / 会话 / 账号）打上持久化的「密级 + 原因 + 有效期」标记。

模块结构：
    constants.py    常量：对象类型、密级、状态
    config.py       [risk_mark] 配置读取（环境变量 > honeypot.ini > 默认值）
    log.py          模块日志器
    models.py       RiskMark / MarkProposal 数据模型与字段规范化
    store.py        持久化层（独立表 risk_mark，兼容 SQLite / MySQL）
    detectors.py    风险识别扩展点：BaseDetector + 注册表 + 内置识别器
    service.py      业务门面（上层只需依赖本模块）
    dashboard_api.py Dashboard 蓝图 /api/risk_mark/*
    static/         独立前端资源（抽屉面板）
    selftest.py     端到端自检脚本

快速上手：
    from risk_mark import service

    service.mark('ip', '1.2.3.4', 'high', '暴力破解尝试', created_by='admin')
    service.list_marks()
    service.evaluate_event(src_ip='1.2.3.4', severity='critical', event_type='sql_injection')

Dashboard 接入（详见 README.md）：
    from risk_mark.dashboard_api import register_dashboard_api
    register_dashboard_api(app, login_required=..., csrf_protect=...)

扩展新的风险识别：
    from risk_mark import detectors
    detectors.register_detector(MyDetector())
"""
from . import config, constants, detectors, models, service, store
from .detectors import (
    BaseDetector,
    DetectionContext,
    RepeatOffenderDetector,
    SeverityDetector,
    detector_registry_info,
    register_builtin_detectors,
    register_detector,
    run_detectors,
    unregister_detector,
)
from .models import MarkProposal, RiskMark
from .service import (
    apply_proposals,
    auto_scan,
    evaluate,
    evaluate_event,
    get_mark,
    list_marks,
    mark,
    marks_for_ips,
    meta,
    on_event,
    summary,
    unmark,
)

__all__ = [
    # 子模块
    'config',
    'constants',
    'detectors',
    'models',
    'service',
    'store',
    # 数据模型
    'RiskMark',
    'MarkProposal',
    'DetectionContext',
    # 业务门面
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
    # 识别器扩展点
    'BaseDetector',
    'SeverityDetector',
    'RepeatOffenderDetector',
    'register_detector',
    'unregister_detector',
    'register_builtin_detectors',
    'detector_registry_info',
    'run_detectors',
]
