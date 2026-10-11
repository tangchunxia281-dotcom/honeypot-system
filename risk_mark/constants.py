# -*- coding: utf-8 -*-
"""密标（Risk Mark）模块常量定义。

密标 = 对风险对象（来源 IP / 会话 / 账号）打上持久化的「密级 + 原因 + 有效期」标记，
用于在态势大屏与事件列表中快速锁定重点关注目标。

本模块独立于 db/、dashboard/、web_honeypot/、ssh_honeypot/ 等既有代码：
删除整个 risk_mark/ 目录即可整体停用，不影响其余功能。
"""

# ---------- 标注对象类型（可扩展：如 domain、fingerprint） ----------
TARGET_IP = 'ip'
TARGET_SESSION = 'session'
TARGET_ACCOUNT = 'account'
TARGET_TYPES = (TARGET_IP, TARGET_SESSION, TARGET_ACCOUNT)
TARGET_TYPE_LABELS = {
    TARGET_IP: '来源 IP',
    TARGET_SESSION: '会话',
    TARGET_ACCOUNT: '账号',
}

# ---------- 密级（与 event_log.severity 口径保持一致，便于统一统计与展示） ----------
LEVEL_LOW = 'low'
LEVEL_MEDIUM = 'medium'
LEVEL_HIGH = 'high'
LEVEL_CRITICAL = 'critical'
LEVELS = (LEVEL_LOW, LEVEL_MEDIUM, LEVEL_HIGH, LEVEL_CRITICAL)
LEVEL_ORDER = {
    LEVEL_LOW: 0,
    LEVEL_MEDIUM: 1,
    LEVEL_HIGH: 2,
    LEVEL_CRITICAL: 3,
}
LEVEL_LABELS = {
    LEVEL_LOW: '低危',
    LEVEL_MEDIUM: '中危',
    LEVEL_HIGH: '高危',
    LEVEL_CRITICAL: '严重',
}

# ---------- 状态 ----------
STATUS_ACTIVE = 'active'
STATUS_EXPIRED = 'expired'
STATUSES = (STATUS_ACTIVE, STATUS_EXPIRED)
STATUS_LABELS = {
    STATUS_ACTIVE: '生效中',
    STATUS_EXPIRED: '已过期',
}

# ---------- 标注来源 ----------
SOURCE_MANUAL = 'manual'                 # 人工在管理端手工标注
SOURCE_DETECTOR_PREFIX = 'detector:'     # 自动识别器写入，完整值形如 detector:severity

# ---------- 数据表 ----------
TABLE_NAME = 'risk_mark'

# ---------- 字段长度与容量上限 ----------
MAX_TARGET_VALUE = 128
MAX_REASON = 500
MAX_MARK_CODE = 64
MAX_OPERATOR = 64
MAX_EXTRA_JSON = 2000
MAX_BATCH_TARGETS = 500

__all__ = [
    'TARGET_IP',
    'TARGET_SESSION',
    'TARGET_ACCOUNT',
    'TARGET_TYPES',
    'TARGET_TYPE_LABELS',
    'LEVEL_LOW',
    'LEVEL_MEDIUM',
    'LEVEL_HIGH',
    'LEVEL_CRITICAL',
    'LEVELS',
    'LEVEL_ORDER',
    'LEVEL_LABELS',
    'STATUS_ACTIVE',
    'STATUS_EXPIRED',
    'STATUSES',
    'STATUS_LABELS',
    'SOURCE_MANUAL',
    'SOURCE_DETECTOR_PREFIX',
    'TABLE_NAME',
    'MAX_TARGET_VALUE',
    'MAX_REASON',
    'MAX_MARK_CODE',
    'MAX_OPERATOR',
    'MAX_EXTRA_JSON',
    'MAX_BATCH_TARGETS',
]
