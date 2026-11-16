# -*- coding: utf-8 -*-
"""密标模块配置读取。

沿用项目统一配置口径：环境变量 > honeypot.ini > 代码默认值。
配置集中在本模块自有的 [risk_mark] 分组，因此无需改动 app_config.py 的映射表，
删除 risk_mark/ 目录即可连同配置一并移除。

对应的 honeypot.ini 片段（见 honeypot.ini.example）：

    [risk_mark]
    auto_detect_enabled = false
    auto_detect_apply = false
    repeat_window_hours = 24
    repeat_threshold = 5
    default_ttl_days = 0
"""
from env_utils import env_bool, env_int

SECTION = 'risk_mark'

# 是否启用自动风险识别（运行 detectors 中的识别器）
AUTO_DETECT_ENABLED = env_bool(
    'RISK_MARK_AUTO_DETECT_ENABLED', False, section=SECTION, key='auto_detect_enabled'
)

# 自动识别结果是否直接落标；false 时仅返回"建议"供人工确认
AUTO_DETECT_APPLY = env_bool(
    'RISK_MARK_AUTO_DETECT_APPLY', False, section=SECTION, key='auto_detect_apply'
)

# 重复高危行为识别的统计窗口（小时）与触发阈值
REPEAT_WINDOW_HOURS = env_int(
    'RISK_MARK_REPEAT_WINDOW_HOURS', 24, 1, 24 * 30, section=SECTION, key='repeat_window_hours'
)
REPEAT_THRESHOLD = env_int(
    'RISK_MARK_REPEAT_THRESHOLD', 5, 1, 100000, section=SECTION, key='repeat_threshold'
)

# 手工密标默认有效期（天）；0 表示长期有效
DEFAULT_TTL_DAYS = env_int(
    'RISK_MARK_DEFAULT_TTL_DAYS', 0, 0, 3650, section=SECTION, key='default_ttl_days'
)

# 列表查询单次返回上限
LIST_MAX_LIMIT = 500

# 一次性自动识别的最大扫描事件数
SCAN_EVENT_LIMIT = 500

__all__ = [
    'SECTION',
    'AUTO_DETECT_ENABLED',
    'AUTO_DETECT_APPLY',
    'REPEAT_WINDOW_HOURS',
    'REPEAT_THRESHOLD',
    'DEFAULT_TTL_DAYS',
    'LIST_MAX_LIMIT',
    'SCAN_EVENT_LIMIT',
]
