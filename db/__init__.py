# -*- coding: utf-8 -*-
"""
数据库对外统一入口
"""
from .connection import USE_MYSQL, get_connection, has_real_data, is_event_log_empty
from .archive import archive_old_logs_sqlite
from .geo import get_geo_info
from .event_activity import (
    log_event_activity,
    get_event_geo_data,
)
from .http_requests import (
    generate_session_id,
    calculate_threat_score,
    log_raw_request,
    update_session_track,
    get_suspicious_requests,
    get_observed_requests,
    get_session_analysis,
)
from .event_logs import (
    severity_from_score,
    log_event,
    get_event_logs,
    get_event_stats,
    get_ssh_suspicious_commands,
)

__all__ = [
    'USE_MYSQL',
    'get_connection',
    'has_real_data',
    'is_event_log_empty',
    'archive_old_logs_sqlite',
    'get_geo_info',
    'log_event_activity',
    'get_event_geo_data',
    'generate_session_id',
    'calculate_threat_score',
    'log_raw_request',
    'update_session_track',
    'get_suspicious_requests',
    'get_observed_requests',
    'get_session_analysis',
    'severity_from_score',
    'log_event',
    'get_event_logs',
    'get_event_stats',
    'get_ssh_suspicious_commands',
]


