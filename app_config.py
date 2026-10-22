# -*- coding: utf-8 -*-
"""
应用配置模块

统一读取顺序：环境变量 > 根目录 honeypot.ini > 代码默认值。
保留原有 Config/DevelopmentConfig/ProductionConfig/config 入口，兼容现有 Flask 配置方式。
"""
import configparser
import os
from typing import Iterable, Optional

# 获取项目根目录
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_ENV_NAME = 'HONEYPOT_CONFIG'
DEFAULT_CONFIG_FILE = os.path.join(BASE_DIR, 'honeypot.ini')
SECRET_KEY_FILE = os.path.join(BASE_DIR, '.secret_key')

_TRUE_VALUES = {'1', 'true', 'yes', 'on', 'y'}
_FALSE_VALUES = {'0', 'false', 'no', 'off', 'n'}


def _resolve_config_path(raw_path: str = '') -> str:
    path = str(raw_path or '').strip() or DEFAULT_CONFIG_FILE
    if not os.path.isabs(path):
        path = os.path.join(BASE_DIR, path)
    return os.path.abspath(path)


CONFIG_PATH = _resolve_config_path(os.environ.get(CONFIG_ENV_NAME, ''))
_CONFIG = configparser.ConfigParser(interpolation=None)
_CONFIG.optionxform = str.lower
CONFIG_LOADED = False
CONFIG_READ_FILES = []
if os.path.exists(CONFIG_PATH):
    CONFIG_READ_FILES = _CONFIG.read(CONFIG_PATH, encoding='utf-8')
    CONFIG_LOADED = bool(CONFIG_READ_FILES)
    os.environ.setdefault(CONFIG_ENV_NAME, CONFIG_PATH)

# 环境变量到根目录配置项的映射。环境变量仍优先，用于兼容旧脚本和临时覆盖。
_ENV_CONFIG_MAP = {
    # app / startup
    'PRODUCTION_MODE': ('app', 'production_mode'),
    'SECRET_KEY': ('app', 'secret_key'),
    'LOG_LEVEL': ('app', 'log_level'),
    'LOG_MAX_BYTES': ('app', 'log_max_bytes'),
    'LOG_BACKUP_COUNT': ('app', 'log_backup_count'),
    'SHOW_CREDENTIAL_LOGS': ('app', 'show_credential_logs'),
    'SHOW_SUMMARY_CREDS': ('app', 'show_summary_creds'),
    'SHOW_DEMO_CREDENTIALS': ('app', 'show_demo_credentials'),
    'EMIT_CREDENTIAL_LINES': ('app', 'emit_credential_lines'),
    'SUMMARY_CRED_WAIT': ('app', 'summary_cred_wait'),
    'SUMMARY_CRED_WAIT_MAX': ('app', 'summary_cred_wait_max'),
    'MAX_RESTART_ATTEMPTS': ('app', 'max_restart_attempts'),
    'RESTART_DELAY': ('app', 'restart_delay'),

    # real dashboard admin
    'ADMIN_USER': ('admin', 'user'),
    'ADMIN_PASS': ('admin', 'password'),

    # database
    'DB_TYPE': ('database', 'type'),
    'USE_MYSQL': ('database', 'use_mysql'),
    'DB_PATH': ('database', 'path'),
    'DB_HOST': ('database', 'host'),
    'DB_PORT': ('database', 'port'),
    'DB_USER': ('database', 'user'),
    'DB_PASS': ('database', 'password'),
    'DB_NAME': ('database', 'name'),
    'DB_CHARSET': ('database', 'charset'),
    'SQLITE_BUSY_RETRY': ('database', 'sqlite_busy_retry'),
    'SQLITE_BUSY_BACKOFF': ('database', 'sqlite_busy_backoff'),
    'SESSION_ID_WINDOW_SECONDS': ('database', 'session_id_window_seconds'),
    'HAS_REAL_CACHE_TTL': ('database', 'has_real_cache_ttl'),

     # AI request-level attack inference service
    'AI_XSS_ENABLED': ('ai', 'enabled'),
    'AI_XSS_URL': ('ai', 'url'),
    'AI_XSS_INFO_URL': ('ai', 'info_url'),
    'AI_XSS_TIMEOUT': ('ai', 'timeout'),
    # Deprecated compatibility key. The v2 detect API uses ai_points,
    # not a confidence threshold, to participate in honeypot scoring.
    'AI_XSS_THRESHOLD': ('ai', 'threshold'),
    'AI_XSS_TEXT_MAX': ('ai', 'text_max'),
    'AI_XSS_FAILURE_THRESHOLD': ('ai', 'failure_threshold'),
    'AI_XSS_BACKOFF_SECONDS': ('ai', 'backoff_seconds'),
    'AI_XSS_MODEL_INFO_TTL': ('ai', 'model_info_ttl'),

    # services
    'SSH_HOST': ('services.ssh', 'host'),
    'SSH_PORT': ('services.ssh', 'port'),
    'SSH_INTERNAL_IP': ('services.ssh', 'internal_ip'),
    'SSH_MAX_WORKERS': ('services.ssh', 'max_workers'),
    'SSH_MAX_AUTH_TRIES': ('services.ssh', 'max_auth_tries'),
    'SSH_MAX_CONCURRENT_CONNECTIONS': ('services.ssh', 'max_concurrent_connections'),
    'SSH_MAX_CONNECTIONS_PER_IP': ('services.ssh', 'max_connections_per_ip'),
    'SSH_CONNECTION_TIMEOUT': ('services.ssh', 'connection_timeout'),
    'SSH_AUTH_TIMEOUT': ('services.ssh', 'auth_timeout'),
    'SUDO_CACHE_TTL': ('services.ssh', 'sudo_cache_ttl'),
    'SSH_BRUTEFORCE_BAN_ENABLED': ('services.ssh', 'bruteforce_ban_enabled'),
    'SSH_BRUTEFORCE_WINDOW_SECONDS': ('services.ssh', 'bruteforce_window_seconds'),
    'SSH_BRUTEFORCE_MAX_FAILS': ('services.ssh', 'bruteforce_max_fails'),
    'SSH_BRUTEFORCE_BASE_BAN_SECONDS': ('services.ssh', 'bruteforce_base_ban_seconds'),
    'SSH_BRUTEFORCE_MAX_BAN_SECONDS': ('services.ssh', 'bruteforce_max_ban_seconds'),
    'SSH_BRUTEFORCE_GC_INTERVAL_SECONDS': ('services.ssh', 'bruteforce_gc_interval_seconds'),
    'SSH_BRUTEFORCE_STALE_KEEP_SECONDS': ('services.ssh', 'bruteforce_stale_keep_seconds'),
    'SSH_SCAN_DETECT_ENABLED': ('services.ssh', 'scan_detect_enabled'),
    'SSH_SCAN_WINDOW_SECONDS': ('services.ssh', 'scan_window_seconds'),
    'SSH_SCAN_CONN_THRESHOLD': ('services.ssh', 'scan_conn_threshold'),
    'SSH_SCAN_ALERT_COOLDOWN_SECONDS': ('services.ssh', 'scan_alert_cooldown_seconds'),
    'SSH_SCAN_STALE_KEEP_SECONDS': ('services.ssh', 'scan_stale_keep_seconds'),

    # 多协议蜜罐：数据库协议（MySQL / Redis）
    'DB_HONEYPOT_ENABLED': ('services.database', 'enabled'),
    'DB_HONEYPOT_HOST': ('services.database', 'host'),
    'MYSQL_PORT': ('services.database', 'mysql_port'),
    'REDIS_PORT': ('services.database', 'redis_port'),
    # 多协议蜜罐：文件共享协议（FTP / SMB 预留）
    'FILE_HONEYPOT_ENABLED': ('services.file', 'enabled'),
    'FTP_HOST': ('services.file', 'host'),
    'FTP_PORT': ('services.file', 'ftp_port'),
    # 多协议蜜罐：远程管理协议（Telnet / RDP 预留）
    'REMOTE_HONEYPOT_ENABLED': ('services.remote', 'enabled'),
    'TELNET_HOST': ('services.remote', 'host'),
    'TELNET_PORT': ('services.remote', 'telnet_port'),

    # 团队数据中心（独立子进程，配置为 JSON 文件路径）
    'TEAM_CENTER_ENABLED': ('team_center', 'enabled'),
    'TEAM_CENTER_CONFIG': ('team_center', 'config'),
    # AI 推理网关（独立子进程，配置为 JSON 文件路径）
    'AI_GATEWAY_ENABLED': ('ai_gateway', 'enabled'),
    'AI_GATEWAY_CONFIG': ('ai_gateway', 'config'),

    'WEB_HOST': ('services.web', 'host'),
    'WEB_PORT': ('services.web', 'port'),
    'WEB_MAX_CONTENT_LENGTH': ('services.web', 'max_content_length'),
    'WEB_MAX_FORM_MEMORY_SIZE': ('services.web', 'max_form_memory_size'),
    'WEB_MAX_FORM_PARTS': ('services.web', 'max_form_parts'),
    'WEB_MAX_URL_PATH_LEN': ('services.web', 'max_url_path_len'),
    'WEB_MAX_QUERY_LEN': ('services.web', 'max_query_len'),
    'WEB_MAX_HEADERS_TOTAL': ('services.web', 'max_headers_total'),
    'WEB_MAX_HEADERS_COUNT': ('services.web', 'max_headers_count'),
    'WEB_TRUSTED_PROXY_IPS': ('services.web', 'trusted_proxy_ips'),
    'WEB_ADMIN_ALLOWED_ORIGINS': ('services.web', 'admin_allowed_origins'),
    'CAPTURE_BODY_MAX': ('services.web', 'capture_body_max'),
    'ADMIN_SID_COOKIE': ('services.web', 'admin_sid_cookie'),
    'DECOY_ROOT_ENABLED': ('services.web.decoy_root', 'enabled'),
    'DECOY_ROOT_USERNAME': ('services.web.decoy_root', 'username'),
    'DECOY_ROOT_ROLE': ('services.web.decoy_root', 'role'),
    'DECOY_ROOT_STATUS': ('services.web.decoy_root', 'status'),
    'DECOY_ROOT_EMAIL': ('services.web.decoy_root', 'email'),
    'DECOY_ROOT_LAST_LOGIN': ('services.web.decoy_root', 'last_login'),
    'DECOY_ROOT_ID': ('services.web.decoy_root', 'id'),
    'DECOY_ROOT_ACTIVE_RECENT_MINUTES': ('services.web.decoy_root', 'active_recent_minutes'),

    'DASHBOARD_HOST': ('services.dashboard', 'host'),
    'DASHBOARD_PORT': ('services.dashboard', 'port'),
    'DASHBOARD_ALLOWED_ORIGINS': ('services.dashboard', 'allowed_origins'),
    'DASHBOARD_TRUSTED_PROXY_IPS': ('services.dashboard', 'trusted_proxy_ips'),
    'DASHBOARD_TRUST_PROXY_HEADERS': ('services.dashboard', 'trust_proxy_headers'),
    'DASHBOARD_SESSION_LIFETIME_MINUTES': ('services.dashboard', 'session_lifetime_minutes'),
    'DASHBOARD_SESSION_COOKIE_SECURE': ('services.dashboard', 'session_cookie_secure'),
    'DASHBOARD_LOGIN_RATE_WINDOW': ('services.dashboard', 'login_rate_window'),
    'DASHBOARD_LOGIN_RATE_MAX': ('services.dashboard', 'login_rate_max'),
    'DASHBOARD_LOGIN_BLOCK_SECONDS': ('services.dashboard', 'login_block_seconds'),
    'DASHBOARD_LOGIN_AUDIT_MAX': ('services.dashboard', 'login_audit_max'),
    'DASHBOARD_LOGIN_AUDIT_RECENT': ('services.dashboard', 'login_audit_recent'),
    'DASHBOARD_ASSET_VERSION': ('services.dashboard', 'asset_version'),

    # shared security/network
    'TRUSTED_PROXY_IPS': ('security', 'trusted_proxy_ips'),
    'TRUST_PROXY_HEADERS': ('security', 'trust_proxy_headers'),

    # alerting
    'ALERT_ENABLED': ('alerting', 'enabled'),
    'ALERT_WEBHOOK_URL': ('alerting', 'webhook_url'),
    'ALERT_TIMEOUT': ('alerting', 'timeout'),
    'ALERT_MIN_INTERVAL': ('alerting', 'min_interval'),
    'ALERT_DEDUP_WINDOW': ('alerting', 'dedup_window'),
    'ALERT_RISK_THRESHOLD': ('alerting', 'risk_threshold'),
    'ALERT_HIGH_THRESHOLD': ('alerting', 'high_threshold'),
    'ALERT_CRITICAL_THRESHOLD': ('alerting', 'critical_threshold'),
    'ALERT_MENTION_ALL': ('alerting', 'mention_all'),
    'ALERT_RETRY': ('alerting', 'retry'),
    'ALERT_DETAIL_URL': ('alerting', 'detail_url'),
    'ALERT_DETAIL_URL_ENABLED': ('alerting', 'detail_url_enabled'),
    'ALERT_MSG_MAX_BYTES': ('alerting', 'msg_max_bytes'),
    'ALERT_ASYNC_ENABLED': ('alerting', 'async_enabled'),
    'ALERT_QUEUE_MAX': ('alerting', 'queue_max'),
    'ALERT_QUEUE_DROP_OLDEST': ('alerting', 'queue_drop_oldest'),
    'ALERT_WORKERS': ('alerting', 'workers'),

    # event/database view tuning
    'EVENT_PAYLOAD_MAX': ('events', 'payload_max'),
    'EVENT_EXTRA_MAX': ('events', 'extra_max'),
    'EVENT_QUERY_BATCH': ('events', 'query_batch'),
    'EVENT_STATS_CACHE_TTL': ('events', 'stats_cache_ttl'),
    'EVENT_STATS_CACHE_MAX_KEYS': ('events', 'stats_cache_max_keys'),
    'EVENT_DEDUP_WINDOW': ('events', 'dedup_window'),
    'EVENT_DEDUP_MAX': ('events', 'dedup_max'),
    'EVENT_GEO_MAP_TOP_IP_SCAN_LIMIT': ('geoip', 'map_top_ip_scan_limit'),
    'EVENT_GEO_MAP_SCAN_MULTIPLIER': ('geoip', 'map_scan_multiplier'),
    'EVENT_GEO_MAP_ONLINE_RESOLVE_LIMIT': ('geoip', 'map_online_resolve_limit'),

    # archive
    'ARCHIVE_HOT_DAYS': ('archive', 'hot_days'),
    'ARCHIVE_CHECK_INTERVAL_SECONDS': ('archive', 'check_interval_seconds'),
    'ARCHIVE_BACKGROUND_INTERVAL_SECONDS': ('archive', 'background_interval_seconds'),
    'ARCHIVE_READ_ENABLED': ('archive', 'read_enabled'),
    'ARCHIVE_QUERY_MAX_FILES': ('archive', 'query_max_files'),

    # risk target annotation
    'RISK_TARGET_ENABLED': ('risk_target', 'enabled'),
    'RISK_TARGET_AUTO_DERIVE': ('risk_target', 'auto_derive'),
    'RISK_TARGET_DERIVE_HOURS': ('risk_target', 'derive_hours'),
    'RISK_TARGET_MIN_EVENTS': ('risk_target', 'min_events'),
    'RISK_TARGET_MIN_SEVERITY': ('risk_target', 'min_severity'),

    # geoip
    'GEOIP_TIMEOUT': ('geoip', 'timeout'),
    'SERVER_LOCATION_CACHE_TTL': ('geoip', 'server_location_cache_ttl'),
    'SERVER_PUBLIC_IP_CACHE_MAX_AGE': ('geoip', 'server_public_ip_cache_max_age'),
    'SERVER_PUBLIC_IP': ('geoip', 'server_public_ip'),
    'GEO_MEM_CACHE_TTL': ('geoip', 'mem_cache_ttl'),
    'GEO_MEM_CACHE_NEG_TTL': ('geoip', 'mem_cache_neg_ttl'),
    'GEO_MEM_CACHE_MAX': ('geoip', 'mem_cache_max'),

    # dashboard data/demo fallback
    'ALLOW_DASHBOARD_MOCK_DATA': ('dashboard_data', 'allow_mock_data'),

    # demo/test helpers
    'DEMO_TARGET_HOST': ('demo', 'target_host'),
    'WEB_SCHEME': ('demo', 'web_scheme'),
    'DASHBOARD_SCHEME': ('demo', 'dashboard_scheme'),
    'PERF_API_CALLS': ('tests.performance', 'api_calls'),
    'PERF_CONCURRENCY': ('tests.performance', 'concurrency'),
    'PERF_TOTAL_REQUESTS': ('tests.performance', 'total_requests'),
    'PERF_TIMEOUT': ('tests.performance', 'timeout'),
    'PERF_SETTLE_SECONDS': ('tests.performance', 'settle_seconds'),
    'SQLI_ATTACK_COUNT': ('tests.sqli', 'attack_count'),
    'SQLI_BENIGN_COUNT': ('tests.sqli', 'benign_count'),
    'SQLI_SEND_INTERVAL': ('tests.sqli', 'send_interval'),
    'SQLI_SETTLE_SECONDS': ('tests.sqli', 'settle_seconds'),
    'SQLI_QUERY_HOURS': ('tests.sqli', 'query_hours'),
    'SQLI_TIMEOUT': ('tests.sqli', 'timeout'),
}


def _get_config_value(section: str, key: str) -> Optional[str]:
    section = str(section or '').strip()
    key = str(key or '').strip().lower()
    if not section or not key or not CONFIG_LOADED:
        return None
    if not _CONFIG.has_section(section):
        return None
    if not _CONFIG.has_option(section, key):
        return None
    return _CONFIG.get(section, key)


def _section_key_for_env(name: str, section: str = None, key: str = None):
    if section and key:
        return section, key
    return _ENV_CONFIG_MAP.get(str(name or '').strip().upper(), (section, key))


def config_raw(section: str, key: str, default=None):
    value = _get_config_value(section, key)
    return default if value is None else value


def config_value(name: str, default=None, section: str = None, key: str = None):
    """读取单项配置：环境变量 > honeypot.ini > 默认值。"""
    env_name = str(name or '').strip()
    if env_name and env_name in os.environ:
        return os.environ.get(env_name)
    mapped_section, mapped_key = _section_key_for_env(env_name, section, key)
    value = _get_config_value(mapped_section, mapped_key)
    return default if value is None else value


def env_str(name: str, default: str = '', section: str = None, key: str = None, strip: bool = True) -> str:
    value = config_value(name, default, section, key)
    if value is None:
        value = '' if default is None else default
    text = str(value)
    return text.strip() if strip else text


def env_bool(name: str, default: bool = False, section: str = None, key: str = None) -> bool:
    value = config_value(name, None, section, key)
    if value is None:
        return bool(default)
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in _TRUE_VALUES:
        return True
    if text in _FALSE_VALUES:
        return False
    return bool(default)


def env_int(name: str, default: int, min_v: int = None, max_v: int = None, section: str = None, key: str = None) -> int:
    try:
        value = int(str(config_value(name, default, section, key)).strip())
    except Exception:
        value = int(default)
    if min_v is not None:
        value = max(min_v, value)
    if max_v is not None:
        value = min(max_v, value)
    return value


def env_float(name: str, default: float, min_v: float = None, max_v: float = None, section: str = None, key: str = None) -> float:
    try:
        value = float(str(config_value(name, default, section, key)).strip())
    except Exception:
        value = float(default)
    if min_v is not None:
        value = max(min_v, value)
    if max_v is not None:
        value = min(max_v, value)
    return value


def env_csv(name: str, default: str = '', section: str = None, key: str = None) -> list:
    raw = env_str(name, default, section, key)
    return [item.strip() for item in raw.split(',') if item.strip()]


def env_path(name: str, default: str, section: str = None, key: str = None) -> str:
    raw = env_str(name, default, section, key)
    if not raw:
        raw = str(default or '')
    if not os.path.isabs(raw):
        raw = os.path.join(BASE_DIR, raw)
    return os.path.abspath(raw)


def apply_config_to_environment(names: Iterable[str] = None) -> None:
    """把配置文件中的值补入 os.environ，兼容仍直接读取环境变量的旧代码。"""
    if not CONFIG_LOADED:
        return
    for env_name in (names or _ENV_CONFIG_MAP.keys()):
        name = str(env_name or '').strip().upper()
        if not name or name in os.environ:
            continue
        section, key = _ENV_CONFIG_MAP.get(name, ('', ''))
        value = _get_config_value(section, key)
        if value is not None:
            os.environ[name] = str(value)


def _read_secret_key_file() -> str:
    try:
        if os.path.exists(SECRET_KEY_FILE):
            with open(SECRET_KEY_FILE, 'r', encoding='utf-8') as f:
                return f.read().strip()
    except Exception:
        pass
    return ''


# 先把 honeypot.ini 补入环境，保证仍直接 os.environ.get 的旧模块也能吃到根配置。
apply_config_to_environment()

# 运行模式开关：仅 true/yes/on/1 视为生产环境；未设置默认为非生产
_IS_PRODUCTION_ENV = env_bool('PRODUCTION_MODE', False)


class Config:
    """基础配置类"""
    # Flask 密钥 - 优先环境变量/配置文件，其次 .secret_key，最后生成随机密钥
    SECRET_KEY = env_str('SECRET_KEY', '') or _read_secret_key_file() or os.urandom(24).hex()

    # JSON 配置
    JSON_AS_ASCII = False

    # 管理员账号配置
    REAL_ADMIN_USER = env_str('ADMIN_USER', 'admin') or 'admin'
    REAL_ADMIN_PASS = env_str('ADMIN_PASS', '')

    # 生产环境必须提供密码
    if _IS_PRODUCTION_ENV and not REAL_ADMIN_PASS:
        raise ValueError("生产环境必须在 honeypot.ini 的 [admin] password 或 ADMIN_PASS 环境变量中设置管理端密码！")

    # 非生产环境默认密码（仅用于本地演示）
    if not REAL_ADMIN_PASS:
        REAL_ADMIN_PASS = 'Admin@2024!'

    # 数据库配置（统一入口）
    _env_db_type = env_str('DB_TYPE', '').strip().lower()
    _env_use_mysql = env_bool('USE_MYSQL', False)
    if _env_db_type:
        DB_TYPE = _env_db_type
    else:
        DB_TYPE = 'mysql' if _env_use_mysql else 'sqlite'
    if DB_TYPE not in ('sqlite', 'mysql'):
        DB_TYPE = 'sqlite'

    # SQLite 配置
    DB_PATH = env_path('DB_PATH', os.path.join('database', 'event_logs.db'))

    # MySQL 配置（仅当 DB_TYPE=mysql 时生效）
    DB_HOST = env_str('DB_HOST', '127.0.0.1') or '127.0.0.1'
    DB_PORT = env_int('DB_PORT', 3306, 1, 65535)
    DB_USER = env_str('DB_USER', 'root') or 'root'
    DB_PASS = env_str('DB_PASS', '')
    DB_NAME = env_str('DB_NAME', 'honeypot_db') or 'honeypot_db'
    DB_CHARSET = env_str('DB_CHARSET', 'utf8mb4') or 'utf8mb4'

    # ============================================
    # AI request-level attack inference service
    # ============================================
    AI_XSS_ENABLED = env_bool('AI_XSS_ENABLED', False)
    AI_XSS_URL = (
        env_str(
            'AI_XSS_URL',
            'http://127.0.0.1:8003/api/v1/detect'
        ).strip()
        or 'http://127.0.0.1:8003/api/v1/detect'
    )
    AI_XSS_INFO_URL = (
        env_str('AI_XSS_INFO_URL', 'http://127.0.0.1:8003/model/info').strip()
        or 'http://127.0.0.1:8003/model/info'
    )
    AI_XSS_TIMEOUT = env_float('AI_XSS_TIMEOUT', 1.0, 0.1, 10.0)
    # Compatibility only; v2 integration does not gate on this value.
    AI_XSS_THRESHOLD = env_float('AI_XSS_THRESHOLD', 0.90, 0.0, 1.0)
    AI_XSS_TEXT_MAX = env_int('AI_XSS_TEXT_MAX', 5000, 128, 100000)
    AI_XSS_FAILURE_THRESHOLD = env_int('AI_XSS_FAILURE_THRESHOLD', 3, 1, 100)
    AI_XSS_BACKOFF_SECONDS = env_float('AI_XSS_BACKOFF_SECONDS', 30.0, 0.0, 3600.0)
    AI_XSS_MODEL_INFO_TTL = env_int('AI_XSS_MODEL_INFO_TTL', 300, 0, 86400)

    # ============================================
    # 日志配置
    # ============================================
    LOG_DIR = os.path.join(BASE_DIR, 'logs')
    LOG_LEVEL = env_str('LOG_LEVEL', 'INFO') or 'INFO'
    LOG_FORMAT = '[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s'
    LOG_DATE_FORMAT = '%Y-%m-%d %H:%M:%S'
    LOG_MAX_BYTES = env_int('LOG_MAX_BYTES', 10 * 1024 * 1024, 1024, 1024 * 1024 * 1024)
    LOG_BACKUP_COUNT = env_int('LOG_BACKUP_COUNT', 30, 1, 365)

    # 各模块日志文件名
    LOG_FILE_SSH = 'ssh.log'
    LOG_FILE_WEB = 'web_honeypot.log'
    LOG_FILE_DASHBOARD = 'dashboard.log'
    LOG_FILE_DB = 'database.log'


class DevelopmentConfig(Config):
    """开发环境配置"""
    DEBUG = True

    # 开发环境可覆盖默认值
    DB_HOST = env_str('DB_HOST', Config.DB_HOST) or '127.0.0.1'
    DB_PORT = env_int('DB_PORT', Config.DB_PORT, 1, 65535)
    DB_PASS = env_str('DB_PASS', Config.DB_PASS) or ('123456' if Config.DB_TYPE == 'mysql' else Config.DB_PASS)


class ProductionConfig(Config):
    """生产环境配置"""
    DEBUG = False

    # 生产环境建议提供稳定 SECRET_KEY；未提供则 .secret_key 或随机生成，避免导入报错。
    SECRET_KEY = env_str('SECRET_KEY', '') or _read_secret_key_file() or os.urandom(32).hex()

    DB_HOST = env_str('DB_HOST', Config.DB_HOST) or '127.0.0.1'
    DB_PORT = env_int('DB_PORT', Config.DB_PORT, 1, 65535)
    DB_USER = env_str('DB_USER', Config.DB_USER) or 'root'
    DB_PASS = env_str('DB_PASS', Config.DB_PASS)
    DB_NAME = env_str('DB_NAME', Config.DB_NAME) or 'honeypot_db'

    # 生产环境若使用 MySQL，必须提供 DB_PASS
    if Config.DB_TYPE == 'mysql' and not DB_PASS:
        raise ValueError("生产环境使用 MySQL 必须在 honeypot.ini 的 [database] password 或 DB_PASS 环境变量中设置数据库密码！")


def validate_runtime_config() -> None:
    """显式触发运行配置校验，供启动脚本或测试复用。"""
    if _IS_PRODUCTION_ENV and not Config.REAL_ADMIN_PASS:
        raise ValueError("生产环境缺少管理端密码")
    if _IS_PRODUCTION_ENV and Config.DB_TYPE == 'mysql' and not ProductionConfig.DB_PASS:
        raise ValueError("生产环境 MySQL 缺少数据库密码")


def describe_config_source() -> str:
    if CONFIG_LOADED:
        return CONFIG_PATH
    return 'environment/defaults'


def is_production() -> bool:
    return _IS_PRODUCTION_ENV


def get_config_path() -> str:
    return CONFIG_PATH


def get_env_config_map() -> dict:
    return dict(_ENV_CONFIG_MAP)


default_config = ProductionConfig if _IS_PRODUCTION_ENV else DevelopmentConfig

# 配置映射字典
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': default_config
}
