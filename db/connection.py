# -*- coding: utf-8 -*-
"""
数据库核心：连接、初始化、通用工具
"""
import os
import logging
import pymysql
import sqlite3
import time
import random
import re
import hashlib
from threading import Lock

from app_config import env_float as _env_float, env_int as _env_int, config
from utils.logger import get_db_logger

logger = get_db_logger()
_config = config['default']

# 设置 GeoLite2 日志级别，便于定位地理库相关问题
geo_logger = logging.getLogger('geoip2')
geo_logger.setLevel(logging.DEBUG)

_BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

_EVENT_PAYLOAD_MAX = _env_int('EVENT_PAYLOAD_MAX', 2048, 128, 20000)

_SQLITE_BUSY_RETRY = _env_int('SQLITE_BUSY_RETRY', 3, 0, 20)
_SQLITE_BUSY_BACKOFF = _env_float('SQLITE_BUSY_BACKOFF', 0.05, 0.0, 10.0)

_SESSION_ID_WINDOW_SECONDS = _env_int('SESSION_ID_WINDOW_SECONDS', 3600, 60, 86400)

_HAS_REAL_CACHE_TTL = _env_float('HAS_REAL_CACHE_TTL', 0.5, 0.0, 60.0)
_HAS_REAL_CACHE = {'ts': 0.0, 'val': False}
_SQLITE_SCHEMA_LOCK = Lock()
_SQLITE_SCHEMA_READY = set()

_SENSITIVE_KEYS = {
    'secret',
    'token', 'access_token', 'refresh_token', 'authorization',
    'api_key', 'apikey',
    '令牌', '密钥'
}
_SENSITIVE_PATTERN = re.compile(
    r'(?i)\b(' + '|'.join(re.escape(k) for k in _SENSITIVE_KEYS) + r')\b\s*([:=])\s*([^\s&;,"\'}<>]+)'
)
_SENSITIVE_PATTERN_CN = re.compile(
    r'(令牌|密钥)\s*([:=])\s*([^\s&;,"\'}<>]+)'
)
_SENSITIVE_JSON_PATTERN = re.compile(
    r'(?i)("?(?:' + '|'.join(re.escape(k) for k in _SENSITIVE_KEYS) + r')"?)\s*:\s*(".*?"|\'.*?\')'
)

# 数据库类型统一从 config 读取；默认 SQLite，MySQL 需显式配置 DB_TYPE=mysql
_DB_TYPE = getattr(_config, 'DB_TYPE', 'sqlite')
USE_MYSQL = str(_DB_TYPE).strip().lower() == 'mysql'


def _hash_secret(value: str) -> str:
    raw = value or ''
    digest = hashlib.sha256(raw.encode('utf-8', errors='ignore')).hexdigest()[:10]
    return f"<redacted:{digest}>"


def _redact_sensitive_text(text: str) -> str:
    if not text:
        return ''

    def _replace_kv(match):
        key = match.group(1)
        sep = match.group(2)
        value = match.group(3) or ''
        return f"{key}{sep}{_hash_secret(value)}"

    def _replace_json(match):
        key = match.group(1)
        raw_value = match.group(2) or ''
        value = raw_value.strip().strip('"').strip("'")
        return f"{key}: \"{_hash_secret(value)}\""

    safe = _SENSITIVE_PATTERN.sub(_replace_kv, text)
    safe = _SENSITIVE_PATTERN_CN.sub(_replace_kv, safe)
    safe = _SENSITIVE_JSON_PATTERN.sub(_replace_json, safe)
    return safe


def _truncate_text(text: str, max_len: int) -> str:
    if max_len <= 0:
        return text
    if len(text) <= max_len:
        return text
    digest = hashlib.sha1(text.encode('utf-8', errors='ignore')).hexdigest()[:8]
    return f"{text[:max_len]}... [len={len(text)}, sha1={digest}]"


def _sqlite_should_retry(err: Exception) -> bool:
    return isinstance(err, sqlite3.OperationalError) and 'locked' in str(err).lower()


def _sqlite_retry_sleep(attempt: int) -> None:
    base = _SQLITE_BUSY_BACKOFF * (2 ** attempt)
    time.sleep(base + random.random() * 0.05)


def _sqlite_run_with_retry(conn, action):
    attempt = 0
    while True:
        try:
            cursor = conn.cursor()
            result = action(cursor)
            conn.commit()
            return result
        except Exception as e:
            if _sqlite_should_retry(e) and attempt < _SQLITE_BUSY_RETRY:
                try:
                    conn.rollback()
                except Exception:
                    pass
                _sqlite_retry_sleep(attempt)
                attempt += 1
                continue
            raise


def _ensure_tables_exist(conn):
    try:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS geo_ip (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL UNIQUE,
                country TEXT, province TEXT, city TEXT,
                latitude REAL, longitude REAL, isp TEXT,
                update_time DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS raw_request (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                src_ip TEXT NOT NULL,
                method TEXT,
                path TEXT,
                query_string TEXT,
                headers TEXT,
                body TEXT,
                user_agent TEXT,
                referer TEXT,
                content_type TEXT,
                content_length INTEGER DEFAULT 0,
                is_suspicious INTEGER DEFAULT 0,
                threat_score INTEGER DEFAULT 0,
                create_time DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS session_track (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL UNIQUE,
                src_ip TEXT NOT NULL,
                first_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                last_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                request_count INTEGER DEFAULT 1,
                path_sequence TEXT,
                is_attacker INTEGER DEFAULT 0,
                threat_level TEXT DEFAULT 'unknown'
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS event_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                source TEXT NOT NULL,
                severity TEXT NOT NULL,
                event_type TEXT NOT NULL,
                src_ip TEXT DEFAULT '',
                session_id TEXT DEFAULT '',
                tags TEXT,
                payload TEXT,
                raw_ref TEXT DEFAULT '',
                raw_request_id INTEGER DEFAULT NULL,
                extra TEXT
            )
        ''')
        try:
            cursor.execute("PRAGMA table_info(event_log)")
            cols = {str(row[1]).strip().lower() for row in (cursor.fetchall() or [])}
            if 'raw_request_id' not in cols:
                cursor.execute("ALTER TABLE event_log ADD COLUMN raw_request_id INTEGER DEFAULT NULL")
        except Exception as e:
            logger.debug(f"event_log 列补齐失败(可忽略): {e}")
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_raw_ip ON raw_request(src_ip)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_raw_session ON raw_request(session_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_raw_suspicious_score_time ON raw_request(is_suspicious, threat_score, create_time)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_session_ip ON session_track(src_ip)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_session_request_count ON session_track(request_count)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_session_last_seen ON session_track(last_seen)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_event_time ON event_log(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_event_source ON event_log(source)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_event_severity ON event_log(severity)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_event_type ON event_log(event_type)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_event_ip ON event_log(src_ip)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_event_raw_request ON event_log(raw_request_id)')
        conn.commit()
        return True
    except Exception as e:
        logger.error(f"自动建表失败: {e}")
        return False


def _ensure_sqlite_schema_ready(db_path: str, conn) -> None:
    db_key = os.path.abspath(str(db_path or ''))
    if not db_key:
        _ensure_tables_exist(conn)
        return

    with _SQLITE_SCHEMA_LOCK:
        if db_key in _SQLITE_SCHEMA_READY:
            return
        if _ensure_tables_exist(conn):
            _SQLITE_SCHEMA_READY.add(db_key)


def get_mysql_connection():
    return pymysql.connect(
        host=_config.DB_HOST, port=_config.DB_PORT, user=_config.DB_USER,
        password=_config.DB_PASS, database=_config.DB_NAME, charset=_config.DB_CHARSET,
        cursorclass=pymysql.cursors.DictCursor
    )


def get_sqlite_connection():
    db_path = getattr(_config, 'DB_PATH', None) or os.path.join(_BASE_DIR, 'database', 'event_logs.db')
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=30.0)
    conn.execute('PRAGMA journal_mode=WAL;')
    conn.execute('PRAGMA busy_timeout=30000;')
    _ensure_sqlite_schema_ready(db_path, conn)
    return conn


def get_connection():
    return get_mysql_connection() if USE_MYSQL else get_sqlite_connection()


def has_real_data() -> bool:
    """检测是否存在任何真实数据（以 event_log 为主，含 raw_request/session_track）。"""
    now = time.time()
    cached = _HAS_REAL_CACHE
    if now - cached['ts'] < _HAS_REAL_CACHE_TTL:
        return bool(cached['val'])
    result = False
    conn = get_connection()
    try:
        cursor = conn.cursor()
        for table in ('event_log', 'raw_request', 'session_track'):
            try:
                cursor.execute(f"SELECT 1 FROM {table} LIMIT 1")
                row = cursor.fetchone()
                if row:
                    result = True
                    break
            except Exception:
                continue
    except Exception as e:
        logger.debug(f"has_real_data 查询失败: {e}")
        result = False
    finally:
        try:
            conn.close()
        except Exception:
            pass
    _HAS_REAL_CACHE['ts'] = now
    _HAS_REAL_CACHE['val'] = result
    return result


def is_event_log_empty():
    """仅检查 event_log 是否为空。"""
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) as cnt FROM event_log")
        res = cursor.fetchone()
        count = res['cnt'] if USE_MYSQL else res[0]
        return int(count or 0) == 0
    except Exception as e:
        logger.debug(f"is_event_log_empty 查询失败(将按空库处理): {e}")
        return True
    finally:
        conn.close()


__all__ = [
    'USE_MYSQL',
    'logger',
    '_EVENT_PAYLOAD_MAX',
    '_SESSION_ID_WINDOW_SECONDS',
    '_redact_sensitive_text',
    '_truncate_text',
    '_sqlite_run_with_retry',
    'get_connection',
    'has_real_data',
    'is_event_log_empty',
]

