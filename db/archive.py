# -*- coding: utf-8 -*-
"""
归档与热数据裁剪
"""
import os
import re
import sqlite3
import time
from datetime import datetime, timedelta
from threading import Lock
from env_utils import env_bool as _env_bool, env_int as _env_int

from .connection import get_connection, USE_MYSQL, logger

_BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
_ARCHIVE_HOT_DAYS = _env_int('ARCHIVE_HOT_DAYS', 7, 1, 3650)
_ARCHIVE_CHECK_INTERVAL_SECONDS = _env_int('ARCHIVE_CHECK_INTERVAL_SECONDS', 300, 30, 86400)
_ARCHIVE_DIR = os.path.join(_BASE_DIR, 'database', 'archive')
_ARCHIVE_READ_ENABLED = _env_bool('ARCHIVE_READ_ENABLED', True)
_ARCHIVE_QUERY_MAX_FILES = _env_int('ARCHIVE_QUERY_MAX_FILES', 60, 1, 3660)
_ARCHIVE_FILE_RE = re.compile(r'^archive_(\d{8})\.sqlite$')
_ARCHIVE_LOCK = Lock()
_LAST_ARCHIVE_CHECK_TS = 0.0


def _ensure_archive_tables(conn) -> None:
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS archive.raw_request (
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
        CREATE TABLE IF NOT EXISTS archive.session_track (
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
        CREATE TABLE IF NOT EXISTS archive.event_log (
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
        cursor.execute("PRAGMA archive.table_info(event_log)")
        cols = {str(row[1]).strip().lower() for row in (cursor.fetchall() or [])}
        if 'raw_request_id' not in cols:
            cursor.execute("ALTER TABLE archive.event_log ADD COLUMN raw_request_id INTEGER DEFAULT NULL")
    except Exception as e:
        logger.debug(f"归档表 event_log 列补齐失败: {e}")


def _attach_archive_db(conn, archive_path: str) -> None:
    safe_path = archive_path.replace("'", "''")
    conn.execute(f"ATTACH DATABASE '{safe_path}' AS archive")


def _detach_archive_db(conn) -> None:
    conn.execute("DETACH DATABASE archive")


def _date_key_from_text(value: str) -> str:
    text = str(value or '').strip()
    if len(text) >= 10 and text[4:5] == '-' and text[7:8] == '-':
        return text[:10]
    return ''


def _archive_day_from_name(name: str) -> str:
    match = _ARCHIVE_FILE_RE.match(str(name or '').strip())
    if not match:
        return ''
    raw = match.group(1)
    return f"{raw[:4]}-{raw[4:6]}-{raw[6:8]}"


def get_archive_paths_for_window(cutoff: str = '') -> list:
    """返回查询窗口内需要读取的归档库路径。"""
    if USE_MYSQL or not _ARCHIVE_READ_ENABLED:
        return []
    if not os.path.isdir(_ARCHIVE_DIR):
        return []
    cutoff_day = _date_key_from_text(cutoff)
    today_day = datetime.now().strftime('%Y-%m-%d')
    items = []
    try:
        for name in os.listdir(_ARCHIVE_DIR):
            day = _archive_day_from_name(name)
            if not day:
                continue
            if cutoff_day and day < cutoff_day:
                continue
            if day > today_day:
                continue
            items.append((day, os.path.join(_ARCHIVE_DIR, name)))
    except Exception as e:
        logger.debug(f"读取归档目录失败: {e}")
        return []
    items.sort(key=lambda x: x[0], reverse=True)
    return [path for _, path in items[:_ARCHIVE_QUERY_MAX_FILES]]


def _open_archive_readonly(path: str):
    uri = 'file:' + os.path.abspath(path).replace('\\', '/') + '?mode=ro'
    conn = sqlite3.connect(uri, uri=True, timeout=10.0)
    conn.row_factory = sqlite3.Row
    return conn


def _table_exists(conn, table: str) -> bool:
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=? LIMIT 1", (table,))
    return cursor.fetchone() is not None


def _rows_to_dict(rows) -> list:
    return [dict(row) for row in rows or []]


def fetch_archive_rows(
    table: str,
    columns,
    where: str = '',
    params=(),
    order_by: str = '',
    limit: int = 0,
    window_cutoff: str = '',
) -> list:
    """从归档库只读查询记录，供管理端跨热库和归档库展示使用。"""
    paths = get_archive_paths_for_window(window_cutoff)
    if not paths:
        return []
    column_sql = ', '.join(columns) if isinstance(columns, (list, tuple)) else str(columns or '*')
    where_sql = f" WHERE {where}" if str(where or '').strip() else ''
    order_sql = f" ORDER BY {order_by}" if str(order_by or '').strip() else ''
    limit_sql = ''
    try:
        limit_v = int(limit or 0)
    except Exception:
        limit_v = 0
    if limit_v > 0:
        limit_sql = f" LIMIT {limit_v}"
    sql = f"SELECT {column_sql} FROM {table}{where_sql}{order_sql}{limit_sql}"
    out = []
    can_stop_by_time = bool(
        limit_v > 0
        and str(order_by or '').strip().lower().startswith(('timestamp desc', 'create_time desc', 'last_seen desc'))
    )
    for path in paths:
        try:
            conn = _open_archive_readonly(path)
            try:
                if not _table_exists(conn, table):
                    continue
                cursor = conn.cursor()
                cursor.execute(sql, tuple(params or ()))
                out.extend(_rows_to_dict(cursor.fetchall()))
                if can_stop_by_time and len(out) >= limit_v:
                    break
            finally:
                conn.close()
        except Exception as e:
            logger.debug(f"读取归档库失败 {path}: {e}")
    return out


def fetch_archive_count(
    table: str,
    where: str = '',
    params=(),
    window_cutoff: str = '',
) -> int:
    paths = get_archive_paths_for_window(window_cutoff)
    if not paths:
        return 0
    where_sql = f" WHERE {where}" if str(where or '').strip() else ''
    sql = f"SELECT COUNT(*) AS count FROM {table}{where_sql}"
    total = 0
    for path in paths:
        try:
            conn = _open_archive_readonly(path)
            try:
                if not _table_exists(conn, table):
                    continue
                cursor = conn.cursor()
                cursor.execute(sql, tuple(params or ()))
                row = cursor.fetchone()
                total += int(row['count'] if row else 0)
            finally:
                conn.close()
        except Exception as e:
            logger.debug(f"读取归档计数失败 {path}: {e}")
    return total


def fetch_archive_group_counts(
    table: str,
    group_column: str,
    where: str = '',
    params=(),
    window_cutoff: str = '',
) -> list:
    paths = get_archive_paths_for_window(window_cutoff)
    if not paths:
        return []
    where_sql = f" WHERE {where}" if str(where or '').strip() else ''
    sql = (
        f"SELECT {group_column} AS group_key, COUNT(*) AS count "
        f"FROM {table}{where_sql} GROUP BY {group_column}"
    )
    out = []
    for path in paths:
        try:
            conn = _open_archive_readonly(path)
            try:
                if not _table_exists(conn, table):
                    continue
                cursor = conn.cursor()
                cursor.execute(sql, tuple(params or ()))
                out.extend(_rows_to_dict(cursor.fetchall()))
            finally:
                conn.close()
        except Exception as e:
            logger.debug(f"读取归档分组失败 {path}: {e}")
    return out


def archive_has_real_data(cutoff: str = '') -> bool:
    if not get_archive_paths_for_window(cutoff):
        return False
    for table in ('event_log', 'raw_request', 'session_track'):
        if fetch_archive_count(table, window_cutoff=cutoff) > 0:
            return True
    return False


def _archive_table_by_day(conn, table: str, date_field: str, day: str, archive_path: str) -> None:
    _attach_archive_db(conn, archive_path)
    try:
        _ensure_archive_tables(conn)
        cursor = conn.cursor()
        table_columns = {
            'raw_request': [
                'id', 'session_id', 'src_ip', 'method', 'path', 'query_string',
                'headers', 'body', 'user_agent', 'referer', 'content_type',
                'content_length', 'is_suspicious', 'threat_score', 'create_time',
            ],
            'session_track': [
                'id', 'session_id', 'src_ip', 'first_seen', 'last_seen',
                'request_count', 'path_sequence', 'is_attacker', 'threat_level',
            ],
            'event_log': [
                'id', 'timestamp', 'source', 'severity', 'event_type', 'src_ip',
                'session_id', 'tags', 'payload', 'raw_ref', 'raw_request_id', 'extra',
            ],
        }
        columns = table_columns.get(table)
        if not columns:
            raise ValueError(f"unsupported archive table: {table}")
        column_sql = ", ".join(columns)
        cursor.execute(
            f"INSERT INTO archive.{table} ({column_sql}) "
            f"SELECT {column_sql} FROM {table} WHERE date({date_field}) = ?",
            (day,)
        )
        cursor.execute(
            f"DELETE FROM {table} WHERE date({date_field}) = ?",
            (day,)
        )
        conn.commit()
    except Exception as e:
        conn.rollback()
        logger.debug(f"归档失败 {table}({day}): {e}")
    finally:
        try:
            _detach_archive_db(conn)
        except Exception:
            pass


def archive_old_logs_sqlite() -> None:
    archive_before = (datetime.now() - timedelta(days=_ARCHIVE_HOT_DAYS)).strftime('%Y-%m-%d')
    conn = get_connection()
    try:
        if USE_MYSQL:
            return
        cursor = conn.cursor()
        cursor.execute(
            "SELECT DISTINCT date(create_time) FROM raw_request WHERE date(create_time) < ? ORDER BY 1",
            (archive_before,)
        )
        raw_days = [row[0] for row in cursor.fetchall() if row and row[0]]
        cursor.execute(
            "SELECT DISTINCT date(last_seen) FROM session_track WHERE date(last_seen) < ? ORDER BY 1",
            (archive_before,)
        )
        session_days = [row[0] for row in cursor.fetchall() if row and row[0]]
        cursor.execute(
            "SELECT DISTINCT date(timestamp) FROM event_log WHERE date(timestamp) < ? ORDER BY 1",
            (archive_before,)
        )
        event_days = [row[0] for row in cursor.fetchall() if row and row[0]]

        if not raw_days and not session_days and not event_days:
            return

        os.makedirs(_ARCHIVE_DIR, exist_ok=True)
        all_days = sorted(set(raw_days + session_days + event_days))
        for day in all_days:
            archive_path = os.path.join(_ARCHIVE_DIR, f"archive_{day.replace('-', '')}.sqlite")
            if day in raw_days:
                _archive_table_by_day(conn, 'raw_request', 'create_time', day, archive_path)
            if day in session_days:
                _archive_table_by_day(conn, 'session_track', 'last_seen', day, archive_path)
            if day in event_days:
                _archive_table_by_day(conn, 'event_log', 'timestamp', day, archive_path)
    finally:
        conn.close()


def _maybe_archive_old_logs() -> None:
    if USE_MYSQL:
        return
    global _LAST_ARCHIVE_CHECK_TS
    now = time.time()
    if now - _LAST_ARCHIVE_CHECK_TS < _ARCHIVE_CHECK_INTERVAL_SECONDS:
        return
    if not _ARCHIVE_LOCK.acquire(False):
        return
    try:
        now = time.time()
        if now - _LAST_ARCHIVE_CHECK_TS < _ARCHIVE_CHECK_INTERVAL_SECONDS:
            return
        _LAST_ARCHIVE_CHECK_TS = now
        archive_old_logs_sqlite()
    except Exception as e:
        logger.debug(f"归档任务执行失败: {e}")
    finally:
        _ARCHIVE_LOCK.release()


__all__ = [
    'archive_old_logs_sqlite',
    '_maybe_archive_old_logs',
    'get_archive_paths_for_window',
    'fetch_archive_rows',
    'fetch_archive_count',
    'fetch_archive_group_counts',
    'archive_has_real_data',
]

