# -*- coding: utf-8 -*-
"""密标持久化层。

设计要点：
1. 复用项目统一数据访问入口 db.get_connection()，天然兼容 SQLite / MySQL；
2. 只新增独立数据表 risk_mark，绝不改动 event_log / raw_request 等既有表结构；
3. 唯一索引 (target_type, target_value) 保证"一个对象只有一条有效密标"，
   重复标注同一对象时执行覆盖更新而非新增记录。
"""
from datetime import datetime, timedelta
from threading import Lock
from typing import Any, Dict, List, Optional, Sequence

from db.connection import (
    USE_MYSQL,
    _sqlite_run_with_retry,
    get_connection,
)

from .constants import (
    LEVEL_CRITICAL,
    LEVEL_HIGH,
    LEVELS,
    MAX_BATCH_TARGETS,
    STATUS_ACTIVE,
    TABLE_NAME,
)
from .log import logger
from .models import RiskMark, dump_extra, now_text

_TABLE_LOCK = Lock()
_TABLE_READY = {'sqlite': False, 'mysql': False}

_COLUMNS = (
    'id', 'target_type', 'target_value', 'level', 'mark_code', 'reason',
    'source', 'status', 'created_by', 'created_at', 'updated_at', 'expires_at', 'extra',
)
_SELECT_COLUMNS = ', '.join(_COLUMNS)


def _placeholder() -> str:
    return '%s' if USE_MYSQL else '?'


def _placeholders(count: int) -> str:
    return ', '.join([_placeholder()] * max(0, count))


def _rows_to_dict(cursor, rows) -> List[Dict[str, Any]]:
    if USE_MYSQL:
        return [dict(r) for r in (rows or [])]
    if not cursor.description:
        return []
    cols = [d[0] for d in cursor.description]
    return [dict(zip(cols, r)) for r in (rows or [])]


def _ensure_table(conn) -> None:
    cursor = conn.cursor()
    if USE_MYSQL:
        cursor.execute(
            f"""
            CREATE TABLE IF NOT EXISTS {TABLE_NAME} (
                id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
                target_type VARCHAR(16) NOT NULL,
                target_value VARCHAR(128) NOT NULL,
                level VARCHAR(16) NOT NULL,
                mark_code VARCHAR(64) DEFAULT '',
                reason VARCHAR(512) DEFAULT '',
                source VARCHAR(64) NOT NULL DEFAULT 'manual',
                status VARCHAR(16) NOT NULL DEFAULT 'active',
                created_by VARCHAR(64) DEFAULT '',
                created_at DATETIME NULL,
                updated_at DATETIME NULL,
                expires_at DATETIME NULL,
                extra TEXT,
                PRIMARY KEY (id),
                UNIQUE KEY uk_risk_mark_target (target_type, target_value),
                KEY idx_risk_mark_level (level),
                KEY idx_risk_mark_status (status),
                KEY idx_risk_mark_updated (updated_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """
        )
    else:
        cursor.execute(
            f"""
            CREATE TABLE IF NOT EXISTS {TABLE_NAME} (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_type TEXT NOT NULL,
                target_value TEXT NOT NULL,
                level TEXT NOT NULL,
                mark_code TEXT DEFAULT '',
                reason TEXT DEFAULT '',
                source TEXT NOT NULL DEFAULT 'manual',
                status TEXT NOT NULL DEFAULT 'active',
                created_by TEXT DEFAULT '',
                created_at DATETIME,
                updated_at DATETIME,
                expires_at DATETIME,
                extra TEXT
            )
            """
        )
        cursor.execute(
            f"CREATE UNIQUE INDEX IF NOT EXISTS uk_risk_mark_target ON {TABLE_NAME}(target_type, target_value)"
        )
        cursor.execute(f"CREATE INDEX IF NOT EXISTS idx_risk_mark_level ON {TABLE_NAME}(level)")
        cursor.execute(f"CREATE INDEX IF NOT EXISTS idx_risk_mark_status ON {TABLE_NAME}(status)")
        cursor.execute(f"CREATE INDEX IF NOT EXISTS idx_risk_mark_updated ON {TABLE_NAME}(updated_at)")
    conn.commit()


def _ensure_table_ready(conn) -> None:
    key = 'mysql' if USE_MYSQL else 'sqlite'
    if _TABLE_READY.get(key):
        return
    with _TABLE_LOCK:
        if _TABLE_READY.get(key):
            return
        _ensure_table(conn)
        _TABLE_READY[key] = True


def _execute_write(conn, sql: str, params: Sequence[Any]):
    """执行写操作；SQLite 走项目统一的 busy 重试逻辑。"""
    def _action(cursor):
        cursor.execute(sql, tuple(params))
        return cursor.lastrowid

    if USE_MYSQL:
        cursor = conn.cursor()
        cursor.execute(sql, tuple(params))
        conn.commit()
        return cursor.lastrowid
    return _sqlite_run_with_retry(conn, _action)


def _fetch_mark_row(conn, target_type: str, target_value: str) -> Optional[Dict[str, Any]]:
    ph = _placeholder()
    cursor = conn.cursor()
    cursor.execute(
        f"SELECT {_SELECT_COLUMNS} FROM {TABLE_NAME} "
        f"WHERE target_type = {ph} AND target_value = {ph} LIMIT 1",
        (target_type, target_value),
    )
    rows = _rows_to_dict(cursor, cursor.fetchall())
    return rows[0] if rows else None


def upsert_mark(mark: RiskMark) -> Optional[int]:
    """新增或覆盖一条密标，返回记录 ID；失败返回 None。

    Raises:
        ValueError: 入参非法（如标注对象为空）。
    """
    mark.validate()
    conn = get_connection()
    try:
        _ensure_table_ready(conn)
        ph = _placeholder()
        existing = _fetch_mark_row(conn, mark.target_type, mark.target_value)
        if existing:
            mark_id = int(existing.get('id') or 0)
            mark.created_at = str(existing.get('created_at') or mark.created_at)
            mark.updated_at = now_text()
            sql = (
                f"UPDATE {TABLE_NAME} SET level = {ph}, mark_code = {ph}, reason = {ph}, "
                f"source = {ph}, status = {ph}, created_by = {ph}, updated_at = {ph}, "
                f"expires_at = {ph}, extra = {ph} WHERE id = {ph}"
            )
            params = (
                mark.level, mark.mark_code, mark.reason, mark.source, mark.status,
                mark.created_by, mark.updated_at, mark.expires_at, dump_extra(mark.extra), mark_id,
            )
            _execute_write(conn, sql, params)
            return mark_id

        mark.updated_at = mark.updated_at or mark.created_at
        sql = (
            f"INSERT INTO {TABLE_NAME} (target_type, target_value, level, mark_code, reason, "
            f"source, status, created_by, created_at, updated_at, expires_at, extra) "
            f"VALUES ({_placeholders(12)})"
        )
        params = (
            mark.target_type, mark.target_value, mark.level, mark.mark_code, mark.reason,
            mark.source, mark.status, mark.created_by, mark.created_at, mark.updated_at,
            mark.expires_at, dump_extra(mark.extra),
        )
        new_id = _execute_write(conn, sql, params)
        return int(new_id) if new_id else None
    except ValueError:
        raise
    except Exception as e:
        logger.error(f"密标写入失败: {e}")
        return None
    finally:
        conn.close()


def get_mark(target_type: str, target_value: str) -> Optional[Dict[str, Any]]:
    conn = get_connection()
    try:
        _ensure_table_ready(conn)
        return _fetch_mark_row(conn, target_type, target_value)
    except Exception as e:
        logger.debug(f"密标查询失败: {e}")
        return None
    finally:
        conn.close()


def list_marks(
    target_type: str = '',
    level: str = '',
    status: str = STATUS_ACTIVE,
    keyword: str = '',
    limit: int = 200,
    offset: int = 0,
):
    """按条件分页查询密标，返回 (记录列表, 命中总数)。"""
    try:
        limit_v = max(1, min(int(limit), 500))
    except (TypeError, ValueError):
        limit_v = 200
    try:
        offset_v = max(0, int(offset))
    except (TypeError, ValueError):
        offset_v = 0

    where, params = _build_filters(target_type, level, status, keyword)
    conn = get_connection()
    try:
        _ensure_table_ready(conn)
        cursor = conn.cursor()
        count_sql = f"SELECT COUNT(*) AS cnt FROM {TABLE_NAME}"
        if where:
            count_sql += ' WHERE ' + ' AND '.join(where)
        cursor.execute(count_sql, tuple(params))
        count_rows = _rows_to_dict(cursor, cursor.fetchall())
        if count_rows:
            first = count_rows[0]
            total = int((first.get('cnt') if USE_MYSQL else list(first.values())[0]) or 0)
        else:
            total = 0

        # 密级排序在 Python 侧完成，避免依赖不同数据库的枚举排序能力
        data_sql = f"SELECT {_SELECT_COLUMNS} FROM {TABLE_NAME}"
        if where:
            data_sql += ' WHERE ' + ' AND '.join(where)
        data_sql += f" ORDER BY updated_at DESC LIMIT {limit_v} OFFSET {offset_v}"
        cursor.execute(data_sql, tuple(params))
        rows = _rows_to_dict(cursor, cursor.fetchall())
        return rows, total
    except Exception as e:
        logger.error(f"密标列表查询失败: {e}")
        return [], 0
    finally:
        conn.close()


def _build_filters(target_type: str, level: str, status: str, keyword: str):
    ph = _placeholder()
    where: List[str] = []
    params: List[Any] = []
    tt = str(target_type or '').strip().lower()
    if tt:
        where.append(f"target_type = {ph}")
        params.append(tt)
    lv = str(level or '').strip().lower()
    if lv in LEVELS:
        where.append(f"level = {ph}")
        params.append(lv)
    st = str(status or '').strip().lower()
    if st:
        where.append(f"status = {ph}")
        params.append(st)
    kw = str(keyword or '').strip()
    if kw:
        like = f"%{kw[:80]}%"
        where.append(
            f"(target_value LIKE {ph} OR reason LIKE {ph} OR mark_code LIKE {ph} OR created_by LIKE {ph})"
        )
        params.extend([like, like, like, like])
    return where, params


def count_by_level(status: str = STATUS_ACTIVE) -> Dict[str, int]:
    """按密级统计数量，用于大屏角标与列表头部。"""
    ph = _placeholder()
    conn = get_connection()
    result = {lv: 0 for lv in LEVELS}
    try:
        _ensure_table_ready(conn)
        cursor = conn.cursor()
        sql = f"SELECT level, COUNT(*) AS cnt FROM {TABLE_NAME}"
        params: List[Any] = []
        if str(status or '').strip():
            sql += f" WHERE status = {ph}"
            params.append(str(status).strip().lower())
        sql += ' GROUP BY level'
        cursor.execute(sql, tuple(params))
        for row in _rows_to_dict(cursor, cursor.fetchall()):
            key = str(row.get('level') or '').strip().lower()
            if key in result:
                result[key] = int(row.get('cnt') or 0)
        return result
    except Exception as e:
        logger.debug(f"密标密级统计失败: {e}")
        return result
    finally:
        conn.close()


def count_total(status: str = STATUS_ACTIVE) -> int:
    ph = _placeholder()
    conn = get_connection()
    try:
        _ensure_table_ready(conn)
        cursor = conn.cursor()
        sql = f"SELECT COUNT(*) AS cnt FROM {TABLE_NAME}"
        params: List[Any] = []
        if str(status or '').strip():
            sql += f" WHERE status = {ph}"
            params.append(str(status).strip().lower())
        cursor.execute(sql, tuple(params))
        rows = _rows_to_dict(cursor, cursor.fetchall())
        if not rows:
            return 0
        first = rows[0]
        return int((first.get('cnt') if USE_MYSQL else list(first.values())[0]) or 0)
    except Exception as e:
        logger.debug(f"密标计数失败: {e}")
        return 0
    finally:
        conn.close()


def delete_mark(mark_id=None, target_type: str = '', target_value: str = '') -> int:
    """删除密标：优先按 ID，其次按 (target_type, target_value)。返回删除行数。"""
    ph = _placeholder()
    conn = get_connection()
    try:
        _ensure_table_ready(conn)
        if mark_id not in (None, ''):
            try:
                mid = int(mark_id)
            except (TypeError, ValueError):
                return 0
            sql = f"DELETE FROM {TABLE_NAME} WHERE id = {ph}"
            params = (mid,)
        else:
            tt = str(target_type or '').strip().lower()
            tv = str(target_value or '').strip()
            if not tt or not tv:
                return 0
            sql = f"DELETE FROM {TABLE_NAME} WHERE target_type = {ph} AND target_value = {ph}"
            params = (tt, tv)
        cursor = conn.cursor()
        cursor.execute(sql, params)
        affected = int(cursor.rowcount or 0)
        conn.commit()
        return affected
    except Exception as e:
        logger.error(f"密标删除失败: {e}")
        return 0
    finally:
        conn.close()


def expire_due_marks(now: str = '') -> int:
    """把已过有效期的密标置为 expired，返回受影响行数。"""
    ph = _placeholder()
    current = str(now or '').strip() or now_text()
    conn = get_connection()
    try:
        _ensure_table_ready(conn)
        sql = (
            f"UPDATE {TABLE_NAME} SET status = {ph}, updated_at = {ph} "
            f"WHERE status = {ph} AND expires_at IS NOT NULL AND expires_at <> '' AND expires_at <= {ph}"
        )
        params = ('expired', current, STATUS_ACTIVE, current)
        cursor = conn.cursor()
        cursor.execute(sql, params)
        affected = int(cursor.rowcount or 0)
        conn.commit()
        return affected
    except Exception as e:
        logger.debug(f"密标过期处理失败: {e}")
        return 0
    finally:
        conn.close()


def get_marks_map(target_type: str, values: Sequence[str]) -> Dict[str, Dict[str, Any]]:
    """批量查询多个对象的密标，返回 {对象值: 密标字典}，用于事件列表打标。"""
    keys = [str(v or '').strip() for v in (values or []) if str(v or '').strip()]
    keys = list(dict.fromkeys(keys))[:MAX_BATCH_TARGETS]
    if not keys:
        return {}
    tt = str(target_type or '').strip().lower()
    ph = _placeholder()
    conn = get_connection()
    result: Dict[str, Dict[str, Any]] = {}
    try:
        _ensure_table_ready(conn)
        cursor = conn.cursor()
        sql = (
            f"SELECT {_SELECT_COLUMNS} FROM {TABLE_NAME} "
            f"WHERE target_type = {ph} AND status = {ph} AND target_value IN ({_placeholders(len(keys))})"
        )
        params = [tt, STATUS_ACTIVE] + keys
        cursor.execute(sql, tuple(params))
        for row in _rows_to_dict(cursor, cursor.fetchall()):
            result[str(row.get('target_value') or '')] = row
        return result
    except Exception as e:
        logger.debug(f"密标批量查询失败: {e}")
        return {}
    finally:
        conn.close()


def count_recent_high_events(ip: str, hours: int = 24) -> int:
    """统计某 IP 在窗口内的高危事件数，供自动识别器使用。"""
    key = str(ip or '').strip()
    if not key:
        return 0
    try:
        hours_v = int(hours)
    except (TypeError, ValueError):
        hours_v = 24
    hours_v = max(1, min(hours_v, 24 * 30))
    cutoff = (datetime.now() - timedelta(hours=hours_v)).strftime('%Y-%m-%d %H:%M:%S')
    ph = _placeholder()
    conn = get_connection()
    try:
        cursor = conn.cursor()
        sql = (
            f"SELECT COUNT(*) AS cnt FROM event_log "
            f"WHERE src_ip = {ph} AND timestamp >= {ph} AND severity IN ({ph}, {ph})"
        )
        cursor.execute(sql, (key, cutoff, LEVEL_HIGH, LEVEL_CRITICAL))
        rows = _rows_to_dict(cursor, cursor.fetchall())
        if not rows:
            return 0
        first = rows[0]
        return int((first.get('cnt') if USE_MYSQL else list(first.values())[0]) or 0)
    except Exception as e:
        logger.debug(f"高危事件统计失败({key}): {e}")
        return 0
    finally:
        conn.close()


__all__ = [
    'upsert_mark',
    'get_mark',
    'list_marks',
    'count_by_level',
    'count_total',
    'delete_mark',
    'expire_due_marks',
    'get_marks_map',
    'count_recent_high_events',
]
