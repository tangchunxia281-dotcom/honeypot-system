# -*- coding: utf-8 -*-
"""
风险目标标注（risk_target）
============================

独立于 event_log 的运营态标注数据：以「攻击源 IP」为维度，
支持「从攻击事件自动识别」与「管理端人工标注」两种来源。

- 不改动 event_log 的写入链路（log_event 不受影响）；
- 本表属运营态标注数据，不纳入 db/archive.py 的冷归档。
"""
import json
from datetime import datetime, timedelta
from threading import Lock

try:
    from zoneinfo import ZoneInfo
except Exception:  # pragma: no cover
    ZoneInfo = None

from app_config import env_bool, env_int, env_str
from .connection import (
    USE_MYSQL,
    get_connection,
    _truncate_text,
    _sqlite_run_with_retry,
    logger,
)
from .event_logs import _HIDDEN_EVENT_TYPES

# 数值上限（不映射到 honeypot.ini，避免扩展配置面）
_NOTE_MAX = 2000
_TAGS_MAX = 400

_RT_ENABLED = env_bool('RISK_TARGET_ENABLED', True)
_RT_AUTO_DERIVE = env_bool('RISK_TARGET_AUTO_DERIVE', True)
_RT_DERIVE_HOURS = env_int('RISK_TARGET_DERIVE_HOURS', 24, 1, 24 * 30)
_RT_MIN_EVENTS = env_int('RISK_TARGET_MIN_EVENTS', 2, 1, 10000)
_RT_MIN_SEVERITY = env_str('RISK_TARGET_MIN_SEVERITY', 'medium')

# 参与自动识别的蜜罐协议来源（排除 dashboard/system 等内部来源）
_RT_HONEYPOT_SOURCES = ('web', 'ssh', 'mysql', 'redis', 'ftp', 'telnet')

_SEVERITY_RANK = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'unknown': 0}
_RANK_SEVERITY = {4: 'critical', 3: 'high', 2: 'medium', 1: 'low'}

_TABLE_LOCK = Lock()
_TABLE_READY = {'sqlite': False, 'mysql': False}


def _now_text() -> str:
    try:
        if ZoneInfo is not None:
            return datetime.now(ZoneInfo('Asia/Shanghai')).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        pass
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')


def _normalize_risk_level(x) -> str:
    s = str(x or '').strip().lower()
    return s if s in ('low', 'medium', 'high', 'critical') else 'medium'


def _normalize_status(x) -> str:
    s = str(x or '').strip().lower()
    return s if s in ('watching', 'banned', 'handled') else 'watching'


def _normalize_tags(tags) -> str:
    if tags is None:
        return '[]'
    items = tags if isinstance(tags, (list, tuple, set)) else str(tags).split(',')
    out = []
    for t in items:
        x = _truncate_text(str(t or '').strip(), 24)
        if x and x not in out:
            out.append(x)
        if len(out) >= 20:
            break
    return _truncate_text(json.dumps(out, ensure_ascii=False), _TAGS_MAX)


def _ensure_risk_target_table(conn) -> None:
    key = 'mysql' if USE_MYSQL else 'sqlite'
    if _TABLE_READY.get(key):
        return
    with _TABLE_LOCK:
        if _TABLE_READY.get(key):
            return
        cursor = conn.cursor()
        if USE_MYSQL:
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS risk_target (
                    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
                    target_type VARCHAR(16) NOT NULL DEFAULT 'ip',
                    target_value VARCHAR(64) NOT NULL,
                    risk_level VARCHAR(16) NOT NULL DEFAULT 'medium',
                    status VARCHAR(16) NOT NULL DEFAULT 'watching',
                    tags TEXT,
                    note TEXT,
                    source VARCHAR(16) NOT NULL DEFAULT 'auto',
                    first_seen DATETIME DEFAULT NULL,
                    last_seen DATETIME DEFAULT NULL,
                    event_count INT DEFAULT 0,
                    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    PRIMARY KEY (id),
                    UNIQUE KEY uk_risk_target_value (target_value),
                    KEY idx_rt_risk_level (risk_level),
                    KEY idx_rt_status (status)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
                """
            )
        else:
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS risk_target (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_type TEXT NOT NULL DEFAULT 'ip',
                    target_value TEXT NOT NULL UNIQUE,
                    risk_level TEXT NOT NULL DEFAULT 'medium',
                    status TEXT NOT NULL DEFAULT 'watching',
                    tags TEXT,
                    note TEXT,
                    source TEXT NOT NULL DEFAULT 'auto',
                    first_seen DATETIME,
                    last_seen DATETIME,
                    event_count INTEGER DEFAULT 0,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_rt_risk_level ON risk_target(risk_level)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_rt_status ON risk_target(status)')
        conn.commit()
        _TABLE_READY[key] = True


def _rows_to_dict(cursor, rows):
    if USE_MYSQL:
        return rows
    cols = [d[0] for d in cursor.description]
    return [dict(zip(cols, r)) for r in rows]


def _fetch_all(conn, sql, params):
    cursor = conn.cursor()
    cursor.execute(sql, tuple(params))
    return _rows_to_dict(cursor, cursor.fetchall())


def _fetch_one(conn, sql, params):
    cursor = conn.cursor()
    cursor.execute(sql, tuple(params))
    rows = _rows_to_dict(cursor, cursor.fetchall())
    return rows[0] if rows else None


def _exec_write(conn, sql_template, params):
    """写操作：SQL 模板统一用 ? 占位，MySQL 下替换为 %s；SQLite 走重试。"""
    ph = '%s' if USE_MYSQL else '?'
    sql = sql_template.replace('?', ph)
    if USE_MYSQL:
        cur = conn.cursor()
        cur.execute(sql, tuple(params))
        conn.commit()
        return cur.lastrowid

    def _action(c):
        c.execute(sql, tuple(params))
        return c.lastrowid

    return _sqlite_run_with_retry(conn, _action)


def derive_risk_targets(hours=None) -> int:
    """从 event_log 聚合攻击源，自动识别风险目标。返回 upsert 数量。"""
    if not _RT_ENABLED:
        return 0
    try:
        h = int(hours) if hours not in (None, '') else _RT_DERIVE_HOURS
    except Exception:
        h = _RT_DERIVE_HOURS
    h = max(1, min(h, 24 * 30))
    min_rank = _SEVERITY_RANK.get(_normalize_risk_level(_RT_MIN_SEVERITY), 2)
    cutoff = (datetime.now() - timedelta(hours=h)).strftime('%Y-%m-%d %H:%M:%S')

    conn = get_connection()
    try:
        _ensure_risk_target_table(conn)
        sql = (
            "SELECT src_ip, COUNT(*) AS cnt, "
            "MAX(CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 "
            "     WHEN 'medium' THEN 2 ELSE 1 END) AS sev_rank, "
            "MIN(timestamp) AS first_seen, MAX(timestamp) AS last_seen "
            "FROM event_log "
            "WHERE timestamp >= ? AND source IN ({srcs}) AND event_type NOT IN ({hidden}) "
            "AND src_ip IS NOT NULL AND src_ip != '' "
            "GROUP BY src_ip"
        ).format(
            srcs=', '.join(['?'] * len(_RT_HONEYPOT_SOURCES)),
            hidden=', '.join(['?'] * len(_HIDDEN_EVENT_TYPES)),
        )
        params = [cutoff] + list(_RT_HONEYPOT_SOURCES) + list(_HIDDEN_EVENT_TYPES)
        rows = _fetch_all(conn, sql, params)

        existing = {
            str(r.get('target_value') or '').strip(): r
            for r in _fetch_all(conn, "SELECT * FROM risk_target", [])
        }

        touched = 0
        for r in rows:
            ip = str(r.get('src_ip') or '').strip()
            if not ip:
                continue
            cnt = int(r.get('cnt') or 0)
            sev_rank = int(r.get('sev_rank') or 0)
            if cnt < _RT_MIN_EVENTS or sev_rank < min_rank:
                continue
            first_seen = str(r.get('first_seen') or '') or _now_text()
            last_seen = str(r.get('last_seen') or '') or _now_text()
            level = _RANK_SEVERITY.get(sev_rank, 'low')

            if ip in existing:
                old = existing[ip]
                new_first = min(str(old.get('first_seen') or '') or first_seen, first_seen)
                new_last = max(str(old.get('last_seen') or '') or last_seen, last_seen)
                if str(old.get('source') or 'auto').strip().lower() == 'manual':
                    # 人工标注目标仅刷新统计，不覆盖标注字段
                    _exec_write(
                        conn,
                        "UPDATE risk_target SET first_seen=?, last_seen=?, event_count=?, updated_at=? WHERE id=?",
                        [new_first, new_last, cnt, _now_text(), old.get('id')],
                    )
                else:
                    _exec_write(
                        conn,
                        "UPDATE risk_target SET risk_level=?, first_seen=?, last_seen=?, event_count=?, updated_at=? WHERE id=?",
                        [level, new_first, new_last, cnt, _now_text(), old.get('id')],
                    )
            else:
                _exec_write(
                    conn,
                    "INSERT INTO risk_target (target_type, target_value, risk_level, status, tags, note, "
                    "source, first_seen, last_seen, event_count, created_at, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    ['ip', ip, level, 'watching', '[]', '', 'auto',
                     first_seen, last_seen, cnt, _now_text(), _now_text()],
                )
            touched += 1
        return touched
    except Exception as e:
        logger.debug(f"risk_target 自动识别失败: {e}")
        return 0
    finally:
        conn.close()


def list_risk_targets(target_type='', risk_level='', status='', keyword='', limit=100, offset=0):
    try:
        limit = max(1, min(int(limit), 500))
    except Exception:
        limit = 100
    try:
        offset = max(0, min(int(offset), 50000))
    except Exception:
        offset = 0

    where = []
    params = []
    tt = str(target_type or '').strip().lower()
    if tt:
        where.append("target_type = ?")
        params.append(tt)
    rl = str(risk_level or '').strip().lower()
    if rl:
        where.append("risk_level = ?")
        params.append(_normalize_risk_level(rl))
    st = str(status or '').strip().lower()
    if st:
        where.append("status = ?")
        params.append(_normalize_status(st))
    kw = str(keyword or '').strip()
    if kw:
        like = f"%{_truncate_text(kw, 80)}%"
        where.append("(target_value LIKE ? OR note LIKE ? OR tags LIKE ?)")
        params.extend([like, like, like])

    conn = get_connection()
    try:
        _ensure_risk_target_table(conn)
        sql = "SELECT * FROM risk_target"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY event_count DESC, updated_at DESC, id DESC"
        sql += f" LIMIT {limit} OFFSET {offset}"
        return _fetch_all(conn, sql, params)
    finally:
        conn.close()


def get_risk_target(target_id=None, target_value=None):
    conn = get_connection()
    try:
        _ensure_risk_target_table(conn)
        if target_id is not None:
            return _fetch_one(conn, "SELECT * FROM risk_target WHERE id = ?", [target_id])
        tv = str(target_value or '').strip()
        if tv:
            return _fetch_one(conn, "SELECT * FROM risk_target WHERE target_value = ?", [tv])
        return None
    finally:
        conn.close()


def upsert_risk_target(target_value, target_type='ip', risk_level=None, status=None,
                       tags=None, note=None, source='manual'):
    tv = _truncate_text(str(target_value or '').strip(), 64)
    if not tv:
        return {'ok': False, 'msg': 'target_value 不能为空'}
    tt = _truncate_text(str(target_type or 'ip').strip().lower(), 16) or 'ip'
    level = _normalize_risk_level(risk_level)
    st = _normalize_status(status)
    tags_text = _normalize_tags(tags)
    note_text = _truncate_text(str(note or ''), _NOTE_MAX)
    src = 'manual' if str(source or 'manual').strip().lower() != 'auto' else 'auto'

    conn = get_connection()
    try:
        _ensure_risk_target_table(conn)
        existing = _fetch_one(conn, "SELECT id, first_seen FROM risk_target WHERE target_value = ?", [tv])
        now = _now_text()
        if existing:
            _exec_write(
                conn,
                "UPDATE risk_target SET target_type=?, risk_level=?, status=?, tags=?, note=?, source=?, updated_at=? WHERE id=?",
                [tt, level, st, tags_text, note_text, src, now, existing.get('id')],
            )
            rid = existing.get('id')
        else:
            rid = _exec_write(
                conn,
                "INSERT INTO risk_target (target_type, target_value, risk_level, status, tags, note, "
                "source, first_seen, last_seen, event_count, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [tt, tv, level, st, tags_text, note_text, src, now, now, 0, now, now],
            )
        return {'ok': True, 'id': rid}
    except Exception as e:
        logger.debug(f"risk_target upsert 失败: {e}")
        return {'ok': False, 'msg': str(e)}
    finally:
        conn.close()


def update_risk_target(target_id, **fields):
    updates = []
    params = []
    if fields.get('target_type') is not None:
        updates.append("target_type = ?")
        params.append(_truncate_text(str(fields.get('target_type')).strip().lower(), 16) or 'ip')
    if fields.get('target_value') is not None:
        tv = _truncate_text(str(fields.get('target_value')).strip(), 64)
        if not tv:
            return {'ok': False, 'msg': 'target_value 不能为空'}
        updates.append("target_value = ?")
        params.append(tv)
    if fields.get('risk_level') is not None:
        updates.append("risk_level = ?")
        params.append(_normalize_risk_level(fields.get('risk_level')))
    if fields.get('status') is not None:
        updates.append("status = ?")
        params.append(_normalize_status(fields.get('status')))
    if fields.get('tags') is not None:
        updates.append("tags = ?")
        params.append(_normalize_tags(fields.get('tags')))
    if fields.get('note') is not None:
        updates.append("note = ?")
        params.append(_truncate_text(str(fields.get('note') or ''), _NOTE_MAX))
    if fields.get('source') is not None:
        updates.append("source = ?")
        params.append('manual' if str(fields.get('source')).strip().lower() != 'auto' else 'auto')

    if not updates:
        return {'ok': False, 'msg': '无可更新字段'}
    updates.append("updated_at = ?")
    params.append(_now_text())
    params.append(int(target_id))

    conn = get_connection()
    try:
        _ensure_risk_target_table(conn)
        _exec_write(conn, "UPDATE risk_target SET " + ", ".join(updates) + " WHERE id = ?", params)
        return {'ok': True, 'id': int(target_id)}
    except Exception as e:
        logger.debug(f"risk_target update 失败: {e}")
        return {'ok': False, 'msg': str(e)}
    finally:
        conn.close()


def delete_risk_target(target_id):
    conn = get_connection()
    try:
        _ensure_risk_target_table(conn)
        _exec_write(conn, "DELETE FROM risk_target WHERE id = ?", [int(target_id)])
        return {'ok': True}
    except Exception as e:
        logger.debug(f"risk_target delete 失败: {e}")
        return {'ok': False, 'msg': str(e)}
    finally:
        conn.close()


__all__ = [
    'derive_risk_targets',
    'list_risk_targets',
    'get_risk_target',
    'upsert_risk_target',
    'update_risk_target',
    'delete_risk_target',
]