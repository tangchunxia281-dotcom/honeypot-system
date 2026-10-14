# -*- coding: utf-8 -*-
"""
统一事件日志（event_log）
用于跨 Web/SSH 的统一事件模型写入与查询。
"""
import json
import os
import copy
import time
from datetime import datetime, timedelta
from collections import Counter
from threading import Lock
from env_utils import env_int as _env_int
try:
    from zoneinfo import ZoneInfo
except Exception:  # pragma: no cover
    ZoneInfo = None

from utils.alerting import ALERT_RISK_THRESHOLD, ALERT_HIGH_THRESHOLD, ALERT_CRITICAL_THRESHOLD
from .connection import (
    USE_MYSQL,
    get_connection,
    _redact_sensitive_text,
    _truncate_text,
    _sqlite_run_with_retry,
    logger,
)
from .archive import fetch_archive_count, fetch_archive_group_counts, fetch_archive_rows

_EVENT_PAYLOAD_MAX = _env_int('EVENT_PAYLOAD_MAX', 2048, 128, 20000)  # payload 最大字符数
_EVENT_EXTRA_MAX = _env_int('EVENT_EXTRA_MAX', 4096, 256, 40000)      # extra 最大字符数
_EVENT_QUERY_BATCH = _env_int('EVENT_QUERY_BATCH', 1000, 100, 5000)   # 聚合查询批次大小
_EVENT_STATS_CACHE_TTL = _env_int('EVENT_STATS_CACHE_TTL', 3, 0, 300) # 统计缓存有效期（秒）
_EVENT_STATS_CACHE_MAX_KEYS = _env_int('EVENT_STATS_CACHE_MAX_KEYS', 16, 1, 256)

_EVENT_TABLE_LOCK = Lock()
_EVENT_TABLE_READY = {'sqlite': False, 'mysql': False}
_EVENT_STATS_CACHE_LOCK = Lock()
_EVENT_STATS_CACHE = {}
_HIDDEN_EVENT_TYPES = ('ssh_cmd_audit', 'ssh_cmd_suspicious', 'web', 'web_activity_note')


def _now_text() -> str:
    try:
        if ZoneInfo is not None:
            return datetime.now(ZoneInfo('Asia/Shanghai')).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        pass
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')


def _clear_event_stats_cache() -> None:
    if _EVENT_STATS_CACHE_TTL <= 0:
        return
    with _EVENT_STATS_CACHE_LOCK:
        _EVENT_STATS_CACHE.clear()


def _get_event_stats_cache(hours: int):
    if _EVENT_STATS_CACHE_TTL <= 0:
        return None
    now = time.monotonic()
    key = str(int(hours))
    with _EVENT_STATS_CACHE_LOCK:
        item = _EVENT_STATS_CACHE.get(key)
        if not item:
            return None
        if now - float(item.get('ts', 0.0)) > _EVENT_STATS_CACHE_TTL:
            _EVENT_STATS_CACHE.pop(key, None)
            return None
        data = item.get('data')
        return copy.deepcopy(data) if isinstance(data, dict) else None


def _set_event_stats_cache(hours: int, data: dict) -> None:
    if _EVENT_STATS_CACHE_TTL <= 0 or not isinstance(data, dict):
        return
    now = time.monotonic()
    key = str(int(hours))
    with _EVENT_STATS_CACHE_LOCK:
        if len(_EVENT_STATS_CACHE) >= _EVENT_STATS_CACHE_MAX_KEYS:
            oldest_key = None
            oldest_ts = None
            for k, v in _EVENT_STATS_CACHE.items():
                ts = float(v.get('ts', 0.0))
                if oldest_ts is None or ts < oldest_ts:
                    oldest_key = k
                    oldest_ts = ts
            if oldest_key is not None:
                _EVENT_STATS_CACHE.pop(oldest_key, None)
        _EVENT_STATS_CACHE[key] = {'ts': now, 'data': copy.deepcopy(data)}


def severity_from_score(score: int) -> str:
    try:
        n = int(score)
    except Exception:
        n = 0
    if n >= ALERT_CRITICAL_THRESHOLD:
        return 'critical'
    if n >= ALERT_HIGH_THRESHOLD:
        return 'high'
    if n >= ALERT_RISK_THRESHOLD:
        return 'medium'
    return 'low'


def _normalize_source(source: str) -> str:
    s = str(source or '').strip().lower()
    if s in ('web', 'ssh', 'dashboard', 'system'):
        return s
    return 'system'


def _normalize_severity(severity: str) -> str:
    s = str(severity or '').strip().lower()
    mapping = {
        'critical': 'critical',
        'high': 'high',
        'medium': 'medium',
        'med': 'medium',
        'low': 'low',
        '严重': 'critical',
        '高危': 'high',
        '警告': 'medium',
        '提示': 'low',
    }
    return mapping.get(s, 'low')


def _normalize_tags(tags) -> list:
    out = []
    if tags is None:
        return out
    items = tags if isinstance(tags, (list, tuple, set)) else [tags]
    for t in items:
        x = str(t or '').strip().lower()
        if not x:
            continue
        x = _truncate_text(x, 24)
        if x not in out:
            out.append(x)
        if len(out) >= 20:
            break
    return out


def _safe_json_dumps(value, max_len: int) -> str:
    if value is None:
        return ''
    if isinstance(value, (dict, list, tuple)):
        text = json.dumps(value, ensure_ascii=False)
    else:
        text = str(value)
    text = _redact_sensitive_text(text)
    return _truncate_text(text, max_len)


def _ensure_event_log_table(conn) -> None:
    cursor = conn.cursor()
    if USE_MYSQL:
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS event_log (
                id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
                timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                source VARCHAR(16) NOT NULL,
                severity VARCHAR(16) NOT NULL,
                event_type VARCHAR(64) NOT NULL,
                src_ip VARCHAR(64) DEFAULT '',
                session_id VARCHAR(64) DEFAULT '',
                tags TEXT,
                payload TEXT,
                raw_ref VARCHAR(128) DEFAULT '',
                raw_request_id BIGINT DEFAULT NULL,
                extra TEXT,
                PRIMARY KEY (id),
                INDEX idx_event_time (timestamp),
                INDEX idx_event_source (source),
                INDEX idx_event_severity (severity),
                INDEX idx_event_type (event_type),
                INDEX idx_event_ip (src_ip),
                INDEX idx_event_raw_request (raw_request_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """
        )
        try:
            cursor.execute(
                """
                SELECT COUNT(*) AS cnt
                FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA = DATABASE()
                  AND TABLE_NAME = 'event_log'
                  AND COLUMN_NAME = 'raw_request_id'
                """
            )
            row = cursor.fetchone() or {}
            cnt = int(row.get('cnt') or 0)
            if cnt == 0:
                cursor.execute("ALTER TABLE event_log ADD COLUMN raw_request_id BIGINT DEFAULT NULL")
            cursor.execute(
                """
                SELECT COUNT(*) AS cnt
                FROM information_schema.STATISTICS
                WHERE TABLE_SCHEMA = DATABASE()
                  AND TABLE_NAME = 'event_log'
                  AND INDEX_NAME = 'idx_event_raw_request'
                """
            )
            idx_row = cursor.fetchone() or {}
            idx_cnt = int(idx_row.get('cnt') or 0)
            if idx_cnt == 0:
                cursor.execute("CREATE INDEX idx_event_raw_request ON event_log(raw_request_id)")
        except Exception:
            pass
    else:
        cursor.execute(
            """
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
            """
        )
        try:
            cursor.execute("PRAGMA table_info(event_log)")
            cols = {str(row[1]).strip().lower() for row in (cursor.fetchall() or [])}
            if 'raw_request_id' not in cols:
                cursor.execute("ALTER TABLE event_log ADD COLUMN raw_request_id INTEGER DEFAULT NULL")
        except Exception:
            pass
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_event_time ON event_log(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_event_source ON event_log(source)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_event_severity ON event_log(severity)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_event_type ON event_log(event_type)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_event_ip ON event_log(src_ip)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_event_raw_request ON event_log(raw_request_id)')
    conn.commit()


def _ensure_event_table_ready(conn) -> None:
    key = 'mysql' if USE_MYSQL else 'sqlite'
    if _EVENT_TABLE_READY.get(key):
        return
    with _EVENT_TABLE_LOCK:
        if _EVENT_TABLE_READY.get(key):
            return
        _ensure_event_log_table(conn)
        _EVENT_TABLE_READY[key] = True


def _rows_to_dict(cursor, rows):
    if USE_MYSQL:
        return rows
    cols = [d[0] for d in cursor.description]
    return [dict(zip(cols, r)) for r in rows]


def _event_row_sort_key(row: dict):
    item = row if isinstance(row, dict) else {}
    try:
        row_id = int(item.get('id') or 0)
    except Exception:
        row_id = 0
    return (str(item.get('timestamp') or ''), row_id)


def _merge_event_rows(rows: list, offset: int, limit: int) -> list:
    rows = [r for r in rows or [] if isinstance(r, dict)]
    rows.sort(key=_event_row_sort_key, reverse=True)
    return rows[offset:offset + limit]


def _merge_archive_group_counts(counter: Counter, rows: list, default_key: str = 'unknown') -> None:
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        key = str(row.get('group_key') or default_key)
        try:
            count = int(row.get('count') or 0)
        except Exception:
            count = 0
        if count > 0:
            counter[key] += count


def _notify_risk_mark(source: str, severity: str, event_type: str, src_ip: str,
                      session_id: str, payload: str, extra) -> None:
    """[risk-mark] 事件落库后通知密标模块做实时识别。

    惰性导入避免 db <-> risk_mark 循环依赖；risk_mark 目录被整体删除时静默跳过。
    on_event 自身异常安全，且默认关闭（[risk_mark] auto_detect_enabled=false），
    因此此处无条件调用即可，不影响主流程性能与稳定性。
    """
    try:
        from risk_mark import service as _risk_mark_service
        _risk_mark_service.on_event(
            source=source, severity=severity, event_type=event_type, src_ip=src_ip,
            session_id=session_id, payload=payload, extra=extra,
        )
    except Exception:
        pass


def log_event(source: str, severity: str, event_type: str, src_ip: str,
              session_id: str = '', tags=None, payload: str = '', raw_ref: str = '',
              raw_request_id=None, extra=None, timestamp: str = ''):
    """
    写入统一事件日志。

    Args:
        source: 事件来源，支持 web/ssh/dashboard/system。
        severity: 风险级别，支持 low/medium/high/critical。
        event_type: 事件类型，如 login_failed、path_probe。
        src_ip: 来源 IP。
        session_id: 会话标识（可选）。
        tags: 标签列表（可选）。
        payload: 事件摘要，会自动脱敏和截断。
        raw_ref: 原始引用信息（可选）。
        raw_request_id: 关联 raw_request 记录 ID（可选）。
        extra: 扩展信息字典（可选）。
        timestamp: 自定义时间戳（可选，默认当前时间）。

    Returns:
        int | None: 新增行 ID，失败返回 None。
    """
    conn = get_connection()
    try:
        _ensure_event_table_ready(conn)
        src = _normalize_source(source)
        sev = _normalize_severity(severity)
        evt = _truncate_text(str(event_type or 'unknown').strip().lower(), 64)
        ip = _truncate_text(str(src_ip or '').strip(), 64)
        sid = _truncate_text(str(session_id or '').strip(), 64)
        raw = _truncate_text(str(raw_ref or '').strip(), 128)
        try:
            raw_req_id = int(raw_request_id) if raw_request_id is not None else None
        except Exception:
            raw_req_id = None
        if raw_req_id is not None and raw_req_id <= 0:
            raw_req_id = None
        tag_text = json.dumps(_normalize_tags(tags), ensure_ascii=False)
        safe_payload = _safe_json_dumps(payload, _EVENT_PAYLOAD_MAX)
        safe_extra = _safe_json_dumps(extra, _EVENT_EXTRA_MAX)
        ts = _truncate_text(str(timestamp or '').strip(), 32)
        if not ts:
            # 统一按北京时间落库，避免受系统时区或 SQLite CURRENT_TIMESTAMP(UTC) 影响
            ts = _now_text()

        placeholder = '%s' if USE_MYSQL else '?'
        params = [ts, src, sev, evt, ip, sid, tag_text, safe_payload, raw, raw_req_id, safe_extra]
        sql = (
            "INSERT INTO event_log "
            f"(timestamp, source, severity, event_type, src_ip, session_id, tags, payload, raw_ref, raw_request_id, extra) "
            f"VALUES ({placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder}, "
            f"{placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder})"
        )

        if USE_MYSQL:
            cursor = conn.cursor()
            cursor.execute(sql, tuple(params))
            conn.commit()
            _clear_event_stats_cache()
            new_id = cursor.lastrowid
        else:
            def _insert_action(c):
                c.execute(sql, tuple(params))
                return c.lastrowid

            new_id = _sqlite_run_with_retry(conn, _insert_action)
            _clear_event_stats_cache()

        # [risk-mark] 实时识别钩子（异常安全；总开关默认关闭）
        _notify_risk_mark(src, sev, evt, ip, sid, safe_payload, extra)
        return new_id
    except Exception as e:
        logger.debug(f"event_log 写入失败: {e}")
        return None
    finally:
        conn.close()


def get_event_logs(
    limit=100,
    offset=0,
    source: str = '',
    severity: str = '',
    event_type: str = '',
    keyword: str = '',
    hours=None,
):
    try:
        limit = int(limit)
    except Exception:
        limit = 100
    try:
        offset = int(offset)
    except Exception:
        offset = 0
    limit = max(1, min(limit, 500))
    offset = max(0, min(offset, 50000))
    try:
        hours_v = int(hours) if hours not in (None, '') else None
    except Exception:
        hours_v = None
    if hours_v is not None:
        hours_v = max(1, min(hours_v, 24 * 30))

    conn = get_connection()
    try:
        _ensure_event_table_ready(conn)
        placeholder = '%s' if USE_MYSQL else '?'
        where = []
        params = []
        cutoff = ''

        s = str(source or '').strip().lower()
        if s:
            where.append(f"source = {placeholder}")
            params.append(s)

        sev = str(severity or '').strip().lower()
        if sev:
            where.append(f"severity = {placeholder}")
            params.append(_normalize_severity(sev))

        et = str(event_type or '').strip().lower()
        if et:
            where.append(f"event_type = {placeholder}")
            params.append(_truncate_text(et, 64))

        kw = str(keyword or '').strip()
        if kw:
            kw_like = f"%{_truncate_text(kw, 80)}%"
            where.append(
                f"(src_ip LIKE {placeholder} OR payload LIKE {placeholder} "
                f"OR event_type LIKE {placeholder} OR tags LIKE {placeholder})"
            )
            params.extend([kw_like, kw_like, kw_like, kw_like])
        for et_hidden in _HIDDEN_EVENT_TYPES:
            where.append(f"event_type <> {placeholder}")
            params.append(et_hidden)
        if hours_v is not None:
            cutoff = (datetime.now() - timedelta(hours=hours_v)).strftime('%Y-%m-%d %H:%M:%S')
            where.append(f"timestamp >= {placeholder}")
            params.append(cutoff)

        sql = "SELECT id, timestamp, source, severity, event_type, src_ip, session_id, tags, payload, raw_ref, raw_request_id, extra FROM event_log"
        if where:
            sql += " WHERE " + " AND ".join(where)
        if USE_MYSQL:
            sql += f" ORDER BY timestamp DESC, id DESC LIMIT {limit} OFFSET {offset}"
        else:
            query_limit = min(50500, offset + limit)
            sql += f" ORDER BY timestamp DESC, id DESC LIMIT {query_limit}"

        cursor = conn.cursor()
        cursor.execute(sql, tuple(params))
        rows = cursor.fetchall()
        rows = _rows_to_dict(cursor, rows)
        if USE_MYSQL or not cutoff:
            return rows
        archive_rows = fetch_archive_rows(
            'event_log',
            ['id', 'timestamp', 'source', 'severity', 'event_type', 'src_ip', 'session_id', 'tags', 'payload', 'raw_ref', 'raw_request_id', 'extra'],
            where=" AND ".join(where),
            params=tuple(params),
            order_by='timestamp DESC, id DESC',
            limit=min(50500, offset + limit),
            window_cutoff=cutoff,
        )
        return _merge_event_rows(rows + archive_rows, offset, limit)
    finally:
        conn.close()


def get_event_stats(hours: int = 24):
    try:
        hours = int(hours)
    except Exception:
        hours = 24
    hours = max(1, min(hours, 24 * 30))
    cached = _get_event_stats_cache(hours)
    if cached is not None:
        return cached

    cutoff = (datetime.now() - timedelta(hours=hours)).strftime('%Y-%m-%d %H:%M:%S')
    placeholder = '%s' if USE_MYSQL else '?'
    conn = get_connection()
    try:
        _ensure_event_table_ready(conn)
        hidden_clause = " AND ".join([f"event_type <> {placeholder}" for _ in _HIDDEN_EVENT_TYPES])
        total_sql = (
            f"SELECT COUNT(*) AS total FROM event_log "
            f"WHERE timestamp >= {placeholder}"
            + (f" AND {hidden_clause}" if hidden_clause else "")
        )
        cursor_total = conn.cursor()
        cursor_total.execute(total_sql, tuple([cutoff] + list(_HIDDEN_EVENT_TYPES)))
        total_row = cursor_total.fetchone()
        if USE_MYSQL:
            total_count = int((total_row or {}).get('total') or 0)
        else:
            total_count = int(total_row[0] if total_row else 0)

        sql = (
            "SELECT source, severity, event_type, src_ip, tags "
            f"FROM event_log WHERE timestamp >= {placeholder} "
            + (f"AND {hidden_clause} " if hidden_clause else "")
            + "ORDER BY id DESC"
        )
        cursor = conn.cursor()
        cursor.execute(sql, tuple([cutoff] + list(_HIDDEN_EVENT_TYPES)))

        source_counter = Counter()
        severity_counter = Counter()
        type_counter = Counter()
        ip_counter = Counter()
        tag_counter = Counter()
        sampled = 0

        while True:
            batch = cursor.fetchmany(_EVENT_QUERY_BATCH)
            if not batch:
                break
            rows = _rows_to_dict(cursor, batch)
            for r in rows:
                sampled += 1
                source_counter[str(r.get('source') or 'unknown')] += 1
                severity_counter[str(r.get('severity') or 'low')] += 1
                type_counter[str(r.get('event_type') or 'unknown')] += 1
                ip = str(r.get('src_ip') or '').strip()
                if ip:
                    ip_counter[ip] += 1
                tags_raw = r.get('tags') or '[]'
                tags = []
                try:
                    tags = json.loads(tags_raw)
                except Exception:
                    if isinstance(tags_raw, str):
                        tags = [x.strip() for x in tags_raw.split(',') if x.strip()]
                for t in _normalize_tags(tags):
                    tag_counter[t] += 1

        if not USE_MYSQL:
            archive_where = "timestamp >= ?"
            archive_params = tuple([cutoff] + list(_HIDDEN_EVENT_TYPES))
            if hidden_clause:
                archive_where += f" AND {hidden_clause}"
            archive_total = fetch_archive_count(
                'event_log',
                where=archive_where,
                params=archive_params,
                window_cutoff=cutoff,
            )
            total_count += int(archive_total or 0)
            _merge_archive_group_counts(
                source_counter,
                fetch_archive_group_counts('event_log', 'source', archive_where, archive_params, cutoff),
            )
            _merge_archive_group_counts(
                severity_counter,
                fetch_archive_group_counts('event_log', 'severity', archive_where, archive_params, cutoff),
                default_key='low',
            )
            _merge_archive_group_counts(
                type_counter,
                fetch_archive_group_counts('event_log', 'event_type', archive_where, archive_params, cutoff),
            )
            archive_ip_where = archive_where + " AND src_ip IS NOT NULL AND src_ip != ''"
            _merge_archive_group_counts(
                ip_counter,
                fetch_archive_group_counts('event_log', 'src_ip', archive_ip_where, archive_params, cutoff),
                default_key='',
            )
            sampled = int(total_count)

        total_count = int(total_count)
        result = {
            'since': cutoff,
            'total': total_count,
            'sampled': sampled,
            'by_source': dict(source_counter),
            'by_severity': dict(severity_counter),
            'top_event_types': [{'event_type': k, 'count': int(v)} for k, v in type_counter.most_common(10)],
            'top_ips': [{'src_ip': k, 'count': int(v)} for k, v in ip_counter.most_common(10)],
            'unique_ips': int(len(ip_counter)),
            'top_tags': [{'tag': k, 'count': int(v)} for k, v in tag_counter.most_common(10)],
        }
        _set_event_stats_cache(hours, result)
        return result
    finally:
        conn.close()


def get_ssh_suspicious_commands(limit=20, hours=None):
    """
    获取 SSH 可疑命令列表（用于“可疑请求分析”面板）。
    数据来源：event_log.event_type in ('ssh_cmd_suspicious', 'ssh_cmd_high_risk')
    """
    try:
        limit_v = int(limit)
    except Exception:
        limit_v = 20
    limit_v = max(1, min(limit_v, 200))
    try:
        hours_v = int(hours) if hours not in (None, '') else None
    except Exception:
        hours_v = None
    if hours_v is not None:
        hours_v = max(1, min(hours_v, 24 * 30))

    conn = get_connection()
    try:
        _ensure_event_table_ready(conn)
        placeholder = '%s' if USE_MYSQL else '?'
        cutoff = ''
        where = [
            f"source = {placeholder}",
            f"(event_type = {placeholder} OR event_type = {placeholder})"
        ]
        params = ['ssh', 'ssh_cmd_suspicious', 'ssh_cmd_high_risk']
        if hours_v is not None:
            cutoff = (datetime.now() - timedelta(hours=hours_v)).strftime('%Y-%m-%d %H:%M:%S')
            where.append(f"timestamp >= {placeholder}")
            params.append(cutoff)

        sql = (
            "SELECT id, timestamp, src_ip, event_type, payload, extra "
            "FROM event_log "
            f"WHERE {' AND '.join(where)} "
            f"ORDER BY id DESC LIMIT {limit_v}"
        )
        cursor = conn.cursor()
        cursor.execute(sql, tuple(params))
        rows = _rows_to_dict(cursor, cursor.fetchall())
        if not USE_MYSQL and cutoff:
            archive_rows = fetch_archive_rows(
                'event_log',
                ['id', 'timestamp', 'src_ip', 'event_type', 'payload', 'extra'],
                where=' AND '.join(where),
                params=tuple(params),
                order_by='timestamp DESC, id DESC',
                limit=limit_v,
                window_cutoff=cutoff,
            )
            rows = _merge_event_rows(rows + archive_rows, 0, limit_v)

        out = []
        for r in rows:
            row_id = r.get('id')
            ts = str(r.get('timestamp') or '')
            ip = str(r.get('src_ip') or '').strip()
            event_type = str(r.get('event_type') or '').strip().lower()
            payload = str(r.get('payload') or '').strip()
            extra = r.get('extra')
            score = 60 if event_type == 'ssh_cmd_high_risk' else 30
            command = payload
            if isinstance(extra, str) and extra:
                try:
                    ex = json.loads(extra)
                    score = int(ex.get('score') or score)
                    command = str(ex.get('raw_command') or payload).strip()
                except Exception:
                    pass
            elif isinstance(extra, dict):
                try:
                    score = int(extra.get('score') or score)
                except Exception:
                    pass
                command = str(extra.get('raw_command') or payload).strip()
            out.append({
                'id': row_id,
                'create_time': ts,
                'src_ip': ip,
                'method': 'SSH',
                'path': '可疑命令行为',
                'query_string': command or payload,
                'command': command or payload,
                'threat_score': score,
            })
        return out
    finally:
        conn.close()


__all__ = ['severity_from_score', 'log_event', 'get_event_logs', 'get_event_stats', 'get_ssh_suspicious_commands']
