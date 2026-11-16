# -*- coding: utf-8 -*-
"""
事件日志与统计聚合视图
说明：
- 对外接口：log_event_activity/get_event_geo_data
- 数据源统一为 event_log
"""
import re
import os
import time
import hashlib
from collections import Counter
from datetime import datetime, timedelta
from threading import Lock
from env_utils import env_bool as _env_bool, env_int as _env_int, env_float as _env_float

from .connection import (
    USE_MYSQL,
    get_connection,
    has_real_data,
    _EVENT_PAYLOAD_MAX,
    _redact_sensitive_text,
    _truncate_text,
    logger,
)
from .archive import archive_has_real_data, fetch_archive_count, fetch_archive_group_counts
from .geo import get_geo_info, has_geo_cache
from .demo_data import get_consistent_mock_data
from .event_logs import log_event
from utils.net import is_private_ip
from utils.ip_location import build_geo_location


_EVENT_TYPE_NORMALIZE = re.compile(r'[^a-z0-9]+')
_PATH_HINT_RE = re.compile(r'/[a-z0-9._\-/]+', re.IGNORECASE)

_EVENT_DEDUP_WINDOW = _env_float('EVENT_DEDUP_WINDOW', 2.5, 0.0, 300.0)
_EVENT_DEDUP_MAX = _env_int('EVENT_DEDUP_MAX', 4096, 64, 100000)
_EVENT_DEDUP_LOCK = Lock()
_EVENT_DEDUP_STATE = {}

_GEO_MEM_CACHE_TTL = _env_float('GEO_MEM_CACHE_TTL', 300.0, 1.0, 86400.0)
_GEO_MEM_CACHE_NEG_TTL = _env_float('GEO_MEM_CACHE_NEG_TTL', 15.0, 1.0, 600.0)
_GEO_MEM_CACHE_MAX = _env_int('GEO_MEM_CACHE_MAX', 2048, 64, 200000)
_GEO_MEM_CACHE_LOCK = Lock()
_GEO_MEM_CACHE = {}

_GEO_MAP_TOP_IP_SCAN_LIMIT = _env_int('EVENT_GEO_MAP_TOP_IP_SCAN_LIMIT', 60, 5, 500)
_GEO_MAP_SCAN_MULTIPLIER = _env_int('EVENT_GEO_MAP_SCAN_MULTIPLIER', 4, 1, 20)
_GEO_MAP_ONLINE_RESOLVE_LIMIT = _env_int('EVENT_GEO_MAP_ONLINE_RESOLVE_LIMIT', 1, 0, 10)
_GEO_MAP_HIDDEN_EVENT_TYPES = ('ssh_cmd_audit', 'web', 'web_activity_note')
_HIDDEN_EVENT_TYPES = ('ssh_cmd_audit', 'ssh_cmd_suspicious', 'web', 'web_activity_note')
_ALLOW_DASHBOARD_MOCK_DATA = _env_bool('ALLOW_DASHBOARD_MOCK_DATA', False)


def _normalize_event_type(event_type: str) -> str:
    text = str(event_type or 'unknown').strip().lower()
    text = _EVENT_TYPE_NORMALIZE.sub('_', text).strip('_')
    return text[:64] or 'unknown'


def _normalize_payload_for_dedup(payload: str) -> str:
    text = str(payload or '').strip().lower()
    if not text:
        return ''
    text = re.sub(r'\s+', ' ', text)
    if len(text) > 260:
        text = text[:260]
    return text


def _build_event_dedup_key(src_ip: str, source: str, event_norm: str, payload: str) -> str:
    payload_norm = _normalize_payload_for_dedup(payload)
    path_hint = ''
    m = _PATH_HINT_RE.search(payload_norm)
    if m:
        path_hint = m.group(0).split('?', 1)[0][:128]
    # path_hint 可将“探测路径:/admin”与“GET /admin?...”归并为同类键
    canonical = path_hint if path_hint else payload_norm
    raw = f"{src_ip}|{source}|{event_norm}|{canonical}"
    return hashlib.sha1(raw.encode('utf-8', errors='ignore')).hexdigest()


def _is_duplicate_event(src_ip: str, source: str, event_norm: str, payload: str) -> bool:
    if _EVENT_DEDUP_WINDOW <= 0:
        return False
    now = time.monotonic()
    key = _build_event_dedup_key(src_ip, source, event_norm, payload)
    with _EVENT_DEDUP_LOCK:
        # 惰性清理过期键，避免内存持续增长
        if len(_EVENT_DEDUP_STATE) >= _EVENT_DEDUP_MAX:
            cutoff = now - _EVENT_DEDUP_WINDOW
            stale = [k for k, ts in _EVENT_DEDUP_STATE.items() if float(ts) < cutoff]
            for k in stale:
                _EVENT_DEDUP_STATE.pop(k, None)
            if len(_EVENT_DEDUP_STATE) >= _EVENT_DEDUP_MAX:
                # 保护性策略：删除最旧 10%
                old = sorted(_EVENT_DEDUP_STATE.items(), key=lambda x: x[1])[:max(1, _EVENT_DEDUP_MAX // 10)]
                for k, _ in old:
                    _EVENT_DEDUP_STATE.pop(k, None)

        last = _EVENT_DEDUP_STATE.get(key)
        _EVENT_DEDUP_STATE[key] = now
        if last is None:
            return False
        return (now - float(last)) <= _EVENT_DEDUP_WINDOW


def _should_drop_duplicate_event(source: str, event_norm: str, payload: str) -> bool:
    """
    统一事件降噪：
    - SSH 登录尝试、SCP 事件已有结构化 event_log，避免重复写入
    - Web 的典型路径探测由 raw_request->event_log 已覆盖，避免重复计数
    """
    src = str(source or '').lower()
    atk = str(event_norm or '').lower()
    p = str(payload or '').lower()

    if src == 'ssh' and atk in ('ssh', 'scp_upload', 'scp_capture'):
        return True

    if src == 'web' and atk in ('web', 'unknown'):
        web_probe_tokens = (
            '探测', 'probe', '/admin', '/.env', '/.git',
            '/backup', '/uploads/', '/old/', '/phpmyadmin',
        )
        if any(t in p for t in web_probe_tokens):
            return True

    return False


def _get_geo_info_cached(ip: str, allow_online: bool = True) -> dict:
    def _is_valid_geo(info: dict) -> bool:
        try:
            lat = float((info or {}).get('latitude') or 0)
            lon = float((info or {}).get('longitude') or 0)
        except Exception:
            return False
        if lat == 0 and lon == 0:
            return False
        return -90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0

    key = str(ip or '').strip()
    if not key:
        return {}

    now = time.monotonic()
    with _GEO_MEM_CACHE_LOCK:
        hit = _GEO_MEM_CACHE.get(key)
        if hit:
            ts, info = hit
            ttl = _GEO_MEM_CACHE_TTL if _is_valid_geo(info) else min(_GEO_MEM_CACHE_NEG_TTL, _GEO_MEM_CACHE_TTL)
            if (now - float(ts)) <= ttl:
                # 仅缓存命中：
                # - 有效坐标可直接复用
                # - 禁止在线查询模式下，允许复用无效坐标缓存以快速返回
                if _is_valid_geo(info) or not allow_online:
                    return dict(info)
                # 允许在线查询时，无效缓存不阻断刷新
                _GEO_MEM_CACHE.pop(key, None)
            else:
                _GEO_MEM_CACHE.pop(key, None)

    info = get_geo_info(key, allow_online=allow_online) or {}
    with _GEO_MEM_CACHE_LOCK:
        old = _GEO_MEM_CACHE.get(key)
        if old:
            _, old_info = old
            # 保护已知有效坐标，避免被一次外部查询失败结果覆盖
            if _is_valid_geo(old_info) and not _is_valid_geo(info):
                return dict(old_info)
        if len(_GEO_MEM_CACHE) >= _GEO_MEM_CACHE_MAX:
            # 超过上限时删除最旧 10%
            old = sorted(_GEO_MEM_CACHE.items(), key=lambda x: x[1][0])[:max(1, _GEO_MEM_CACHE_MAX // 10)]
            for k, _ in old:
                _GEO_MEM_CACHE.pop(k, None)
        _GEO_MEM_CACHE[key] = (now, dict(info))
    return info


def _map_source_from_event_type(event_type: str) -> str:
    t = str(event_type or '').strip().upper()
    if not t:
        return 'system'
    if 'WEB' in t:
        return 'web'
    if t.startswith('SSH') or t in (
        'SHELL_CMD', 'SCP-CAPTURE', 'SCP-UPLOAD', 'SCP_CAPTURE',
        'WGET', 'SU_LOGIN', 'PASSWD_GUESS', 'PASSWD_CHANGE', 'SSH_PIVOT'
    ):
        return 'ssh'
    return 'system'


def _severity_from_event_type(event_type: str) -> str:
    t = str(event_type or '').strip().upper()
    if t in ('SCP-CAPTURE', 'SCP_CAPTURE', 'PASSWD_CHANGE', 'SU_LOGIN', 'SSH_PIVOT'):
        return 'high'
    if t in ('SHELL_CMD', 'WGET', 'SSH-EXEC', 'SSH_EXEC'):
        return 'medium'
    if t in ('SSH', 'WEB'):
        return 'low'
    return 'low'


def _build_location(geo: dict) -> str:
    return build_geo_location(
        geo.get('country'),
        geo.get('province'),
        geo.get('city'),
    )


def _query_top_event_ips(limit: int = 100, hours: int = None, hidden_event_types=None):
    try:
        hours_v = int(hours) if hours not in (None, '') else None
    except Exception:
        hours_v = None
    if hours_v is not None:
        hours_v = max(1, min(hours_v, 24 * 30))
    cutoff = (datetime.now() - timedelta(hours=hours_v)).strftime('%Y-%m-%d %H:%M:%S') if hours_v is not None else ''

    conn = get_connection()
    try:
        cursor = conn.cursor()
        hidden_types = tuple(hidden_event_types or _HIDDEN_EVENT_TYPES)
        hidden_cond_mysql = " AND ".join(["event_type <> %s" for _ in hidden_types])
        hidden_cond_sqlite = " AND ".join(["event_type <> ?" for _ in hidden_types])
        hidden_sql_mysql = f" AND {hidden_cond_mysql}" if hidden_cond_mysql else ''
        hidden_sql_sqlite = f" AND {hidden_cond_sqlite}" if hidden_cond_sqlite else ''
        hidden_args = list(hidden_types)

        if USE_MYSQL:
            if hours_v is not None:
                cursor.execute(
                    f"""
                    SELECT src_ip, COUNT(*) AS count
                    FROM event_log
                    WHERE src_ip IS NOT NULL AND src_ip != ''
                      AND timestamp >= %s
                      {hidden_sql_mysql}
                    GROUP BY src_ip
                    ORDER BY count DESC
                    LIMIT %s
                    """,
                    tuple([cutoff] + hidden_args + [int(limit)])
                )
            else:
                cursor.execute(
                    f"""
                    SELECT src_ip, COUNT(*) AS count
                    FROM event_log
                    WHERE src_ip IS NOT NULL AND src_ip != ''
                      {hidden_sql_mysql}
                    GROUP BY src_ip
                    ORDER BY count DESC
                    LIMIT %s
                    """,
                    tuple(hidden_args + [int(limit)])
                )
        else:
            if hours_v is not None:
                cursor.execute(
                    f"""
                    SELECT src_ip, COUNT(*) AS count
                    FROM event_log
                    WHERE src_ip IS NOT NULL AND src_ip != ''
                      AND timestamp >= ?
                      {hidden_sql_sqlite}
                    GROUP BY src_ip
                    ORDER BY count DESC
                    LIMIT {int(limit)}
                    """,
                    tuple([cutoff] + hidden_args)
                )
            else:
                cursor.execute(
                    f"""
                    SELECT src_ip, COUNT(*) AS count
                    FROM event_log
                    WHERE src_ip IS NOT NULL AND src_ip != ''
                      {hidden_sql_sqlite}
                    GROUP BY src_ip
                    ORDER BY count DESC
                    LIMIT {int(limit)}
                    """,
                    tuple(hidden_args)
                )
        rows = cursor.fetchall()
        if not USE_MYSQL:
            cols = [d[0] for d in cursor.description]
            rows = [dict(zip(cols, row)) for row in rows]
            archive_where = "src_ip IS NOT NULL AND src_ip != ''"
            archive_params = []
            if hours_v is not None:
                archive_where += " AND timestamp >= ?"
                archive_params.append(cutoff)
            if hidden_cond_sqlite:
                archive_where += f" AND {hidden_cond_sqlite}"
                archive_params.extend(hidden_args)
            archive_rows = fetch_archive_group_counts(
                'event_log',
                'src_ip',
                where=archive_where,
                params=tuple(archive_params),
                window_cutoff=cutoff,
            )
            if archive_rows:
                merged = Counter()
                for row in rows or []:
                    ip = str(row.get('src_ip') or '').strip()
                    if ip:
                        merged[ip] += int(row.get('count') or 0)
                for row in archive_rows:
                    ip = str(row.get('group_key') or '').strip()
                    if ip:
                        merged[ip] += int(row.get('count') or 0)
                rows = [
                    {'src_ip': ip, 'count': int(count)}
                    for ip, count in merged.most_common(int(limit))
                ]
        return rows
    finally:
        conn.close()


def _query_ip_event_count(src_ip: str, hours: int = None, hidden_event_types=None) -> int:
    ip = str(src_ip or '').strip()
    if not ip:
        return 0
    try:
        hours_v = int(hours) if hours not in (None, '') else None
    except Exception:
        hours_v = None
    if hours_v is not None:
        hours_v = max(1, min(hours_v, 24 * 30))
    cutoff = (datetime.now() - timedelta(hours=hours_v)).strftime('%Y-%m-%d %H:%M:%S') if hours_v is not None else ''

    conn = get_connection()
    try:
        cursor = conn.cursor()
        hidden_types = tuple(hidden_event_types or _HIDDEN_EVENT_TYPES)
        hidden_cond_mysql = " AND ".join(["event_type <> %s" for _ in hidden_types])
        hidden_cond_sqlite = " AND ".join(["event_type <> ?" for _ in hidden_types])
        hidden_sql_mysql = f" AND {hidden_cond_mysql}" if hidden_cond_mysql else ''
        hidden_sql_sqlite = f" AND {hidden_cond_sqlite}" if hidden_cond_sqlite else ''
        hidden_args = list(hidden_types)

        if USE_MYSQL:
            if hours_v is not None:
                cursor.execute(
                    f"""
                    SELECT COUNT(*) AS count
                    FROM event_log
                    WHERE src_ip = %s
                      AND timestamp >= %s
                      {hidden_sql_mysql}
                    """,
                    tuple([ip, cutoff] + hidden_args)
                )
            else:
                cursor.execute(
                    f"""
                    SELECT COUNT(*) AS count
                    FROM event_log
                    WHERE src_ip = %s
                      {hidden_sql_mysql}
                    """,
                    tuple([ip] + hidden_args)
                )
            row = cursor.fetchone() or {}
            return int((row or {}).get('count') or 0)
        if hours_v is not None:
            cursor.execute(
                f"""
                SELECT COUNT(*) AS count
                FROM event_log
                WHERE src_ip = ?
                  AND timestamp >= ?
                  {hidden_sql_sqlite}
                """,
                tuple([ip, cutoff] + hidden_args)
            )
        else:
            cursor.execute(
                f"""
                SELECT COUNT(*) AS count
                FROM event_log
                WHERE src_ip = ?
                  {hidden_sql_sqlite}
                """,
                tuple([ip] + hidden_args)
            )
        row = cursor.fetchone()
        count = 0
        if isinstance(row, dict):
            count = int(row.get('count') or 0)
        elif isinstance(row, (list, tuple)) and row:
            count = int(row[0] or 0)
        archive_where = "src_ip = ?"
        archive_params = [ip]
        if hours_v is not None:
            archive_where += " AND timestamp >= ?"
            archive_params.append(cutoff)
        if hidden_cond_sqlite:
            archive_where += f" AND {hidden_cond_sqlite}"
            archive_params.extend(hidden_args)
        count += fetch_archive_count(
            'event_log',
            where=archive_where,
            params=tuple(archive_params),
            window_cutoff=cutoff,
        )
        return int(count)
    finally:
        conn.close()


def _query_ip_raw_request_count(src_ip: str, hours: int = None) -> int:
    ip = str(src_ip or '').strip()
    if not ip:
        return 0
    try:
        hours_v = int(hours) if hours not in (None, '') else None
    except Exception:
        hours_v = None
    if hours_v is not None:
        hours_v = max(1, min(hours_v, 24 * 30))
    cutoff = (datetime.now() - timedelta(hours=hours_v)).strftime('%Y-%m-%d %H:%M:%S') if hours_v is not None else ''

    conn = get_connection()
    try:
        cursor = conn.cursor()
        if USE_MYSQL:
            if hours_v is not None:
                cursor.execute(
                    """
                    SELECT COUNT(*) AS count
                    FROM raw_request
                    WHERE src_ip = %s
                      AND create_time >= %s
                    """,
                    (ip, cutoff)
                )
            else:
                cursor.execute(
                    """
                    SELECT COUNT(*) AS count
                    FROM raw_request
                    WHERE src_ip = %s
                    """,
                    (ip,)
                )
            row = cursor.fetchone() or {}
            return int((row or {}).get('count') or 0)

        if hours_v is not None:
            cursor.execute(
                """
                SELECT COUNT(*) AS count
                FROM raw_request
                WHERE src_ip = ?
                  AND create_time >= ?
                """,
                (ip, cutoff)
            )
        else:
            cursor.execute(
                """
                SELECT COUNT(*) AS count
                FROM raw_request
                WHERE src_ip = ?
                """,
                (ip,)
            )
        row = cursor.fetchone()
        count = 0
        if isinstance(row, dict):
            count = int(row.get('count') or 0)
        elif isinstance(row, (list, tuple)) and row:
            count = int(row[0] or 0)
        archive_where = "src_ip = ?"
        archive_params = [ip]
        if hours_v is not None:
            archive_where += " AND create_time >= ?"
            archive_params.append(cutoff)
        count += fetch_archive_count(
            'raw_request',
            where=archive_where,
            params=tuple(archive_params),
            window_cutoff=cutoff,
        )
        return int(count)
    except Exception:
        # 兼容早期库结构缺少 raw_request 表的场景
        return 0
    finally:
        conn.close()


def log_event_activity(src_ip: str, event_type: str, payload: str):
    """
    记录事件日志，统一写入 event_log。
    """
    try:
        payload = '' if payload is None else str(payload)
        payload = _redact_sensitive_text(payload)
        payload = _truncate_text(payload, _EVENT_PAYLOAD_MAX)

        normalized_event = _normalize_event_type(event_type)
        source = _map_source_from_event_type(event_type)
        severity = _severity_from_event_type(event_type)
        if _should_drop_duplicate_event(source, normalized_event, payload):
            return
        if _is_duplicate_event(src_ip, source, normalized_event, payload):
            return

        geo = _get_geo_info_cached(src_ip)
        location = _build_location(geo)

        log_event(
            source=source,
            severity=severity,
            event_type=normalized_event,
            src_ip=src_ip,
            session_id='',
            tags=['activity', normalized_event],
            payload=payload,
            raw_ref='',
            extra={
                'source_event_type_raw': str(event_type or ''),
                'location': location,
                'latitude': float(geo.get('latitude') or 0),
                'longitude': float(geo.get('longitude') or 0),
            },
        )
    except Exception as e:
        logger.error(f"[ERROR] 事件写入失败 (Ignored): {e}")


def get_event_geo_data(hours: int = None, focus_ip: str = '', limit: int = None):
    try:
        hours_v = int(hours) if hours not in (None, '') else None
    except Exception:
        hours_v = None
    if hours_v is not None:
        hours_v = max(1, min(hours_v, 24 * 30))
    cutoff = (datetime.now() - timedelta(hours=hours_v)).strftime('%Y-%m-%d %H:%M:%S') if hours_v is not None else ''
    real_available = has_real_data() or (not USE_MYSQL and archive_has_real_data(cutoff))
    if not real_available and _ALLOW_DASHBOARD_MOCK_DATA:
        try:
            limit_v = int(limit) if limit not in (None, '') else int(_GEO_MAP_TOP_IP_SCAN_LIMIT)
        except Exception:
            limit_v = int(_GEO_MAP_TOP_IP_SCAN_LIMIT)
        limit_v = max(1, min(limit_v, 500))
        return [
            {
                'src_ip': m['src_ip'],
                'location': m['location'],
                'latitude': m['latitude'],
                'longitude': m['longitude'],
                'event_count': m['count'],
            }
            for m in get_consistent_mock_data()[:limit_v]
            if m['latitude'] != 0
        ]
    if not real_available:
        return []

    try:
        result_limit = int(limit) if limit not in (None, '') else int(_GEO_MAP_TOP_IP_SCAN_LIMIT)
    except Exception:
        result_limit = int(_GEO_MAP_TOP_IP_SCAN_LIMIT)
    result_limit = max(1, min(result_limit, 500))
    scan_limit = min(500, max(result_limit, result_limit * max(1, int(_GEO_MAP_SCAN_MULTIPLIER))))
    rows = _query_top_event_ips(
        limit=scan_limit,
        hours=hours,
        hidden_event_types=_GEO_MAP_HIDDEN_EVENT_TYPES,
    )

    out = []
    seen = set()
    online_probe_count = 0
    focus_online_probe_count = 0

    def _append_geo_row(row):
        nonlocal online_probe_count
        ip = str(row.get('src_ip') or '').strip()
        if not ip or ip in seen or is_private_ip(ip):
            return
        count = int(row.get('count') or 0)

        # 地图接口优先走本地缓存/数据库，确保响应稳定
        info = _get_geo_info_cached(ip, allow_online=False)
        lat = float(info.get('latitude') or 0)
        lon = float(info.get('longitude') or 0)

        # 仅对“缓存里从未出现过的新IP”做在线补齐，避免重复外网查询
        if (
            lat == 0 and lon == 0
            and online_probe_count < int(_GEO_MAP_ONLINE_RESOLVE_LIMIT)
            and not has_geo_cache(ip)
        ):
            info = _get_geo_info_cached(ip, allow_online=True)
            online_probe_count += 1
            lat = float(info.get('latitude') or 0)
            lon = float(info.get('longitude') or 0)

        if lat == 0 and lon == 0:
            return

        out.append({
            'src_ip': ip,
            'location': _build_location(info),
            'latitude': lat,
            'longitude': lon,
            'event_count': count,
        })
        seen.add(ip)

    for row in rows:
        _append_geo_row(row)
        if len(out) >= result_limit:
            break

    # 当前窗口没有可绘制点时，回退到历史窗口，避免地图“整块空白”
    if not out and hours not in (None, ''):
        rows = _query_top_event_ips(
            limit=scan_limit,
            hours=None,
            hidden_event_types=_GEO_MAP_HIDDEN_EVENT_TYPES,
        )
        for row in rows:
            _append_geo_row(row)
            if len(out) >= result_limit:
                break

    focus_ip_v = str(focus_ip or '').strip()
    out_ip_set = {str(item.get('src_ip') or '').strip() for item in out}
    if focus_ip_v and focus_ip_v not in out_ip_set and not is_private_ip(focus_ip_v):
        focus_count = _query_ip_event_count(
            focus_ip_v,
            hours=hours,
            hidden_event_types=_GEO_MAP_HIDDEN_EVENT_TYPES,
        )
        if focus_count <= 0:
            focus_count = _query_ip_raw_request_count(
                focus_ip_v,
                hours=hours,
            )
        if focus_count > 0:
            info = _get_geo_info_cached(focus_ip_v, allow_online=False)
            lat = float(info.get('latitude') or 0)
            lon = float(info.get('longitude') or 0)
            if (
                lat == 0 and lon == 0
                and focus_online_probe_count < int(_GEO_MAP_ONLINE_RESOLVE_LIMIT)
                and not has_geo_cache(focus_ip_v)
            ):
                info = _get_geo_info_cached(focus_ip_v, allow_online=True)
                focus_online_probe_count += 1
                lat = float(info.get('latitude') or 0)
                lon = float(info.get('longitude') or 0)
            if not (lat == 0 and lon == 0):
                out.append({
                    'src_ip': focus_ip_v,
                    'location': _build_location(info),
                    'latitude': lat,
                    'longitude': lon,
                    'event_count': int(focus_count),
                })
    return out


__all__ = ['log_event_activity', 'get_event_geo_data']




