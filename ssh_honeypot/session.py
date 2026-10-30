# -*- coding: utf-8 -*-
"""
SSH 蜜罐 - 会话/连接控制
"""
import time
import threading
from collections import defaultdict, deque

from env_utils import env_bool as _env_bool, env_int as _env_int
from utils.logger import get_ssh_logger
from ssh_honeypot.ssh_config import MAX_CONCURRENT_CONNECTIONS, MAX_CONNECTIONS_PER_IP

logger = get_ssh_logger()

active_connections = 0
ip_connections = defaultdict(int)
connection_lock = threading.Lock()


SSH_BRUTEFORCE_BAN_ENABLED = _env_bool('SSH_BRUTEFORCE_BAN_ENABLED', True)
SSH_BRUTEFORCE_WINDOW_SECONDS = _env_int('SSH_BRUTEFORCE_WINDOW_SECONDS', 60, 5, 3600)
SSH_BRUTEFORCE_MAX_FAILS = _env_int('SSH_BRUTEFORCE_MAX_FAILS', 12, 3, 500)
SSH_BRUTEFORCE_BASE_BAN_SECONDS = _env_int('SSH_BRUTEFORCE_BASE_BAN_SECONDS', 600, 10, 86400)
SSH_BRUTEFORCE_MAX_BAN_SECONDS = _env_int('SSH_BRUTEFORCE_MAX_BAN_SECONDS', 7200, 30, 604800)
SSH_BRUTEFORCE_GC_INTERVAL_SECONDS = _env_int('SSH_BRUTEFORCE_GC_INTERVAL_SECONDS', 60, 10, 3600)
SSH_BRUTEFORCE_STALE_KEEP_SECONDS = _env_int('SSH_BRUTEFORCE_STALE_KEEP_SECONDS', 3600, 60, 604800)
SSH_SCAN_DETECT_ENABLED = _env_bool('SSH_SCAN_DETECT_ENABLED', True)
SSH_SCAN_WINDOW_SECONDS = _env_int('SSH_SCAN_WINDOW_SECONDS', 10, 1, 600)
SSH_SCAN_CONN_THRESHOLD = _env_int('SSH_SCAN_CONN_THRESHOLD', 18, 3, 20000)
SSH_SCAN_ALERT_COOLDOWN_SECONDS = _env_int('SSH_SCAN_ALERT_COOLDOWN_SECONDS', 120, 1, 3600)
SSH_SCAN_STALE_KEEP_SECONDS = _env_int('SSH_SCAN_STALE_KEEP_SECONDS', 1800, 30, 86400)

ip_fail_events = defaultdict(deque)  # {ip: deque([ts,...])}
ip_ban_until = {}                    # {ip: ts}
ip_ban_level = defaultdict(int)      # {ip: level}
ip_scan_connect_events = defaultdict(deque)  # {ip: deque([ts,...])}
ip_scan_last_alert_ts = {}           # {ip: ts}
_last_bruteforce_gc_ts = 0.0


def _cleanup_fail_events(ip: str, now_ts: float) -> None:
    q = ip_fail_events.get(ip)
    if not q:
        return
    cutoff = now_ts - float(SSH_BRUTEFORCE_WINDOW_SECONDS)
    while q and q[0] < cutoff:
        q.popleft()
    if not q:
        ip_fail_events.pop(ip, None)


def _maybe_global_cleanup(now_ts: float) -> None:
    """
    惰性全局清理（需在 connection_lock 下调用）：
    - 低频（默认 60s）清理失败队列中的过期项
    - 清理已过期且无活跃状态的封禁记录
    - 清理无引用的惩罚等级状态
    """
    global _last_bruteforce_gc_ts
    if (now_ts - float(_last_bruteforce_gc_ts)) < float(SSH_BRUTEFORCE_GC_INTERVAL_SECONDS):
        return
    _last_bruteforce_gc_ts = now_ts

    # 1) 按窗口清理所有失败队列
    for ip in list(ip_fail_events.keys()):
        _cleanup_fail_events(ip, now_ts)

    # 2) 清理过期封禁（且已无失败队列、无活跃连接）
    stale_cutoff = now_ts - float(SSH_BRUTEFORCE_STALE_KEEP_SECONDS)
    removed_bans = 0
    for ip in list(ip_ban_until.keys()):
        ban_until = float(ip_ban_until.get(ip, 0.0) or 0.0)
        has_fail_events = bool(ip_fail_events.get(ip))
        has_active_conn = int(ip_connections.get(ip, 0) or 0) > 0
        if (ban_until <= now_ts and not has_fail_events and not has_active_conn) or (ban_until <= stale_cutoff):
            ip_ban_until.pop(ip, None)
            removed_bans += 1

    # 3) 清理孤立 ban level（不在封禁且无失败队列）
    removed_levels = 0
    for ip in list(ip_ban_level.keys()):
        if int(ip_ban_level.get(ip, 0) or 0) <= 0 and ip not in ip_ban_until and not ip_fail_events.get(ip):
            ip_ban_level.pop(ip, None)
            removed_levels += 1

    # 4) 扫描检测状态清理
    removed_scan_events = 0
    removed_scan_alerts = 0
    if SSH_SCAN_DETECT_ENABLED:
        scan_cutoff = now_ts - float(SSH_SCAN_WINDOW_SECONDS)
        scan_stale_cutoff = now_ts - float(SSH_SCAN_STALE_KEEP_SECONDS)
        for ip in list(ip_scan_connect_events.keys()):
            q = ip_scan_connect_events.get(ip)
            if not q:
                ip_scan_connect_events.pop(ip, None)
                continue
            while q and q[0] < scan_cutoff:
                q.popleft()
            if not q:
                ip_scan_connect_events.pop(ip, None)
                removed_scan_events += 1
                continue
            if q and q[-1] < scan_stale_cutoff and int(ip_connections.get(ip, 0) or 0) <= 0:
                ip_scan_connect_events.pop(ip, None)
                removed_scan_events += 1
        for ip in list(ip_scan_last_alert_ts.keys()):
            last_ts = float(ip_scan_last_alert_ts.get(ip, 0.0) or 0.0)
            if last_ts <= scan_stale_cutoff and ip not in ip_scan_connect_events:
                ip_scan_last_alert_ts.pop(ip, None)
                removed_scan_alerts += 1

    if removed_bans or removed_levels or removed_scan_events or removed_scan_alerts:
        logger.debug(
            f"[连接状态GC] 清理完成 bans={removed_bans}, levels={removed_levels}, "
            f"scan_events={removed_scan_events}, scan_alerts={removed_scan_alerts}"
        )


def get_ban_remaining(client_ip: str) -> int:
    if not SSH_BRUTEFORCE_BAN_ENABLED:
        return 0
    now_ts = time.time()
    with connection_lock:
        _maybe_global_cleanup(now_ts)
        ban_until = float(ip_ban_until.get(client_ip, 0.0) or 0.0)
        if ban_until <= now_ts:
            if client_ip in ip_ban_until:
                ip_ban_until.pop(client_ip, None)
            return 0
        return int(max(1, ban_until - now_ts))


def rate_limit_check(client_ip: str) -> bool:
    global active_connections
    with connection_lock:
        if SSH_BRUTEFORCE_BAN_ENABLED:
            now_ts = time.time()
            _maybe_global_cleanup(now_ts)
            ban_until = float(ip_ban_until.get(client_ip, 0.0) or 0.0)
            if ban_until > now_ts:
                remain = int(max(1, ban_until - now_ts))
                logger.warning(f"[拒绝] IP处于防爆破封禁期 {client_ip} (剩余{remain}s)")
                return False
            if ban_until > 0:
                ip_ban_until.pop(client_ip, None)

        if active_connections >= MAX_CONCURRENT_CONNECTIONS:
            logger.warning(f"[拒绝] 连接数超限 {client_ip}")
            return False
        if ip_connections[client_ip] >= MAX_CONNECTIONS_PER_IP:
            logger.warning(f"[拒绝] IP连接超限 {client_ip}")
            return False
        active_connections += 1
        ip_connections[client_ip] += 1
        return True


def release_connection(client_ip: str):
    global active_connections
    with connection_lock:
        _maybe_global_cleanup(time.time())
        active_connections = max(0, active_connections - 1)
        if client_ip in ip_connections:
            ip_connections[client_ip] -= 1
        if ip_connections.get(client_ip, 0) <= 0:
            ip_connections.pop(client_ip, None)


def record_auth_success(client_ip: str) -> None:
    if not SSH_BRUTEFORCE_BAN_ENABLED:
        return
    now_ts = time.time()
    with connection_lock:
        _maybe_global_cleanup(now_ts)
        _cleanup_fail_events(client_ip, now_ts)
        ip_fail_events.pop(client_ip, None)
        # 成功认证后平滑衰减惩罚等级，避免永久高惩罚
        if ip_ban_level.get(client_ip, 0) > 0:
            ip_ban_level[client_ip] = max(0, int(ip_ban_level[client_ip]) - 1)


def record_auth_failure(client_ip: str) -> int:
    """
    记录认证失败并在触发阈值时封禁来源 IP。
    返回值为本次新触发的封禁时长（秒）；未触发则返回 0。
    """
    if not SSH_BRUTEFORCE_BAN_ENABLED:
        return 0
    now_ts = time.time()
    with connection_lock:
        _maybe_global_cleanup(now_ts)
        _cleanup_fail_events(client_ip, now_ts)
        q = ip_fail_events.setdefault(client_ip, deque())
        q.append(now_ts)

        if len(q) < SSH_BRUTEFORCE_MAX_FAILS:
            return 0

        level = int(ip_ban_level.get(client_ip, 0)) + 1
        ip_ban_level[client_ip] = level

        ban_seconds = SSH_BRUTEFORCE_BASE_BAN_SECONDS * (2 ** (level - 1))
        ban_seconds = min(int(ban_seconds), int(SSH_BRUTEFORCE_MAX_BAN_SECONDS))
        ip_ban_until[client_ip] = now_ts + ban_seconds

        # 进入封禁后清空窗口计数，避免解封瞬间立刻二次封禁
        q.clear()
        logger.warning(
            f"[防爆破] 封禁来源IP {client_ip} {ban_seconds}s "
            f"(窗口{SSH_BRUTEFORCE_WINDOW_SECONDS}s失败达到{SSH_BRUTEFORCE_MAX_FAILS}次, level={level})"
        )
        return ban_seconds


def record_preauth_connection(client_ip: str):
    """
    记录预认证连接频率，用于识别高频端口扫描行为。
    返回:
    - dict: 触发扫描告警（包含 count/window/threshold）
    - None: 未触发
    """
    if not SSH_SCAN_DETECT_ENABLED:
        return None
    now_ts = time.time()
    with connection_lock:
        _maybe_global_cleanup(now_ts)
        q = ip_scan_connect_events.setdefault(client_ip, deque())
        q.append(now_ts)
        cutoff = now_ts - float(SSH_SCAN_WINDOW_SECONDS)
        while q and q[0] < cutoff:
            q.popleft()

        count = len(q)
        threshold = int(SSH_SCAN_CONN_THRESHOLD)
        if count < threshold:
            return None

        last_alert = float(ip_scan_last_alert_ts.get(client_ip, 0.0) or 0.0)
        if (now_ts - last_alert) < float(SSH_SCAN_ALERT_COOLDOWN_SECONDS):
            return None

        ip_scan_last_alert_ts[client_ip] = now_ts
        return {
            'count': int(count),
            'window_seconds': int(SSH_SCAN_WINDOW_SECONDS),
            'threshold': int(threshold),
            'cooldown_seconds': int(SSH_SCAN_ALERT_COOLDOWN_SECONDS),
        }
