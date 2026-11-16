# -*- coding: utf-8 -*-
"""
数据库蜜罐统一入口（单进程双监听）
==================================

- MySQL 协议：端口由 --port 指定（main.py 传入 13306）
- Redis 协议：端口由 --redis-port 指定（默认读取 REDIS_PORT / 16379）

两个协议各自持有独立的 ConnectionGuard / ProtocolReporter，互不影响；
事件统一写入 event_log（source 分别为 mysql / redis）。
"""
import argparse
import os
import socket
import sys
import threading
import signal

_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _BASE_DIR)

from app_config import env_str, env_int, env_bool  # noqa: E402
from utils.logger import setup_logger  # noqa: E402
from utils.protocol_guard import ConnectionGuard, ProtocolReporter  # noqa: E402
from db_honeypot.mysql_handler import MySQLHoneypot, DECOY_ACCOUNTS  # noqa: E402
from db_honeypot.redis_handler import RedisHoneypot  # noqa: E402

logger = setup_logger('db_honeypot', 'db_honeypot.log')

_stop_event = threading.Event()


def _emit_credentials():
    """启动时输出诱饵凭证行，供 main.py 汇总展示。"""
    if not env_bool('EMIT_CREDENTIAL_LINES', False):
        return
    for user, pwd in DECOY_ACCOUNTS:
        print(f"CRED::{user}::{pwd}", flush=True)


def _serve(host: str, port: int, handler, guard: ConnectionGuard, label: str):
    """通用 TCP 接入循环：准入 -> worker 信号量 -> 协议处理器。"""
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server_sock.bind((host, port))
    except OSError as exc:
        logger.error(f"[{label}] 端口 {port} 绑定失败: {exc}")
        _stop_event.set()
        return
    server_sock.listen(128)
    server_sock.settimeout(1.0)
    logger.info(f"[{label}] 监听 {host}:{port}")

    while not _stop_event.is_set():
        try:
            conn, addr = server_sock.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        client_ip = addr[0]
        threading.Thread(
            target=_handle_client,
            args=(conn, client_ip, handler, guard, label),
            daemon=True,
        ).start()

    try:
        server_sock.close()
    except OSError:
        pass


def _handle_client(conn, client_ip, handler, guard: ConnectionGuard, label: str):
    # 预认证扫描检测
    scan = guard.record_preauth_connection(client_ip)
    if scan:
        reporter = getattr(handler, 'reporter', None)
        if reporter is not None:
            reporter.event(
                'db_port_scan' if label == 'MySQL' else 'redis_port_scan',
                client_ip, score=45,
                payload=f"{label} 端口扫描：{scan['window_seconds']}s 内 {scan['count']} 次连接",
                tags=[label.lower(), 'port_scan', 'attack_technique:T1595'],
            )

    if not guard.acquire_worker(timeout=1.0):
        conn.close()
        return
    admitted, reason = guard.admit(client_ip)
    if not admitted:
        if reason == 'banned':
            logger.info(f"[{label}] 拒绝已封禁 IP {client_ip}")
        conn.close()
        guard.release_worker()
        return
    try:
        handler.handle(conn, client_ip)
    except Exception as exc:
        logger.debug(f"[{label}] {client_ip} 处理异常: {exc}")
    finally:
        guard.release(client_ip)
        guard.release_worker()


def main():
    parser = argparse.ArgumentParser(description='数据库蜜罐（MySQL + Redis）')
    parser.add_argument('-H', '--host', default=env_str('DB_HONEYPOT_HOST', '0.0.0.0'))
    parser.add_argument('-p', '--port', type=int,
                        default=env_int('MYSQL_PORT', 13306, 1, 65535), help='MySQL 端口')
    parser.add_argument('--redis-host', default=env_str('DB_HONEYPOT_HOST', '0.0.0.0'))
    parser.add_argument('--redis-port', type=int,
                        default=env_int('REDIS_PORT', 16379, 1, 65535), help='Redis 端口')
    args = parser.parse_args()

    _emit_credentials()

    mysql_guard = ConnectionGuard(
        'mysql',
        max_workers=env_int('SSH_MAX_WORKERS', 80, 10, 500),
        max_active_total=60, max_active_per_ip=10,
        fail_window_seconds=60, fail_threshold=12,
        ban_base_seconds=600, ban_max_seconds=7200,
        scan_window_seconds=10, scan_threshold=18, scan_cooldown_seconds=120,
    )
    redis_guard = ConnectionGuard(
        'redis',
        max_workers=env_int('SSH_MAX_WORKERS', 80, 10, 500),
        max_active_total=60, max_active_per_ip=10,
        fail_window_seconds=60, fail_threshold=12,
        ban_base_seconds=600, ban_max_seconds=7200,
        scan_window_seconds=10, scan_threshold=18, scan_cooldown_seconds=120,
    )
    mysql = MySQLHoneypot(mysql_guard, ProtocolReporter('mysql', logger), logger)
    redis = RedisHoneypot(redis_guard, ProtocolReporter('redis', logger), logger)

    threads = [
        threading.Thread(target=_serve, args=(args.host, args.port, mysql, mysql_guard, 'MySQL'),
                         daemon=True),
        threading.Thread(target=_serve, args=(args.redis_host, args.redis_port, redis,
                                               redis_guard, 'Redis'), daemon=True),
    ]
    for t in threads:
        t.start()

    def _shutdown(signum, frame):
        _stop_event.set()

    signal.signal(signal.SIGINT, _shutdown)
    if hasattr(signal, 'SIGTERM'):
        signal.signal(signal.SIGTERM, _shutdown)

    try:
        while not _stop_event.is_set() and any(t.is_alive() for t in threads):
            _stop_event.wait(1.0)
    except KeyboardInterrupt:
        _stop_event.set()
    if _stop_event.is_set() and not any(t.is_alive() for t in threads):
        sys.exit(1)


if __name__ == '__main__':
    main()
