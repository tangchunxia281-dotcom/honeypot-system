# -*- coding: utf-8 -*-
"""
远程接入蜜罐入口（Telnet）
==========================

端口由 --port 指定（main.py 传入 2223），
事件统一写入 event_log（source = telnet）。
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
from remote_honeypot.telnet_handler import TelnetHoneypot, DECOY_ACCOUNTS  # noqa: E402

logger = setup_logger('remote_honeypot', 'remote_honeypot.log')

_stop_event = threading.Event()


def _emit_credentials():
    if not env_bool('EMIT_CREDENTIAL_LINES', False):
        return
    for user, pwd in DECOY_ACCOUNTS:
        print(f"CRED::{user}::{pwd}", flush=True)


def _handle_client(conn, client_ip, guard: ConnectionGuard, reporter):
    # TelnetHoneypot 持有连接级缓冲/协商状态，每连接独立实例
    handler = TelnetHoneypot(guard, reporter, logger)
    scan = guard.record_preauth_connection(client_ip)
    if scan:
        reporter.event(
            'telnet_port_scan', client_ip, score=45,
            payload=f"Telnet 端口扫描：{scan['window_seconds']}s 内 {scan['count']} 次连接",
            tags=['telnet', 'port_scan', 'attack_technique:T1595'],
        )
    if not guard.acquire_worker(timeout=1.0):
        conn.close()
        return
    admitted, reason = guard.admit(client_ip)
    if not admitted:
        if reason == 'banned':
            logger.info(f"[Telnet] 拒绝已封禁 IP {client_ip}")
        conn.close()
        guard.release_worker()
        return
    try:
        handler.handle(conn, client_ip)
    except Exception as exc:
        logger.debug(f"[Telnet] {client_ip} 处理异常: {exc}")
    finally:
        guard.release(client_ip)
        guard.release_worker()


def main():
    parser = argparse.ArgumentParser(description='远程接入蜜罐（Telnet）')
    parser.add_argument('-H', '--host', default=env_str('TELNET_HOST', '0.0.0.0'))
    parser.add_argument('-p', '--port', type=int,
                        default=env_int('TELNET_PORT', 2223, 1, 65535))
    args = parser.parse_args()

    _emit_credentials()

    guard = ConnectionGuard(
        'telnet',
        max_workers=env_int('SSH_MAX_WORKERS', 80, 10, 500),
        max_active_total=60, max_active_per_ip=10,
        fail_window_seconds=60, fail_threshold=12,
        ban_base_seconds=600, ban_max_seconds=7200,
        scan_window_seconds=10, scan_threshold=18, scan_cooldown_seconds=120,
    )
    reporter = ProtocolReporter('telnet', logger)

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server_sock.bind((args.host, args.port))
    except OSError as exc:
        logger.error(f"[Telnet] 端口 {args.port} 绑定失败: {exc}")
        sys.exit(1)
    server_sock.listen(128)
    server_sock.settimeout(1.0)
    logger.info(f"[Telnet] 监听 {args.host}:{args.port}")

    def _shutdown(signum, frame):
        _stop_event.set()

    signal.signal(signal.SIGINT, _shutdown)
    if hasattr(signal, 'SIGTERM'):
        signal.signal(signal.SIGTERM, _shutdown)

    while not _stop_event.is_set():
        try:
            conn, addr = server_sock.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        threading.Thread(
            target=_handle_client,
            args=(conn, addr[0], guard, reporter),
            daemon=True,
        ).start()

    try:
        server_sock.close()
    except OSError:
        pass


if __name__ == '__main__':
    main()
