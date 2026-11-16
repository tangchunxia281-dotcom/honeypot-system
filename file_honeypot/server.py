# -*- coding: utf-8 -*-
"""
文件共享蜜罐入口（FTP）
=======================

端口由 --port 指定（main.py 传入 2121），
事件统一写入 event_log（source = ftp）。
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
from file_honeypot.ftp_handler import FTPHoneypot, DECOY_ACCOUNTS  # noqa: E402

logger = setup_logger('file_honeypot', 'file_honeypot.log')

_stop_event = threading.Event()


def _emit_credentials():
    if not env_bool('EMIT_CREDENTIAL_LINES', False):
        return
    for user, pwd in DECOY_ACCOUNTS:
        print(f"CRED::{user}::{pwd}", flush=True)
    print("CRED::anonymous::(任意邮箱)", flush=True)


def _handle_client(conn, client_ip, guard: ConnectionGuard, reporter, logger):
    # FTPHoneypot 持有连接级状态（PASV 套接字/登录态/工作目录），每连接独立实例
    handler = FTPHoneypot(guard, reporter, logger)
    scan = guard.record_preauth_connection(client_ip)
    if scan:
        handler.reporter.event(
            'ftp_port_scan', client_ip, score=45,
            payload=f"FTP 端口扫描：{scan['window_seconds']}s 内 {scan['count']} 次连接",
            tags=['ftp', 'port_scan', 'attack_technique:T1595'],
        )
    if not guard.acquire_worker(timeout=1.0):
        conn.close()
        return
    admitted, reason = guard.admit(client_ip)
    if not admitted:
        if reason == 'banned':
            logger.info(f"[FTP] 拒绝已封禁 IP {client_ip}")
        conn.close()
        guard.release_worker()
        return
    try:
        handler.handle(conn, client_ip)
    except Exception as exc:
        logger.debug(f"[FTP] {client_ip} 处理异常: {exc}")
    finally:
        guard.release(client_ip)
        guard.release_worker()


def main():
    parser = argparse.ArgumentParser(description='文件共享蜜罐（FTP）')
    parser.add_argument('-H', '--host', default=env_str('FTP_HOST', '0.0.0.0'))
    parser.add_argument('-p', '--port', type=int,
                        default=env_int('FTP_PORT', 2121, 1, 65535))
    args = parser.parse_args()

    _emit_credentials()

    guard = ConnectionGuard(
        'ftp',
        max_workers=env_int('SSH_MAX_WORKERS', 80, 10, 500),
        max_active_total=60, max_active_per_ip=10,
        fail_window_seconds=60, fail_threshold=12,
        ban_base_seconds=600, ban_max_seconds=7200,
        scan_window_seconds=10, scan_threshold=18, scan_cooldown_seconds=120,
    )
    reporter = ProtocolReporter('ftp', logger)

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server_sock.bind((args.host, args.port))
    except OSError as exc:
        logger.error(f"[FTP] 端口 {args.port} 绑定失败: {exc}")
        sys.exit(1)
    server_sock.listen(128)
    server_sock.settimeout(1.0)
    logger.info(f"[FTP] 监听 {args.host}:{args.port}")

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
            args=(conn, addr[0], guard, reporter, logger),
            daemon=True,
        ).start()

    try:
        server_sock.close()
    except OSError:
        pass


if __name__ == '__main__':
    main()
