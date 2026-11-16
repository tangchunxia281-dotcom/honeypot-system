# -*- coding: utf-8 -*-
"""本机各协议蜜罐测试流量生成器（仅 127.0.0.1，有限次数）。

覆盖 MySQL / Redis / FTP / Telnet / SSH 五类诱捕入口，用于产生真实事件后
在 Dashboard 与 AI 工作区核对。不会扫描、不爆破、不访问外部目标。

用法：
    uv run python scripts/demo/protocol_traffic.py --ssh-password <本次启动的密码>
    uv run python scripts/demo/protocol_traffic.py --ssh-password xxx --json docs/test-run/protocol.json
"""
import argparse
import json
import socket
import sys
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RECORDS = []


def record(protocol, action, status, detail=''):
    RECORDS.append({'at': datetime.now().isoformat(timespec='seconds'), 'protocol': protocol,
                    'action': action, 'status': status, 'detail': str(detail)[:300]})
    print(f'[{len(RECORDS):02d}] {protocol:8s} {action:28s} {status:22s} {detail}', flush=True)


def probe_mysql(host, port):
    try:
        import pymysql
    except ImportError:
        record('mysql', '依赖缺失', 'dependency_missing', 'pymysql')
        return
    for user, password in (('root', '123456'), ('admin', 'admin888')):
        try:
            conn = pymysql.connect(host=host, port=port, user=user, password=password,
                                   connect_timeout=5, read_timeout=5, write_timeout=5)
            try:
                with conn.cursor() as cur:
                    cur.execute("SELECT VERSION()")
                    record('mysql', f'登录 {user}', 'connected', str(cur.fetchone())[:120])
                    cur.execute("SELECT * FROM users WHERE id=1 UNION SELECT user,password FROM mysql.user")
                    record('mysql', 'UNION 查询', 'query_sent', '')
            finally:
                conn.close()
        except Exception as exc:
            record('mysql', f'认证 {user}', 'auth_rejected', type(exc).__name__)
        time.sleep(0.5)


def resp(client, *parts):
    payload = f"*{len(parts)}\r\n" + ''.join(f'${len(str(p))}\r\n{p}\r\n' for p in parts)
    client.sendall(payload.encode())
    time.sleep(0.4)
    try:
        client.settimeout(2)
        data = client.recv(4096)
        return data.decode('utf-8', 'replace')[:200]
    except socket.timeout:
        return ''


def probe_redis(host, port):
    try:
        client = socket.create_connection((host, port), timeout=5)
    except OSError as exc:
        record('redis', '连接', 'transport_error', type(exc).__name__)
        return
    try:
        for label, parts in (
            ('AUTH', ('AUTH', 'admin888')),
            ('INFO', ('INFO', 'server')),
            ('KEYS *', ('KEYS', '*')),
            ('CONFIG GET', ('CONFIG', 'GET', 'requirepass')),
            ('GET flag', ('GET', 'flag')),
        ):
            reply = resp(client, *parts)
            record('redis', f'命令 {label}', 'response_received', reply.replace('\r\n', ' ')[:120])
    finally:
        client.close()


def probe_ftp(host, port):
    import ftplib
    for user, password, label in (('anonymous', 'guest@example.com', '匿名'),
                                  ('admin', 'admin', '弱口令')):
        try:
            ftp = ftplib.FTP()
            ftp.connect(host, port, timeout=5)
            ftp.login(user, password)
            record('ftp', f'{label}登录 {user}', 'virtual_login_accepted', '')
            try:
                files = []
                ftp.retrlines('LIST', files.append)
                record('ftp', 'LIST 目录', 'listing_received', f'{len(files)} 行')
            except Exception as exc:
                record('ftp', 'LIST 目录', 'listing_failed', type(exc).__name__)
            try:
                ftp.retrbinary('RETR /etc/passwd', lambda chunk: None)
                record('ftp', 'RETR /etc/passwd', 'file_returned')
            except Exception as exc:
                record('ftp', 'RETR /etc/passwd', 'file_denied', type(exc).__name__)
            try:
                ftp.quit()
            except Exception:
                pass
        except Exception as exc:
            record('ftp', f'{label}登录 {user}', 'auth_rejected', type(exc).__name__)
        time.sleep(0.5)


def probe_telnet(host, port, user='root', password='123456'):
    try:
        client = socket.create_connection((host, port), timeout=5)
    except OSError as exc:
        record('telnet', '连接', 'transport_error', type(exc).__name__)
        return
    client.settimeout(4)
    try:
        time.sleep(0.6)
        try:
            banner = client.recv(4096).decode('utf-8', 'replace')
            record('telnet', '读取 banner', 'banner_received', banner.replace('\r', ' ').strip()[:100])
        except socket.timeout:
            record('telnet', '读取 banner', 'timeout')
        for label, payload in ((f'用户名 {user}', user + '\r\n'), ('密码', password + '\r\n'),
                               ('命令 uname -a', 'uname -a\r\n'),
                               ('命令 cat /etc/passwd', 'cat /etc/passwd\r\n'),
                               ('命令 ls -la', 'ls -la\r\n'), ('退出', 'exit\r\n')):
            client.sendall(payload.encode())
            time.sleep(0.5)
            try:
                data = client.recv(8192).decode('utf-8', 'replace')
                record('telnet', label, 'response_received', data.replace('\r', ' ').strip()[:120])
            except socket.timeout:
                record('telnet', label, 'timeout')
    finally:
        client.close()


def probe_ssh(host, port, user, password):
    try:
        import paramiko
    except ImportError:
        record('ssh', '依赖缺失', 'dependency_missing', 'paramiko')
        return
    for attempt, (name, pwd) in enumerate((('root', 'wrong-pass-1'), ('root', 'wrong-pass-2'),
                                           (user, password)), 1):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(host, port=port, username=name, password=pwd,
                           look_for_keys=False, allow_agent=False, timeout=6,
                           banner_timeout=8, auth_timeout=10)
        except paramiko.AuthenticationException:
            record('ssh', f'登录失败 #{attempt} {name}', 'auth_failed', '')
            continue
        except Exception as exc:
            record('ssh', f'连接 {name}', 'transport_error', type(exc).__name__)
            continue

        try:
            record('ssh', f'登录成功 {name}', 'virtual_login_accepted', '')
            for command in ('whoami', 'uname -a', 'cat /etc/passwd', 'ls -la /root',
                            'ip addr', 'sysinfo', 'appctl status', 'demo_unknown_cmd'):
                try:
                    _in, out, _err = client.exec_command(command, timeout=10)
                    text = out.read().decode('utf-8', 'replace')
                    record('ssh', f'命令 {command}', 'response_received', text.replace('\r', ' ').strip()[:140])
                except Exception as exc:
                    record('ssh', f'命令 {command}', 'command_error', type(exc).__name__)
                time.sleep(0.6)
        finally:
            client.close()
        return


def main(argv=None):
    parser = argparse.ArgumentParser(description='本机多协议蜜罐测试流量（仅回环地址）')
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--mysql-port', type=int, default=13306)
    parser.add_argument('--redis-port', type=int, default=16379)
    parser.add_argument('--ftp-port', type=int, default=2121)
    parser.add_argument('--telnet-port', type=int, default=2223)
    parser.add_argument('--ssh-port', type=int, default=2222)
    parser.add_argument('--ssh-user', default='root')
    parser.add_argument('--ssh-password', default='')
    parser.add_argument('--telnet-user', default='root')
    parser.add_argument('--telnet-password', default='123456')
    parser.add_argument('--only', default='', help='只跑指定协议：mysql,redis,ftp,telnet,ssh')
    parser.add_argument('--json', default='')
    args = parser.parse_args(argv)
    if args.host not in ('127.0.0.1', 'localhost', '::1'):
        parser.error('本脚本只允许回环地址')

    selected = {item.strip().lower() for item in str(args.only or '').split(',') if item.strip()}
    wanted = (lambda name: not selected or name in selected)

    for name, fn in (('mysql', lambda: probe_mysql(args.host, args.mysql_port)),
                     ('redis', lambda: probe_redis(args.host, args.redis_port)),
                     ('ftp', lambda: probe_ftp(args.host, args.ftp_port)),
                     ('telnet', lambda: probe_telnet(args.host, args.telnet_port,
                                                     args.telnet_user, args.telnet_password))):
        if not wanted(name):
            continue
        try:
            fn()
        except Exception as exc:
            record(name, 'unexpected_error', 'error', type(exc).__name__)
        time.sleep(0.6)

    if wanted('ssh') and args.ssh_password:
        try:
            probe_ssh(args.host, args.ssh_port, args.ssh_user, args.ssh_password)
        except Exception as exc:
            record('ssh', 'unexpected_error', 'error', type(exc).__name__)
    elif wanted('ssh'):
        record('ssh', '跳过', 'no_password', '未提供 --ssh-password')

    if args.json:
        target = Path(args.json)
        if not target.is_absolute():
            target = ROOT / target
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps({'generated_at': datetime.now().isoformat(timespec='seconds'),
                                      'records': RECORDS}, ensure_ascii=False, indent=2), encoding='utf-8')
        print('结果：' + str(target), flush=True)
    return 0


if __name__ == '__main__':
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, 'reconfigure'):
            stream.reconfigure(encoding='utf-8', errors='replace')
    raise SystemExit(main())
