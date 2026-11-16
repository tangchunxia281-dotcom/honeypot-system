# -*- coding: utf-8 -*-
"""
FTP 协议仿真处理器（纯 Socket，无第三方依赖）
==============================================

伪装 vsftpd 3.0.5：
1. 匿名登录 + 弱口令（admin/admin、root/123456、ftpuser/ftp123、test/test）
2. PASV/EPSV/PORT 主动/被动数据通道
3. 内存诱饵文件：backup_2024.sql.gz、.env
4. RETR 诱饵文件 -> 高危数据窃取事件；STOR 上传内容丢弃不落盘，仅记录预览

所有事件经 utils.protocol_guard 统一上报。仅用于合法授权的教学/演示/研究。
"""
import io
import os
import socket

BANNER = '220 (vsFTPd 3.0.5)'
ANONYMOUS_USERS = ('anonymous', 'ftp')

# 诱饵弱口令（匿名不需要密码；这里的凭证启动时输出 CRED 行）
DECOY_ACCOUNTS = [
    ('admin', 'admin'),
    ('root', '123456'),
    ('ftpuser', 'ftp123'),
    ('test', 'test'),
]
_ACCOUNT_MAP = dict(DECOY_ACCOUNTS)

# 诱饵文件：name -> (ls 行, 内容 bytes)
_ENV_CONTENT = (
    'APP_ENV=production\r\n'
    'DB_HOST=10.0.12.10\r\n'
    'DB_USER=backup\r\n'
    'DB_PASSWORD=Backup@Prod_2024!\r\n'
    'JWT_SECRET=do-not-use-this-decoy-secret\r\n'
).encode('utf-8')
_SQL_DUMP_CONTENT = (
    '-- MySQL dump decoy (honeypot, not a real backup)\r\n'
    'CREATE TABLE `users` (`id` int, `username` varchar(64), `password` varchar(128));\r\n'
    "INSERT INTO `users` VALUES (1,'admin','*DECOYHASH000000000000000000');\r\n"
).encode('utf-8')

DECOY_FILES = {
    '.': None,  # 目录占位
    'backup_2024.sql.gz': (
        '-rw-r--r--    1 0        0            18432 Jun 01 02:11 backup_2024.sql.gz\r\n',
        _SQL_DUMP_CONTENT),
    '.env': (
        '-rw-------    1 0        0              186 Jun 01 02:12 .env\r\n',
        _ENV_CONTENT),
    'readme.txt': (
        '-rw-r--r--    1 0        0               72 Jun 01 02:13 readme.txt\r\n',
        b'Internal file server. Authorized users only.\r\n'),
}
_LISTING = (
    'drwxr-xr-x    2 0        0             4096 Jun 01 02:10 .\r\n'
    'drwxr-xr-x    3 0        0             4096 May 30 18:02 ..\r\n'
    'drwxr-xr-x    2 1001     1001           4096 Jun 01 02:14 uploads\r\n'
    + DECOY_FILES['backup_2024.sql.gz'][0]
    + DECOY_FILES['.env'][0]
    + DECOY_FILES['readme.txt'][0]
)
# NLST 协议只返回纯名称（每行一个）
_NLST = 'uploads\r\nbackup_2024.sql.gz\r\n.env\r\nreadme.txt\r\n'

_FEAT_REPLY = (
    '215-Features:\r\n'
    ' UTF8\r\n'
    ' EPRT\r\n'
    ' EPSV\r\n'
    ' PASV\r\n'
    ' REST STREAM\r\n'
    ' SIZE\r\n'
    '215 End\r\n'
)


class FTPHoneypot:
    """单条 FTP 控制连接处理器。"""

    def __init__(self, guard, reporter, logger):
        self.guard = guard
        self.reporter = reporter
        self.logger = logger
        self.conn = None
        self.client_ip = ''
        self.user = ''
        self.authenticated = False
        self.cwd = '/'
        self._pasv_sock = None
        self._active_addr = None

    # ---------------- 基础收发 ----------------
    def _send(self, text: str):
        # 规范化为 CRLF，并保证应答以 CRLF 结尾（FTP 行协议要求）
        data = text.encode('utf-8', errors='replace')
        data = (data.replace(b'\r\n', b'\n').replace(b'\r', b'\n')
                    .replace(b'\n', b'\r\n'))
        if not data.endswith(b'\r\n'):
            data += b'\r\n'
        self.conn.sendall(data)

    def _read_command(self, rfile) -> str:
        line = rfile.readline()
        if not line:
            return ''
        return line.decode('utf-8', errors='replace').strip()

    # ---------------- 数据通道 ----------------
    def _open_pasv_listener(self, extended: bool = False) -> str:
        """新建被动监听端口，返回控制面回复文本。"""
        self._close_pasv_listener()
        bind_ip = self.conn.getsockname()[0]
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((bind_ip, 0))
        srv.listen(1)
        srv.settimeout(30)
        self._pasv_sock = srv
        port = srv.getsockname()[1]
        if extended:
            return f'229 Entering Extended Passive Mode (|||{port}|).'
        # PASV 需要客户端能路由到的地址：优先控制连接目的地址，回退本机 IPv4
        public_ip = self._local_ipv4(bind_ip)
        # PASV 格式要求四个 IP 段之间也用逗号：(h1,h2,h3,h4,p1,p2)
        octets = ','.join(public_ip.split('.'))
        return f'227 Entering Passive Mode ({octets},{port >> 8},{port & 0xFF}).'

    @staticmethod
    def _local_ipv4(bind_ip: str) -> str:
        if bind_ip and bind_ip not in ('0.0.0.0', '::', '127.0.0.1'):
            return bind_ip
        try:
            probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            probe.connect(('8.8.8.8', 80))
            ip = probe.getsockname()[0]
            probe.close()
            if ip:
                return ip
        except OSError:
            pass
        return '127.0.0.1'

    def _close_pasv_listener(self):
        if self._pasv_sock is not None:
            try:
                self._pasv_sock.close()
            except OSError:
                pass
            self._pasv_sock = None

    def _open_data_conn(self):
        """按当前状态建立数据连接，返回 socket（失败返回 None）。"""
        if self._pasv_sock is not None:
            try:
                data, _ = self._pasv_sock.accept()
                return data
            except OSError:
                return None
            finally:
                # vsftpd 每次传输后需要重新 PASV
                self._close_pasv_listener()
        if self._active_addr is not None:
            host, port = self._active_addr
            self._active_addr = None
            try:
                data = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                data.settimeout(15)
                data.connect((host, port))
                return data
            except OSError:
                return None
        return None

    # ---------------- 主流程 ----------------
    def handle(self, conn: socket.socket, client_ip: str):
        self.conn = conn
        self.client_ip = client_ip
        conn.settimeout(120)
        self._send(BANNER)
        try:
            rfile = conn.makefile('rb')
            while True:
                raw = self._read_command(rfile)
                if not raw:
                    return
                parts = raw.split(None, 1)
                verb = parts[0].upper()
                arg = parts[1].strip() if len(parts) > 1 else ''
                if not self._dispatch(verb, arg):
                    return
        except (OSError, ConnectionResetError, BrokenPipeError):
            return
        except Exception as exc:
            self.logger.debug(f"[ftp] {client_ip} 处理异常: {exc}")
        finally:
            self._close_pasv_listener()
            try:
                conn.close()
            except OSError:
                pass

    def _dispatch(self, verb: str, arg: str) -> bool:
        """返回 False 表示关闭连接。"""
        # 封禁中的 IP 直接断开
        if self.guard.ban_remaining(self.client_ip) > 0 and verb not in ('QUIT',):
            self._send('421 Service not available, closing control connection.')
            return False

        if verb == 'USER':
            return self._cmd_user(arg)
        if verb == 'PASS':
            return self._cmd_pass(arg)
        if verb == 'QUIT':
            self._send('221 Goodbye.')
            return False
        if verb in ('SYST',):
            self._send('215 UNIX Type: L8')
            return True
        if verb == 'FEAT':
            self._send(_FEAT_REPLY)
            return True
        if verb in ('PWD', 'XPWD'):
            self._send(f'257 "{self.cwd}" is the current directory')
            return True
        if verb == 'TYPE':
            mode = (arg or 'A').upper()[:1] or 'A'
            self._send(f'200 Switching to {("ASCII" if mode == "A" else "Binary")} mode.')
            return True
        if verb in ('NOOP', 'ALLO'):
            self._send('200 NOOP ok.')
            return True
        if verb == 'HELP':
            self._send('214-The following commands are recognized:\r\n214 USER PASS PASV EPSV PORT '
                       'EPRT LIST NLST RETR STOR QUIT PWD CWD CDUP SYST TYPE NOOP HELP')
            return True
        if verb == 'PASV':
            self._send(self._open_pasv_listener(extended=False))
            return True
        if verb in ('EPSV', 'LPSV'):
            self._send(self._open_pasv_listener(extended=True))
            return True
        if verb == 'PORT':
            return self._cmd_port(arg, extended=False)
        if verb == 'EPRT':
            return self._cmd_port(arg, extended=True)
        if verb in ('LIST', 'NLST'):
            return self._cmd_list(names_only=(verb == 'NLST'))
        if verb == 'RETR':
            return self._cmd_retr(arg)
        if verb in ('STOR', 'STOU', 'APPE'):
            return self._cmd_stor(arg, verb)
        if verb in ('CWD', 'XCWD'):
            self.cwd = '/' if arg in ('/', '') else f'/{arg.strip("/").split("/")[0]}'
            self._send(f'250 Directory successfully changed.')
            return True
        if verb in ('CDUP', 'XCUP'):
            self.cwd = '/'
            self._send('250 Directory successfully changed.')
            return True
        if verb in ('MKD', 'XMKD'):
            self._send(f'257 "/{arg}" - Directory successfully created')
            return True
        if verb in ('RMD', 'XRMD', 'DELE'):
            self._send('250 Requested file action okay, completed.')
            return True
        if verb == 'RNFR':
            self._send('350 Ready for RNTO.')
            return True
        if verb == 'RNTO':
            self._send('250 Rename successful.')
            return True
        if verb == 'SIZE':
            name = os.path.basename(arg)
            entry = DECOY_FILES.get(name)
            if entry is not None:
                self._send(f'213 {len(entry[1])}')
            else:
                self._send('550 Could not get file size.')
            return True
        if verb in ('REST',):
            self._send('350 Restart position accepted (0).')
            return True
        if verb in ('OPTS',):
            self._send('200 Always in UTF8 mode.')
            return True
        self._send(f'500 Unknown command: {verb}.')
        return True

    # ---------------- 认证 ----------------
    def _cmd_user(self, arg: str) -> bool:
        self.user = arg
        self.authenticated = False
        if not arg:
            self._send('501 USER : permission denied.')
            return True
        self._send('331 Please specify the password.')
        return True

    def _cmd_pass(self, arg: str) -> bool:
        if not self.user:
            self._send('503 Login with USER first.')
            return True
        user_lower = self.user.lower()
        is_anonymous = user_lower in ANONYMOUS_USERS
        success = False
        kind = 'weak_password'
        if is_anonymous:
            success = True
            kind = 'anonymous'
        elif self.user in _ACCOUNT_MAP and _ACCOUNT_MAP[self.user] == arg:
            success = True
        if success:
            self.authenticated = True
            self._send('230 Login successful.')
            tags = ['ftp', kind, 'valid_accounts', 'attack_technique:T1078']
            if kind == 'anonymous':
                tags.append('anonymous')
            self.reporter.event(
                'ftp_login_success', self.client_ip, score=40,
                payload=f"FTP 登录成功 user={self.user} kind={kind}",
                tags=tags,
            )
            return True

        self._send('530 Login incorrect.')
        ban_seconds = self.guard.record_auth_failure(self.client_ip)
        self.reporter.event(
            'ftp_login_attempt', self.client_ip, score=15,
            payload=f"FTP 登录失败 user={self.user}",
            tags=['ftp', 'bruteforce', 'attack_technique:T1110'],
        )
        if ban_seconds:
            self.reporter.event(
                'ftp_bruteforce_ban', self.client_ip, score=60,
                payload=f"FTP 爆破触发封禁 {ban_seconds}s user={self.user}",
                tags=['ftp', 'bruteforce', 'rate_ban'],
            )
        return True

    # ---------------- 主动/被动数据 ----------------
    def _cmd_port(self, arg: str, extended: bool) -> bool:
        try:
            if extended:
                # EPRT: |family|address|port|  family 1=IPv4 2=IPv6
                fields = arg.strip().strip('|').split('|')
                if len(fields) != 3:
                    raise ValueError
                host = fields[1]
                port = int(fields[2])
            else:
                nums = [int(x) for x in arg.split(',')]
                if len(nums) != 6:
                    raise ValueError
                host = '.'.join(str(x) for x in nums[:4])
                port = (nums[4] << 8) + nums[5]
            self._active_addr = (host, port)
            self._close_pasv_listener()
            self._send('200 PORT command successful. Consider using PASV.')
        except (ValueError, OSError):
            self._send('500 Illegal PORT command.')
        return True

    def _cmd_list(self, names_only: bool = False) -> bool:
        data = self._open_data_conn()
        if data is None:
            self._send('425 Use PORT or PASV first.')
            return True
        try:
            self._send('150 Here comes the directory listing.')
            listing = _NLST if names_only else _LISTING
            data.sendall(listing.encode('utf-8'))
            self._send('226 Directory send OK.')
            self.reporter.event(
                'ftp_directory_list', self.client_ip, score=40,
                payload=f"FTP 目录列举 cwd={self.cwd}",
                tags=['ftp', 'directory_listing', 'recon', 'attack_technique:T1083'],
            )
        except OSError:
            self._send('426 Connection closed; transfer aborted.')
        finally:
            data.close()
        return True

    def _cmd_retr(self, arg: str) -> bool:
        name = os.path.basename(arg)
        entry = DECOY_FILES.get(name)
        data = self._open_data_conn()
        if data is None:
            self._send('425 Use PORT or PASV first.')
            return True
        if entry is None:
            self._send(f'550 {arg}: No such file or directory.')
            data.close()
            return True
        try:
            self._send(f'150 Opening BINARY mode data connection for {name}.')
            data.sendall(entry[1])
            self._send('226 Transfer complete.')
            self.reporter.event(
                'ftp_data_theft', self.client_ip, score=70,
                payload=f"FTP 下载敏感诱饵文件 {name}（{len(entry[1])} 字节）",
                tags=['ftp', 'data_exfiltration', 'sensitive_file', 'attack_technique:T1213'],
                force_alert=True,
            )
        except OSError:
            self._send('426 Connection closed; transfer aborted.')
        finally:
            data.close()
        return True

    def _cmd_stor(self, arg: str, verb: str) -> bool:
        data = self._open_data_conn()
        if data is None:
            self._send('425 Use PORT or PASV first.')
            return True
        preview = b''
        total = 0
        try:
            self._send(f'150 Ok to send data.')
            data.settimeout(30)
            while True:
                chunk = data.recv(4096)
                if not chunk:
                    break
                total += len(chunk)
                if len(preview) < 512:
                    preview += chunk[:512 - len(preview)]
            self._send('226 Transfer complete.')
        except OSError:
            self._send('426 Connection closed; transfer aborted.')
        finally:
            data.close()

        # 上传内容一律丢弃不落盘，仅做特征识别与预览记录
        low = preview.lower()
        is_payload = (b'\x7felf' in low or b'#!/bin/sh' in low or b'#!/bin/bash' in low
                      or b'wget ' in low or b'curl ' in low or b'mknod' in low)
        self.reporter.event(
            'ftp_upload', self.client_ip, score=80 if is_payload else 35,
            payload=(f"FTP 上传文件 {os.path.basename(arg)}（{total} 字节，内容已丢弃），"
                     f"预览: {preview[:200].decode('utf-8', errors='replace')!r}"),
            tags=(['ftp', 'file_upload', 'malware_drop', 'attack_technique:T1105']
                  if is_payload else ['ftp', 'file_upload']),
            force_alert=is_payload,
        )
        return True
