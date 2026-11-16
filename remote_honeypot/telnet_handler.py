# -*- coding: utf-8 -*-
"""
Telnet 协议仿真处理器（纯 Socket，无第三方依赖）
================================================

伪装 D-Link DI-8003 企业级路由器，登录后进入 BusyBox ash shell：
1. IAC 选项协商（ECHO / SUPPRESS-GO-AHEAD / TERMINAL-TYPE / NAWS）
2. 弱口令登录：admin/admin、root/123456、guest/guest
3. 内置诱饵 BusyBox 命令集（ls/cat/ps/ifconfig 等）
4. wget/curl/tftp 下载执行 -> critical telnet_malware_download（IoT 僵尸网络）

所有事件经 utils.protocol_guard 统一上报。仅用于合法授权的教学/演示/研究。
"""
import select
import time

# ------------------------------------------------------------
# Telnet IAC 常量
# ------------------------------------------------------------
IAC = 255
DONT = 254
DO = 253
WONT = 252
WILL = 251
SB = 250
SE = 240

OPT_ECHO = 1
OPT_SGA = 3
OPT_TTYPE = 24
OPT_NAWS = 31

# 服务端初始协商：我来回显 + 要求客户端抑制 Go-Ahead / 提供终端信息
INIT_NEGOTIATION = bytes([
    IAC, WILL, OPT_ECHO,
    IAC, DO, OPT_SGA,
    IAC, DO, OPT_TTYPE,
    IAC, DO, OPT_NAWS,
])

DEVICE_BANNER = (
    '\r\n'
    '************************************************\r\n'
    '*       D-Link DI-8003 Enterprise Gateway       *\r\n'
    '*       Firmware 3.2.1 Build 20240115           *\r\n'
    '************************************************\r\n'
)
SHELL_BANNER = (
    '\r\n'
    'BusyBox v1.27.2 (2024-01-15 12:00:00 CST) built-in shell (ash)\r\n'
    "Enter 'help' for a list of built-in commands.\r\n"
)

# 诱饵弱口令（启动时输出 CRED 行）
DECOY_ACCOUNTS = [
    ('admin', 'admin'),
    ('root', '123456'),
    ('guest', 'guest'),
]
_ACCOUNT_MAP = dict(DECOY_ACCOUNTS)

# BusyBox 诱饵环境
_FAKE_PASSWD = (
    'root:$1$abc$DECOYHASH0000000000000000000000:0:0:root:/root:/bin/ash\r\n'
    'admin:$1$abc$DECOYHASH0000000000000000000001:0:0:admin:/home/admin:/bin/ash\r\n'
    'nobody:x:65534:65534:nobody:/:/bin/false\r\n'
)
_FAKE_SHADOW = (
    'root:$1$salt$DECOYHASH000000000000000000:19000:0:99999:7:::\r\n'
    'admin:$1$salt$DECOYHASH00000000000000000:19000:0:99999:7:::\r\n'
)
_FAKE_PS = (
    '  PID USER       VSZ STAT COMMAND\r\n'
    '    1 root      1236 S    /sbin/init\r\n'
    '   42 root       860 S    /usr/sbin/httpd -f /etc/httpd.conf\r\n'
    '   88 root       744 S    telnetd -l /bin/ash\r\n'
    '  105 root       640 S    /bin/dropbear -p 22\r\n'
    '  318 admin      912 R    ps\r\n'
)
_FAKE_IFCONFIG = (
    'br0       Link encap:Ethernet  HWaddr C8:BE:19:1A:2B:3C\r\n'
    '          inet addr:192.168.0.1  Bcast:192.168.0.255  Mask:255.255.255.0\r\n'
    '          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1\r\n'
    'eth0      Link encap:Ethernet  HWaddr C8:BE:19:1A:2B:3D\r\n'
    '          inet addr:10.0.12.15  Bcast:10.0.12.255  Mask:255.255.255.0\r\n'
    '          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1\r\n'
    'lo        Link encap:Local Loopback\r\n'
    '          inet addr:127.0.0.1  Mask:255.0.0.0\r\n'
)
_FAKE_LS_HOME = (
    'drwxr-xr-x    2 root     root           0 Jun  1  2024 .\r\n'
    'drwxr-xr-x   12 root     root           0 May 30  2024 ..\r\n'
    '-rwxr-xr-x    1 root     root        2412 Jun  1  2024 start.sh\r\n'
    '-rw-r--r--    1 root     root         512 Jun  1  2024 wan.conf\r\n'
    '-rw-------    1 root     root         256 Jun  1  2024 nvram.bak\r\n'
)
_HELP_TEXT = (
    'Built-in commands:\r\n'
    '  help ? cd ls cat ps ifconfig netstat ping uname id whoami pwd echo\r\n'
    '  uptime free df mount busybox exit logout wget curl tftp chmod\r\n'
)


class TelnetHoneypot:
    """单条 Telnet 连接处理器（设备登录 -> BusyBox ash）。"""

    def __init__(self, guard, reporter, logger):
        self.guard = guard
        self.reporter = reporter
        self.logger = logger
        self.conn = None
        self.client_ip = ''
        self.user = ''
        self.cwd = '/root'
        # 接收缓冲与 IAC 解析状态
        self._recv_buf = bytearray()
        self._iac_state = 'normal'
        self._iac_buf = bytearray()

    # ---------------- 收发 ----------------
    def _send(self, text: str):
        self.conn.sendall(text.encode('utf-8', errors='replace'))

    def _send_bytes(self, data: bytes):
        self.conn.sendall(data)

    def _next_byte(self, timeout: int):
        """从接收缓冲取一个字节，不足则 recv；EOF 返回 None。"""
        if not self._recv_buf:
            self.conn.settimeout(timeout)
            chunk = self.conn.recv(256)
            if not chunk:
                return None
            self._recv_buf.extend(chunk)
        return self._recv_buf.pop(0)

    def _peek_byte(self, wait: float = 0.05):
        """窥视下一字节但不消费；缓冲为空时最多等待 wait 秒，不可达返回 None。"""
        if self._recv_buf:
            return self._recv_buf[0]
        ready, _, _ = select.select([self.conn], [], [], wait)
        if ready:
            chunk = self.conn.recv(256)
            if chunk:
                self._recv_buf.extend(chunk)
                return self._recv_buf[0]
        return None

    def _consume_peeked(self):
        if self._recv_buf:
            del self._recv_buf[0]

    def _read_line(self, timeout: int = 120, echo: bool = True):
        """
        读取一行，逐字节处理 Telnet IAC 协商。
        echo=True 时由服务端回显普通字符（用户名/Shell），False 用于密码。
        EOF 返回 None。
        """
        line = bytearray()
        while True:
            byte = self._next_byte(timeout)
            if byte is None:
                return None
            text_byte = self._feed_byte(byte, echo)
            if text_byte is None:
                continue
            if text_byte == b'':
                return line.decode('utf-8', errors='replace').strip()
            line.extend(text_byte)

    def _feed_byte(self, byte: int, echo: bool):
        """
        IAC 状态机。返回：
          None  -> 字节被协议消费
          b''   -> 行结束（\r 或 \n；\r\n 只算一次）
          bytes -> 普通文本字节
        """
        st = self._iac_state
        if st == 'normal':
            if byte == IAC:
                self._iac_state = 'iac'
                return None
            if byte in (13, 10):
                # \r 行尾：仅当“紧跟可读的 \n”时吞掉它，绝不为等 \n 而阻塞
                # （部分客户端只发 \r；Telnet 规范中的 CR NUL 亦在此消费）
                if byte == 13:
                    nxt = self._peek_byte(wait=0.05)
                    if nxt in (10, 0):
                        self._consume_peeked()
                if echo:
                    self._send('\r\n')
                return b''
            if byte in (8, 127):  # 退格
                return None
            if echo:
                self._send_bytes(bytes([byte]))
            return bytes([byte])
        if st == 'iac':
            if byte == IAC:
                self._iac_state = 'normal'
                return bytes([IAC]) if echo else None
            if byte in (WILL, WONT, DO, DONT):
                self._iac_state = 'iac_option'
                self._iac_buf = bytearray([byte])
                return None
            if byte == SB:
                self._iac_state = 'subneg'
                self._iac_buf = bytearray()
                return None
            # NOP / DM 等双字节命令
            self._iac_state = 'normal'
            return None
        if st == 'iac_option':
            verb = self._iac_buf[0]
            self._reply_negotiation(verb, byte)
            self._iac_state = 'normal'
            return None
        if st == 'subneg':
            if byte == IAC:
                self._iac_state = 'subneg_iac'
                return None
            self._iac_buf.append(byte)
            return None
        if st == 'subneg_iac':
            if byte == SE:
                self._handle_subneg(bytes(self._iac_buf))
                self._iac_state = 'normal'
                return None
            if byte == IAC:
                self._iac_buf.append(IAC)
                self._iac_state = 'subneg'
                return None
            self._iac_state = 'normal'
            return None
        self._iac_state = 'normal'
        return None

    def _reply_negotiation(self, verb: int, option: int):
        # 客户端 WILL 提供能力：对 TTYPE/NAWS/SGA 回 DO，其余 DONT
        if verb == WILL:
            reply = DO if option in (OPT_TTYPE, OPT_NAWS, OPT_SGA) else DONT
            self._send_bytes(bytes([IAC, reply, option]))
        elif verb == WONT:
            self._send_bytes(bytes([IAC, DONT, option]))
        elif verb == DO:
            # 客户端要求我们启用能力：ECHO/SGA 同意，其余 WONT
            reply = WILL if option in (OPT_ECHO, OPT_SGA) else WONT
            self._send_bytes(bytes([IAC, reply, option]))
        elif verb == DONT:
            self._send_bytes(bytes([IAC, WONT, option]))

    def _handle_subneg(self, data: bytes):
        # TTYPE SEND -> 回 xterm；NAWS 无需应答
        if len(data) >= 2 and data[0] == OPT_TTYPE and data[1] == 1:
            self._send_bytes(bytes([IAC, SB, OPT_TTYPE, 0]) + b'xterm'
                             + bytes([IAC, SE]))

    # ---------------- 登录阶段 ----------------
    def handle(self, conn, client_ip: str):
        self.conn = conn
        self.client_ip = client_ip
        conn.settimeout(120)
        self._send_bytes(INIT_NEGOTIATION)
        self._send(DEVICE_BANNER)
        try:
            if not self._do_login():
                return
            self._shell_loop()
        except (OSError, ConnectionResetError, BrokenPipeError):
            return
        except Exception as exc:
            self.logger.debug(f"[telnet] {client_ip} 处理异常: {exc}")
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _do_login(self, max_attempts: int = 3) -> bool:
        for attempt in range(1, max_attempts + 1):
            self._send('login: ')
            user = self._read_line()
            if user is None:
                return False
            user = user.strip()
            self._send('Password: ')
            password = self._read_line(echo=False)
            if password is None:
                return False

            if user in _ACCOUNT_MAP and _ACCOUNT_MAP[user] == password:
                self.user = user
                self.guard.record_auth_success(self.client_ip)
                self._send('\r\n')
                self.reporter.event(
                    'telnet_login_success', self.client_ip, score=45,
                    payload=f"Telnet 设备登录成功 user={user}（D-Link DI-8003）",
                    tags=['telnet', 'valid_accounts', 'iot', 'attack_technique:T1078'],
                )
                return True

            self._send('\r\nLogin incorrect\r\n\r\n')
            ban_seconds = self.guard.record_auth_failure(self.client_ip)
            self.reporter.event(
                'telnet_login_attempt', self.client_ip, score=15,
                payload=f"Telnet 登录失败 user={user} (第 {attempt} 次)",
                tags=['telnet', 'bruteforce', 'iot', 'attack_technique:T1110'],
            )
            if ban_seconds:
                self.reporter.event(
                    'telnet_bruteforce_ban', self.client_ip, score=60,
                    payload=f"Telnet 爆破触发封禁 {ban_seconds}s user={user}",
                    tags=['telnet', 'bruteforce', 'rate_ban'],
                )
                self._send('Connection closed due to too many failures.\r\n')
                return False
        self._send('Too many login attempts. Connection closed.\r\n')
        return False

    # ---------------- BusyBox shell ----------------
    def _shell_loop(self):
        self._send(SHELL_BANNER)
        while True:
            self._send(self._prompt())
            cmdline = self._read_line(timeout=300)
            if cmdline is None:
                return
            cmdline = cmdline.strip()
            if not cmdline:
                continue
            if not self._run_command(cmdline):
                return

    def _prompt(self) -> str:
        cwd = '~' if self.cwd == '/root' else self.cwd
        return f'{cwd} # '

    def _run_command(self, cmdline: str) -> bool:
        """返回 False 表示退出 shell/关闭连接。"""
        parts = cmdline.split()
        cmd = parts[0]
        args = parts[1:]
        send = self._send

        if cmd in ('exit', 'logout', 'quit'):
            send('Connection closed.\r\n')
            return False

        # ---- 恶意下载执行（IoT 僵尸网络核心特征）----
        if cmd in ('wget', 'curl', 'tftp'):
            url = ''
            for a in args:
                if a.startswith(('http://', 'https://', 'ftp://', 'tftp://')):
                    url = a
                    break
            if not url and args:
                url = args[-1]
            self.reporter.event(
                'telnet_malware_download', self.client_ip, score=85,
                payload=f"下载执行命令: {cmdline}（目标 {url}）—— IoT 僵尸网络投毒特征",
                tags=['telnet', 'malware_download', 'botnet', 'iot', 'mirai',
                      'attack_technique:T1105'],
                force_alert=True,
            )
            if cmd == 'wget':
                send(f'Connecting to {url}\r\n')
                send('Downloading... 100% |*******************************|  8192  0:00:00 ETA\r\n')
                send('8192 bytes saved to /tmp/a.out\r\n')
            elif cmd == 'curl':
                send('\x7fELF (binary payload)\r\n')
            else:
                send(f'tftp: transfer successful ({url})\r\n')
            return True

        # ---- 凭证/敏感文件窥探 ----
        if cmd == 'cat' and args:
            target = args[-1]
            if target == '/etc/passwd':
                send(_FAKE_PASSWD)
                self.reporter.event(
                    'telnet_sensitive_access', self.client_ip, score=30,
                    payload='读取 /etc/passwd',
                    tags=['telnet', 'sensitive_file', 'credential_access'],
                )
                return True
            if target == '/etc/shadow':
                send(_FAKE_SHADOW)
                self.reporter.event(
                    'telnet_sensitive_access', self.client_ip, score=50,
                    payload='读取 /etc/shadow（Linux 凭证文件）',
                    tags=['telnet', 'sensitive_file', 'credential_access',
                          'attack_technique:T1003'],
                )
                return True
            if target in ('wan.conf', 'nvram.bak', '/etc/config/wireless'):
                send('pppoe_user=admin@isp\r\npppoe_pass=Isp@Decoy2024\r\n')
                self.reporter.event(
                    'telnet_sensitive_access', self.client_ip, score=45,
                    payload=f'读取设备配置 {target}',
                    tags=['telnet', 'sensitive_file', 'iot', 'credential_access'],
                )
                return True
            send(f'cat: {target}: not found\r\n')
            return True

        if cmd in ('ls', 'dir'):
            target = args[-1] if args else ''
            if target in ('/etc', '/etc/'):
                send('passwd\r\nshadow\r\ngroup\r\ninit.d\r\nconfig\r\n')
            else:
                send(_FAKE_LS_HOME)
            self.reporter.event(
                'telnet_command', self.client_ip, score=40,
                payload=f'命令: {cmdline}', tags=['telnet', 'recon'],
            )
            return True
        if cmd in ('ps', 'top'):
            send(_FAKE_PS)
            return True
        if cmd in ('ifconfig', 'ip'):
            send(_FAKE_IFCONFIG)
            return True
        if cmd == 'netstat':
            send('Active Internet connections (servers and established)\r\n'
                 'Proto Recv-Q Send-Q Local Address           Foreign Address         State\r\n'
                 'tcp        0      0 0.0.0.0:23              0.0.0.0:*               LISTEN\r\n'
                 'tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\r\n'
                 'tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN\r\n')
            return True
        if cmd == 'uname':
            if '-a' in args:
                send('Linux DI-8003 3.4.113 #1 SMP Mon Jan 15 12:00:00 CST 2024 mips GNU/Linux\r\n')
            else:
                send('Linux\r\n')
            return True
        if cmd == 'id':
            send('uid=0(root) gid=0(root) groups=0(root)\r\n')
            return True
        if cmd == 'whoami':
            send((self.user or 'root') + '\r\n')
            return True
        if cmd == 'pwd':
            send(self.cwd + '\r\n')
            return True
        if cmd == 'cd':
            target = args[0] if args else '/root'
            if target in ('~', '/root', ''):
                self.cwd = '/root'
            elif target == '/':
                self.cwd = '/'
            else:
                self.cwd = self.cwd.rstrip('/') + '/' + target.strip('/')
            return True
        if cmd == 'echo':
            send(' '.join(args).strip('"').strip("'") + '\r\n')
            return True
        if cmd == 'uptime':
            send(f' {time.strftime("%H:%M:%S")} up 42 days,  3:14,  1 user\r\n')
            return True
        if cmd == 'free':
            send('              total         used         free       shared      buffers\r\n'
                 'Mem:         61528        41236        20292            0         5120\r\n')
            return True
        if cmd == 'df':
            send('Filesystem           1K-blocks      Used Available Use% Mounted on\r\n'
                 '/dev/root                 8192      5468      2724  67% /\r\n'
                 'tmpfs                    30764        128     30636   0% /tmp\r\n')
            return True
        if cmd == 'mount':
            send('rootfs on / type rootfs (rw)\r\n'
                 '/dev/root on / type squashfs (ro,relatime)\r\n'
                 'proc on /proc type proc (rw,relatime)\r\n')
            return True
        if cmd == 'busybox':
            send('BusyBox v1.27.2 (2024-01-15 12:00:00 CST) multi-call binary.\r\n')
            return True
        if cmd in ('help', '?'):
            send(_HELP_TEXT)
            return True
        if cmd == 'ping':
            host = args[-1] if args else '192.168.0.1'
            send(f'PING {host}: 56 data bytes\r\n')
            for seq in (1, 2):
                send(f'64 bytes from {host}: seq={seq} ttl=64 time=1.{2 + seq} ms\r\n')
            return True
        if cmd == 'chmod':
            send('chmod: mode changed\r\n')
            return True
        if cmd in ('reboot', 'halt', 'shutdown'):
            send(f'{cmd}: operation not permitted\r\n')
            return True
        if cmd in ('nvram', 'goahead', 'iptables'):
            send(f'{cmd}: not found\r\n')
            return True

        send(f'{cmd}: command not found\r\n')
        return True
