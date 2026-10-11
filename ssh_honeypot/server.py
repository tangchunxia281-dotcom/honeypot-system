# -*- coding: utf-8 -*-
"""
SSH 蜜罐核心模块
基于 paramiko 实现 SSH 协议仿真
"""
import socket
import threading
import time
import paramiko
from paramiko import ServerInterface, Ed25519Key, AUTH_SUCCESSFUL, OPEN_SUCCEEDED
from paramiko.message import Message
from paramiko.common import cMSG_DISCONNECT, DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE
import os
import sys
from datetime import datetime, timedelta
import random
from collections import defaultdict
import copy
import re
import shlex
import logging
import base64
import fnmatch
import hashlib
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

# 确保从项目根目录导入本地模块
_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

# 导入数据库模块
from env_utils import env_int as _env_int, env_str as _env_str
from db import log_event_activity, log_event
# 导入日志系统
from utils.logger import get_ssh_logger
from ssh_honeypot.ssh_config import (
    PERSISTENT_SESSIONS,
    PERSISTENT_SESSIONS_LOCK,
    REBOOT_IPS,
    REBOOT_IPS_LOCK,
    REBOOT_DELAY_SECONDS,
    HONEYPOT_IDENTITY,
    KERNEL_RELEASE,
    KERNEL_VERSION_STRING,
    SSH_CREDENTIALS,
    DNS_CACHE,
    SERVER_START_TIME,
    CONNECTION_TIMEOUT,
    AUTH_TIMEOUT,
    init_honeypot_identity,
)
from ssh_honeypot.session import (
    rate_limit_check,
    release_connection,
    record_auth_failure,
    record_auth_success,
    record_preauth_connection,
    get_ban_remaining,
    SSH_BRUTEFORCE_WINDOW_SECONDS,
)
from ssh_honeypot.vfs import (
    VIRTUAL_FS,
    VIRTUAL_FILES,
    GLOBAL_FS_STATE,
    GLOBAL_FILES_CONTENT,
)
from ssh_honeypot import commands
from utils.alerting import alert_ssh_login_success, alert_scp_capture

# 初始化日志
logger = get_ssh_logger()
logging.getLogger("paramiko").setLevel(logging.CRITICAL)


_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
HOST_KEY_FILE_ED25519 = os.path.abspath(os.path.join(_BASE_DIR, 'state', 'ssh_host_ed25519_key'))
_AUTH_LOG_MAX_BYTES = 20000


MAX_SSH_WORKERS = _env_int('SSH_MAX_WORKERS', 80, 10, 2000)
SSH_WORKER_SEM = threading.BoundedSemaphore(MAX_SSH_WORKERS)
SSH_MAX_AUTH_TRIES = _env_int('SSH_MAX_AUTH_TRIES', 5, 2, 32)
_TTY_ALLOC_LOCK = threading.Lock()
_NEXT_TTY_ID = 0


def _allocate_ssh_tty() -> str:
    """
    为每条连接分配独立伪终端。
    主机状态仍可按攻击者会话复用，但终端态必须随连接隔离。
    """
    global _NEXT_TTY_ID
    with _TTY_ALLOC_LOCK:
        tty_id = _NEXT_TTY_ID
        _NEXT_TTY_ID += 1
    return f"/dev/pts/{tty_id}"


def _build_ssh_mac_address(src_ip: str, username: str) -> str:
    seed = hashlib.sha1(f"{src_ip}|{username}".encode('utf-8', errors='ignore')).digest()
    return f"52:54:00:{seed[0]:02x}:{seed[1]:02x}:{seed[2]:02x}"


def _build_ssh_event_session_id(src_ip: str, username: str, client_port: int = None) -> str:
    port = 0
    try:
        port = int(client_port or 0)
    except Exception:
        port = 0
    # 5分钟窗口，保证同一攻击会话可聚合，同时避免长周期重用
    window = int(time.time() // 300)
    raw = f"ssh|{src_ip}|{username}|{port}|{window}"
    return hashlib.sha1(raw.encode('utf-8', errors='ignore')).hexdigest()[:20]


def _append_auth_log(entry: str) -> None:
    """追加 /var/log/auth.log，并同步到已存在会话"""
    try:
        if not entry:
            return
        base = GLOBAL_FILES_CONTENT.get('/var/log/auth.log', VIRTUAL_FILES.get('/var/log/auth.log', ''))
        new_content = (base or '') + entry

        if len(new_content) > _AUTH_LOG_MAX_BYTES:
            # 简易滚动：旧内容进 auth.log.1，新内容只保留本次追加
            rotated = base or ''
            if rotated:
                GLOBAL_FILES_CONTENT['/var/log/auth.log.1'] = rotated
                VIRTUAL_FILES['/var/log/auth.log.1'] = rotated
            new_content = entry[-_AUTH_LOG_MAX_BYTES:]

        GLOBAL_FILES_CONTENT['/var/log/auth.log'] = new_content
        VIRTUAL_FILES['/var/log/auth.log'] = new_content

        # 同步已有会话，避免不同会话看到的日志断层
        with PERSISTENT_SESSIONS_LOCK:
            for _ip, sess in list(PERSISTENT_SESSIONS.items()):
                files = sess.get('files_content')
                if isinstance(files, dict):
                    files['/var/log/auth.log'] = new_content
                    if '/var/log' in sess.get('fs_state', {}):
                        if 'auth.log' not in sess['fs_state']['/var/log']:
                            sess['fs_state']['/var/log'].append('auth.log')
                        if 'auth.log.1' in GLOBAL_FILES_CONTENT:
                            if 'auth.log.1' not in sess['fs_state']['/var/log']:
                                sess['fs_state']['/var/log'].append('auth.log.1')
                sizes = sess.get('file_sizes')
                if isinstance(sizes, dict):
                    sizes['/var/log/auth.log'] = len(new_content)
                    if '/var/log/auth.log.1' in GLOBAL_FILES_CONTENT:
                        sizes['/var/log/auth.log.1'] = len(GLOBAL_FILES_CONTENT.get('/var/log/auth.log.1', ''))
    except Exception:
        pass


def _get_reboot_marker(client_ip: str) -> float:
    with REBOOT_IPS_LOCK:
        try:
            return float(REBOOT_IPS.get(client_ip, 0.0) or 0.0)
        except Exception:
            return 0.0


def _set_reboot_marker(client_ip: str, ts: float = None) -> float:
    marker = float(ts if ts is not None else time.time())
    with REBOOT_IPS_LOCK:
        REBOOT_IPS[client_ip] = marker
    return marker


def _clear_reboot_marker(client_ip: str, expected_ts: float = None) -> bool:
    with REBOOT_IPS_LOCK:
        current = REBOOT_IPS.get(client_ip)
        if current is None:
            return False
        if expected_ts is not None:
            try:
                if float(current) != float(expected_ts):
                    return False
            except Exception:
                return False
        REBOOT_IPS.pop(client_ip, None)
        return True

def generate_host_key():
    # 优先使用 ED25519 文件
    if os.path.exists(HOST_KEY_FILE_ED25519):
        try:
            return Ed25519Key.from_private_key_file(HOST_KEY_FILE_ED25519)
        except Exception:
            # 现有文件损坏/不可读：尝试重新生成覆盖
            try:
                os.remove(HOST_KEY_FILE_ED25519)
            except Exception:
                pass

    # 生成新密钥：优先 ED25519
    logger.info("正在生成新的 ED25519 密钥...")
    # 确保 state 目录存在：目录缺失时写密钥会抛 ENOENT，导致 SSH 蜜罐整体启动失败
    try:
        os.makedirs(os.path.dirname(HOST_KEY_FILE_ED25519), exist_ok=True)
    except OSError as e:
        logger.error(f"创建密钥目录失败: {e}")
        raise
    try:
        if hasattr(Ed25519Key, 'generate'):
            key = Ed25519Key.generate()
            key.write_private_key_file(HOST_KEY_FILE_ED25519)
        else:
            # paramiko 未提供 generate 时，使用 cryptography 生成 OpenSSH 私钥
            priv = ed25519.Ed25519PrivateKey.generate()
            pem = priv.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.OpenSSH,
                encryption_algorithm=serialization.NoEncryption(),
            )
            with open(HOST_KEY_FILE_ED25519, 'wb') as f:
                f.write(pem)
            key = Ed25519Key.from_private_key_file(HOST_KEY_FILE_ED25519)
        logger.info(f"密钥已保存至 {HOST_KEY_FILE_ED25519}")
        return key
    except Exception as e:
        logger.error(f"ED25519 生成失败: {e}")
        raise

class HoneypotSSHServer(ServerInterface):
    def __init__(self, client_ip: str, client_port: int = None):
        self.client_ip = client_ip
        self.client_port = client_port
        self.username = None
        self.auth_session_id = ''
        self.event = threading.Event()
        self.exec_command = None # 存储 exec 请求的命令
        self._channel_request_cv = threading.Condition()
        self._channel_requests = {}
        self._transport = None
        self._auth_failures = 0
        self._auth_close_scheduled = False
        self.pty_width = 80
        self.pty_height = 24

    def bind_transport(self, transport) -> None:
        self._transport = transport

    def _schedule_auth_disconnect(self, reason: str, client_message: str = "Too many authentication failures") -> None:
        if self._auth_close_scheduled:
            return
        self._auth_close_scheduled = True

        def _closer():
            time.sleep(0.08)
            try:
                transport = self._transport
                if transport is not None and transport.is_active():
                    try:
                        msg = Message()
                        msg.add_byte(cMSG_DISCONNECT)
                        msg.add_int(DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE)
                        msg.add_string(str(client_message or "Too many authentication failures"))
                        msg.add_string("en")
                        transport._send_message(msg)
                        time.sleep(0.08)
                    except Exception:
                        logger.debug("auth disconnect message send failed", exc_info=True)
                    logger.info(f"[认证断开] {self.client_ip} {reason}")
                    transport.close()
            except Exception:
                logger.debug("auth disconnect close failed", exc_info=True)

        threading.Thread(target=_closer, daemon=True).start()

    def _channel_id(self, channel) -> str:
        try:
            return str(channel.get_id())
        except Exception:
            return str(id(channel))

    def _remember_channel_request(self, channel, kind: str, command: str = "") -> None:
        chan_id = self._channel_id(channel)
        payload = {
            'kind': str(kind or '').strip(),
            'command': str(command or ''),
        }
        with self._channel_request_cv:
            self._channel_requests[chan_id] = payload
            self._channel_request_cv.notify_all()

    def wait_for_channel_request(self, channel, timeout: float):
        chan_id = self._channel_id(channel)
        deadline = time.time() + max(0.1, float(timeout or 0.1))
        with self._channel_request_cv:
            while True:
                payload = self._channel_requests.pop(chan_id, None)
                if payload is not None:
                    return payload
                remaining = deadline - time.time()
                if remaining <= 0:
                    return None
                self._channel_request_cv.wait(timeout=remaining)

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == 'session': return OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username: str, password: str) -> int:
        # 模拟鉴权延时，避免出现“秒回”特征
        time.sleep(random.uniform(1.0, 2.5))

        self.username = username
        payload = f"SSH登录尝试: 用户名={username}, 密码={password}"
        log_event_activity(self.client_ip, 'SSH', payload)

        # 2. 核心鉴权逻辑：比对动态生成的凭证表
        # 只有特定的 用户+密码 组合才能通过
        timestamp = datetime.now().strftime("%b %d %H:%M:%S")
        event_session_id = _build_ssh_event_session_id(self.client_ip, username, self.client_port)

        if username in SSH_CREDENTIALS and SSH_CREDENTIALS[username] == password:

            logger.critical(f"[入侵] SSH爆破成功 {self.client_ip}: {username}/{password}")
            self._auth_failures = 0
            record_auth_success(self.client_ip)
            try:
                alert_ssh_login_success(self.client_ip, username)
            except Exception:
                pass
            try:
                log_event(
                    source='ssh',
                    severity='high',
                    event_type='ssh_login_success',
                    src_ip=self.client_ip,
                    session_id=event_session_id,
                    tags=['ssh', 'auth', 'login_success'],
                    payload=f"SSH 登录成功: {username}",
                    extra={
                        'username': username,
                        'password': password,
                        'client_port': int(self.client_port) if self.client_port else 0,
                    },
                )
            except Exception:
                logger.debug("ssh login success event log failed", exc_info=True)
            self.auth_session_id = event_session_id

            # 写入虚拟日志 auth.log (成功)
            peer_port = int(self.client_port) if self.client_port else random.randint(30000, 60000)
            log_entry = f"{timestamp} {HONEYPOT_IDENTITY['hostname']} sshd[{os.getpid()}]: Accepted password for {username} from {self.client_ip} port {peer_port} ssh2\n"
            _append_auth_log(log_entry)

            return AUTH_SUCCESSFUL

        # 3. 失败处理
        logger.info(f"[失败] SSH认证失败 {self.client_ip}: {username}/{password}")

        # 写入虚拟日志 auth.log (失败)
        peer_port = int(self.client_port) if self.client_port else random.randint(30000, 60000)
        log_entry = f"{timestamp} {HONEYPOT_IDENTITY['hostname']} sshd[{os.getpid()}]: Failed password for {username} from {self.client_ip} port {peer_port} ssh2\n"
        _append_auth_log(log_entry)
        try:
                log_event(
                    source='ssh',
                    # 口令失败尝试属于入侵前兆，避免在大屏显示为低风险
                severity='medium',
                event_type='ssh_login_failed',
                src_ip=self.client_ip,
                session_id=event_session_id,
                tags=['ssh', 'auth', 'login_failed'],
                payload=f"SSH 登录失败: {username}",
                    extra={
                        'username': username,
                        'password': password,
                        'client_port': peer_port,
                    },
                )
        except Exception:
            logger.debug("ssh login failed event log failed", exc_info=True)
        self._auth_failures += 1
        ban_seconds = record_auth_failure(self.client_ip)
        if ban_seconds > 0:
            try:
                log_event(
                    source='ssh',
                    severity='high',
                    event_type='ssh_bruteforce_ban',
                    src_ip=self.client_ip,
                    session_id=event_session_id,
                    tags=['ssh', 'auth', 'bruteforce', 'ban'],
                    payload=f"SSH 防爆破封禁触发: {self.client_ip} 封禁 {ban_seconds}s",
                    extra={
                        'ban_seconds': int(ban_seconds),
                        'window_seconds': int(SSH_BRUTEFORCE_WINDOW_SECONDS),
                        'reason': 'too_many_auth_failures',
                    },
                )
            except Exception:
                logger.debug("ssh bruteforce ban event log failed", exc_info=True)
        reached_attempt_limit = self._auth_failures >= SSH_MAX_AUTH_TRIES
        if reached_attempt_limit or ban_seconds > 0:
            disconnect_reason = "触发防爆破封禁" if ban_seconds > 0 else f"达到最大认证尝试次数({SSH_MAX_AUTH_TRIES})"
            logger.warning(f"[断开] SSH认证连接 {self.client_ip}: {disconnect_reason}")
            auth_fail_log = (
                f"{timestamp} {HONEYPOT_IDENTITY['hostname']} sshd[{os.getpid()}]: "
                f"maximum authentication attempts exceeded for {username} from {self.client_ip} "
                f"port {peer_port} ssh2 [preauth]\n"
            )
            _append_auth_log(auth_fail_log)
            self._schedule_auth_disconnect(
                disconnect_reason,
                "Too many authentication failures",
            )
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username: str, key) -> int:
        self.username = username
        key_type = 'unknown'
        key_fp = '-'
        try:
            key_type = str(key.get_name() or 'unknown')
        except Exception:
            pass
        try:
            key_fp = hashlib.sha1(key.asbytes()).hexdigest()[:16]
        except Exception:
            pass

        payload = f"SSH公钥认证尝试: 用户名={username}, 类型={key_type}, 指纹={key_fp}"
        log_event_activity(self.client_ip, 'SSH-PubKey', payload)
        logger.warning(f"[拒绝] SSH公钥认证 {self.client_ip}: {username} ({key_type}, fp={key_fp})")
        self._auth_failures += 1
        if self._auth_failures >= SSH_MAX_AUTH_TRIES:
            peer_port = int(self.client_port) if self.client_port else random.randint(30000, 60000)
            timestamp = datetime.now().strftime("%b %d %H:%M:%S")
            auth_fail_log = (
                f"{timestamp} {HONEYPOT_IDENTITY['hostname']} sshd[{os.getpid()}]: "
                f"maximum authentication attempts exceeded for {username} from {self.client_ip} "
                f"port {peer_port} ssh2 [preauth]\n"
            )
            _append_auth_log(auth_fail_log)
            self._schedule_auth_disconnect(
                f"公钥认证达到最大尝试次数({SSH_MAX_AUTH_TRIES})",
                "Too many authentication failures",
            )
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username: str) -> str:
        return 'password,publickey'

    def check_channel_shell_request(self, channel) -> bool:
        self.exec_command = None
        self._remember_channel_request(channel, 'shell')
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height,
                                   pixelwidth, pixelheight, modes) -> bool:
        try:
            self.pty_width = max(40, min(int(width or 80), 240))
        except Exception:
            self.pty_width = 80
        try:
            self.pty_height = max(12, min(int(height or 24), 120))
        except Exception:
            self.pty_height = 24
        return True

    def check_channel_exec_request(self, channel, command) -> bool:
        # 记录 exec 命令 (paramiko 传过来的是 bytes)
        try:
            self.exec_command = command.decode('utf-8')
        except Exception:
            self.exec_command = str(command)
        self._remember_channel_request(channel, 'exec', self.exec_command)
        self.event.set()
        return True

class VirtualShell:
    def __init__(self, client_ip: str, username: str = 'root', client_port: int = None,
                 term_width: int = 80, term_height: int = 24, session_id: str = None):
        self.client_ip = client_ip
        self.username = username
        self.session_user = username
        try:
            self.client_port = int(client_port) if client_port else random.randint(32768, 61000)
        except Exception:
            self.client_port = random.randint(32768, 61000)
        self.tty_name = _allocate_ssh_tty()
        try:
            self.term_width = max(40, min(int(term_width or 80), 240))
        except Exception:
            self.term_width = 80
        try:
            self.term_height = max(12, min(int(term_height or 24), 120))
        except Exception:
            self.term_height = 24
        self.mac_address = _build_ssh_mac_address(self.client_ip, self.session_user)
        self.hostname = HONEYPOT_IDENTITY['hostname']
        self.current_path = '/home/' + username if username != 'root' else '/root'
        self.interactive_state = None  # 交互式命令状态
        self.user_stack = []  # 用户切换栈 (Nested sessions)
        self.last_logged_cmd = None # 用于去重
        self.shutdown_deadline = None # 计划关机的截止时间戳
        self.sudo_cache_ttl = _env_int('SUDO_CACHE_TTL', 300, 1, 86400)
        self.sudo_cache = {}


        # 会话持久化按 (IP + 登录用户名) 分桶，减少 NAT 场景下会话互串。
        persistence_key = f"{self.client_ip}|{self.session_user}"
        self.persistence_key = persistence_key
        session_key = str(session_id or _build_ssh_event_session_id(self.client_ip, self.session_user, self.client_port)).strip()
        self.session_key = session_key or persistence_key
        with PERSISTENT_SESSIONS_LOCK:
            saved_session = PERSISTENT_SESSIONS.get(persistence_key)
        if saved_session is not None:
            # 命中历史会话，恢复状态
            session_data = copy.deepcopy(saved_session)
            self.fs_state = session_data.get('fs_state', copy.deepcopy(GLOBAL_FS_STATE))
            self.files_content = session_data.get('files_content', copy.deepcopy(GLOBAL_FILES_CONTENT))
            self.history = session_data.get('history', [])
            self.file_timestamps = session_data.get('file_timestamps', {})
            self.file_sizes = session_data.get('file_sizes', {})
            self.file_perms = session_data.get('file_perms', {})  # 恢复权限
            self.file_owners = session_data.get('file_owners', {}) # 恢复所有者
            self.killed_pids = session_data.get('killed_pids', set())
            self.processes = session_data.get('processes', {}) # 恢复进程列表 (防止 ps 为空)
            # 环境变量按连接复制，避免并发终端互相覆盖 SSH_TTY/SSH_CONNECTION。
            self.env = copy.deepcopy(session_data.get('env', self._get_default_env()))
            self.login_history = session_data.get('login_history', [])
            self._perf_state = session_data.get('perf_state')
            self._proc_last_ts = session_data.get('proc_last_ts')
            self.shutdown_deadline = session_data.get('shutdown_deadline')
            self.sudo_cache = session_data.get('sudo_cache', {})
            self.services_state = session_data.get('services_state', {})
            self.service_logs = session_data.get('service_logs', {})
            self.sshd_pid = str(session_data.get('sshd_pid') or '').strip()
            self.shell_pid = str(session_data.get('shell_pid') or '').strip()

            if not isinstance(self.file_perms, dict):
                self.file_perms = {}
            if not isinstance(self.file_owners, dict):
                self.file_owners = {}
            if not isinstance(self.sudo_cache, dict):
                self.sudo_cache = {}
            if not isinstance(self.services_state, dict):
                self.services_state = {}
            if not isinstance(self.service_logs, dict):
                self.service_logs = {}

            # 清掉上一条连接留下的交互进程，再补当前连接这组新的。
            self._drop_connection_processes(session_data)
            self._init_processes()
            self._refresh_ssh_session_env()
            self._sync_virtual_binaries()
            # 会话缺少权限/所有者元数据时补齐
            self._init_file_timestamps()
            commands.ensure_service_state(self)
            self._save_session_state()

            logger.info(f"[持久化] 攻击者 {client_ip} 重连，恢复会话状态")
        else:
            # 检查会话数量，防止 OOM
            with PERSISTENT_SESSIONS_LOCK:
                session_count = len(PERSISTENT_SESSIONS)
                if session_count > 200:
                    # 简单清理：删除最早加入的 50 个会话
                    logger.warning(f"[系统] 会话表过载({session_count})，执行清理...")
                    try:
                        # 优先清理最久未访问会话，降低活跃会话被回收概率
                        stale = sorted(
                            PERSISTENT_SESSIONS.items(),
                            key=lambda item: float((item[1] or {}).get('last_seen', 0.0))
                        )
                        keys_to_remove = [k for k, _ in stale[:50]]
                        for k in keys_to_remove:
                            PERSISTENT_SESSIONS.pop(k, None)
                        logger.info(f"[系统] 已清理 {len(keys_to_remove)} 个过期会话")
                    except Exception as e:
                        logger.error(f"[系统] 清理会话失败: {e}")
                        PERSISTENT_SESSIONS.clear()

            # 首次会话初始化独立文件系统
            self.fs_state = copy.deepcopy(GLOBAL_FS_STATE)
            self.files_content = copy.deepcopy(GLOBAL_FILES_CONTENT)
            self.history = []
            # 预置常见历史命令，提升初始会话一致性
            self.history.extend(['ls -la', 'ps -ef', 'ss -tulpn', 'whoami'])
            self.file_timestamps = {}
            self.file_sizes = {}
            self.file_perms = {} # 权限元数据
            self.file_owners = {} # 所有者 (path -> (user, group))
            self.killed_pids = set() # 被杀死的进程列表
            self.login_history = []
            self._perf_state = None
            self._proc_last_ts = None
            self.shutdown_deadline = None
            self.sudo_cache = {}
            self.services_state = {}
            self.service_logs = {}

            # 填充完整文件系统
            self._populate_full_system()
            self._sync_virtual_binaries()

            # 初始化进程列表
            self._init_processes()
            commands.ensure_service_state(self)

            # 初始化性能态
            self._init_perf_state()

            # 初始化环境变量
            self.env = self._get_default_env()
            self._refresh_ssh_session_env()

            self._init_file_timestamps()

            # 保存到持久化存储
            self._save_session_state()
            logger.info(f"[持久化] 新攻击者 {client_ip} 初始化会话")

    def _get_default_env(self) -> dict:
        """生成默认环境变量"""
        return {
            'USER': self.username,
            'HOME': f'/home/{self.username}' if self.username != 'root' else '/root',
            'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin',
            'SHELL': '/bin/bash',
            'PWD': self.current_path,
            'OLDPWD': self.current_path, # 支持 cd -
            '?': '0', # 记录最后一次命令的退出码
            # SSH 会话环境变量
            'SSH_CLIENT': f'{self.client_ip} {self.client_port} 22',
            'SSH_CONNECTION': f"{self.client_ip} {self.client_port} {HONEYPOT_IDENTITY.get('server_ip')} 22",
            'SSH_TTY': self.tty_name,
            'TERM': 'xterm-256color',
            'LANG': 'en_US.UTF-8',
            'COLUMNS': str(self.term_width),
            'LINES': str(self.term_height),
        }

    def _refresh_ssh_session_env(self) -> None:
        """刷新会话相关 SSH 环境变量，避免恢复会话后字段陈旧。"""
        if not isinstance(self.env, dict):
            self.env = {}
        server_ip = HONEYPOT_IDENTITY.get('server_ip')
        self.env['SSH_CLIENT'] = f'{self.client_ip} {self.client_port} 22'
        self.env['SSH_CONNECTION'] = f'{self.client_ip} {self.client_port} {server_ip} 22'
        self.env['SSH_TTY'] = self.tty_name
        self.env['COLUMNS'] = str(self.term_width)
        self.env['LINES'] = str(self.term_height)

    def _tty_label(self) -> str:
        """返回适合 ps/w/who 展示的短 TTY 名称。"""
        tty = str(getattr(self, 'tty_name', '') or self.env.get('SSH_TTY') or '').strip()
        tty = tty.replace('\\', '/')
        if '/dev/' in tty:
            tty = tty.split('/dev/', 1)[1]
        return tty.lstrip('/') or '?'

    def _drop_connection_processes(self, session_data: dict = None) -> None:
        """
        清理上一条 SSH 连接留下的交互进程链。
        会话状态按 (IP + 用户) 复用，但连接级的 sshd/-bash 不应无限累积。
        """
        if not isinstance(getattr(self, 'processes', None), dict):
            self.processes = {}
        if not isinstance(getattr(self, 'killed_pids', None), set):
            self.killed_pids = set()

        old_sshd = str((session_data or {}).get('sshd_pid') or getattr(self, 'sshd_pid', '') or '').strip()
        old_shell = str((session_data or {}).get('shell_pid') or getattr(self, 'shell_pid', '') or '').strip()
        removable = set(pid for pid in (old_sshd, old_shell) if pid)

        sshd_prefix = f"sshd: {self.session_user}@pts/"
        prior_sshd_pids = []
        for pid, info in list(self.processes.items()):
            cmd = str((info or {}).get('cmd') or '').strip()
            ppid = str((info or {}).get('ppid') or '').strip()
            if pid == '512':
                continue
            if ppid == '512' and cmd.startswith(sshd_prefix):
                prior_sshd_pids.append(str(pid))
        removable.update(prior_sshd_pids)

        if old_sshd:
            prior_sshd_pids.append(old_sshd)
        parent_candidates = {str(pid) for pid in prior_sshd_pids if pid}
        for pid, info in list(self.processes.items()):
            cmd = str((info or {}).get('cmd') or '').strip()
            ppid = str((info or {}).get('ppid') or '').strip()
            if cmd == '-bash' and ppid in parent_candidates:
                removable.add(str(pid))

        for pid in removable:
            self.processes.pop(pid, None)
            self.killed_pids.discard(pid)

    def _save_session_state(self):
        """保存当前会话状态到持久化存储"""
        session_key = getattr(self, 'persistence_key', f"{self.client_ip}|{self.session_user}")
        snapshot = {
            'fs_state': self.fs_state,
            'files_content': self.files_content,
            'history': self.history,
            'file_timestamps': self.file_timestamps,
            'file_sizes': self.file_sizes,
            'file_perms': self.file_perms,
            'file_owners': self.file_owners,
            'killed_pids': self.killed_pids,
            'processes': self.processes,
            'env': self.env, # 保存环境变量
            'login_history': self.login_history,
            'perf_state': self._perf_state,
            'proc_last_ts': self._proc_last_ts,
            'shutdown_deadline': self.shutdown_deadline,
            'sudo_cache': self.sudo_cache,
            'services_state': getattr(self, 'services_state', {}),
            'service_logs': getattr(self, 'service_logs', {}),
            'sshd_pid': getattr(self, 'sshd_pid', ''),
            'shell_pid': getattr(self, 'shell_pid', ''),
            'last_seen': time.time(),
        }
        with PERSISTENT_SESSIONS_LOCK:
            PERSISTENT_SESSIONS[session_key] = copy.deepcopy(snapshot)

    def _sudo_cache_key(self, user: str) -> str:
        tty = str(getattr(self, 'tty_name', '') or self.env.get('SSH_TTY') or '').strip()
        return f"{user}@{tty}"

    def _sudo_cache_valid(self, user: str) -> bool:
        try:
            ts = self.sudo_cache.get(self._sudo_cache_key(user))
            if not ts:
                return False
            return (time.time() - float(ts)) <= float(self.sudo_cache_ttl)
        except Exception:
            return False

    def _touch_sudo_cache(self, user: str) -> None:
        try:
            self.sudo_cache[self._sudo_cache_key(user)] = time.time()
            self._save_session_state()
        except Exception:
            pass

    def _clear_sudo_cache(self, user: str = None) -> None:
        try:
            if user:
                self.sudo_cache.pop(self._sudo_cache_key(user), None)
            else:
                self.sudo_cache.clear()
            self._save_session_state()
        except Exception:
            pass

    def _clear_sudo_cache_all_tty(self, user: str) -> None:
        try:
            prefix = f"{user}@"
            for key in list(self.sudo_cache.keys()):
                if str(key).startswith(prefix):
                    self.sudo_cache.pop(key, None)
            self._save_session_state()
        except Exception:
            pass

    def _init_file_timestamps(self):
        """为所有文件预生成固定时间戳和大小，避免 ls 每次不同"""
        now = datetime.now()
        # 遍历所有虚拟文件和目录，初始化其元数据
        all_paths = set(self.fs_state.keys())
        all_paths.update(self.files_content.keys())
        all_paths.update(VIRTUAL_FILES.keys()) # 确保虚拟文件也有元数据

        for path in all_paths:
            if path not in self.file_timestamps:
                # 随机生成过去 2 年内的日期 (不再是短短6个月)
                days_ago = random.randint(0, 730)
                hours_ago = random.randint(0, 23)
                mins_ago = random.randint(0, 59)
                self.file_timestamps[path] = now - timedelta(days=days_ago, hours=hours_ago, minutes=mins_ago)

            if path not in self.file_sizes:
                is_dir = path in self.fs_state
                # 目录统一 4096，文件大小随机化
                self.file_sizes[path] = 4096 if is_dir else random.randint(100, 10240)

            if path not in self.file_perms:
                is_dir = path in self.fs_state
                self.file_perms[path] = "drwxr-xr-x" if is_dir else "-rw-r--r--"

            if path not in self.file_owners:
                # 默认所有者为 root:root
                owner = "root"
                group = "root"
                # 启发式：/home/user 目录及其内容属于该用户
                if path.startswith('/home/'):
                    parts = path.split('/')
                    if len(parts) > 2 and parts[2] not in ['root', 'bin', 'etc']:
                        owner = parts[2]
                        group = parts[2]
                self.file_owners[path] = (owner, group)

            # 二进制文件大小修正
            # 如果是 /bin, /usr/bin, /sbin 下的文件，赋予更真实的大小 (20KB - 2MB)
            if path not in self.file_sizes or self.file_sizes[path] < 20480:
                 if any(path.startswith(p) for p in ['/bin/', '/usr/bin/', '/sbin/', '/usr/sbin/']):
                     if not is_dir:
                        # 随机 20KB ~ 2MB
                        self.file_sizes[path] = random.randint(20480, 2097152)

    def _init_perf_state(self):
        """初始化性能态（用于 uptime/top/ps 等输出一致性）"""
        now = time.time()
        l1 = round(random.uniform(0.02, 0.18), 2)
        l5 = round(random.uniform(0.01, 0.12), 2)
        l15 = round(random.uniform(0.00, 0.08), 2)

        cpu_user = round(random.uniform(0.3, 1.8), 1)
        cpu_sys = round(random.uniform(0.1, 0.8), 1)
        cpu_wa = round(random.uniform(0.0, 0.3), 1)
        cpu_idle = max(0.0, round(100.0 - cpu_user - cpu_sys - cpu_wa, 1))

        total = 4030464
        used = 1277952 + random.randint(-80000, 80000)
        used = max(600000, min(used, total - 200000))
        free = total - used
        buffers = 1191936 + random.randint(-50000, 50000)
        available = free + buffers // 2

        disk_total = 50264772
        disk_used = 14352124 + random.randint(0, 65536)

        self._perf_state = {
            'last_ts': now,
            'load': (l1, l5, l15),
            'cpu': {
                'user': cpu_user,
                'sys': cpu_sys,
                'wa': cpu_wa,
                'idle': cpu_idle
            },
            'mem': {
                'total': total,
                'used': used,
                'free': free,
                'shared': 12288,
                'buffers_cache': buffers,
                'available': available,
                'swap_total': 2097148,
                'swap_used': 0,
                'swap_free': 2097148
            },
            'disk': {
                'total': disk_total,
                'used': disk_used,
                'available': max(0, disk_total - disk_used),
                'use_percent': f"{int(disk_used / disk_total * 100)}%"
            }
        }

    def _get_perf_state(self) -> dict:
        if not self._perf_state:
            self._init_perf_state()
            return self._perf_state

        now = time.time()
        if (now - self._perf_state['last_ts']) < 1.5:
            return self._perf_state

        def drift(val, step, min_v, max_v):
            new_val = val + random.uniform(-step, step)
            return max(min_v, min(max_v, new_val))

        l1, l5, l15 = self._perf_state['load']
        l1 = round(drift(l1, 0.05, 0.00, 0.40), 2)
        l5 = round(drift(l5, 0.04, 0.00, 0.30), 2)
        l15 = round(drift(l15, 0.03, 0.00, 0.25), 2)
        self._perf_state['load'] = (l1, l5, l15)

        cpu = self._perf_state['cpu']
        cpu_user = drift(cpu['user'], 0.6, 0.1, 5.0)
        cpu_sys = drift(cpu['sys'], 0.4, 0.1, 3.0)
        cpu_wa = drift(cpu['wa'], 0.2, 0.0, 1.5)
        cpu_idle = max(0.0, round(100.0 - cpu_user - cpu_sys - cpu_wa, 1))
        self._perf_state['cpu'] = {
            'user': round(cpu_user, 1),
            'sys': round(cpu_sys, 1),
            'wa': round(cpu_wa, 1),
            'idle': cpu_idle
        }

        mem = self._perf_state['mem']
        total = mem['total']
        used = int(drift(mem['used'], 60000, 500000, total - 200000))
        free = total - used
        buffers = int(drift(mem['buffers_cache'], 40000, 300000, total // 2))
        available = free + buffers // 2
        self._perf_state['mem'] = {
            **mem,
            'used': used,
            'free': free,
            'buffers_cache': buffers,
            'available': available
        }

        disk = self._perf_state['disk']
        disk_used = disk['used'] + random.randint(0, 2048)
        disk_used = min(disk_used, disk['total'] - 1024)
        disk_available = max(0, disk['total'] - disk_used)
        self._perf_state['disk'] = {
            **disk,
            'used': disk_used,
            'available': disk_available,
            'use_percent': f"{int(disk_used / disk['total'] * 100)}%"
        }

        self._perf_state['last_ts'] = now
        return self._perf_state

    def _tick_process_times(self):
        """让 ps/top 中 TIME 持续增长"""
        now = time.time()
        if self._proc_last_ts is None:
            self._proc_last_ts = now
            return
        delta = now - self._proc_last_ts
        if delta < 0.8:
            return
        for pid, info in self.processes.items():
            if pid in self.killed_pids:
                continue
            base = info.get('cpu_time', random.uniform(0.2, 5.0))
            weight = 0.8
            if 'sshd' in info.get('cmd', ''):
                weight = 1.2
            if 'bash' in info.get('cmd', ''):
                weight = 1.0
            inc = random.uniform(0.0, delta * 0.05 * weight)
            info['cpu_time'] = base + inc
            # CPU 百分比：平滑漂移，避免忽高忽低
            cpu_base = info.get('cpu_pct', random.uniform(0.1, 2.0))
            cpu_target = cpu_base + random.uniform(-0.6, 0.6)
            if 'sshd' in info.get('cmd', ''):
                cpu_target = max(0.1, min(cpu_target, 3.5))
            elif 'cron' in info.get('cmd', ''):
                cpu_target = max(0.0, min(cpu_target, 1.5))
            else:
                cpu_target = max(0.0, min(cpu_target, 2.5))
            info['cpu_pct'] = round(cpu_base * 0.7 + cpu_target * 0.3, 1)

            mem_base = info.get('mem_pct', random.uniform(0.1, 0.8))
            mem_target = mem_base + random.uniform(-0.2, 0.2)
            info['mem_pct'] = round(max(0.0, min(mem_target, 3.0)), 1)
        self._proc_last_ts = now

    def _record_login(self, username: str, src_ip: str):
        now = datetime.now()
        entry = {
            'user': username or self.username,
            'ip': src_ip or self.client_ip,
            'login_at': now,
            'logout_at': None,
            'tty': self._tty_label(),
        }
        self.login_history.insert(0, entry)
        if len(self.login_history) > 20:
            self.login_history = self.login_history[:20]
        self._save_session_state()

    def _record_logout(self):
        now = datetime.now()
        for entry in self.login_history:
            if entry.get('logout_at') is None and entry.get('ip') == self.client_ip:
                entry['logout_at'] = now
                break
        self._save_session_state()


    def _get_file_timestamp(self, path: str) -> str:
        """获取文件的时间戳字符串"""
        if path in self.file_timestamps:
            dt = self.file_timestamps[path]
        else:
            dt = datetime.now()

        # ls -l 格式：如果时间超过6个月，显示年份
        now = datetime.now()
        if abs((now - dt).days) > 180:
             return dt.strftime("%b %d  %Y") # "Jan 01  2023"
        return dt.strftime("%b %d %H:%M") # "Jan 01 12:30"

    def _get_file_size(self, path: str, is_dir: bool = False) -> int:
        """获取文件大小"""
        if path in self.file_sizes:
            return self.file_sizes[path]
        return 4096 if is_dir else 0

    def _ensure_virtual_binary(self, path: str) -> None:
        norm = str(path or '').replace('\\', '/')
        if not norm.startswith('/'):
            return
        parent = os.path.dirname(norm).replace('\\', '/') or '/'
        name = os.path.basename(norm)
        if not name:
            return
        if parent not in self.fs_state:
            self.fs_state[parent] = []
        if name not in self.fs_state[parent]:
            self.fs_state[parent].append(name)
        if norm not in self.fs_state and norm not in self.files_content:
            self.files_content[norm] = ''
        self.file_owners.setdefault(norm, ('root', 'root'))
        self.file_perms.setdefault(norm, '-rwxr-xr-x')
        digest = hashlib.sha1(norm.encode('utf-8', errors='ignore')).hexdigest()
        synthetic_size = 32768 + (int(digest[:6], 16) % 786432)
        self.file_sizes.setdefault(norm, synthetic_size)
        boot_time = HONEYPOT_IDENTITY.get('boot_time') or datetime.now()
        self.file_timestamps.setdefault(norm, boot_time)

    def _sync_virtual_binaries(self) -> None:
        for base in ('/bin', '/usr/bin', '/sbin', '/usr/sbin'):
            for name in list(self.fs_state.get(base, [])):
                text = str(name or '').strip()
                if not text or '/' in text or text in ('.', '..'):
                    continue
                self._ensure_virtual_binary(f"{base}/{text}")
        for path in (
            '/usr/bin/python3',
            '/usr/bin/python',
            '/usr/bin/ssh',
            '/usr/bin/systemctl',
            '/usr/bin/hostnamectl',
            '/usr/bin/last',
            '/usr/sbin/sshd',
            '/usr/sbin/ip',
            '/sbin/ip',
        ):
            self._ensure_virtual_binary(path)

    # 共享内核状态辅助函数
    def _get_load_average(self) -> tuple:
        """获取稳定的系统负载（1m/5m/15m）。"""
        perf = self._get_perf_state()
        return perf['load']

    def _get_mem_status(self) -> dict:
        """获取带轻微抖动的内存状态。"""
        perf = self._get_perf_state()
        return perf['mem']

    def _get_disk_status(self) -> dict:
        """获取带轻微抖动的磁盘状态。"""
        perf = self._get_perf_state()
        return perf['disk']

    def _populate_full_system(self):
        """构建高保真文件系统结构"""
        # 1. 根目录结构 (FHS 标准)
        root_dirs = ['bin', 'boot', 'cdrom', 'dev', 'etc', 'home', 'lib', 'lib32', 'lib64', 'libx32', 'media', 'mnt', 'opt', 'proc', 'root', 'run', 'sbin', 'snap', 'srv', 'sys', 'tmp', 'usr', 'var']
        for d in root_dirs:
            if '/' not in self.fs_state: self.fs_state['/'] = []
            if d not in self.fs_state['/']: self.fs_state['/'].append(d)
            if f"/{d}" not in self.fs_state: self.fs_state[f"/{d}"] = []
        if 'lost+found' not in self.fs_state['/']:
            self.fs_state['/'].append('lost+found')
        if '/lost+found' not in self.fs_state:
            self.fs_state['/lost+found'] = []
        if 'swapfile' not in self.fs_state['/']:
            self.fs_state['/'].append('swapfile')

        # 2. 依据已实现命令动态填充命令目录，避免目录太瘦或出现不可执行占位符
        implemented_cmds = set()
        for attr in dir(commands):
            if not attr.startswith('cmd_'):
                continue
            name = attr[4:]
            if not name or name.startswith('_'):
                continue
            handler = getattr(commands, attr, None)
            if callable(handler):
                implemented_cmds.add(name)

        builtin_only = set(getattr(commands, '_SHELL_BUILTINS', set()))
        builtin_only.update(getattr(commands, '_SHELL_KEYWORDS', set()))
        command_aliases = dict(getattr(commands, '_COMMAND_ALIASES', {}))
        alias_targets = set(command_aliases.values())
        dual_mode_bins = {'echo', 'kill', 'pwd', 'test', 'true', 'false'}
        sbin_seed = set(VIRTUAL_FS.get('/sbin', []))
        sbin_seed.update({
            'deluser', 'fdisk', 'groupadd', 'halt', 'init', 'ip', 'iptables',
            'poweroff', 'reboot', 'service', 'shutdown', 'sshd', 'sysctl',
            'ufw', 'useradd', 'usermod', 'visudo',
        })

        exec_cmds = {
            name for name in implemented_cmds
            if name not in builtin_only or name in dual_mode_bins
        }
        public_exec_cmds = set(exec_cmds.difference(alias_targets))
        for public_name, internal_name in command_aliases.items():
            if internal_name in exec_cmds:
                public_exec_cmds.add(public_name)

        sbins = sorted(name for name in public_exec_cmds if name in sbin_seed)
        bins = sorted(public_exec_cmds.difference(sbins))

        self.fs_state['/usr/bin'] = bins
        self.fs_state['/bin'] = bins

        # 3. /usr/sbin 与 /sbin 共享同一批已实现管理命令
        self.fs_state['/usr/sbin'] = sbins
        self.fs_state['/sbin'] = sbins
        if 'lost+found' in self.fs_state.get('/boot', []) and '/boot/lost+found' not in self.fs_state:
            self.fs_state['/boot/lost+found'] = []

        # 4. 规范化 /etc，统一为 Ubuntu 24.04 LTS 云主机口径
        etc_dirs = ['apt', 'cron.d', 'cron.daily', 'cron.hourly', 'cron.monthly', 'cron.weekly',
                    'init.d', 'network', 'pam.d', 'ssh', 'ssl', 'systemd', 'udev', 'update-motd.d',
                    'X11', 'alternatives', 'default', 'skel', 'vim', 'logrotate.d', 'rsyslog.d', 'sudoers.d']
        if '/etc' not in self.fs_state: self.fs_state['/etc'] = []

        # 清理过于跳戏的条目，再补齐常见 24.04 项
        remove_etc = {'credstore', 'credstore.encrypted', 'needrestart', 'python3.13'}
        self.fs_state['/etc'] = [x for x in self.fs_state['/etc'] if x not in remove_etc]
        existing_etc = set(self.fs_state['/etc'])
        for d in etc_dirs:
            if d not in existing_etc:
                self.fs_state['/etc'].append(d)
            if f"/etc/{d}" not in self.fs_state: self.fs_state[f"/etc/{d}"] = []

        etc_files = ['bash.bashrc', 'fstab', 'group', 'gshadow', 'login.defs', 'mime.types', 'mtab',
                     'networks', 'profile', 'protocols', 'services', 'shells', 'timezone', 'localtime',
                     'ld.so.conf', 'host.conf', 'nsswitch.conf', 'sysctl.conf', 'ucf.conf', 'updatedb.conf',
                     'sudoers', 'shadow', 'passwd', 'hostname', 'hosts', 'resolv.conf', 'issue', 'issue.net', 'os-release', 'lsb-release', 'python3.12']

        for f in etc_files:
            if f not in existing_etc:
                self.fs_state['/etc'].append(f)
        self.fs_state['/etc'].sort()


        # /etc/issue 与版本标识统一为 24.04.2 LTS
        self.files_content['/etc/issue'] = "Ubuntu 24.04.2 LTS \\n \\l\n\n"
        self.files_content['/etc/issue.net'] = "Ubuntu 24.04.2 LTS"

        self.files_content['/etc/os-release'] = """PRETTY_NAME="Ubuntu 24.04.2 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION="24.04.2 LTS (Noble Numbat)"
VERSION_CODENAME=noble
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
UBUNTU_CODENAME=noble
"""
        self.files_content['/etc/lsb-release'] = """DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=24.04
DISTRIB_CODENAME=noble
DISTRIB_DESCRIPTION="Ubuntu 24.04.2 LTS"
"""
        self.files_content['/etc/apt/sources.list'] = """# Ubuntu sources list
deb http://archive.ubuntu.com/ubuntu/ noble main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu/ noble-updates main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu/ noble-backports main restricted universe multiverse
deb http://security.ubuntu.com/ubuntu noble-security main restricted universe multiverse
"""

        # 4.1 规范化 /home，避免诱饵路径和登录用户主目录打架
        home_layout = {
            'admin': ['.bash_history', '.bashrc', '.profile', '.ssh', 'credentials.bak'],
            'backup': ['.bash_history', '.bashrc', '.profile', '.ssh', 'README.txt'],
            'ubuntu': ['.bash_history', '.bashrc', '.profile', '.ssh'],
        }
        self.fs_state.setdefault('/home', [])
        for user_name, entries in home_layout.items():
            home_name = f"/home/{user_name}"
            if user_name not in self.fs_state['/home']:
                self.fs_state['/home'].append(user_name)
            self.fs_state.setdefault(home_name, [])
            for entry in entries:
                if entry not in self.fs_state[home_name]:
                    self.fs_state[home_name].append(entry)
            if '.ssh' in entries:
                self.fs_state.setdefault(f"{home_name}/.ssh", [])

        self.files_content.setdefault('/home/admin/.bashrc', """# ~/.bashrc
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'
""")
        self.files_content.setdefault('/home/admin/.profile', """# ~/.profile
if [ -n "$BASH_VERSION" ]; then
    if [ -f "$HOME/.bashrc" ]; then
        . "$HOME/.bashrc"
    fi
fi
""")
        self.files_content.setdefault('/home/admin/.bash_history', """cd /var/www
ls -lah
tail -n 50 /var/log/syslog
grep -n "PasswordAuthentication" /etc/ssh/sshd_config
""")
        self.files_content.setdefault('/home/admin/.ssh/authorized_keys', "")
        self.files_content.setdefault('/home/admin/.ssh/known_hosts', """10.0.12.50 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB3s6xM7A9K4YwF7pM5h1v3uS9O9m5J2c5bJ8QfL2p7u
10.0.12.51 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIF5zvY7tZ9M2cX0hQ2uJ4bN1w8rT6kL0mP4qN7vS1d4g
""")
        self.files_content.setdefault('/home/ubuntu/.bashrc', """# ~/.bashrc
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'
""")
        self.files_content.setdefault('/home/ubuntu/.profile', """# ~/.profile
if [ -n "$BASH_VERSION" ]; then
    if [ -f "$HOME/.bashrc" ]; then
        . "$HOME/.bashrc"
    fi
fi
""")
        self.files_content.setdefault('/home/ubuntu/.bash_history', """sudo apt update
sudo systemctl status ssh
tail -f /var/log/auth.log
""")
        self.files_content.setdefault('/home/backup/.bashrc', """# ~/.bashrc
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
alias ll='ls -alF'
alias la='ls -A'
""")
        self.files_content.setdefault('/home/backup/.profile', """# ~/.profile
if [ -n "$BASH_VERSION" ]; then
    if [ -f "$HOME/.bashrc" ]; then
        . "$HOME/.bashrc"
    fi
fi
""")
        self.files_content.setdefault('/home/backup/.bash_history', """cd /var/backups
ls -lah
tar -tf daily-web-2026-01-14.tar.gz | head
""")
        self.files_content.setdefault('/home/backup/README.txt', """Nightly backup operator home.
Use this account for inventory checks and archive verification only.
""")
        self.files_content.setdefault('/home/admin/credentials.bak', """SSH Backup: backup@10.0.12.51 / Backup#2024!
内网跳板: 10.0.12.50 / JumpServer@123
VPN Gateway: 10.0.12.1 / admin:vpn2024
""")

        # 5. 填充 /var
        var_dirs = ['backups', 'cache', 'crash', 'lib', 'local', 'lock', 'log', 'mail', 'opt', 'run', 'snap', 'spool', 'tmp', 'www']
        if '/var' not in self.fs_state: self.fs_state['/var'] = []

        for d in var_dirs:
            if d not in self.fs_state['/var']: self.fs_state['/var'].append(d)
            if f"/var/{d}" not in self.fs_state: self.fs_state[f"/var/{d}"] = []

        # /var/log
        log_files = ['auth.log', 'syslog', 'kern.log', 'dpkg.log', 'bootstrap.log', 'faillog', 'lastlog', 'wtmp', 'btmp']
        self.fs_state['/var/log'] = sorted(list(set(log_files)))

        # /var/www/html
        self.fs_state['/var/www'] = ['html']
        self.fs_state['/var/www/html'] = ['index.html', 'index.nginx-debian.html']

        # /usr local
        self.fs_state['/usr/local'] = ['bin', 'etc', 'games', 'include', 'lib', 'man', 'sbin', 'share', 'src']
        for d in self.fs_state['/usr/local']:
             self.fs_state[f"/usr/local/{d}"] = []

        # 6. 保留较完整的 /dev 视图，避免被一眼看出是手搓目录
        dev_files = [
            'autofs', 'block', 'bsg', 'btrfs-control', 'bus', 'char', 'console', 'core',
            'cpu_dma_latency', 'disk', 'dm-0', 'fd', 'full', 'fuse', 'hugepages', 'hwrng',
            'initctl', 'input', 'kmsg', 'log', 'loop-control', 'loop0', 'loop1', 'loop2',
            'loop3', 'loop4', 'loop5', 'loop6', 'loop7', 'mapper', 'mem', 'mqueue', 'net',
            'null', 'nvram', 'port', 'ptmx', 'pts', 'random', 'rfkill', 'rtc', 'rtc0',
            'sda', 'sda1', 'sda2', 'sda3', 'sg0', 'shm', 'stderr', 'stdin', 'stdout', 'tty',
            'tty0', 'tty1', 'tty2', 'tty3', 'tty4', 'tty5', 'tty6', 'ttyS0', 'ttyS1',
            'ubuntu-vg', 'urandom', 'vcs', 'vcs1', 'vcsa', 'vcsa1', 'vhost-net', 'zero',
        ]
        existing_dev = list(self.fs_state.get('/dev', []))
        self.fs_state['/dev'] = sorted(set(existing_dev + dev_files))
        # /dev/pts 终端列表
        self.fs_state['/dev/pts'] = ['0', 'ptmx']
        self.fs_state['/dev/shm'] = []
        self.fs_state.setdefault('/dev/mapper', ['ubuntu--vg-root'])
        self.fs_state.setdefault('/dev/block', [])
        self.fs_state.setdefault('/dev/bus', [])
        self.fs_state.setdefault('/dev/char', [])
        self.fs_state.setdefault('/dev/disk', ['by-id', 'by-path', 'by-uuid'])
        self.fs_state.setdefault('/dev/disk/by-id', [])
        self.fs_state.setdefault('/dev/disk/by-path', [])
        self.fs_state.setdefault('/dev/disk/by-uuid', [])
        self.fs_state.setdefault('/dev/input', [])
        self.fs_state.setdefault('/dev/mqueue', [])
        self.fs_state.setdefault('/dev/net', [])

        # 7. 填充 /proc
        # 虽然 _cmd_cat 是动态生成的，但 ls 需要看到它们
        proc_files = ['cpuinfo', 'meminfo', 'version', 'uptime', 'loadavg', 'stat', 'mounts', 'net', 'sys', '1', '512']
        self.fs_state['/proc'] = sorted(proc_files)
        self.fs_state['/proc/net'] = ['dev', 'tcp', 'udp', 'arp']
        self.fs_state['/proc/sys'] = ['kernel', 'net', 'vm']

    def _get_fake_ip(self, domain: str) -> str:
        """
        获取域名对应的 IP。
        策略：为了避免对外探测，仅允许本地回环；其他域名统一视为被拦截。
        """
        # 本地缓存命中
        if domain in DNS_CACHE:
            return DNS_CACHE[domain]


        # 仅允许本地回环域名，其他请求统一视为被拦截
        if domain in ['localhost', '127.0.0.1', HONEYPOT_IDENTITY.get('hostname')]:
            return '127.0.0.1'

        logger.debug(f"[DNS] 防火墙拦截: {domain}")
        return None


    def get_prompt(self) -> str:
        # 动态主机名
        hostname = self.hostname
        if '/etc/hostname' in self.files_content:
            hostname = self.files_content['/etc/hostname'].strip()
        elif '/etc/hostname' in VIRTUAL_FILES:
            hostname = VIRTUAL_FILES['/etc/hostname'].strip()

        display_path = self.current_path
        home = self.env['HOME']
        if self.current_path == home:
            display_path = '~'
        elif self.current_path.startswith(home + '/'):
            display_path = '~' + self.current_path[len(home):]
        symbol = '#' if self.username == 'root' else '$'
        return f"{self.username}@{hostname}:{display_path}{symbol} "

    def normalize_path(self, path: str) -> str:
        # 处理相对路径、绝对路径、. 和 ..
        if not path.startswith('/'):
            base = self.current_path if self.current_path != '/' else ''
            path = base + '/' + path

        parts = path.split('/')
        stack = []
        for part in parts:
            if part == '' or part == '.':
                continue
            elif part == '..':
                if stack: stack.pop()
            else:
                stack.append(part)
        return '/' + '/'.join(stack) if stack else '/'

    def _expand_variables(self, args: list) -> list:
        """Shell 变量展开 ($VAR, ~, $?)"""
        new_args = []
        for arg in args:
            # 波浪号展开
            if arg == '~':
                arg = self.env['HOME']
            elif arg.startswith('~/'):
                arg = self.env['HOME'] + arg[1:]

            # 环境变量展开
            if '$' in arg:
                # 简单处理 $VAR 和 ${VAR}
                # 优先匹配长变量名
                for key in sorted(self.env.keys(), key=len, reverse=True):
                    val = self.env[key]
                    arg = arg.replace(f'${key}', val)
                    arg = arg.replace(f'${{{key}}}', val)

                # 处理未定义的变量 -> 空字符串 (bash行为)
                # 比如 echo $NOTEXIST -> echo ""
                # 使用各种正则太复杂，这里简化：如果还有 $XX 格式，替换为空
                # 暂不处理，保留原样可能更安全，避免误删非变量的 $
                pass

            new_args.append(arg)
        return new_args

    def _expand_wildcards(self, args: list) -> list:
        """Shell 通配符展开 (*, ?)"""
        expanded = []
        for arg in args:
            if '*' in arg or '?' in arg:
                # 简单处理：仅支持当前目录或指定目录的简单匹配
                # case 1: *.log (当前目录)
                # case 2: /var/log/*.log (指定目录)

                dirname = os.path.dirname(arg)
                basename_pattern = os.path.basename(arg)

                # 确定搜索目录
                search_path = self.current_path
                if dirname:
                    search_path = self.normalize_path(dirname)

                if search_path in self.fs_state:
                    matches = []
                    for filename in self.fs_state[search_path]:
                        if fnmatch.fnmatch(filename, basename_pattern):
                            # 如果原参数带路径，结果也要带路径
                            if dirname:
                                full_match = os.path.join(search_path, filename).replace('\\', '/')
                                matches.append(full_match)
                            else:
                                matches.append(filename)

                    if matches:
                        expanded.extend(sorted(matches))
                    else:
                        expanded.append(arg) # 无匹配保持原样
                else:
                    expanded.append(arg)
            else:
                expanded.append(arg)
        return expanded


    def execute_command(self, command_line: str, record_history: bool = True) -> str:
        return commands.execute_command(self, command_line, record_history=record_history)

    def _execute_single_command(self, command_line: str) -> str:
        return commands.execute_single_command(self, command_line)

    def _parse_args(self, command_line):
        return commands.parse_args(command_line)

    def _handle_redirection(self, path: str, content: str, mode: str):
        """处理文件重定向写入"""
        target_path = self.normalize_path(path)

        # 重定向写文件
        if not self._check_write_permission(target_path):
            return False

        # 处理 /dev/null, /dev/zero, /dev/random 等黑洞
        if target_path in ['/dev/null', '/dev/zero', '/dev/random', '/dev/urandom']:
            return True # 成功写入黑洞

        parent_dir = os.path.dirname(target_path)
        filename = os.path.basename(target_path)

        # 简单的父目录检查
        if parent_dir not in self.fs_state:
            # 如果父目录不存在，则无法写入
            return False

        if filename not in self.fs_state[parent_dir]:
            self.fs_state[parent_dir].append(filename)
            # 如果是新文件，设置所有者
            self.file_owners[target_path] = (self.username, self.username)


        if mode == '>':
            self.files_content[target_path] = content.strip() + "\n"
        elif mode == '>>':
            old = self.files_content.get(target_path, '')
            self.files_content[target_path] = old + content.strip() + "\n"

        # 保存会话状态
        self._save_session_state()
        return True

    # === 基础命令 ===

    def _cmd_true(self, args: list) -> str:
        return commands.cmd_true(self, args)

    def _cmd_false(self, args: list) -> str:
        return commands.cmd_false(self, args)

    def _cmd_whoami(self, args: list) -> str:
        return commands.cmd_whoami(self, args)

    def _cmd_sudo(self, args: list) -> str:
        return commands.cmd_sudo(self, args)

    def _sudo_authenticate(self, password, context):
        """sudo 第二步: 验证密码并执行"""
        self.interactive_state = None # 重置状态

        # noop 模式：仅验证密码，不执行命令（例如 sudo -v/-k/-K）
        if isinstance(context, dict):
            user = str(context.get('user') or self.username)
            expected = SSH_CREDENTIALS.get(user)
            if user != 'root':
                if not expected or expected != password:
                    return "Sorry, try again.\n"

            mode = context.get('mode')
            if mode == 'noop':
                logger.info(f"[SUDO] 用户 {user} 使用口令 {password} 更新凭据缓存")
                self._touch_sudo_cache(user)
                return ""
            if mode == 'exec':
                cmd_list = context.get('cmd') or []
                old_user = self.username
                self.username = 'root'
                try:
                    cmd = " ".join(cmd_list)
                    logger.info(f"[SUDO] 用户 {old_user} 使用口令 {password} 提权执行: {cmd}")
                    self._touch_sudo_cache(old_user)
                    return self.execute_command(cmd, record_history=False)
                finally:
                    self.username = old_user
                return ""
        if isinstance(context, list) and len(context) == 1 and context[0].startswith('-'):
            logger.info(f"[SUDO] 用户 {self.username} 使用口令 {password} 执行选项 {context[0]}")
            self._touch_sudo_cache(self.username)
            return ""

        old_user = self.username
        self.username = 'root'
        try:
            # 重构命令并执行
            cmd = " ".join(context)
            # 记录这次操作
            logger.info(f"[SUDO] 用户 {old_user} 使用口令 {password} 提权执行: {cmd}")
            self._touch_sudo_cache(old_user)

            # 执行命令 (record_history=False 防止 sudo 命令本身被重复记录)
            return self.execute_command(cmd, record_history=False)
        finally:
            self.username = old_user





    def _cmd_ls(self, args: list) -> str:
        return commands.cmd_ls(self, args)

    def _format_ls_item(self, item_path: str, display_name: str, is_proc_path: bool = False) -> str:
        return commands.format_ls_item(self, item_path, display_name, is_proc_path)

    def _cmd_cd(self, args: list) -> str:
        return commands.cmd_cd(self, args)

    def _cmd_pwd(self, args: list) -> str:
        return commands.cmd_pwd(self, args)

    def _cmd_groups(self, args: list) -> str:
        return commands.cmd_groups(self, args)

    def _cmd_id(self, args: list) -> str:
        return commands.cmd_id(self, args)
    def _cmd_cat(self, args: list) -> str:
        return commands.cmd_cat(self, args)

    def _cmd_head(self, args: list) -> str:
        return commands.cmd_head(self, args)

    def _cmd_tail(self, args: list) -> str:
        return commands.cmd_tail(self, args)

    def _cmd_echo(self, args: list) -> str:
        return commands.cmd_echo(self, args)

    def _cmd_command(self, args: list) -> str:
        return commands.cmd_command(self, args)

    def _cmd_printf(self, args: list) -> str:
        return commands.cmd_printf(self, args)

    def _cmd_hash(self, args: list) -> str:
        return commands.cmd_hash(self, args)

    def _cmd_times(self, args: list) -> str:
        return commands.cmd_times(self, args)




    def _cmd_alias(self, args: list) -> str:
        return commands.cmd_alias(self, args)


    def _cmd_ss(self, args: list) -> str:
        return commands.cmd_ss(self, args)










    def _cmd_uname(self, args: list) -> str:
        return commands.cmd_uname(self, args)

    def _cmd_hostname(self, args: list) -> str:
        return commands.cmd_hostname(self, args)




    def _seed_file_timestamps(self):
        """为系统文件生成真实的旧时间戳"""
        now = datetime.now()
        # 假设系统安装在 1-2 年前
        install_date = now - timedelta(days=random.randint(300, 700))

        # 遍历所有已知文件路径
        all_paths = []
        for d, files in self.fs_state.items():
            for f in files:
                all_paths.append(self.normalize_path(f"{d}/{f}"))

        for path in all_paths:
            # 系统目录下的文件通常有较早的时间戳
            if any(path.startswith(p) for p in ['/bin', '/sbin', '/usr', '/lib', '/etc', '/boot']):
                # 基础安装时间 +/- 几天
                jitter = timedelta(days=random.randint(-5, 5), hours=random.randint(0, 23), minutes=random.randint(0, 59))
                self.file_timestamps[path] = install_date + jitter
            # /tmp, /run, /proc 应该是新的
            elif any(path.startswith(p) for p in ['/tmp', '/run', '/dev']):
                continue  # 保持默认当前时间
            # 用户目录随机
            elif path.startswith('/home') or path.startswith('/root'):
                # 最近 30 天
                jitter = timedelta(days=random.randint(1, 30))
                self.file_timestamps[path] = now - jitter

    def _cmd_ip(self, args: list) -> str:
        return commands.cmd_ip(self, args)

    # 进程与服务状态管理
    # 定义服务状态，用于链接 ps, systemctl, ss
    def _init_processes(self):
        if not hasattr(self, 'processes'):
            # PID -> 进程信息
            self.processes = {
                '1': {'user': 'root', 'ppid': '0', 'cmd': '/sbin/init', 'port': None},
                '512': {'user': 'root', 'ppid': '1', 'cmd': '/usr/sbin/sshd -D', 'port': 22},
                # 系统服务（内网场景）
                '680': {'user': 'root', 'ppid': '1', 'cmd': '/lib/systemd/systemd-journald', 'port': None},
                '720': {'user': 'root', 'ppid': '1', 'cmd': '/lib/systemd/systemd-resolved', 'port': 53}, # UDP/TCP 53
                '850': {'user': 'root', 'ppid': '1', 'cmd': '/usr/sbin/cron -f', 'port': None},
                '900': {'user': 'syslog', 'ppid': '1', 'cmd': '/usr/sbin/rsyslogd -n', 'port': None},
            }
            # 内核线程（PIDs < 100）
            kernel_threads = [
                (2, 'kthreadd'), (3, 'rcu_gp'), (4, 'rcu_par_gp'), (6, 'kworker/0:0H-kblockd'),
                (9, 'mm_percpu_wq'), (10, 'rcu_tasks_rude_'), (11, 'rcu_tasks_trace_'),
                (12, 'ksoftirqd/0'), (13, 'rcu_sched'), (14, 'migration/0'),
                (15, 'idle_inject/0'), (18, 'kdevtmpfs'), (19, 'netns'), (20, 'inet_frag_wq'),
                (21, 'kauditd'), (22, 'khungtaskd'), (23, 'oom_reaper'), (24, 'writeback'),
                (25, 'kcompactd0'), (26, 'ksmd'), (27, 'khugepaged')
            ]
            for pid, name in kernel_threads:
                self.processes[str(pid)] = {'user': 'root', 'ppid': '2', 'cmd': f'[{name}]', 'port': None}

            # 动态添加当前 Shell 和 SSHD 会话进程
        # 进程树：init(1) -> sshd(512) -> sshd: user@pts/N (sshd_pid) -> bash(shell_pid)

        # 1. SSHD 会话进程（持有 socket 连接）
        self.sshd_pid = str(random.randint(2000, 2500))
        sshd_cmd = f"sshd: {self.username}@{self._tty_label()}"
        self.processes[self.sshd_pid] = {'user': 'root', 'ppid': '512', 'cmd': sshd_cmd, 'port': 22}

        # 2. Bash 交互进程（用户 Shell）
        self.shell_pid = str(int(self.sshd_pid) + random.randint(1, 5)) # PID 略大于父进程
        self.processes[self.shell_pid] = {'user': self.username, 'ppid': self.sshd_pid, 'cmd': '-bash', 'port': None}

        # 初始化进程 CPU 时间与启动时间
        boot_time = HONEYPOT_IDENTITY.get('boot_time') or datetime.now()
        for pid, info in self.processes.items():
            if 'cpu_time' not in info:
                info['cpu_time'] = random.uniform(0.1, 8.0)
            if 'start_time' not in info:
                delta_minutes = random.randint(1, 1800)
                info['start_time'] = boot_time + timedelta(minutes=delta_minutes)
            if 'cpu_pct' not in info:
                info['cpu_pct'] = round(random.uniform(0.1, 2.0), 1)
            if 'mem_pct' not in info:
                info['mem_pct'] = round(random.uniform(0.1, 0.8), 1)

    # 动态网络统计
    def _get_net_stats(self) -> dict:
        """Calculate dynamic RX/TX counters based on uptime"""
        now = datetime.now()
        boot_time = HONEYPOT_IDENTITY.get('boot_time') or now
        uptime_sec = (now - boot_time).total_seconds()

        # 基础流量 + 随机速率（字节/秒）
        # 内网空闲主机平均约 500 bytes/sec
        rx_base = 123456789 + int(uptime_sec * random.randint(100, 800))
        tx_base = 987654321 + int(uptime_sec * random.randint(200, 1500))

        return {
            'rx_bytes': rx_base,
            'tx_bytes': tx_base,
            'rx_packets': rx_base // 1000,
            'tx_packets': tx_base // 800
        }


    def _cmd_ps(self, args: list) -> str:
        return commands.cmd_ps(self, args)

    def _cmd_kill(self, args: list) -> str:
        return commands.cmd_kill(self, args)


    def _cmd_service(self, args: list) -> str:
        return commands.cmd_service(self, args)

    def _cmd_ssh(self, args: list) -> str:
        return commands.cmd_ssh(self, args)





    def _cmd_exit(self, args: list) -> str:
        return commands.cmd_exit(self, args)

    def _cmd_logout(self, args: list) -> str:
        return commands.cmd_logout(self, args)




    def _cmd_who(self, args: list) -> str:
        return commands.cmd_who(self, args)




    def _cmd_w(self, args: list) -> str:
        return commands.cmd_w(self, args)

    def _cmd_free(self, args: list) -> str:
        return commands.cmd_free(self, args)

    def _cmd_df(self, args: list) -> str:
        return commands.cmd_df(self, args)

    def _cmd_clear(self, args: list) -> str:
        return commands.cmd_clear(self, args)

    def _cmd_unalias(self, args: list) -> str:
        return commands.cmd_unalias(self, args)

    def _cmd_source(self, args: list) -> str:
        return commands.cmd_source(self, args)

    def _cmd_set(self, args: list) -> str:
        return commands.cmd_set(self, args)

    def _cmd_unset(self, args: list) -> str:
        return commands.cmd_unset(self, args)

    def _cmd_declare(self, args: list) -> str:
        return commands.cmd_declare(self, args)

    def _cmd_typeset(self, args: list) -> str:
        return commands.cmd_typeset(self, args)

    def _cmd_readonly(self, args: list) -> str:
        return commands.cmd_readonly(self, args)

    def _cmd_wait(self, args: list) -> str:
        return commands.cmd_wait(self, args)

    def _cmd_fg(self, args: list) -> str:
        return commands.cmd_fg(self, args)

    def _cmd_bg(self, args: list) -> str:
        return commands.cmd_bg(self, args)

    def _cmd_jobs(self, args: list) -> str:
        return commands.cmd_jobs(self, args)

    def _cmd_time(self, args: list) -> str:
        return commands.cmd_time(self, args)

    def _cmd_help(self, args: list) -> str:
        return commands.cmd_help(self, args)

    def _cmd_type(self, args: list) -> str:
        return commands.cmd_type(self, args)

    def _cmd_umask(self, args: list) -> str:
        return commands.cmd_umask(self, args)

    def _cmd_exec(self, args: list) -> str:
        return commands.cmd_exec(self, args)

    def _cmd_trap(self, args: list) -> str:
        return commands.cmd_trap(self, args)

    def _cmd_function(self, args: list) -> str:
        return commands.cmd_function(self, args)

    def _cmd_return(self, args: list) -> str:
        return commands.cmd_return(self, args)

    def _cmd_if(self, args: list) -> str:
        return commands.cmd_if(self, args)

    def _cmd_then(self, args: list) -> str:
        return commands.cmd_then(self, args)

    def _cmd_else(self, args: list) -> str:
        return commands.cmd_else(self, args)

    def _cmd_elif(self, args: list) -> str:
        return commands.cmd_elif(self, args)

    def _cmd_fi(self, args: list) -> str:
        return commands.cmd_fi(self, args)

    def _cmd_while(self, args: list) -> str:
        return commands.cmd_while(self, args)

    def _cmd_until(self, args: list) -> str:
        return commands.cmd_until(self, args)

    def _cmd_for(self, args: list) -> str:
        return commands.cmd_for(self, args)

    def _cmd_break(self, args: list) -> str:
        return commands.cmd_break(self, args)

    def _cmd_continue(self, args: list) -> str:
        return commands.cmd_continue(self, args)

    def _cmd_select(self, args: list) -> str:
        return commands.cmd_select(self, args)

    # more/less 在非交互模式下可以直接输出内容
    def _cmd_more(self, args: list) -> str:
        return commands.cmd_more(self, args)

    def _cmd_less(self, args: list) -> str:
        return commands.cmd_less(self, args)

    def _cmd_tar(self, args: list) -> str:
        return commands.cmd_tar(self, args)

    def _cmd_history(self, args: list) -> str:
        return commands.cmd_history(self, args)

    def _cmd_env(self, args: list) -> str:
        return commands.cmd_env(self, args)

    def _cmd_export(self, args: list) -> str:
        return commands.cmd_export(self, args)

    def _cmd_su(self, args: list) -> str:
        return commands.cmd_su(self, args)

    def _check_write_permission(self, path: str) -> bool:
        """检查是否有写权限。"""
        if self.username == 'root':
            return True

        # 允许用户目录和临时目录
        user_home = self.env.get('HOME', f'/home/{self.username}')
        if path.startswith(user_home) or path.startswith('/tmp') or path.startswith('/var/tmp'):
            return True

        # 其他默认只读
        return False

    def _check_read_permission(self, path: str) -> bool:
        """检查是否有读权限。"""
        if self.username == 'root':
            return True

        # 敏感文件黑名单
        if path in ['/etc/shadow', '/etc/shadow-', '/etc/gshadow', '/etc/gshadow-', '/etc/sudoers', '/root/.ssh/id_rsa', '/etc/ssh/sshd_config']:
            return False

        # 敏感目录 (如果 path 是目录)
        if path == '/root' or path.startswith('/root/'):
            return False

        # 其他用户的主目录默认不可读
        if path.startswith('/home/'):
            parts = path.split('/')
            if len(parts) > 2:
                owner = parts[2]
                if owner != self.username and owner != 'root': # root 目录上面已经处理
                    return False

        # 中交互场景下其余路径默认可读，减少误拒绝
        return True

    def _cmd_bash(self, args: list) -> str:
        return commands.cmd_bash(self, args)

    def _cmd_sh(self, args: list) -> str:
        return commands.cmd_sh(self, args)





    def _cmd_apt(self, args: list) -> str:
        return commands.cmd_apt(self, args)

    def _cmd_unminimize(self, args: list) -> str:
        return commands.cmd_unminimize(self, args)

    def _unminimize_confirm(self, user_input, context):
        """unminimize 确认步骤"""
        self.interactive_state = None

        if user_input.lower() == 'y':
            # 通过延时与阶段性输出模拟执行过程
            logger.info(f"[命令] {self.client_ip} 尝试执行 unminimize (已确认)")
            output = "\nUnminimizing this system...\n"
            # 当前实现返回单段文本，这里通过 sleep 形成阶段感
            time.sleep(1.2)
            output += "Getting new release of 'unminimize'...\n"
            output += "Downloading packages and content...\n"
            time.sleep(1.6)
            output += "Unpacking packages...\n"
            output += "Setting up packages...\n"
            time.sleep(1.4)
            # 复用 apt 输出风格
            output += "Reading package lists... Done\n"
            output += "Building dependency tree... Done\n"
            output += "Reading state information... Done\n"
            time.sleep(2.0)
            output += self._cmd_apt(['update']) # 复用 apt 的网络失败逻辑
            return output
        else:
             return "\nAborted.\n"

    # apt-get 别名
    def _cmd_apt_get(self, args: list) -> str:
        return commands.cmd_apt_get(self, args)

    # grep 命令
    def _cmd_grep(self, args: list) -> str:
        return commands.cmd_grep(self, args)

    # awk 已移除 - Ubuntu 最小安装不包含 (需要 gawk/mawk 包)

    def _cmd_sed(self, args: list) -> str:
        return commands.cmd_sed(self, args)

    def _cmd_cut(self, args: list) -> str:
        return commands.cmd_cut(self, args)

    def _cmd_sort(self, args: list) -> str:
        return commands.cmd_sort(self, args)




    # wget 常用于投递载荷，单独保留 URL 捕获
    def _cmd_wget(self, args: list) -> str:
        return commands.cmd_wget(self, args)

    def _cmd_uniq(self, args: list) -> str:
        return commands.cmd_uniq(self, args)

    def _cmd_wc(self, args: list) -> str:
        return commands.cmd_wc(self, args)

    def _cmd_stat(self, args: list) -> str:
        return commands.cmd_stat(self, args)

    def _cmd_base64(self, args: list) -> str:
        return commands.cmd_base64(self, args)

    def _cmd_md5sum(self, args: list) -> str:
        return commands.cmd_md5sum(self, args)

    # curl/nc/scp 不在交互命令集，由专用链路处理

    # === 管道处理函数 ===
    def _pipe_grep(self, input_data: str, args: list) -> str:
        return commands.pipe_grep(input_data, args)

    def _pipe_head(self, input_data: str, args: list) -> str:
        return commands.pipe_head(input_data, args)

    def _pipe_tail(self, input_data: str, args: list) -> str:
        return commands.pipe_tail(input_data, args)

    def _pipe_wc(self, input_data: str, args: list) -> str:
        return commands.pipe_wc(input_data, args)

    # _pipe_awk 已移除 - Ubuntu 最小安装不包含 awk

    def _pipe_sed(self, input_data: str, args: list) -> str:
        return commands.pipe_sed(input_data, args)

    def _pipe_cut(self, input_data: str, args: list) -> str:
        return commands.pipe_cut(input_data, args)

    def _pipe_sort(self, input_data: str, args: list) -> str:
        return commands.pipe_sort(input_data, args)

    def _pipe_uniq(self, input_data: str, args: list) -> str:
        return commands.pipe_uniq(input_data, args)

    # === 文件操作（核心仿真） ===

    # 真正可用的 mkdir
    def _cmd_mkdir(self, args: list) -> str:
        return commands.cmd_mkdir(self, args)

    # 真正可用的 touch (创建空文件)
    def _cmd_touch(self, args: list) -> str:
        return commands.cmd_touch(self, args)

    def _delete_recursive(self, path: str):
        """递归删除目录及其内容"""
        if path not in self.fs_state:
            return

        # 获取目录下的所有项（复制列表以防迭代时修改）
        items = list(self.fs_state[path])
        for item in items:
            item_path = f"{path}/{item}" if path != '/' else f"/{item}"

            # 如果是子目录，递归删除
            if item_path in self.fs_state:
                self._delete_recursive(item_path)
            else:
                # 删除文件内容
                if item_path in self.files_content:
                    del self.files_content[item_path]
                # 删除文件元数据
                if item_path in self.file_timestamps: del self.file_timestamps[item_path]
                if item_path in self.file_perms: del self.file_perms[item_path]
                if item_path in self.file_owners: del self.file_owners[item_path]
                if item_path in self.file_sizes: del self.file_sizes[item_path]

        # 清除目录本身的元数据（如果有）
        if path in self.file_timestamps: del self.file_timestamps[path]
        if path in self.file_perms: del self.file_perms[path]
        if path in self.file_owners: del self.file_owners[path]
        if path in self.file_sizes: del self.file_sizes[path]

        # 最后删除目录在 fs_state 中的条目
        del self.fs_state[path]

    def _copy_file(self, src_path, target_path, keep_metadata=False):
        if src_path in self.files_content:
            self.files_content[target_path] = self.files_content[src_path]

        # 复制元数据
        if keep_metadata and src_path in self.file_owners:
            self.file_owners[target_path] = self.file_owners[src_path]
        else:
            self.file_owners[target_path] = (self.username, self.username)

        if keep_metadata and src_path in self.file_perms:
            self.file_perms[target_path] = self.file_perms[src_path]
        else:
            self.file_perms[target_path] = "-rw-r--r--"

        if src_path in self.file_sizes:
            self.file_sizes[target_path] = self.file_sizes[src_path]
        else:
            self.file_sizes[target_path] = len(self.files_content.get(target_path, "")) if target_path in self.files_content else 0

        if keep_metadata and src_path in self.file_timestamps:
             self.file_timestamps[target_path] = self.file_timestamps[src_path]
        else:
             self.file_timestamps[target_path] = datetime.now()

        # 写入父目录 fs_state
        parent = os.path.dirname(target_path)
        name = os.path.basename(target_path)
        if parent in self.fs_state:
            if name not in self.fs_state[parent]:
                self.fs_state[parent].append(name)

    def _copy_recursive(self, src_path, target_path, keep_metadata=False):
        # 创建目标目录
        if target_path not in self.fs_state:
            self.fs_state[target_path] = []
            parent = os.path.dirname(target_path)
            name = os.path.basename(target_path)
            if parent in self.fs_state:
                if name not in self.fs_state[parent]:
                    self.fs_state[parent].append(name)

            # 复制目录元数据
            if keep_metadata and src_path in self.file_owners:
                self.file_owners[target_path] = self.file_owners[src_path]
            else:
                self.file_owners[target_path] = (self.username, self.username)

            if keep_metadata and src_path in self.file_perms:
                self.file_perms[target_path] = self.file_perms[src_path]
            else:
                self.file_perms[target_path] = "drwxr-xr-x"
            if keep_metadata and src_path in self.file_timestamps:
                 self.file_timestamps[target_path] = self.file_timestamps[src_path]
            else:
                 self.file_timestamps[target_path] = datetime.now()

        # 遍历子项
        if src_path in self.fs_state:
            for item in self.fs_state[src_path]:
                s_item = f"{src_path}/{item}" if src_path != '/' else f"/{item}"
                t_item = f"{target_path}/{item}" if target_path != '/' else f"/{item}"

                if s_item in self.fs_state:
                    self._copy_recursive(s_item, t_item, keep_metadata)
                else:
                    self._copy_file(s_item, t_item, keep_metadata)

    def _cmd_cp(self, args: list) -> str:
        return commands.cmd_cp(self, args)

    def _cmd_mv(self, args: list) -> str:
        return commands.cmd_mv(self, args)

    def _cmd_rm(self, args: list) -> str:
        return commands.cmd_rm(self, args)

    def _cmd_chmod(self, args: list) -> str:
        return commands.cmd_chmod(self, args)

    def _cmd_chown(self, args: list) -> str:
        return commands.cmd_chown(self, args)

    def _cmd_which(self, args: list) -> str:
        return commands.cmd_which(self, args)

    def _cmd_python3(self, args: list) -> str:
        return commands.cmd_python3(self, args)

    def _cmd_python(self, args: list) -> str:
        return commands.cmd_python(self, args)




    def _cmd_passwd(self, args: list) -> str:
        return commands.cmd_passwd(self, args)


    def _cmd_useradd(self, args: list) -> str:
        return commands.cmd_useradd(self, args)

    def _cmd_groupadd(self, args: list) -> str:
        return commands.cmd_groupadd(self, args)

    def _cmd_usermod(self, args: list) -> str:
        return commands.cmd_usermod(self, args)

    def _cmd_deluser(self, args: list) -> str:
        return commands.cmd_deluser(self, args)

    def _cmd_lscpu(self, args: list) -> str:
        return commands.cmd_lscpu(self, args)

    def _cmd_systemctl(self, args: list) -> str:
        return commands.cmd_systemctl(self, args)

    def _cmd_hostnamectl(self, args: list) -> str:
        return commands.cmd_hostnamectl(self, args)

    def _cmd_last(self, args: list) -> str:
        return commands.cmd_last(self, args)

    def _cmd_journalctl(self, args: list) -> str:
        return commands.cmd_journalctl(self, args)

    def _cmd_sysctl(self, args: list) -> str:
        return commands.cmd_sysctl(self, args)

    def _cmd_ufw(self, args: list) -> str:
        return commands.cmd_ufw(self, args)

    def _cmd_visudo(self, args: list) -> str:
        return commands.cmd_visudo(self, args)

    def _cmd_sshd(self, args: list) -> str:
        return commands.cmd_sshd(self, args)

    def _cmd_date(self, args: list) -> str:
        return commands.cmd_date(self, args)

    def _cmd_uptime(self, args: list) -> str:
        return commands.cmd_uptime(self, args)






    def _cmd_lsb_release(self, args: list) -> str:
        return commands.cmd_lsb_release(self, args)

    def _cmd_top(self, args: list) -> str:
        return commands.cmd_top(self, args)








    # 模拟 kill
    def _cmd_poweroff(self, args: list) -> str:
        return commands.cmd_poweroff(self, args)

    def _cmd_halt(self, args: list) -> str:
        return commands.cmd_halt(self, args)

    def _cmd_shutdown(self, args: list) -> str:
        return commands.cmd_shutdown(self, args)




    # 模拟 reboot
    def _cmd_reboot(self, args: list) -> str:
        return commands.cmd_reboot(self, args)

    # 动态 Find 命令
    def _cmd_find(self, args: list) -> str:
        return commands.cmd_find(self, args)


    # 模拟 dmesg 命令
    def _cmd_dmesg(self, args: list) -> str:
        return commands.cmd_dmesg(self, args)



def handle_ssh_session(channel, client_ip: str, username: str, client_port: int = None,
                       term_width: int = 80, term_height: int = 24, session_id: str = None):
    shell = VirtualShell(client_ip, username, client_port=client_port, term_width=term_width, term_height=term_height, session_id=session_id)
    try:
        # 记录登录历史 & 追加 auth.log
        shell._record_login(username, client_ip)
        ts = datetime.now().strftime("%b %d %H:%M:%S")
        _append_auth_log(f"{ts} {HONEYPOT_IDENTITY['hostname']} sshd[{os.getpid()}]: pam_unix(sshd:session): session opened for user {username} by (uid=0)\n")

        # 检查是否是 reboot 后重连，模拟启动延迟
        reboot_time = _get_reboot_marker(client_ip)
        if reboot_time > 0:
            elapsed = time.time() - reboot_time
            if elapsed < REBOOT_DELAY_SECONDS:
                # 还在"启动中"，等待剩余时间
                remaining = REBOOT_DELAY_SECONDS - elapsed
                logger.info(f"[Reboot] {client_ip} 重连，模拟等待 {remaining:.1f} 秒启动")
                time.sleep(remaining)
            # 启动完成，清除记录
            _clear_reboot_marker(client_ip, reboot_time)

        last_login_ip = HONEYPOT_IDENTITY.get('last_login_ip', '10.0.12.50')
        # 计算上一条登录记录（如果没有，就伪造一个更真实的时间）
        prev_login = None
        if isinstance(shell.login_history, list) and len(shell.login_history) > 1:
            prev_login = shell.login_history[1]
        if prev_login and isinstance(prev_login, dict):
            last_dt = prev_login.get('login_at') or (datetime.now() - timedelta(hours=random.randint(6, 72)))
            last_ip = prev_login.get('ip') or last_login_ip
        else:
            last_dt = datetime.now() - timedelta(hours=random.randint(6, 72))
            last_ip = last_login_ip

        # 格式化 "Mon Feb  2 09:35:21 2026"
        day = last_dt.day
        last_login_str = f"{last_dt:%a} {last_dt:%b} {day:2d} {last_dt:%H:%M:%S} {last_dt:%Y}"
        welcome = (
            f"Welcome to Ubuntu 24.04.2 LTS (GNU/Linux {KERNEL_RELEASE} x86_64)\n\n"
            " * Documentation:  https://help.ubuntu.com\n"
            " * Management:     https://landscape.canonical.com\n"
            " * Support:        https://ubuntu.com/pro\n\n"
            "This system has been minimized by removing packages and content that are\n"
            "not required on a system that users do not log into.\n\n"
            "To restore this content, you can run the 'unminimize' command.\n"
            "Failed to connect to https://changelogs.ubuntu.com/meta-release. Check your Internet connection or proxy settings\n\n"
            f"Last login: {last_login_str} from {last_ip}\n"
        )

        welcome = welcome.replace('\n', '\r\n')
        channel.send(welcome.encode('utf-8'))
        channel.send(shell.get_prompt().encode('utf-8'))
        command_buffer = ''
        cursor_pos = 0 # 光标位置 (相对于 command_buffer 开头)
        history_index = -1 # 历史记录索引
        escape_buffer = '' # ESC 序列缓冲

        while True:
            # 根据关机计划动态设置超时
            if shell.shutdown_deadline:
                if time.time() >= shell.shutdown_deadline:
                    channel.send_exit_status(0)
                    channel.close()
                    return
                remaining = max(0.1, shell.shutdown_deadline - time.time())
                channel.settimeout(min(1.0, remaining))
            else:
                # 设置空闲超时 (10分钟)
                channel.settimeout(600.0)
            try:
                data = channel.recv(1024)
            except socket.timeout:
                # 如果在关机等待期内超时，继续轮询
                if shell.shutdown_deadline:
                    continue
                logger.warning(f"[超时] {client_ip} 会话空闲过久")
                channel.send(b"\r\n\r\nTimed out waiting for input: auto-logout\r\n")
                break
            except Exception:
                break

            if not data:
                break
            try:
                char = data.decode('utf-8')
            except UnicodeDecodeError:
                continue

            # 过滤 Bracketed Paste Mode (粘贴模式) 的控制字符
            # 防止用户粘贴时出现 [200~ 和 [201~ 乱码
            if '\x1b[200~' in char or '\x1b[201~' in char:
                char = char.replace('\x1b[200~', '').replace('\x1b[201~', '')

            # 处理 ESC 序列 (方向键)
            i = 0
            while i < len(char):
                c = char[i]

                # 优先处理交互模式 (sudo/su/passwd 等)
                # 交互输入改为“行缓冲”，回车才触发 callback
                if hasattr(shell, 'interactive_state') and shell.interactive_state:
                    state = shell.interactive_state
                    callback = state['func']
                    context = state.get('args')
                    echo = state.get('echo', True)
                    buf = state.get('buf', '')

                    if c == '\x03':
                        # Ctrl+C 中断交互
                        shell.interactive_state = None
                        channel.send(b'^C\r\n')
                        try:
                            msg = state.get('on_interrupt')
                            if msg:
                                channel.send(msg.replace('\n', '\r\n').encode('utf-8'))
                        except Exception:
                            pass
                        channel.send(shell.get_prompt().encode('utf-8'))
                        command_buffer = ''
                        i += 1
                        continue

                    if c == '\x7f' or c == '\x08':
                        if buf:
                            buf = buf[:-1]
                            state['buf'] = buf
                            if echo:
                                channel.send(b'\x08 \x08')
                        i += 1
                        continue

                    if c == '\r' or c == '\n':
                        channel.send(b'\r\n')
                        state['buf'] = ''
                        try:
                            output = callback(buf, context)
                        except Exception as e:
                            logger.error(f"Interactive callback error: {e}")
                            output = ""
                            shell.interactive_state = None

                        # 交互回调中处理特殊指令（sudo reboot/poweroff/shutdown 等）
                        if isinstance(output, str) and output.startswith('__SHUTDOWN__'):
                            parts = output.split('\n', 1)
                            msg = parts[1] if len(parts) > 1 else ""
                            if msg:
                                channel.send(msg.replace('\n', '\r\n').encode('utf-8'))
                            shell.shutdown_deadline = time.time() + 300
                            shell._save_session_state()
                            output = ""
                        elif output == '__REBOOT__':
                            _set_reboot_marker(client_ip)
                            logger.info(f"[Reboot] {client_ip} 触发了 reboot，将模拟 {REBOOT_DELAY_SECONDS} 秒启动延迟")
                            channel.send_exit_status(0)
                            channel.close()
                            return
                        elif output == '__POWEROFF__':
                            channel.send_exit_status(0)
                            channel.close()
                            return

                        if output:
                            output = output.replace('\n', '\r\n')
                            channel.send(output.encode('utf-8'))

                        if not shell.interactive_state:
                            channel.send(shell.get_prompt().encode('utf-8'))
                            command_buffer = ''

                        i += 1
                        continue

                    if c.isprintable():
                        buf += c
                        state['buf'] = buf
                        if echo:
                            channel.send(c.encode('utf-8'))

                    i += 1
                    continue

                # ESC 序列开始

                # ESC 序列开始
                if c == '\x1b':
                    if i + 2 < len(char) and char[i+1] == '[':
                        arrow = char[i+2]
                        if arrow == 'A': # 上箭头
                            if shell.history and history_index < len(shell.history) - 1:
                                history_index += 1
                                # 清除当前行
                                channel.send(b'\r' + shell.get_prompt().encode('utf-8') + b' ' * len(command_buffer) + b'\r' + shell.get_prompt().encode('utf-8'))
                                command_buffer = shell.history[-(history_index+1)]
                                cursor_pos = len(command_buffer) # 光标移到末尾
                                channel.send(command_buffer.encode('utf-8'))
                            i += 3
                            continue
                        elif arrow == 'B': # 下箭头
                            if history_index > 0:
                                history_index -= 1
                                channel.send(b'\r' + shell.get_prompt().encode('utf-8') + b' ' * len(command_buffer) + b'\r' + shell.get_prompt().encode('utf-8'))
                                command_buffer = shell.history[-(history_index+1)]
                                cursor_pos = len(command_buffer) # 光标移到末尾
                                channel.send(command_buffer.encode('utf-8'))
                            elif history_index == 0:
                                history_index = -1
                                channel.send(b'\r' + shell.get_prompt().encode('utf-8') + b' ' * len(command_buffer) + b'\r' + shell.get_prompt().encode('utf-8'))
                                command_buffer = ''
                                cursor_pos = 0
                            i += 3
                            continue
                        elif arrow == 'C': # 右箭头
                            if cursor_pos < len(command_buffer):
                                cursor_pos += 1
                                channel.send(b'\x1b[C') # 光标右移
                            i += 3
                            continue
                        elif arrow == 'D': # 左箭头
                            if cursor_pos > 0:
                                cursor_pos -= 1
                                channel.send(b'\x1b[D') # 光标左移
                            i += 3
                            continue
                    i += 1
                    continue

                if c == '\r' or c == '\n':
                    channel.send(b'\r\n')

                    if command_buffer.strip():

                        output = shell.execute_command(command_buffer)
                        if output.startswith('__SHUTDOWN__'):
                            parts = output.split('\n', 1)
                            msg = parts[1] if len(parts) > 1 else ""
                            if msg:
                                channel.send(msg.replace('\n', '\r\n').encode('utf-8'))
                            # 标记关机倒计时，稍后断线
                            shell.shutdown_deadline = time.time() + 300
                            shell._save_session_state()
                            output = ""
                        if output == '__EXIT__':
                            shell._record_logout()
                            ts = datetime.now().strftime("%b %d %H:%M:%S")
                            _append_auth_log(f"{ts} {HONEYPOT_IDENTITY['hostname']} sshd[{os.getpid()}]: pam_unix(sshd:session): session closed for user {shell.username}\n")
                            channel.send(b'logout\r\n')
                            channel.send_exit_status(0)
                            time.sleep(0.1)
                            channel.close()
                            return
                        elif output == '__REBOOT__':
                            # 真实的 reboot: 记录 IP 并断开连接
                            _set_reboot_marker(client_ip)
                            logger.info(f"[Reboot] {client_ip} 触发了 reboot，将模拟 {REBOOT_DELAY_SECONDS} 秒启动延迟")

                            channel.send_exit_status(0)
                            channel.close()
                            return
                        elif output == '__POWEROFF__':
                            # 关机提示并断开
                            channel.send_exit_status(0)
                            channel.close()
                            return
                        if output:
                            # 如果输出不以换行结尾，补一个，避免 prompt 紧贴上一行
                            # 交互式命令（如 passwd/sudo）保持原始提示不强行换行
                            if (not output.endswith('\n')) and (not (hasattr(shell, 'interactive_state') and shell.interactive_state)):
                                output += '\n'
                            output = output.replace('\n', '\r\n')
                            channel.send(output.encode('utf-8'))
                    command_buffer = ''
                    cursor_pos = 0 # 重置光标位置
                    history_index = -1 # 重置历史索引
                    # 如果进入交互模式（passwd/sudo/su 等），不要立刻输出 shell prompt
                    if hasattr(shell, 'interactive_state') and shell.interactive_state:
                        state = shell.interactive_state
                        prompt = state.get('prompt', '')
                        if prompt and (not output):
                            channel.send(prompt.encode('utf-8'))
                    else:
                        channel.send(shell.get_prompt().encode('utf-8'))
                elif c == '\x7f' or c == '\x08':
                    if cursor_pos > 0:
                        # 删除光标前的字符
                        command_buffer = command_buffer[:cursor_pos-1] + command_buffer[cursor_pos:]
                        cursor_pos -= 1
                        # 重绘：光标左移，输出剩余部分+空格，再回退
                        tail = command_buffer[cursor_pos:]
                        channel.send(b'\x08' + tail.encode('utf-8') + b' ' + b'\x08' * (len(tail) + 1))
                elif c == '\x03':
                    channel.send(b'^C\r\n')
                    command_buffer = ''
                    cursor_pos = 0
                    channel.send(shell.get_prompt().encode('utf-8'))
                elif c == '\x04':
                    if not command_buffer:
                        shell._record_logout()
                        ts = datetime.now().strftime("%b %d %H:%M:%S")
                        _append_auth_log(f"{ts} {HONEYPOT_IDENTITY['hostname']} sshd[{os.getpid()}]: pam_unix(sshd:session): session closed for user {shell.username}\n")
                        channel.send(b'logout\r\n')
                        channel.send_exit_status(0)
                        time.sleep(0.1)
                        channel.close()
                        return
                elif c == '\t':
                    # Tab 键自动补全
                    if not command_buffer.strip():
                        continue

                    # 1. 获取最后一个单词 (作为补全前缀)
                    parts = command_buffer.split()
                    if not parts: continue
                    last_part = parts[-1]
                    is_first_word = len(parts) == 1 and not command_buffer.startswith(' ')

                    matches = []

                    # 2. 如果是第一个单词，尝试命令补全
                    if is_first_word and '/' not in last_part:
                        # 从 /bin, /usr/bin 收集所有命令
                        all_commands = set()
                        for bin_path in ['/bin', '/usr/bin', '/sbin', '/usr/sbin']:
                            if bin_path in shell.fs_state:
                                all_commands.update(shell.fs_state[bin_path])
                        matches = [cmd for cmd in all_commands if cmd.startswith(last_part)]

                    # 3. 文件路径补全
                    if not matches:
                        if '/' in last_part:
                            # 支持路径补全，例如 /etc/pa -> /etc/passwd
                            dirname = '/'.join(last_part.split('/')[:-1]) or '/'
                            basename = last_part.split('/')[-1]
                            dirname = shell.normalize_path(dirname)
                        else:
                            dirname = shell.current_path
                            basename = last_part

                        # 查找 fs_state 中 dirname 下以 basename 开头的文件
                        if dirname in shell.fs_state:
                             matches = [f for f in shell.fs_state[dirname] if f.startswith(basename)]

                    if len(matches) == 1:
                        # 唯一匹配：补全剩余部分
                        if is_first_word and '/' not in last_part:
                            # 命令补全
                            completion = matches[0][len(last_part):]
                        else:
                            # 文件补全
                            completion = matches[0][len(basename) if '/' in last_part or not is_first_word else len(last_part):]
                        command_buffer += completion
                        cursor_pos = len(command_buffer)
                        channel.send(completion.encode('utf-8'))
                    elif len(matches) > 1:
                        # 多个匹配：找到公共前缀并补全
                        common = matches[0]
                        for m in matches[1:]:
                            while not m.startswith(common):
                                common = common[:-1]
                        if len(common) > len(last_part if is_first_word else basename):
                            completion = common[len(last_part if is_first_word else basename):]
                            command_buffer += completion
                            cursor_pos = len(command_buffer)
                            channel.send(completion.encode('utf-8'))
                        else:
                            channel.send(b'\x07') # Bell

                elif c.isprintable():
                    # 在光标位置插入字符
                    command_buffer = command_buffer[:cursor_pos] + c + command_buffer[cursor_pos:]
                    cursor_pos += 1
                    # 检查是否回显 (例如密码输入不回显)
                    should_echo = True
                    if hasattr(shell, 'interactive_state') and shell.interactive_state:
                        should_echo = shell.interactive_state.get('echo', True)

                    if should_echo:
                        # 输出插入字符+后续内容，然后回退光标
                        tail = command_buffer[cursor_pos:]
                        if tail:
                            channel.send((c + tail).encode('utf-8') + b'\x1b[' + str(len(tail)).encode() + b'D')
                        else:
                            channel.send(c.encode('utf-8'))
                i += 1
    except Exception as e:
        logger.error(f"会话错误: {e}")
    finally:
        # 确保 finally 缩进与 try/except 对齐
        pass


def _handle_exec(channel, command: str, client_ip: str, username: str, client_port: int = None,
                 term_width: int = 80, term_height: int = 24, session_id: str = None):
    """处理非交互式命令执行 (如 ssh user@host 'ls -la')"""
    shell = VirtualShell(client_ip, username, client_port=client_port, term_width=term_width, term_height=term_height, session_id=session_id)
    logger.info(f"[Exec] {client_ip}: {command}")
    log_event_activity(client_ip, 'SSH-Exec', f"命令: {command}")
    shell._record_login(username, client_ip)
    ts = datetime.now().strftime("%b %d %H:%M:%S")
    _append_auth_log(f"{ts} {HONEYPOT_IDENTITY['hostname']} sshd[{os.getpid()}]: pam_unix(sshd:session): session opened for user {username} by (uid=0)\n")

    output = shell.execute_command(command)

    def _guess_exit_status(text: str) -> int:
        if not text:
            return 0
        lowered = text.lower()
        if "command not found" in lowered:
            return 127
        if "permission denied" in lowered:
            return 1
        if "no such file or directory" in lowered:
            return 1
        if "not found" in lowered and "could not be found" in lowered:
            return 1
        return 0

    if output.startswith('__SHUTDOWN__'):
        parts = output.split('\n', 1)
        msg = parts[1] if len(parts) > 1 else ""
        if msg:
            msg = msg.replace('\n', '\r\n')
            channel.send(msg.encode('utf-8'))
        channel.send_exit_status(0)
        shell._record_logout()
        ts = datetime.now().strftime("%b %d %H:%M:%S")
        _append_auth_log(f"{ts} {HONEYPOT_IDENTITY['hostname']} sshd[{os.getpid()}]: pam_unix(sshd:session): session closed for user {shell.username}\n")
        channel.close()
        return

    if output == '__REBOOT__':
        _set_reboot_marker(client_ip)
        logger.info(f"[Reboot] {client_ip} 触发了 reboot，将模拟 {REBOOT_DELAY_SECONDS} 秒启动延迟")
        channel.send_exit_status(0)
        shell._record_logout()
        ts = datetime.now().strftime("%b %d %H:%M:%S")
        _append_auth_log(f"{ts} {HONEYPOT_IDENTITY['hostname']} sshd[{os.getpid()}]: pam_unix(sshd:session): session closed for user {shell.username}\n")
        channel.close()
        return

    if output == '__POWEROFF__':
        channel.send_exit_status(0)
        shell._record_logout()
        ts = datetime.now().strftime("%b %d %H:%M:%S")
        _append_auth_log(f"{ts} {HONEYPOT_IDENTITY['hostname']} sshd[{os.getpid()}]: pam_unix(sshd:session): session closed for user {shell.username}\n")
        channel.close()
        return

    # exec 模式通常只返回结果，不返回 prompt
    if output:
        # 如果输出不以换行结尾，补一个，避免调用方紧贴同一行
        if not output.endswith('\n'):
            output += '\n'
        # 处理换行，SSH exec 结果通常需要 CRLF
        output = output.replace('\n', '\r\n')
        channel.send(output.encode('utf-8'))

    status = shell.env.get('?', '')
    try:
        status = int(status)
    except Exception:
        status = _guess_exit_status(output)
    channel.send_exit_status(status)
    shell._record_logout()
    ts = datetime.now().strftime("%b %d %H:%M:%S")
    _append_auth_log(f"{ts} {HONEYPOT_IDENTITY['hostname']} sshd[{os.getpid()}]: pam_unix(sshd:session): session closed for user {shell.username}\n")
    channel.close()

def _scp_mode_to_perm(mode_token: str, is_dir: bool = False) -> str:
    token = str(mode_token or '').strip()
    if not token:
        return "drwxr-xr-x" if is_dir else "-rw-r--r--"
    mode_text = token[1:] if token and token[0] in ('C', 'D') else token
    mode_text = ''.join(ch for ch in mode_text if ch in '01234567')
    try:
        mode_value = int(mode_text[-4:] if len(mode_text) >= 4 else mode_text or '755', 8)
    except Exception:
        mode_value = 0o755 if is_dir else 0o644
    head = 'd' if is_dir else '-'
    perm_chars = []
    for shift in (6, 3, 0):
        bits = (mode_value >> shift) & 0o7
        perm_chars.append('r' if bits & 0o4 else '-')
        perm_chars.append('w' if bits & 0o2 else '-')
        perm_chars.append('x' if bits & 0o1 else '-')
    return head + ''.join(perm_chars)


def _scp_ensure_virtual_dir(shell, dir_path: str, owner: str) -> None:
    normalized = shell.normalize_path(dir_path)
    if normalized in shell.fs_state:
        shell.file_owners.setdefault(normalized, (owner, owner))
        shell.file_perms.setdefault(normalized, "drwxr-xr-x")
        shell.file_timestamps.setdefault(normalized, datetime.now())
        shell.file_sizes.setdefault(normalized, 4096)
        return

    parent_dir = os.path.dirname(normalized) or '/'
    if parent_dir and parent_dir != normalized:
        _scp_ensure_virtual_dir(shell, parent_dir, owner)

    shell.fs_state.setdefault(normalized, [])
    shell.fs_state.setdefault(parent_dir, [])
    entry_name = os.path.basename(normalized)
    if entry_name and entry_name not in shell.fs_state[parent_dir]:
        shell.fs_state[parent_dir].append(entry_name)
    shell.file_owners[normalized] = (owner, owner)
    shell.file_perms[normalized] = "drwxr-xr-x"
    shell.file_timestamps[normalized] = datetime.now()
    shell.file_sizes[normalized] = 4096


def _handle_scp(channel, command: str, client_ip: str, username: str, client_port: int = None, session_id: str = None):
    """处理 SCP 上传请求（sink 模式），用于采集文件样本。"""
    logger.info(f"[SCP] {client_ip} 尝试上传: {command}")
    log_event_activity(client_ip, 'SCP-Upload', f"尝试上传: {command}")
    event_session_id = str(session_id or _build_ssh_event_session_id(client_ip, username, client_port)).strip()

    # SCP 接收协议（简化实现：仅接收，不做完整校验）
    # 1. 发送 ACK0 确认连接
    channel.send(b'\x00')

    try:
        shell = VirtualShell(client_ip, username, client_port=client_port, session_id=event_session_id)
        base_dir = shell.normalize_path(shell.env['HOME'])
        _scp_ensure_virtual_dir(shell, base_dir, username)
        current_dir_stack = []

        while True:
            metadata = b''
            while True:
                char = channel.recv(1)
                if not char:
                    metadata = b''
                    break
                if char == b'\n':
                    break
                metadata += char

            metadata_str = metadata.decode('utf-8', errors='ignore').strip()
            if not metadata_str:
                break
            logger.info(f"[SCP] 元数据: {metadata_str}")

            parts = metadata_str.split(maxsplit=2)
            if not parts:
                break

            token = parts[0]
            current_base_dir = shell.normalize_path('/'.join([base_dir] + current_dir_stack))

            if token.startswith('C') and len(parts) >= 3:
                file_mode = token
                file_size = int(parts[1])
                file_name = parts[2]

                if file_size > 10 * 1024 * 1024:
                    logger.warning(f"[拒绝] SCP文件过大 ({file_size} bytes) - {client_ip}")
                    channel.send(b'\x01File too large (max 10MB)\n')
                    try:
                        log_event(
                            source='ssh',
                            severity='medium',
                            event_type='scp_upload_rejected',
                            src_ip=client_ip,
                            session_id=event_session_id,
                            tags=['ssh', 'scp', 'upload_rejected', 'oversize'],
                            payload=f"SCP 上传被拒绝: {file_name} ({file_size} bytes)",
                            extra={'reason': 'file_too_large', 'size': int(file_size)},
                        )
                    except Exception:
                        logger.debug("scp oversize event log failed", exc_info=True)
                    exit_status = 1
                    return

                channel.send(b'\x00')

                content = bytearray()
                preview = bytearray()
                max_store = 1024 * 1024
                received = 0
                while received < file_size:
                    chunk = channel.recv(min(4096, file_size - received))
                    if not chunk:
                        break
                    if len(preview) < 2000:
                        need = 2000 - len(preview)
                        preview.extend(chunk[:need])
                    if len(content) < max_store:
                        need_store = max_store - len(content)
                        content.extend(chunk[:need_store])
                    received += len(chunk)

                try:
                    trailing = channel.recv(1)
                    if trailing not in (b'', b'\x00'):
                        logger.debug(f"[SCP] unexpected trailing byte: {trailing!r}")
                except Exception:
                    pass

                logger.critical(f"[捕获] SCP文件 {file_name} ({file_size} bytes)")
                content_preview = preview.decode('utf-8', errors='ignore')
                if file_size > len(preview):
                    content_preview += f"\n...[truncated {max(0, file_size - len(preview))} bytes]"
                log_event_activity(client_ip, 'SCP-Capture', f"文件名: {file_name}\n内容预览:\n{content_preview}")
                try:
                    alert_scp_capture(client_ip, file_name, file_size)
                except Exception:
                    pass
                try:
                    log_event(
                        source='ssh',
                        severity='medium',
                        event_type='scp_upload',
                        src_ip=client_ip,
                        session_id=event_session_id,
                        tags=['ssh', 'scp', 'file_upload'],
                        payload=f"SCP 上传文件: {file_name} ({file_size} bytes)",
                        extra={
                            'file_name': file_name,
                            'size': int(file_size),
                            'mode': file_mode,
                        },
                    )
                except Exception:
                    logger.debug("scp upload event log failed", exc_info=True)

                _scp_ensure_virtual_dir(shell, current_base_dir, username)
                target_path = f"{current_base_dir.rstrip('/')}/{file_name}"
                normalized_path = shell.normalize_path(target_path)
                p_dir = os.path.dirname(normalized_path) or '/'
                f_name = os.path.basename(normalized_path)
                shell.fs_state.setdefault(p_dir, [])
                if f_name not in shell.fs_state[p_dir]:
                    shell.fs_state[p_dir].append(f_name)

                stored_text = content.decode('utf-8', errors='ignore')
                if file_size > len(content):
                    stored_text += f"\n...[truncated {file_size - len(content)} bytes]"
                shell.files_content[normalized_path] = stored_text
                shell.file_timestamps[normalized_path] = datetime.now()
                shell.file_sizes[normalized_path] = file_size
                shell.file_owners[normalized_path] = (username, username)
                shell.file_perms[normalized_path] = _scp_mode_to_perm(file_mode, is_dir=False)
                shell._save_session_state()
                channel.send(b'\x00')
                continue

            if token.startswith('D') and len(parts) >= 3:
                dir_mode = token
                dir_name = parts[2]
                logger.info(f"[SCP] Start Directory: {dir_name}")
                current_dir_stack.append(dir_name)
                dir_path = shell.normalize_path('/'.join([base_dir] + current_dir_stack))
                _scp_ensure_virtual_dir(shell, dir_path, username)
                shell.file_perms[dir_path] = _scp_mode_to_perm(dir_mode, is_dir=True)
                shell.file_timestamps[dir_path] = datetime.now()
                shell.file_sizes[dir_path] = 4096
                shell._save_session_state()
                channel.send(b'\x00')
                continue

            if token == 'E':
                logger.info("[SCP] End Directory")
                if current_dir_stack:
                    current_dir_stack.pop()
                channel.send(b'\x00')
                continue

            if token.startswith('T'):
                channel.send(b'\x00')
                continue

            logger.debug(f"[SCP] unsupported metadata: {metadata_str}")
            break

    except Exception as e:
        logger.error(f"SCP处理错误: {e}")
        exit_status = 1

    finally:
        channel.send_exit_status(exit_status)
        channel.close()

def handle_client(client_socket: socket.socket, client_addr: tuple, host_key):
    client_ip = client_addr[0]
    client_port = client_addr[1] if len(client_addr) > 1 else None
    conn_acquired = False

    # 模拟重启延迟
    reboot_time = _get_reboot_marker(client_ip)
    if reboot_time > 0:
        elapsed = time.time() - reboot_time
        if elapsed < REBOOT_DELAY_SECONDS:
            logger.info(f"[重启中] 拒绝 {client_ip} 连接 (系统正在重启)")
            try:
                client_socket.close()
            except Exception as e:
                logger.debug(f"client_socket close failed: {e}")
            try:
                SSH_WORKER_SEM.release()
            except Exception:
                pass
            return
        else:
            # 重启完成
            _clear_reboot_marker(client_ip, reboot_time)

    # 预认证阶段连接频率检测：用于识别高频端口扫描
    try:
        scan_info = record_preauth_connection(client_ip)
        if scan_info:
            cnt = int(scan_info.get('count') or 0)
            win = int(scan_info.get('window_seconds') or 0)
            th = int(scan_info.get('threshold') or 0)
            severity = 'high' if cnt >= max(th * 2, th + 10) else 'medium'
            log_event(
                source='ssh',
                severity=severity,
                event_type='ssh_port_scan_probe',
                src_ip=client_ip,
                session_id='',
                tags=['ssh', 'scan', 'port_probe'],
                payload=f"SSH预认证高频连接: {cnt}/{win}s (阈值{th})",
                extra={
                    'count': cnt,
                    'window_seconds': win,
                    'threshold': th,
                    'client_port': int(client_port) if client_port else 0,
                },
            )
            logger.warning(f"[扫描] SSH高频探测 {client_ip} {cnt}/{win}s (阈值{th})")
    except Exception:
        logger.debug("record preauth scan failed", exc_info=True)

    if not rate_limit_check(client_ip):
        try:
            # 连接受限（并发超限或防爆破封禁）时仍返回常见协议头，保持“像真机”
            remain = get_ban_remaining(client_ip)
            client_socket.send(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n")
            if remain > 0:
                logger.warning(f"[防爆破] 拒绝封禁IP连接 {client_ip} (剩余{remain}s)")
            client_socket.close()
        except Exception as e:
            logger.debug(f"preauth drop failed: {e}")
        try:
            SSH_WORKER_SEM.release()
        except Exception:
            pass
        return
    conn_acquired = True

    transport = None
    try:
        transport = paramiko.Transport(client_socket)
        transport.add_server_key(host_key)
        transport.local_version = "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5"
        server = HoneypotSSHServer(client_ip, client_port=client_port)
        server.bind_transport(transport)
        try:
            transport.start_server(server=server)
        except paramiko.SSHException as e:
            logger.warning(f"[失败] SSH协商 {client_ip}")
            return
        accept_timeout = float(CONNECTION_TIMEOUT)
        while transport.is_active():
            channel = transport.accept(accept_timeout)
            if channel is None:
                if not transport.is_active():
                    break
                accept_timeout = 1.0
                continue

            accept_timeout = 1.0
            request = server.wait_for_channel_request(channel, AUTH_TIMEOUT)
            if not request:
                try:
                    channel.send_exit_status(1)
                except Exception:
                    pass
                try:
                    channel.close()
                except Exception:
                    pass
                continue

            req_kind = str(request.get('kind') or '').strip().lower()
            command = str(request.get('command') or '')

            if req_kind == 'exec':
                # 检查是否是 SCP 请求
                if command.startswith('scp -t'):
                     # 允许上传（接收模式）：用于捕获工具/脚本
                     _handle_scp(channel, command, client_ip, server.username or 'root', client_port=client_port, session_id=getattr(server, 'auth_session_id', ''))
                elif command.startswith('scp -f'):
                     # 禁止下载（源端模式）：防止敏感虚拟文件（如 shadow）外泄
                     logger.warning(f"[阻止] 拒绝 SCP 下载请求 {client_ip}: {command}")
                     # SCP 协议错误: \x01 + 消息 + \n
                     channel.send(b'\x01SCP download prohibited by security policy.\n')
                     channel.send_exit_status(1)
                     channel.close()
                else:
                     _handle_exec(
                         channel,
                         command,
                         client_ip,
                         server.username or 'root',
                         client_port=client_port,
                         term_width=getattr(server, 'pty_width', 80),
                         term_height=getattr(server, 'pty_height', 24),
                         session_id=getattr(server, 'auth_session_id', ''),
                     )
                continue

            if req_kind == 'shell':
                # 交互式 Shell
                handle_ssh_session(
                    channel,
                    client_ip,
                    server.username or 'root',
                    client_port=client_port,
                    term_width=getattr(server, 'pty_width', 80),
                    term_height=getattr(server, 'pty_height', 24),
                    session_id=getattr(server, 'auth_session_id', ''),
                )
                continue

            try:
                channel.send_exit_status(1)
            except Exception:
                pass
            try:
                channel.close()
            except Exception:
                pass
    except Exception as e:
        logger.error(f"客户端处理错误: {e}")
    finally:
        # 始终释放连接计数，避免连接槽位泄漏
        if conn_acquired:
            release_connection(client_ip)
        try:
            SSH_WORKER_SEM.release()
        except Exception:
            pass

        if transport:
            try:
                transport.close()
            except Exception as e:
                logger.debug(f"transport close failed: {e}")
        try:
            client_socket.close()
        except Exception as e:
            logger.debug(f"client_socket close failed: {e}")

def start_ssh_server(host='0.0.0.0', port=2222):
    """启动 SSH 蜜罐服务器"""
    # 在启动监听前加载或生成主机密钥
    host_key = generate_host_key()

    # 初始化蜜罐身份信息
    init_honeypot_identity(VIRTUAL_FILES)

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(100)
    try:
        while True:
            try:
                client_socket, client_addr = server_socket.accept()

                # 使用独立信号量限制并发 worker
                if not SSH_WORKER_SEM.acquire(blocking=False):
                    logger.warning(f"[拒绝] SSH worker 过载 (max={MAX_SSH_WORKERS}) - {client_addr[0]}")
                    client_socket.close()
                    continue

                try:
                    client_thread = threading.Thread(
                        target=handle_client,
                        args=(client_socket, client_addr, host_key),
                        daemon=True
                    )
                    client_thread.start()
                except Exception:
                    try:
                        SSH_WORKER_SEM.release()
                    except Exception:
                        pass
                    client_socket.close()
                    raise
            except KeyboardInterrupt:
                logger.info("正在关闭...")
                break
            except Exception as e:
                logger.error(f"Accept错误: {e}")
    finally:
        server_socket.close()
        logger.info("SSH服务已停止")

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='SSH 蜜罐服务器')
    parser.add_argument('-H', '--host', default=_env_str('SSH_HOST', '0.0.0.0'), help='监听地址')
    parser.add_argument('-p', '--port', type=int, default=_env_int('SSH_PORT', 2222, 1, 65535), help='监听端口')
    args = parser.parse_args()
    start_ssh_server(args.host, args.port)




