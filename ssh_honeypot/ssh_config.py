# -*- coding: utf-8 -*-
"""
SSH 蜜罐配置与身份信息
"""
import os
import ipaddress
import random
import hashlib
import secrets
import threading
from datetime import datetime, timedelta

from env_utils import env_bool as _env_bool, env_int as _env_int, env_str as _env_str
from utils.logger import get_ssh_logger

logger = get_ssh_logger()


def _private_host_ip(base_ip: str, host_octet: int, fallback: str) -> str:
    try:
        ip_text = str(ipaddress.ip_address(str(base_ip or '').strip()))
        parts = ip_text.split('.')
        if len(parts) == 4:
            parts[-1] = str(max(1, min(int(host_octet), 254)))
            return '.'.join(parts)
    except Exception:
        pass
    return fallback

# === 会话与状态 ===

# 兼容旧模块导出；不再使用 IP/用户名共享虚拟状态。
PERSISTENT_SESSIONS = {}
PERSISTENT_SESSIONS_LOCK = threading.RLock()

# 记录执行 reboot 的来源地址与时间，用于模拟启动延迟
REBOOT_IPS = {}  # {ip: reboot_timestamp}
REBOOT_IPS_LOCK = threading.RLock()
REBOOT_DELAY_SECONDS = 15  # 模拟服务器启动需要的时间

# === 蜜罐身份配置：统一服务器特征 ===
HONEYPOT_IDENTITY = {
    'hostname': 'ubuntu-server',           # 主机名
    'server_ip': _env_str('SSH_INTERNAL_IP', '10.0.12.10') or '10.0.12.10',  # 服务器机内视角 IP
    'boot_time': None,                     # 系统启动时间（动态生成）
    'last_login_ip': None,                 # 上次登录 IP（动态生成）
}

# 内核版本常量（单一数据源）
KERNEL_RELEASE = "6.8.0-57-generic"
KERNEL_VERSION_STRING = "#59-Ubuntu SMP PREEMPT_DYNAMIC Wed Mar 19 18:26:39 UTC 2025"


def init_honeypot_identity(virtual_files):
    """初始化蜜罐身份信息"""
    now = datetime.now()
    server_ip = HONEYPOT_IDENTITY['server_ip']
    hostname = HONEYPOT_IDENTITY['hostname']
    db_ip = _private_host_ip(server_ip, 50, '10.0.12.50')
    backup_ip = _private_host_ip(server_ip, 51, '10.0.12.51')
    vpn_ip = _private_host_ip(server_ip, 1, '10.0.12.1')
    # 系统启动时间：过去 3-30 天内随机
    boot_days_ago = random.randint(3, 30)
    boot_hours_ago = random.randint(0, 23)
    HONEYPOT_IDENTITY['boot_time'] = now - timedelta(days=boot_days_ago, hours=boot_hours_ago)
    # 上次登录地址：保持同一内网网段，减少系统口径冲突
    HONEYPOT_IDENTITY['last_login_ip'] = _private_host_ip(server_ip, random.randint(20, 240), '10.0.12.23')

    # 动态更新 /etc/hosts 中的服务器地址
    virtual_files['/etc/hosts'] = f'''127.0.0.1   localhost
127.0.1.1   {hostname}
{server_ip}   {hostname}
{db_ip}    db-server
{backup_ip}    backup-server
{vpn_ip}       vpn-gateway'''

    logger.info(f"[蜜罐身份] 主机名: {hostname}, IP: {server_ip}, 启动时间: {HONEYPOT_IDENTITY['boot_time']}")


# SSH 弱口令池（与 Web 端风格一致）
_WEAK_PASSWORD_POOL = [
    '123456', '12345678', 'password', '111111', 'qwerty',
    'admin123', 'admin888', 'Admin@123', 'System123',
    'Aa123456', 'root123', 'toor', 'linux', 'ubuntu'
]

# 允许登录的 SSH 用户及其密码（启动时动态生成）
SSH_CREDENTIALS = {}
_SHOW_CREDENTIAL_LOGS = _env_bool('SHOW_CREDENTIAL_LOGS', False)
_EMIT_CREDENTIAL_LINES = _env_bool('EMIT_CREDENTIAL_LINES', False)


def _shadow_password_hash(password: str, salt: str = None) -> str:
    salt_text = str(salt or secrets.token_hex(8))
    digest = hashlib.sha512((salt_text + str(password or '')).encode('utf-8', errors='ignore')).hexdigest()
    return f"$6${salt_text}${digest}"


def _sync_virtual_login_accounts() -> None:
    try:
        from ssh_honeypot import vfs as _vfs
    except Exception:
        return

    passwd_content = str(_vfs.VIRTUAL_FILES.get('/etc/passwd', '') or '')
    shadow_content = str(_vfs.VIRTUAL_FILES.get('/etc/shadow', '') or '')

    login_profiles = {
        'root': ('root', '/root', '/bin/bash'),
        'ubuntu': ('1000', '/home/ubuntu', '/bin/bash'),
        'backup': ('34', '/home/backup', '/bin/bash'),
    }

    passwd_lines = passwd_content.splitlines()
    shadow_lines = shadow_content.splitlines()

    def _set_or_append(lines: list, username: str, builder):
        replaced = False
        new_lines = []
        for line in lines:
            if line.startswith(f"{username}:"):
                new_lines.append(builder(line))
                replaced = True
            else:
                new_lines.append(line)
        if not replaced:
            new_lines.append(builder(''))
        return new_lines

    for username, password in SSH_CREDENTIALS.items():
        gid, home_dir, shell_path = login_profiles.get(username, ('1000', f"/home/{username}", '/bin/bash'))

        def _passwd_builder(existing: str) -> str:
            parts = existing.split(':') if existing else []
            if len(parts) >= 7:
                parts[5] = home_dir
                parts[6] = shell_path
                return ':'.join(parts)
            return f"{username}:x:{gid}:{gid}:{username}:{home_dir}:{shell_path}"

        def _shadow_builder(existing: str) -> str:
            parts = existing.split(':') if existing else []
            salt = None
            if len(parts) > 1:
                hash_parts = str(parts[1] or '').split('$')
                if len(hash_parts) >= 4 and hash_parts[1] == '6':
                    salt = hash_parts[2]
            hashed = _shadow_password_hash(password, salt=salt)
            if len(parts) >= 9:
                parts[1] = hashed
                return ':'.join(parts)
            return f"{username}:{hashed}:20483:0:99999:7:::"

        passwd_lines = _set_or_append(passwd_lines, username, _passwd_builder)
        shadow_lines = _set_or_append(shadow_lines, username, _shadow_builder)

        if home_dir.startswith('/home/'):
            home_parent = '/home'
            home_name = os.path.basename(home_dir)
            for fs_map in (_vfs.VIRTUAL_FS, _vfs.GLOBAL_FS_STATE):
                fs_map.setdefault(home_parent, [])
                if home_name not in fs_map[home_parent]:
                    fs_map[home_parent].append(home_name)
                fs_map.setdefault(home_dir, [])

    normalized_passwd = '\n'.join(passwd_lines) + '\n'
    normalized_shadow = '\n'.join(shadow_lines) + '\n'
    _vfs.VIRTUAL_FILES['/etc/passwd'] = normalized_passwd
    _vfs.GLOBAL_FILES_CONTENT['/etc/passwd'] = normalized_passwd
    _vfs.VIRTUAL_FILES['/etc/shadow'] = normalized_shadow
    _vfs.GLOBAL_FILES_CONTENT['/etc/shadow'] = normalized_shadow


def init_ssh_credentials():
    """初始化 SSH 凭证：随机分配，拒绝全通"""
    target_users = ['root', 'ubuntu', 'backup']

    # 打乱密码池
    pool = list(_WEAK_PASSWORD_POOL)
    random.shuffle(pool)

    SSH_CREDENTIALS.clear()

    if _SHOW_CREDENTIAL_LOGS:
        logger.info("========= SSH 凭证初始化 =========")
    for i, user in enumerate(target_users):
        # 循环分配密码
        pwd = pool[i % len(pool)]
        SSH_CREDENTIALS[user] = pwd
        if _SHOW_CREDENTIAL_LOGS:
            logger.info(f"用户: {user:<10} | 密码: {pwd}")
        # 仅在主控进程明确要求时输出明文凭证行
        if _EMIT_CREDENTIAL_LINES:
            print(f"CRED::{user}::{pwd}", flush=True)
    if _SHOW_CREDENTIAL_LOGS:
        logger.info("==================================")
    _sync_virtual_login_accounts()


# 在模块加载时直接初始化
init_ssh_credentials()

# 全局 DNS 缓存（仅保留本地回环）
# 公网域名统一走实时解析，不做硬编码
DNS_CACHE = {
    'localhost': '127.0.0.1',
    '127.0.0.1': '127.0.0.1',
}

# 记录服务启动时间，用于计算 uptime
SERVER_START_TIME = datetime.now()

# === 连接限制与速率控制 ===
MAX_CONCURRENT_CONNECTIONS = _env_int('SSH_MAX_CONCURRENT_CONNECTIONS', 50, 1, 10000)
MAX_CONNECTIONS_PER_IP = _env_int('SSH_MAX_CONNECTIONS_PER_IP', 5, 1, 1000)
CONNECTION_TIMEOUT = _env_int('SSH_CONNECTION_TIMEOUT', 30, 1, 3600)
AUTH_TIMEOUT = _env_int('SSH_AUTH_TIMEOUT', 10, 1, 3600)

