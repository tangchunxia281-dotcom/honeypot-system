# -*- coding: utf-8 -*-
"""
SSH 蜜罐 - 命令解析与调度
"""
import fnmatch
import hashlib
import os
import random
import re
import time
from datetime import datetime, timedelta

from db import log_event_activity, log_event
from ssh_honeypot.vfs import VIRTUAL_FILES
from ssh_honeypot.ssh_config import (
    HONEYPOT_IDENTITY,
    KERNEL_RELEASE,
    KERNEL_VERSION_STRING,
    SERVER_START_TIME,
    SSH_CREDENTIALS,
)
from utils.logger import get_ssh_logger
from utils.alerting import alert_event

logger = get_ssh_logger()

_ANSI_ESCAPE_RE = re.compile(r'\x1b\[[0-9;]*m')
_LS_ARCHIVE_EXTS = {
    '.7z', '.apk', '.arj', '.bz2', '.cab', '.cpio', '.deb', '.gz', '.iso',
    '.jar', '.lz', '.lz4', '.lzma', '.rar', '.rpm', '.tar', '.tbz', '.tbz2',
    '.tgz', '.txz', '.xz', '.zip', '.zst',
}
_LS_MEDIA_EXTS = {
    '.bmp', '.gif', '.jpeg', '.jpg', '.m4a', '.m4v', '.mkv', '.mov', '.mp3',
    '.mp4', '.ogg', '.png', '.svg', '.tif', '.tiff', '.wav', '.webm', '.webp',
}


def _arg_has_short_option(args: list, option: str) -> bool:
    needle = str(option or '').strip()
    if not needle.startswith('-') or len(needle) != 2:
        return False
    flag = needle[1]
    for arg in args or []:
        text = str(arg or '').strip()
        if text == needle:
            return True
        if text.startswith('-') and not text.startswith('--') and len(text) > 2 and flag in text[1:]:
            return True
    return False


def _ls_color_mode(args: list) -> str:
    for arg in args or []:
        text = str(arg or '').strip().lower()
        if text == '--color':
            return 'always'
        if text.startswith('--color='):
            mode = text.split('=', 1)[1].strip()
            if mode in ('always', 'yes', 'force'):
                return 'always'
            if mode in ('never', 'no', 'none'):
                return 'never'
            return 'auto'
    return 'auto'


def _ls_should_color(shell, args: list) -> bool:
    mode = _ls_color_mode(args)
    if mode == 'never':
        return False
    if mode == 'always':
        return True
    term = str(getattr(shell, 'env', {}).get('TERM', '') or '').strip().lower()
    return bool(term and term != 'dumb')


def _strip_ansi(text: str) -> str:
    return _ANSI_ESCAPE_RE.sub('', str(text or ''))


def _ansi_ljust(text: str, width: int) -> str:
    value = str(text or '')
    visible_len = len(_strip_ansi(value))
    if visible_len >= width:
        return value
    return value + (' ' * (width - visible_len))


def _ls_entry_suffix(perm: str, is_dir: bool) -> str:
    perm_text = str(perm or '')
    if is_dir or perm_text.startswith('d'):
        return '/'
    if perm_text.startswith('l'):
        return '@'
    if perm_text.startswith('p'):
        return '|'
    if perm_text.startswith('s'):
        return '='
    if 'x' in perm_text[1:]:
        return '*'
    return ''


def _ls_entry_color_code(display_name: str, perm: str, is_dir: bool) -> str:
    perm_text = str(perm or '')
    lower_name = str(display_name or '').strip().lower()
    _, ext = os.path.splitext(lower_name)
    if is_dir or perm_text.startswith('d'):
        return '01;34'
    if perm_text.startswith('l'):
        return '01;36'
    if perm_text.startswith(('c', 'b')):
        return '01;33'
    if perm_text.startswith('p'):
        return '33'
    if perm_text.startswith('s'):
        return '01;35'
    if 'x' in perm_text[1:]:
        return '01;32'
    if ext in _LS_ARCHIVE_EXTS:
        return '01;31'
    if ext in _LS_MEDIA_EXTS:
        return '01;35'
    return ''


def _ls_render_name(display_name: str, perm: str, is_dir: bool, color_enabled: bool = False, classify: bool = False) -> str:
    name = str(display_name or '')
    if classify:
        name += _ls_entry_suffix(perm, is_dir)
    color_code = _ls_entry_color_code(display_name, perm, is_dir) if color_enabled else ''
    if color_code:
        return f"\x1b[{color_code}m{name}\x1b[0m"
    return name


def _shell_tty_label(shell) -> str:
    try:
        tty = str(shell._tty_label()).strip() if hasattr(shell, '_tty_label') else ''
    except Exception:
        tty = ''
    if tty:
        return tty
    try:
        raw = str(getattr(shell, 'tty_name', '') or getattr(shell, 'env', {}).get('SSH_TTY') or '').strip()
    except Exception:
        raw = ''
    raw = raw.replace('\\', '/')
    if '/dev/' in raw:
        raw = raw.split('/dev/', 1)[1]
    return raw.lstrip('/') or '?'


_PATH_EXECUTABLE_DIRS = {
    '/bin',
    '/sbin',
    '/usr/bin',
    '/usr/sbin',
    '/usr/local/bin',
    '/usr/local/sbin',
}

_SHELL_BUILTINS = {
    '.', ':', '[', '[[', ']]', 'alias', 'bg', 'break', 'cd', 'command',
    'continue', 'declare', 'echo', 'exec', 'exit', 'export', 'false', 'fg',
    'hash', 'help', 'history', 'jobs', 'kill', 'logout', 'printf', 'pwd',
    'readonly', 'return', 'set', 'source', 'test', 'times', 'trap', 'true',
    'type', 'typeset', 'umask', 'unalias', 'unset', 'wait',
}

_SHELL_KEYWORDS = {
    'case', 'coproc', 'do', 'done', 'elif', 'else', 'esac', 'fi', 'for',
    'function', 'if', 'in', 'select', 'then', 'time', 'until', 'while',
}

_COMMAND_ALIASES = {
    'apt-get': 'apt_get',
}


def _virtual_path_exists(shell, path: str):
    norm = shell.normalize_path(path)
    if norm in shell.fs_state:
        return norm, True
    if norm in shell.files_content or norm in VIRTUAL_FILES:
        return norm, False
    parent = os.path.dirname(norm)
    name = os.path.basename(norm)
    if parent in shell.fs_state and name in shell.fs_state[parent]:
        return norm, False
    return None, False


def _default_virtual_perm(path: str, is_dir: bool = False) -> str:
    if is_dir:
        return "drwxr-xr-x"
    parent = os.path.dirname(path)
    if parent in _PATH_EXECUTABLE_DIRS:
        return "-rwxr-xr-x"
    return "-rw-r--r--"


def _is_virtual_executable_path(path: str) -> bool:
    norm = str(path or '').replace('\\', '/')
    return os.path.dirname(norm) in _PATH_EXECUTABLE_DIRS and os.path.basename(norm) not in ('', '.', '..')


def _synthetic_binary_stub(path: str) -> str:
    digest = hashlib.sha256(str(path or '').encode('utf-8', errors='ignore')).digest()
    payload = ''.join(chr(33 + (b % 94)) for b in digest[:48])
    return "\x7fELF\x02\x01\x01\x00" + payload + "\n"


def _read_virtual_file(shell, path: str, binary_stub: bool = False):
    norm = shell.normalize_path(path)
    if norm in shell.fs_state:
        return False, "", False
    if norm in shell.files_content:
        content = shell.files_content[norm]
        if content == "" and binary_stub and _is_virtual_executable_path(norm):
            return True, _synthetic_binary_stub(norm), True
        return True, content, False
    if norm in VIRTUAL_FILES:
        return True, VIRTUAL_FILES[norm], False
    if binary_stub:
        exists_path, is_dir = _virtual_path_exists(shell, norm)
        if exists_path and not is_dir and _is_virtual_executable_path(norm):
            return True, _synthetic_binary_stub(norm), True
    return False, "", False


def _find_command_in_path(shell, name: str):
    target = str(name or '').strip()
    if not target:
        return None
    if '/' in target:
        norm, is_dir = _virtual_path_exists(shell, target)
        return norm if norm and not is_dir else None
    candidates = [target]
    alias_target = _COMMAND_ALIASES.get(target)
    if alias_target and alias_target not in candidates:
        candidates.append(alias_target)
    for base in [p for p in str(shell.env.get('PATH', '')).split(':') if p]:
        for candidate_name in candidates:
            candidate = shell.normalize_path(f"{base.rstrip('/')}/{candidate_name}")
            norm, is_dir = _virtual_path_exists(shell, candidate)
            if norm and not is_dir:
                if candidate_name != target:
                    return shell.normalize_path(f"{base.rstrip('/')}/{target}")
                return norm
    return None


def _current_login_entry(shell):
    if not isinstance(getattr(shell, 'login_history', None), list):
        return None
    for entry in shell.login_history:
        if isinstance(entry, dict):
            return entry
    return None


def _login_entry_started_at(shell, entry=None):
    login_entry = entry if isinstance(entry, dict) else _current_login_entry(shell)
    login_at = login_entry.get('login_at') if isinstance(login_entry, dict) else None
    if isinstance(login_at, datetime):
        return login_at
    return datetime.now()


def _login_entry_tty(shell, entry=None, index: int = 0) -> str:
    if isinstance(entry, dict):
        tty = str(entry.get('tty') or '').strip()
        if tty:
            return tty
    if index == 0:
        return _shell_tty_label(shell)
    return f"pts/{index}"


def _format_last_login_stamp(dt: datetime) -> str:
    return f"{dt:%a} {dt:%b} {dt.day:2d} {dt:%H:%M}"


def _format_last_wtmp_stamp(dt: datetime) -> str:
    return f"{dt:%a} {dt:%b} {dt.day:2d} {dt:%H:%M:%S} {dt:%Y}"


def _format_last_duration(start_at: datetime, end_at: datetime) -> str:
    if not isinstance(start_at, datetime) or not isinstance(end_at, datetime) or end_at < start_at:
        return "(00:00)"
    total_minutes = max(0, int((end_at - start_at).total_seconds() // 60))
    hours, minutes = divmod(total_minutes, 60)
    return f"({hours:02d}:{minutes:02d})"


def _command_v_line(shell, name: str) -> str:
    if name in _SHELL_KEYWORDS:
        return name
    if name in _SHELL_BUILTINS:
        return name
    resolved = _find_command_in_path(shell, name)
    return resolved or ""


_SERVICE_ALIASES = {
    "ssh": "ssh",
    "sshd": "ssh",
    "ssh.service": "ssh",
    "cron": "cron",
    "cron.service": "cron",
    "rsyslog": "rsyslog",
    "rsyslog.service": "rsyslog",
    "systemd-journald": "systemd-journald",
    "systemd-journald.service": "systemd-journald",
    "systemd-resolved": "systemd-resolved",
    "systemd-resolved.service": "systemd-resolved",
    "systemd-timesyncd": "systemd-timesyncd",
    "systemd-timesyncd.service": "systemd-timesyncd",
    "systemd-networkd": "systemd-networkd",
    "systemd-networkd.service": "systemd-networkd",
    "networking": "systemd-networkd",
    "networking.service": "systemd-networkd",
    "dbus": "dbus",
    "dbus.service": "dbus",
    "ufw": "ufw",
    "ufw.service": "ufw",
    "apparmor": "apparmor",
    "apparmor.service": "apparmor",
    "systemd-logind": "systemd-logind",
    "systemd-logind.service": "systemd-logind",
    # 虚拟业务主机（与 utils/decoy_profiles.py 的人设保持一致）
    "nginx": "nginx",
    "nginx.service": "nginx",
    "postgresql": "postgresql",
    "postgresql.service": "postgresql",
    "postgres": "postgresql",
    "redis": "redis",
    "redis-server": "redis",
    "redis.service": "redis",
    "erp-api": "erp-api",
    "erp-api.service": "erp-api",
    "support-api": "support-api",
    "support-api.service": "support-api",
    "backup-worker": "backup-worker",
    "backup-worker.service": "backup-worker",
}

_SERVICE_DESCRIPTIONS = {
    "ssh": "OpenBSD Secure Shell server",
    "cron": "Regular background program processing daemon",
    "rsyslog": "System Logging Service",
    "systemd-journald": "Journal Service",
    "systemd-resolved": "Network Name Resolution",
    "systemd-timesyncd": "Network Time Synchronization",
    "systemd-networkd": "Network Service",
    "dbus": "D-Bus System Message Bus",
    "ufw": "Uncomplicated firewall",
    "apparmor": "Load AppArmor profiles",
    "systemd-logind": "User Login Management",
    "nginx": "A high performance web server and a reverse proxy server",
    "postgresql": "PostgreSQL RDBMS",
    "redis": "Advanced key-value store",
    "erp-api": "ERP business API service",
    "support-api": "Support portal API service",
    "backup-worker": "Scheduled backup worker",
}

_SERVICE_PROCESS_HINTS = {
    "ssh": ["sshd -D", "sshd"],
    "cron": ["cron -f", "cron"],
    "rsyslog": ["rsyslogd"],
    "systemd-journald": ["systemd-journald"],
    "systemd-resolved": ["systemd-resolved"],
    "systemd-timesyncd": ["systemd-timesyncd"],
    "systemd-networkd": ["systemd-networkd"],
    "dbus": ["dbus-daemon", "dbus"],
    "ufw": ["ufw"],
    "apparmor": ["apparmor"],
    "systemd-logind": ["systemd-logind"],
    "nginx": ["nginx"],
    "postgresql": ["postgres"],
    "redis": ["redis-server"],
    "erp-api": ["erp-api"],
    "support-api": ["support-api"],
    "backup-worker": ["backup-worker"],
}

def _normalize_cmd_for_dedup(cmd: str) -> str:
    text = ' '.join(str(cmd or '').strip().split())
    return text[:600]


def _short_cmd(cmd: str, max_len: int = 320) -> str:
    text = str(cmd or '').strip()
    if len(text) <= max_len:
        return text
    digest = hashlib.sha1(text.encode('utf-8', errors='ignore')).hexdigest()[:8]
    return f"{text[:max_len]}... [len={len(text)}, sha1={digest}]"


def _build_command_meta(cmd: str, max_len: int = 3000) -> dict:
    """
    为事件 extra 构造命令元信息：
    - raw_command: 尽量保留完整命令（超长时安全截断）
    - command_len/command_sha1: 用于和摘要校验一致性
    - command_truncated: 标记 extra 中是否被截断
    """
    text = str(cmd or '').strip()
    digest = hashlib.sha1(text.encode('utf-8', errors='ignore')).hexdigest()[:12] if text else ''
    truncated = len(text) > max_len
    return {
        'raw_command': text[:max_len],
        'command_len': int(len(text)),
        'command_sha1': digest,
        'command_truncated': bool(truncated),
    }


def _match_high_risk_command(cmd: str):
    """
    命中高风险命令特征时返回 (title, level, tags, reasons)；否则返回 None。
    """
    c = str(cmd or '').lower()
    if not c:
        return None

    reasons = []
    tags = ['ssh', 'cmd', 'high_risk']

    # 持久化后门：向 authorized_keys 写入公钥、修改 .ssh 权限/属性
    if 'authorized_keys' in c and (
        'ssh-rsa ' in c or 'ssh-ed25519 ' in c or '>> authorized_keys' in c or 'chattr -i' in c
    ):
        reasons.append('ssh_key_persistence')
        tags.append('persistence')

    # 远程下载并执行
    if (('curl ' in c or 'wget ' in c) and ('| sh' in c or '| bash' in c)) or 'bash -c' in c and ('curl ' in c or 'wget ' in c):
        reasons.append('remote_script_exec')
        tags.append('download_exec')

    # 系统清痕/日志破坏
    if 'history -c' in c or 'rm -rf /var/log' in c or '> /var/log/' in c:
        reasons.append('log_tamper')
        tags.append('anti_forensics')

    if not reasons:
        return None

    return ("SSH 高危命令行为", '高危', tags, reasons)


def _match_suspicious_command(cmd: str):
    """
    命中中风险命令特征时返回 (title, level, tags, reasons, score)；否则返回 None。
    说明：用于“可疑请求分析”面板，不触发高危告警。
    """
    c = str(cmd or '').lower()
    if not c:
        return None

    reasons = []
    tags = ['ssh', 'cmd', 'suspicious']

    # 侦察与环境摸底
    token_to_reason = {
        'uname -a': 'host_fingerprint',
        'nproc': 'cpu_probe',
        'lscpu': 'cpu_probe',
        'nvidia-smi': 'gpu_probe',
        'cat /etc/passwd': 'account_enum',
        'cat /proc/cpuinfo': 'host_fingerprint',
        'ip a': 'network_probe',
        'ifconfig': 'network_probe',
        'netstat': 'network_probe',
        'ss -': 'network_probe',
        'ps aux': 'process_enum',
        'crontab -l': 'task_enum',
    }
    for token, reason in token_to_reason.items():
        if token in c and reason not in reasons:
            reasons.append(reason)

    # 轻度可疑：下载或批量文件搜索（但不包含高危“下载执行”）
    if ('wget ' in c or 'curl ' in c) and ('| sh' not in c and '| bash' not in c):
        if 'remote_fetch' not in reasons:
            reasons.append('remote_fetch')
    if 'find /' in c and '-name' in c:
        if 'filesystem_scan' not in reasons:
            reasons.append('filesystem_scan')

    if not reasons:
        return None

    return ("SSH 可疑命令行为", '警告', tags, reasons, 30)


def _audit_command_to_db(shell, normalized_cmd: str) -> None:
    """
    全量命令审计落库：即使前端不展示，也保留证据链。
    仅做连续重复去重，避免刷库。
    """
    if not normalized_cmd:
        return
    last_audit_cmd = getattr(shell, 'last_audit_cmd', '')
    if normalized_cmd == last_audit_cmd:
        return
    try:
        log_event(
            source='ssh',
            severity='low',
            event_type='ssh_cmd_audit',
            src_ip=shell.client_ip,
            session_id=getattr(shell, 'session_key', ''),
            tags=['ssh', 'cmd', 'audit_hidden'],
            payload=str(normalized_cmd or '').strip(),
            extra={
                'username': getattr(shell, 'username', ''),
                'client_port': int(getattr(shell, 'client_port', 0) or 0),
                'display': 'hidden',
                **_build_command_meta(normalized_cmd),
            },
        )
        shell.last_audit_cmd = normalized_cmd
    except Exception:
        pass


def _record_command_risk_events(shell, normalized_cmd: str) -> None:
    # 高危优先，命中后直接返回，避免同一命令重复打“疑似”
    high = _match_high_risk_command(normalized_cmd)
    if high:
        title, level, tags, reasons = high
        dedup_key = hashlib.sha1(
            f"ssh_cmd_high|{shell.client_ip}|{','.join(reasons)}|{_normalize_cmd_for_dedup(normalized_cmd)}".encode('utf-8', errors='ignore')
        ).hexdigest()[:16]
        try:
            log_event(
                source='ssh',
                severity='high',
                event_type='ssh_cmd_high_risk',
                src_ip=shell.client_ip,
                session_id=getattr(shell, 'session_key', ''),
                tags=tags,
                payload=str(normalized_cmd or '').strip(),
                extra={
                    'username': getattr(shell, 'username', ''),
                    'client_port': int(getattr(shell, 'client_port', 0) or 0),
                    'reasons': reasons,
                    'score': 60,
                    **_build_command_meta(normalized_cmd),
                },
            )
        except Exception:
            pass
        try:
            alert_event(
                title=title,
                src_ip=shell.client_ip,
                subject=getattr(shell, 'username', ''),
                subject_label='用户',
                summary=f"命令: {_short_cmd(normalized_cmd, 260)}",
                extra=f"命中信号: {', '.join(reasons)}",
                dedup_key=dedup_key,
                category='ssh',
                level=level,
                layout='multi',
                event_type='ssh_cmd_high_risk',
                tags=tags,
            )
        except Exception:
            pass
        return

    suspicious = _match_suspicious_command(normalized_cmd)
    if not suspicious:
        return
    title, _level, tags, reasons, score = suspicious
    sig = hashlib.sha1(
        f"ssh_cmd_susp|{shell.client_ip}|{','.join(reasons)}|{_normalize_cmd_for_dedup(normalized_cmd)}".encode('utf-8', errors='ignore')
    ).hexdigest()[:16]
    if getattr(shell, 'last_suspicious_sig', '') == sig:
        return
    shell.last_suspicious_sig = sig
    try:
        log_event(
            source='ssh',
            severity='medium',
            event_type='ssh_cmd_suspicious',
            src_ip=shell.client_ip,
            session_id=getattr(shell, 'session_key', ''),
            tags=tags,
            payload=str(normalized_cmd or '').strip(),
            extra={
                'title': title,
                'username': getattr(shell, 'username', ''),
                'client_port': int(getattr(shell, 'client_port', 0) or 0),
                'reasons': reasons,
                'score': int(score),
                **_build_command_meta(normalized_cmd),
            },
        )
    except Exception:
        pass

_SERVICE_DEFAULT_PROCESS = {
    "ssh": ("/usr/sbin/sshd -D", "root", "1", 22),
    "cron": ("/usr/sbin/cron -f", "root", "1", None),
    "rsyslog": ("/usr/sbin/rsyslogd -n", "syslog", "1", None),
    "systemd-journald": ("/lib/systemd/systemd-journald", "root", "1", None),
    "systemd-resolved": ("/lib/systemd/systemd-resolved", "root", "1", 53),
    "systemd-timesyncd": ("/lib/systemd/systemd-timesyncd", "root", "1", None),
    "systemd-networkd": ("/lib/systemd/systemd-networkd", "root", "1", None),
    "dbus": ("/usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation", "messagebus", "1", None),
    "ufw": ("/lib/ufw/ufw-init start", "root", "1", None),
    "apparmor": ("/lib/apparmor/apparmor.systemd reload", "root", "1", None),
    "systemd-logind": ("/lib/systemd/systemd-logind", "root", "1", None),
    # 虚拟业务主机：与 decoy_profiles 的服务清单对应
    "nginx": ("nginx: master process /usr/sbin/nginx -g daemon on; master_process on;", "root", "1", 80),
    "postgresql": ("/usr/lib/postgresql/16/bin/postgres -D /var/lib/postgresql/16/main", "postgres", "1", 5432),
    "redis": ("/usr/bin/redis-server 127.0.0.1:6379", "redis", "1", 6379),
    "erp-api": ("/opt/erp/bin/erp-api --port 8080", "erp", "1", 8080),
    "support-api": ("/opt/support/bin/support-api --port 8081", "support", "1", 8081),
    "backup-worker": ("/opt/backup/bin/backup-worker --daemon", "root", "1", None),
}


def _normalize_service_name(name: str) -> str:
    raw = str(name or "").strip()
    if not raw:
        return ""
    lowered = raw.lower()
    if lowered in _SERVICE_ALIASES:
        return _SERVICE_ALIASES[lowered]
    if lowered.endswith(".service"):
        lowered = lowered[:-8]
    return _SERVICE_ALIASES.get(lowered, lowered)


def _find_service_pid(shell, service_key: str):
    markers = _SERVICE_PROCESS_HINTS.get(service_key, [])
    for pid, info in getattr(shell, "processes", {}).items():
        cmdline = str(info.get("cmd", ""))
        if any(marker in cmdline for marker in markers):
            return str(pid), cmdline
    return None, None


def _alloc_service_pid(shell) -> str:
    used = set()
    for pid in getattr(shell, "processes", {}).keys():
        if str(pid).isdigit():
            used.add(int(pid))
    for _ in range(512):
        candidate = random.randint(600, 30000)
        if candidate not in used:
            return str(candidate)
    return str((max(used) + 1) if used else 1200)


def _append_service_log(shell, service_key: str, line: str) -> None:
    if not isinstance(getattr(shell, "service_logs", None), dict):
        shell.service_logs = {}
    logs = list(shell.service_logs.get(service_key, []))
    logs.append(line)
    shell.service_logs[service_key] = logs[-200:]


def ensure_service_state(shell) -> None:
    if not hasattr(shell, "processes") or not shell.processes:
        shell._init_processes()
    if not isinstance(getattr(shell, "services_state", None), dict):
        shell.services_state = {}
    if not isinstance(getattr(shell, "service_logs", None), dict):
        shell.service_logs = {}
    if not isinstance(getattr(shell, "killed_pids", None), set):
        shell.killed_pids = set()

    boot_time = HONEYPOT_IDENTITY.get("boot_time") or datetime.now()
    boot_ts = boot_time.strftime("%b %d %H:%M:%S")
    host = HONEYPOT_IDENTITY.get("hostname")

    for key in _SERVICE_DEFAULT_PROCESS.keys():
        pid, cmdline = _find_service_pid(shell, key)
        detected_running = bool(pid) and pid not in shell.killed_pids
        state = shell.services_state.get(key, {})
        if "running" not in state:
            state["running"] = detected_running
        if not state.get("pid") and pid:
            state["pid"] = pid
        if not state.get("cmd"):
            state["cmd"] = cmdline or _SERVICE_DEFAULT_PROCESS[key][0]
        if not state.get("started_at"):
            state["started_at"] = boot_time
        shell.services_state[key] = state

        if key not in shell.service_logs:
            shell.service_logs[key] = []
        if not shell.service_logs[key]:
            desc = _SERVICE_DESCRIPTIONS.get(key, f"{key}.service")
            action = "Started" if bool(state.get("running")) else "Stopped"
            _append_service_log(shell, key, f"{boot_ts} {host} systemd[1]: {action} {desc}.")


def _service_exists(service_key: str) -> bool:
    return service_key in _SERVICE_DEFAULT_PROCESS


def _service_running(shell, service_key: str) -> bool:
    ensure_service_state(shell)
    state = shell.services_state.get(service_key, {})
    running = bool(state.get("running"))
    pid = str(state.get("pid") or "")
    if running and pid and pid in shell.killed_pids:
        return False
    return running


def _service_pid_cmd(shell, service_key: str):
    ensure_service_state(shell)
    state = shell.services_state.get(service_key, {})
    pid = str(state.get("pid") or "")
    cmdline = str(state.get("cmd") or "")
    if pid and pid in getattr(shell, "processes", {}):
        proc = shell.processes.get(pid, {})
        if proc:
            cmdline = proc.get("cmd", cmdline)
    if not pid:
        pid, detected_cmd = _find_service_pid(shell, service_key)
        if detected_cmd:
            cmdline = detected_cmd
    return (pid or None), cmdline


def _set_service_running(shell, service_key: str, running: bool, save: bool = True) -> None:
    ensure_service_state(shell)
    if not _service_exists(service_key):
        return

    prev_running = _service_running(shell, service_key)
    now = datetime.now()
    now_ts = now.strftime("%b %d %H:%M:%S")
    host = HONEYPOT_IDENTITY.get("hostname")

    state = dict(shell.services_state.get(service_key, {}))
    pid = str(state.get("pid") or "")
    cmdline = str(state.get("cmd") or _SERVICE_DEFAULT_PROCESS[service_key][0])

    if running:
        if not pid or pid not in shell.processes:
            new_pid, detected_cmd = _find_service_pid(shell, service_key)
            if new_pid:
                pid = str(new_pid)
                if detected_cmd:
                    cmdline = detected_cmd
            else:
                pid = _alloc_service_pid(shell)
                default_cmd, default_user, default_ppid, default_port = _SERVICE_DEFAULT_PROCESS[service_key]
                shell.processes[pid] = {
                    "user": default_user,
                    "ppid": default_ppid,
                    "cmd": default_cmd,
                    "port": default_port,
                    "cpu_time": random.uniform(0.1, 2.0),
                    "start_time": now,
                    "cpu_pct": round(random.uniform(0.1, 1.5), 1),
                    "mem_pct": round(random.uniform(0.1, 0.6), 1),
                }
                cmdline = default_cmd
        if pid in shell.killed_pids:
            shell.killed_pids.remove(pid)
        state["running"] = True
        state["pid"] = pid
        state["cmd"] = cmdline
        state["started_at"] = now
        shell.services_state[service_key] = state

        if not prev_running:
            desc = _SERVICE_DESCRIPTIONS.get(service_key, f"{service_key}.service")
            _append_service_log(shell, service_key, f"{now_ts} {host} systemd[1]: Started {desc}.")
            if service_key == "ssh":
                _append_service_log(shell, service_key, f"{now_ts} {host} sshd[{pid or '512'}]: Server listening on 0.0.0.0 port 22.")
                _append_service_log(shell, service_key, f"{now_ts} {host} sshd[{pid or '512'}]: Server listening on :: port 22.")
    else:
        if not pid:
            pid, _ = _find_service_pid(shell, service_key)
        if pid:
            shell.killed_pids.add(pid)
        state["running"] = False
        state["pid"] = pid
        state["cmd"] = cmdline
        shell.services_state[service_key] = state
        if prev_running:
            desc = _SERVICE_DESCRIPTIONS.get(service_key, f"{service_key}.service")
            _append_service_log(shell, service_key, f"{now_ts} {host} systemd[1]: Stopped {desc}.")

    if save:
        try:
            shell._save_session_state()
        except Exception:
            pass


def parse_args(command_line: str):
    """简单的参数解析，处理引号"""
    import shlex
    try:
        return shlex.split(command_line)
    except Exception:
        return command_line.split()


def execute_command(shell, command_line: str, record_history: bool = True) -> str:
    """执行命令的主入口，支持管道、重定向和命令链"""
    if not command_line.strip():
        return ""

    def _set_status(code: int):
        try:
            shell.env['?'] = str(int(code))
        except Exception:
            shell.env['?'] = str(code)

    def _guess_status(output: str) -> int:
        if not output:
            return 0
        lowered = output.lower()
        if "command not found" in lowered:
            return 127
        if "permission denied" in lowered:
            return 1
        if "no such file or directory" in lowered:
            return 1
        if "not found" in lowered and "could not be found" in lowered:
            return 1
        return 0

    def _run_and_status(cmd: str) -> str:
        out = execute_command(shell, cmd, record_history=False)
        _set_status(_guess_status(out))
        return out

    def _eval_if(line: str) -> str:
        # 支持：if <cmd>; then <cmd>; else <cmd>; fi
        text = line.strip()
        if not text.startswith('if '):
            return ""
        text = text[3:].strip()
        # 允许没有 else
        # 拆分 then/else/fi
        if ' then ' in text:
            cond_part, rest = text.split(' then ', 1)
        elif '; then ' in text:
            cond_part, rest = text.split('; then ', 1)
        else:
            return "bash: syntax error near unexpected token `then'\n"

        cond_out = _run_and_status(cond_part.strip())
        ok = shell.env.get('?', '0') == '0'

        if ' fi' in rest:
            body_part, _ = rest.split(' fi', 1)
        elif '; fi' in rest:
            body_part, _ = rest.split('; fi', 1)
        else:
            return "bash: syntax error: unexpected end of file\n"

        if ' else ' in body_part:
            then_part, else_part = body_part.split(' else ', 1)
        elif '; else ' in body_part:
            then_part, else_part = body_part.split('; else ', 1)
        else:
            then_part, else_part = body_part, ""

        if ok:
            return _run_and_status(then_part.strip())
        if else_part.strip():
            return _run_and_status(else_part.strip())
        return ""

    def _eval_for(line: str) -> str:
        # 支持：for x in a b; do <cmd>; done
        text = line.strip()
        if not text.startswith('for '):
            return ""
        if ' do ' not in text and '; do ' not in text:
            return "bash: syntax error near unexpected token `do'\n"
        header, body = (text.split(' do ', 1) if ' do ' in text else text.split('; do ', 1))
        if ' done' in body:
            body_cmd, _ = body.split(' done', 1)
        elif '; done' in body:
            body_cmd, _ = body.split('; done', 1)
        else:
            return "bash: syntax error: unexpected end of file\n"

        header = header[4:].strip()
        if ' in ' not in header:
            return "bash: syntax error near unexpected token `in'\n"
        var, items = header.split(' in ', 1)
        var = var.strip()
        items = [i for i in items.replace(';', ' ').split() if i]

        out = ""
        for item in items:
            shell.env[var] = item
            out += _run_and_status(body_cmd.strip())
        return out

    def _eval_while(line: str) -> str:
        # 支持：while <cmd>; do <cmd>; done （最多循环 10 次）
        text = line.strip()
        if not text.startswith('while '):
            return ""
        if ' do ' not in text and '; do ' not in text:
            return "bash: syntax error near unexpected token `do'\n"
        header, body = (text.split(' do ', 1) if ' do ' in text else text.split('; do ', 1))
        if ' done' in body:
            body_cmd, _ = body.split(' done', 1)
        elif '; done' in body:
            body_cmd, _ = body.split('; done', 1)
        else:
            return "bash: syntax error: unexpected end of file\n"
        cond_cmd = header[6:].strip()

        out = ""
        for _ in range(10):
            _run_and_status(cond_cmd)
            ok = shell.env.get('?', '0') == '0'
            if not ok:
                break
            out += _run_and_status(body_cmd.strip())
        return out

    def _eval_case(line: str) -> str:
        # 支持：case WORD in pat) cmd ;; pat2) cmd ;; esac
        text = line.strip()
        if not text.startswith('case '):
            return ""
        if ' in ' not in text:
            return "bash: syntax error near unexpected token `in'\n"
        head, rest = text.split(' in ', 1)
        word = head[5:].strip()
        if word.startswith('"') and word.endswith('"') and len(word) >= 2:
            word = word[1:-1]
        if ' esac' not in rest and '\nesac' not in rest:
            return "bash: syntax error: unexpected end of file\n"
        body, _ = (rest.split(' esac', 1) if ' esac' in rest else rest.split('\nesac', 1))
        segments = [s.strip() for s in body.split(';;') if s.strip()]
        for seg in segments:
            if ')' not in seg:
                continue
            pat, cmd = seg.split(')', 1)
            pat = pat.strip()
            cmd = cmd.strip()
            patterns = [p.strip() for p in pat.split('|') if p.strip()]
            for p in patterns:
                if p == '*':
                    return _run_and_status(cmd)
                if p == word:
                    return _run_and_status(cmd)
                try:
                    if fnmatch.fnmatch(word, p):
                        return _run_and_status(cmd)
                except Exception:
                    pass
        return ""

    stripped = command_line.strip()
    normalized_cmd = _normalize_cmd_for_dedup(stripped)

    # record_history=True 代表用户真实输入入口：
    # - 全量审计入库（可隐藏展示）
    # - 风险命令写入高危/疑似事件（高危触发告警）
    if record_history and stripped:
        _audit_command_to_db(shell, stripped)
        _record_command_risk_events(shell, stripped)

    if '\n' in stripped:
        out = ""
        for line in [l for l in stripped.split('\n') if l.strip()]:
            out += execute_command(shell, line, record_history=False)
        return out
    if stripped.startswith('if '):
        return _eval_if(stripped)
    if stripped.startswith('for '):
        return _eval_for(stripped)
    if stripped.startswith('while '):
        return _eval_while(stripped)
    if stripped.startswith('case '):
        return _eval_case(stripped)

    # 命令日志降噪
    # 1. 忽略低价值高频命令
    cmd_blacklist = {'clear', 'history', 'exit', 'logout', 'pwd', 'whoami', 'id', 'w'}

    should_log = True
    normalized_cmd = command_line.strip()

    if normalized_cmd in cmd_blacklist:
        should_log = False

    # 2. 连续重复命令去重（如重复执行 ls）
    if normalized_cmd == shell.last_logged_cmd:
        should_log = False

    if record_history and should_log:
        try:
            log_event_activity(shell.client_ip, 'SHELL_CMD', normalized_cmd)
            shell.last_logged_cmd = normalized_cmd
        except Exception:
            pass

    # 统一记录命令历史
    history_changed = False
    if record_history and (not shell.history or shell.history[-1] != command_line.strip()):
        shell.history.append(command_line.strip())
        if len(shell.history) > 1000:
            shell.history.pop(0)
        history_changed = True
    if history_changed and hasattr(shell, '_save_session_state'):
        shell._save_session_state()

    # 命令链解析（递归），优先级：; < || < && < |

    # 1. 分号 (顺序执行)
    if ';' in command_line:
        parts = command_line.split(';', 1)
        out1 = execute_command(shell, parts[0], record_history=False)
        out2 = execute_command(shell, parts[1], record_history=False)
        return out1 + out2

    # 2. && (成功后执行)
    if '&&' in command_line:
        parts = command_line.split('&&', 1)
        out1 = execute_command(shell, parts[0], record_history=False)
        status = shell.env.get('?', '0')
        if status == '0':
            out2 = execute_command(shell, parts[1], record_history=False)
            return out1 + out2
        return out1

    # 3. || (失败后执行)
    if '||' in command_line:
        parts = command_line.split('||', 1)
        out1 = execute_command(shell, parts[0], record_history=False)
        status = shell.env.get('?', '0')
        if status != '0':
            out2 = execute_command(shell, parts[1], record_history=False)
            return out1 + out2
        return out1

    # 4. 管道 |
    if '|' in command_line:
        parts = command_line.split('|', 1)
        input_data = execute_command(shell, parts[0], record_history=False)

        right_cmd = parts[1].strip()
        args = parse_args(right_cmd)
        if not args:
            return input_data

        cmd_name = args[0]
        pipe_handler = f"_pipe_{cmd_name}"
        if hasattr(shell, pipe_handler):
            return getattr(shell, pipe_handler)(input_data, args[1:])

        # 未实现专用 pipe handler 时，按普通命令执行右侧
        return execute_command(shell, right_cmd, record_history=False)

    # 5. 重定向 > >> <
    output_file = None
    append = False
    input_file = None
    clean_cmd = command_line

    if '>>' in command_line:
        parts = command_line.split('>>', 1)
        clean_cmd = parts[0]
        output_file = parts[1].strip()
        append = True
    elif '>' in command_line:
        parts = command_line.split('>', 1)
        clean_cmd = parts[0]
        output_file = parts[1].strip()
        append = False
    if '<' in clean_cmd:
        parts = clean_cmd.split('<', 1)
        clean_cmd = parts[0].strip()
        input_file = parts[1].strip()

    # 执行核心命令
    if input_file:
        in_path = shell.normalize_path(input_file)
        shell._stdin_buffer = shell.files_content.get(in_path, VIRTUAL_FILES.get(in_path, ""))
    # 执行核心命令（经 shell 钩子进入交互审计；未知命令由模型选择封闭策略）
    runner = getattr(shell, '_execute_single_command', None)
    output = runner(clean_cmd) if callable(runner) else execute_single_command(shell, clean_cmd)
    if hasattr(shell, '_stdin_buffer'):
        shell._stdin_buffer = None
    # 记录退出码
    if hasattr(shell, '_last_status_explicit') and shell._last_status_explicit is not None:
        shell.env['?'] = str(shell._last_status_explicit)
        shell._last_status_explicit = None
    else:
        if output:
            lower = output.lower()
            if "command not found" in lower:
                shell.env['?'] = '127'
            elif "permission denied" in lower or "no such file or directory" in lower:
                shell.env['?'] = '1'
            else:
                shell.env['?'] = '0'
        else:
            shell.env['?'] = '0'

    if output_file:
        target = shell.normalize_path(output_file)

        # 检查写权限
        parent = os.path.dirname(target)
        if not shell._check_write_permission(parent):
            return f"-bash: {output_file}: Permission denied\n"
        if parent not in shell.fs_state:
            return f"-bash: {output_file}: No such file or directory\n"

        current_content = ""
        if append:
            current_content = shell.files_content.get(target, VIRTUAL_FILES.get(target, ""))

        is_new_file = os.path.basename(target) not in shell.fs_state[parent]
        shell.files_content[target] = current_content + output

        # 更新元数据
        if is_new_file:
            shell.fs_state[parent].append(os.path.basename(target))
            shell.file_owners[target] = (shell.username, shell.username)
            shell.file_perms[target] = "-rw-r--r--"
        else:
            shell.file_owners.setdefault(target, (shell.username, shell.username))
            shell.file_perms.setdefault(target, "-rw-r--r--")
        shell.file_timestamps[target] = datetime.now()
        shell.file_sizes[target] = len(shell.files_content[target])
        if hasattr(shell, '_save_session_state'):
            shell._save_session_state()

        return ""  # 重定向不输出到屏幕

    return output


def execute_single_command(shell, command_line: str) -> str:
    """执行单个命令 (无管道/重定向)"""
    args = parse_args(command_line)
    if not args:
        return ""

    args = shell._expand_variables(args)
    args = shell._expand_wildcards(args)

    cmdor = args[0]
    cmd = os.path.basename(cmdor) if '/' in cmdor else cmdor
    resolved_cmd = _COMMAND_ALIASES.get(cmd, cmd)

    # Bash 内建特殊处理
    if cmd == ':':
        shell._last_status_explicit = 0
        return ""
    if cmd in ['[', 'test', '[[', ']]']:
        return cmd_test(shell, args[1:])
    if cmd == '.':
        return cmd_source(shell, args[1:])

    handler_name = f"_cmd_{resolved_cmd}"
    if hasattr(shell, handler_name):
        try:
            return getattr(shell, handler_name)(args[1:])
        except Exception as e:
            logger.error(f"Error executing {resolved_cmd}: {e}")
            import traceback
            traceback.print_exc()
            return f"-bash: {cmd}: command execution error\n"

    # 检查命令是否存在于 VIRTUAL_FS 的 /bin, /sbin, /usr/bin, /usr/sbin
    search_paths = ['/bin', '/sbin', '/usr/bin', '/usr/sbin']
    found_binary = None
    for p in search_paths:
        if p in shell.fs_state and cmd in shell.fs_state[p]:
            found_binary = f"{p}/{cmd}"
            break

    if found_binary:
        return f"-bash: {found_binary}: cannot execute binary file: Exec format error\n"

    suggestions = {
        'curl': 'curl',
        'nmap': 'nmap',
        'git': 'git', 'docker': 'docker.io', 'python': 'python-is-python3',
        'java': 'default-jre', 'gcc': 'gcc', 'make': 'make'
    }

    if cmd in suggestions:
        return f"Command '{cmd}' not found, but can be installed with:\napt install {suggestions[cmd]}\n"

    return f"{cmdor}: command not found\n"


def pipe_grep(input_data: str, args: list) -> str:
    if not args:
        return input_data
    invert = False
    ignore_case = False
    pattern = None
    for arg in args:
        if arg == '-v':
            invert = True
        elif arg == '-i':
            ignore_case = True
        elif arg.startswith('-'):
            if 'v' in arg:
                invert = True
            if 'i' in arg:
                ignore_case = True
        else:
            if pattern is None:
                pattern = arg.replace('"', '').replace("'", "")
    if pattern is None:
        return input_data
    result = ""
    for line in input_data.split('\n'):
        check_line = line.lower() if ignore_case else line
        check_pattern = pattern.lower() if ignore_case else pattern
        match = check_pattern in check_line
        if (match and not invert) or (not match and invert):
            result += line + "\n"
    return result


def pipe_head(input_data: str, args: list) -> str:
    lines = input_data.split('\n')
    count = 10
    if args and args[0].startswith('-n'):
        try:
            count = int(args[1])
        except Exception:
            pass
    elif args and args[0].startswith('-'):
        try:
            count = int(args[0][1:])
        except Exception:
            pass
    if lines and lines[-1] == '':
        lines.pop()
    return '\n'.join(lines[:count]) + '\n'


def pipe_tail(input_data: str, args: list) -> str:
    lines = input_data.split('\n')
    if lines and lines[-1] == '':
        lines.pop()
    count = 10
    if args and args[0].startswith('-n'):
        try:
            count = int(args[1])
        except Exception:
            pass
    return '\n'.join(lines[-count:]) + '\n'


def pipe_wc(input_data: str, args: list) -> str:
    lines = input_data.split('\n')
    if lines and lines[-1] == '':
        lines.pop()
    l_count = len(lines)
    w_count = sum(len(line.split()) for line in lines)
    c_count = len(input_data)
    if '-l' in args:
        return f"{l_count}\n"
    if '-w' in args:
        return f"{w_count}\n"
    if '-c' in args:
        return f"{c_count}\n"
    return f"{l_count} {w_count} {c_count}\n"


def pipe_sed(input_data: str, args: list) -> str:
    if not args:
        return input_data
    command = None
    for arg in args:
        if 's/' in arg:
            command = arg.replace("'", "").replace('"', '')
            break
    if not command:
        return input_data
    parts = command.split('/')
    if len(parts) < 3:
        return input_data
    pattern = parts[1]
    replacement = parts[2]
    global_replace = len(parts) > 3 and 'g' in parts[3]
    result = ""
    for line in input_data.split('\n'):
        if global_replace:
            new_line = line.replace(pattern, replacement)
        else:
            new_line = line.replace(pattern, replacement, 1)
        if line or new_line:
            result += new_line + "\n"
    return result


def pipe_cut(input_data: str, args: list) -> str:
    delimiter = '\t'
    fields = []
    i = 0
    while i < len(args):
        if args[i] == '-d' and i + 1 < len(args):
            delimiter = args[i + 1].replace("'", "").replace('"', '')
            i += 2
        elif args[i].startswith('-d'):
            delimiter = args[i][2:].replace("'", "").replace('"', '')
            i += 1
        elif args[i] == '-f' and i + 1 < len(args):
            fields = [int(x) for x in args[i + 1].split(',') if x.isdigit()]
            i += 2
        elif args[i].startswith('-f'):
            fields = [int(x) for x in args[i][2:].split(',') if x.isdigit()]
            i += 1
        else:
            i += 1
    if not fields:
        return input_data
    result = ""
    for line in input_data.split('\n'):
        if not line:
            continue
        parts = line.split(delimiter)
        selected = []
        for f in fields:
            if f > 0 and f <= len(parts):
                selected.append(parts[f - 1])
        result += delimiter.join(selected) + "\n"
    return result


def pipe_sort(input_data: str, args: list) -> str:
    reverse = '-r' in args
    numeric = '-n' in args
    lines = [l for l in input_data.split('\n') if l]
    if numeric:
        try:
            lines.sort(key=lambda x: int(x.split()[0]) if x.split() else 0, reverse=reverse)
        except Exception:
            lines.sort(reverse=reverse)
    else:
        lines.sort(reverse=reverse)
    return '\n'.join(lines) + '\n'


def pipe_uniq(input_data: str, args: list) -> str:
    lines = input_data.split('\n')
    result = []
    prev = None
    for line in lines:
        if line != prev:
            if line:
                result.append(line)
            prev = line
    return '\n'.join(result) + '\n'


def cmd_true(shell, args: list) -> str:
    shell._last_status_explicit = 0
    return ""


def cmd_false(shell, args: list) -> str:
    shell._last_status_explicit = 1
    return ""


def cmd_whoami(shell, args: list) -> str:
    return f"{shell.username}\n"


def cmd_pwd(shell, args: list) -> str:
    return shell.current_path + "\n"


def _read_virtual_account_file(shell, path: str) -> str:
    return str(shell.files_content.get(path, VIRTUAL_FILES.get(path, '')) or '')


def _resolve_user_identity(shell, target_user: str):
    target = str(target_user or '').strip()
    if not target:
        return None

    uid = None
    gid = None
    primary_group = target
    passwd_content = _read_virtual_account_file(shell, '/etc/passwd')
    for line in passwd_content.splitlines():
        parts = line.split(':')
        if len(parts) < 7 or parts[0] != target:
            continue
        uid = parts[2]
        gid = parts[3]
        break

    if uid is None or gid is None:
        return None

    groups = []
    seen = set()

    def _push_group(group_id: str, group_name: str) -> None:
        key = (str(group_id), str(group_name))
        if key in seen:
            return
        seen.add(key)
        groups.append((str(group_id), str(group_name)))

    group_content = _read_virtual_account_file(shell, '/etc/group')
    for line in group_content.splitlines():
        parts = line.split(':')
        if len(parts) < 3:
            continue
        group_name = str(parts[0] or '').strip()
        group_id = str(parts[2] or '').strip()
        members = []
        if len(parts) > 3:
            members = [member.strip() for member in parts[3].split(',') if member.strip()]
        if group_id == str(gid):
            primary_group = group_name or primary_group
            _push_group(group_id, primary_group)
            continue
        if target in members:
            _push_group(group_id, group_name)

    primary_entry = None
    for index, (group_id, group_name) in enumerate(groups):
        if group_id == str(gid):
            primary_entry = (group_id, group_name)
            groups.pop(index)
            break
    if primary_entry is None:
        primary_entry = (str(gid), primary_group)
    groups.insert(0, primary_entry)

    return {
        'user': target,
        'uid': str(uid),
        'gid': str(gid),
        'primary_group': primary_group,
        'groups': groups,
    }


def _write_virtual_text(shell, path: str, content: str, timestamp: datetime = None) -> None:
    now = timestamp or datetime.now()
    shell.files_content[path] = content
    shell.file_timestamps[path] = now
    shell.file_sizes[path] = len(content)


def _list_account_lines(shell, path: str) -> list:
    content = _read_virtual_account_file(shell, path)
    return [line for line in content.splitlines() if line.strip()]


def _persist_account_files(shell, timestamp: datetime = None) -> None:
    now = timestamp or datetime.now()
    for path in ('/etc/passwd', '/etc/shadow', '/etc/group', '/etc/gshadow'):
        if path in shell.files_content:
            shell.file_timestamps[path] = now
            shell.file_sizes[path] = len(shell.files_content[path])
    if hasattr(shell, '_save_session_state'):
        shell._save_session_state()


def _replace_group_line_members(group_line: str, members: list) -> str:
    parts = group_line.split(':')
    while len(parts) < 4:
        parts.append('')
    normalized = []
    for member in members:
        text = str(member or '').strip()
        if text and text not in normalized:
            normalized.append(text)
    parts[3] = ','.join(normalized)
    return ':'.join(parts[:4])


def _rename_virtual_home(shell, old_home: str, new_home: str) -> None:
    old_norm = shell.normalize_path(old_home)
    new_norm = shell.normalize_path(new_home)
    if old_norm == new_norm:
        return

    old_parent = os.path.dirname(old_norm) or '/'
    new_parent = os.path.dirname(new_norm) or '/'
    old_name = os.path.basename(old_norm)
    new_name = os.path.basename(new_norm)

    if old_parent in shell.fs_state and old_name in shell.fs_state[old_parent]:
        shell.fs_state[old_parent] = [entry for entry in shell.fs_state[old_parent] if entry != old_name]
    shell.fs_state.setdefault(new_parent, [])
    if new_name not in shell.fs_state[new_parent]:
        shell.fs_state[new_parent].append(new_name)

    dir_moves = {}
    file_moves = {}
    for path in list(shell.fs_state.keys()):
        if path == old_norm or path.startswith(old_norm.rstrip('/') + '/'):
            suffix = path[len(old_norm):]
            dir_moves[path] = new_norm + suffix
    for path in list(shell.files_content.keys()):
        if path == old_norm or path.startswith(old_norm.rstrip('/') + '/'):
            suffix = path[len(old_norm):]
            file_moves[path] = new_norm + suffix

    for source, target in sorted(dir_moves.items(), key=lambda item: len(item[0]), reverse=True):
        shell.fs_state[target] = shell.fs_state.pop(source)
    for source, target in sorted(file_moves.items(), key=lambda item: len(item[0]), reverse=True):
        shell.files_content[target] = shell.files_content.pop(source)

    for mapping in (shell.file_owners, shell.file_perms, shell.file_sizes, shell.file_timestamps):
        for source in list(mapping.keys()):
            if source == old_norm or source.startswith(old_norm.rstrip('/') + '/'):
                suffix = source[len(old_norm):]
                mapping[new_norm + suffix] = mapping.pop(source)


def _remove_virtual_tree(shell, root_path: str) -> None:
    root_norm = shell.normalize_path(root_path)
    parent = os.path.dirname(root_norm) or '/'
    name = os.path.basename(root_norm)
    if parent in shell.fs_state and name in shell.fs_state[parent]:
        shell.fs_state[parent] = [entry for entry in shell.fs_state[parent] if entry != name]

    for path in list(shell.files_content.keys()):
        if path == root_norm or path.startswith(root_norm.rstrip('/') + '/'):
            shell.files_content.pop(path, None)
    for path in list(shell.fs_state.keys()):
        if path == root_norm or path.startswith(root_norm.rstrip('/') + '/'):
            shell.fs_state.pop(path, None)
    for mapping in (shell.file_owners, shell.file_perms, shell.file_sizes, shell.file_timestamps):
        for path in list(mapping.keys()):
            if path == root_norm or path.startswith(root_norm.rstrip('/') + '/'):
                mapping.pop(path, None)


def cmd_groups(shell, args: list) -> str:
    target = args[0] if args else shell.username
    identity = _resolve_user_identity(shell, target)
    if not identity:
        shell._last_status_explicit = 1
        return f"groups: '{target}': no such user\n"
    shell._last_status_explicit = 0
    group_names = " ".join(group_name for _, group_name in identity['groups'])
    if args:
        return f"{identity['user']} : {group_names}\n"
    return f"{group_names}\n"


def cmd_echo(shell, args: list) -> str:
    text = " ".join(args)
    return text + "\n"


def cmd_alias(shell, args: list) -> str:
    if args:
        return ""
    return "alias ls='ls --color=auto'\nalias ll='ls -alF'\nalias la='ls -A'\nalias grep='grep --color=auto'\n"


def cmd_unalias(shell, args: list) -> str:
    if not args:
        return "unalias: usage: unalias [-a] name [name ...]\n"
    return ""


def cmd_source(shell, args: list) -> str:
    if not args:
        return "source: filename argument required\n"
    path = shell.normalize_path(args[0])
    if path not in shell.files_content and path not in VIRTUAL_FILES:
        return f"-bash: source: {args[0]}: No such file or directory\n"
    return ""


def cmd_set(shell, args: list) -> str:
    if args:
        return ""
    lines = []
    for k in sorted(shell.env.keys()):
        lines.append(f"{k}={shell.env[k]}")
    return "\n".join(lines) + ("\n" if lines else "")


def cmd_unset(shell, args: list) -> str:
    for k in args:
        if k in shell.env:
            del shell.env[k]
    return ""


def cmd_declare(shell, args: list) -> str:
    return cmd_set(shell, []) if not args else ""


def cmd_typeset(shell, args: list) -> str:
    return cmd_declare(shell, args)


def cmd_readonly(shell, args: list) -> str:
    return cmd_set(shell, []) if not args else ""


def cmd_wait(shell, args: list) -> str:
    return ""


def cmd_fg(shell, args: list) -> str:
    return "bash: fg: no job control in this shell\n"


def cmd_bg(shell, args: list) -> str:
    return "bash: bg: no job control in this shell\n"


def cmd_jobs(shell, args: list) -> str:
    return ""


def cmd_time(shell, args: list) -> str:
    if not args:
        return "time: usage: time COMMAND [args...]\n"
    output = execute_command(shell, " ".join(args), record_history=False)
    timing = "real\t0m0.02s\nuser\t0m0.00s\nsys\t0m0.00s\n"
    return output + timing


def cmd_help(shell, args: list) -> str:
    return "Shell builtins: : alias bg break cd command continue declare echo exec exit export false fg hash help history jobs kill logout printf pwd readonly return set source test times trap true type typeset umask unalias unset wait\n"


def cmd_type(shell, args: list) -> str:
    if not args:
        shell._last_status_explicit = 1
        return ""
    lines = []
    status = 0
    for name in args:
        if name in _SHELL_KEYWORDS:
            lines.append(f"{name} is a shell keyword\n")
            continue
        if name in _SHELL_BUILTINS:
            lines.append(f"{name} is a shell builtin\n")
            continue
        resolved = _find_command_in_path(shell, name)
        if resolved:
            lines.append(f"{name} is {resolved}\n")
            continue
        status = 1
        lines.append(f"{name} not found\n")
    shell._last_status_explicit = status
    return ''.join(lines)


def cmd_umask(shell, args: list) -> str:
    if not args:
        return shell.env.get('UMASK', '0022') + "\n"
    shell.env['UMASK'] = args[0]
    return ""


def cmd_exec(shell, args: list) -> str:
    if not args:
        return ""
    return execute_command(shell, " ".join(args), record_history=False)


def cmd_command(shell, args: list) -> str:
    if not args:
        shell._last_status_explicit = 0
        return ""
    if args[0] in ('-v', '-V'):
        verbose = args[0] == '-V'
        names = args[1:]
        if not names:
            shell._last_status_explicit = 1
            return ""
        if verbose:
            return cmd_type(shell, names)
        lines = []
        status = 0
        for name in names:
            found = _command_v_line(shell, name)
            if found:
                lines.append(found + "\n")
            else:
                status = 1
        shell._last_status_explicit = status
        return ''.join(lines)
    shell._last_status_explicit = 0
    return execute_command(shell, " ".join(args), record_history=False)


def cmd_printf(shell, args: list) -> str:
    if not args:
        shell._last_status_explicit = 0
        return ""
    fmt = bytes(str(args[0]), 'utf-8').decode('unicode_escape', errors='ignore')
    output = ""
    values = list(args[1:])
    i = 0
    while i < len(fmt):
        if fmt[i] == '%' and i + 1 < len(fmt):
            token = fmt[i + 1]
            if token == '%':
                output += '%'
                i += 2
                continue
            value = values.pop(0) if values else ''
            if token == 'b':
                output += bytes(str(value), 'utf-8').decode('unicode_escape', errors='ignore')
            elif token in ('d', 'i'):
                try:
                    output += str(int(str(value).strip() or '0', 10))
                except Exception:
                    output += '0'
            else:
                output += str(value)
            i += 2
            continue
        output += fmt[i]
        i += 1
    shell._last_status_explicit = 0
    return output


def cmd_hash(shell, args: list) -> str:
    shell._last_status_explicit = 0
    return ""


def cmd_times(shell, args: list) -> str:
    shell._last_status_explicit = 0
    return "0m0.00s 0m0.00s\n0m0.01s 0m0.00s\n"


def cmd_logout(shell, args: list) -> str:
    return cmd_exit(shell, args)


def cmd_trap(shell, args: list) -> str:
    return ""


def cmd_function(shell, args: list) -> str:
    return ""


def cmd_return(shell, args: list) -> str:
    return ""


def cmd_test(shell, args: list) -> str:
    if not args:
        shell._last_status_explicit = 1
        return "test: missing argument\n"
    # 处理 [ ... ] 的结尾 ]
    if args and args[-1] == ']':
        args = args[:-1]
    # 一元测试运算
    def _exists(path):
        p, _ = _virtual_path_exists(shell, path)
        return bool(p)
    if len(args) == 2 and args[0] in ['-f', '-d', '-e']:
        flag, target = args
        ok = _exists(target)
        if flag == '-f':
            _, is_dir = _virtual_path_exists(shell, target)
            ok = ok and not is_dir
        if flag == '-d':
            _, is_dir = _virtual_path_exists(shell, target)
            ok = is_dir
        shell._last_status_explicit = 0 if ok else 1
        return ""
    if len(args) == 2 and args[0] in ['-z', '-n']:
        val = args[1]
        ok = (val == "") if args[0] == '-z' else (val != "")
        shell._last_status_explicit = 0 if ok else 1
        return ""
    # 二元字符串比较运算
    if len(args) >= 3:
        left = args[0]
        op = args[1]
        right = args[2]
        ok = False
        if op in ['=', '==']:
            ok = left == right
        elif op == '!=':
            ok = left != right
        shell._last_status_explicit = 0 if ok else 1
        return ""
    shell._last_status_explicit = 1
    return ""


def cmd_if(shell, args: list) -> str:
    return ""


def cmd_then(shell, args: list) -> str:
    return ""


def cmd_else(shell, args: list) -> str:
    return ""


def cmd_elif(shell, args: list) -> str:
    return ""


def cmd_fi(shell, args: list) -> str:
    return ""


def cmd_while(shell, args: list) -> str:
    return ""


def cmd_until(shell, args: list) -> str:
    return ""


def cmd_for(shell, args: list) -> str:
    return ""


def cmd_break(shell, args: list) -> str:
    return ""


def cmd_continue(shell, args: list) -> str:
    return ""


def cmd_select(shell, args: list) -> str:
    return ""


def _format_ls_columns(items: list, term_width: int) -> str:
    entries = [str(item or '') for item in items if str(item or '')]
    if not entries:
        return "\n"

    try:
        width = max(40, min(int(term_width or 80), 240))
    except Exception:
        width = 80

    count = len(entries)
    best_cols = 1
    best_widths = [max(len(_strip_ansi(item)) for item in entries)]
    for cols in range(count, 0, -1):
        rows = (count + cols - 1) // cols
        col_widths = []
        total_width = 0
        for col in range(cols):
            col_items = [entries[idx] for idx in range(col, count, cols)]
            col_width = max((len(_strip_ansi(item)) for item in col_items), default=0)
            col_widths.append(col_width)
            total_width += col_width
        total_width += max(0, cols - 1) * 2
        if total_width <= width:
            best_cols = cols
            best_widths = col_widths
            break

    rows = (count + best_cols - 1) // best_cols
    lines = []
    for row in range(rows):
        chunks = []
        for col in range(best_cols):
            idx = row * best_cols + col
            if idx >= count:
                continue
            item = entries[idx]
            if col == best_cols - 1 or row * best_cols + col + 1 >= count:
                chunks.append(item)
            else:
                chunks.append(_ansi_ljust(item, best_widths[col] + 2))
        lines.append(''.join(chunks).rstrip())
    return '\n'.join(lines) + '\n'

def cmd_ls(shell, args: list) -> str:
    show_all = _arg_has_short_option(args, '-a')
    long_fmt = _arg_has_short_option(args, '-l')
    show_dir_entries = _arg_has_short_option(args, '-d')
    classify = _arg_has_short_option(args, '-F')
    color_enabled = _ls_should_color(shell, args)

    targets = []
    for arg in args:
        if not arg.startswith('-'):
            targets.append(shell.normalize_path(arg))

    if not targets:
        targets = [shell.current_path]

    final_output = ""
    show_header = len(targets) > 1

    for i, target in enumerate(targets):
        if show_header:
            final_output += f"{target}:\n"

        norm, target_is_dir = _virtual_path_exists(shell, target)
        if not norm:
            final_output += f"ls: cannot access '{target}': No such file or directory\n"
            if show_header and i < len(targets) - 1:
                final_output += "\n"
            continue
        if not target_is_dir:
            if long_fmt:
                final_output += format_ls_item(shell, target, target, False, color_enabled, classify)
            else:
                perm = shell.file_perms.get(target, _default_virtual_perm(target, False))
                final_output += _ls_render_name(target, perm, False, color_enabled, classify) + "\n"
            if show_header and i < len(targets) - 1:
                final_output += "\n"
            continue

        if show_dir_entries:
            if long_fmt:
                final_output += format_ls_item(shell, target, target, target == '/proc', color_enabled, classify)
            else:
                perm = shell.file_perms.get(target, _default_virtual_perm(target, True))
                final_output += _ls_render_name(target, perm, True, color_enabled, classify) + "\n"
            if show_header and i < len(targets) - 1:
                final_output += "\n"
            continue

        items = sorted(shell.fs_state[target])

        if target == '/proc':
            if not hasattr(shell, 'processes') or not shell.processes:
                shell._init_processes()

            active_pids = []
            for pid in shell.processes.keys():
                if pid not in shell.killed_pids:
                    active_pids.append(pid)

            active_pids.sort(key=lambda x: int(x) if x.isdigit() else 0)
            items.extend(active_pids)
            items = sorted(list(set(items)))

        if show_all:
            items = ['.', '..'] + items
        else:
            items = [x for x in items if not x.startswith('.')]

        if long_fmt:
            total_blocks = 0
            for item in items:
                base = target.rstrip('/') or '/'
                item_path = shell.normalize_path(f"{base}/{item}")
                is_dir = item_path in shell.fs_state
                size = shell._get_file_size(item_path, is_dir)
                blocks = max(1, int((size + 1023) / 1024))
                total_blocks += blocks
            final_output += f"total {total_blocks}\n"
            for item in items:
                base = target.rstrip('/') or '/'
                item_path = shell.normalize_path(f"{base}/{item}")
                final_output += format_ls_item(shell, item_path, item, target == '/proc', color_enabled, classify)
        else:
            rendered_items = []
            for item in items:
                base = target.rstrip('/') or '/'
                item_path = shell.normalize_path(f"{base}/{item}")
                is_dir = item_path in shell.fs_state or (target == '/proc' and item.isdigit())
                perm = shell.file_perms.get(item_path, _default_virtual_perm(item_path, is_dir))
                rendered_items.append(_ls_render_name(item, perm, is_dir, color_enabled, classify))
            final_output += _format_ls_columns(
                rendered_items,
                getattr(shell, 'term_width', shell.env.get('COLUMNS', 80)),
            )

        if show_header and i < len(targets) - 1:
            final_output += "\n"

    return final_output


def format_ls_item(shell, item_path: str, display_name: str, is_proc_path: bool = False, color_enabled: bool = False, classify: bool = False) -> str:
    is_proc_pid = is_proc_path and display_name.isdigit()
    is_dir = item_path in shell.fs_state or is_proc_pid

    perm = shell.file_perms.get(item_path, _default_virtual_perm(item_path, is_dir))

    size = shell._get_file_size(item_path, is_dir)
    if is_proc_pid:
        size = 0

    date_str = shell._get_file_timestamp(item_path)
    if is_proc_path:
        date_str = datetime.now().strftime("%b %d %H:%M")

    if item_path in shell.file_owners:
        owner, group = shell.file_owners[item_path]
    else:
        owner = "root"
        group = "root"
        if item_path.startswith('/home/'):
            parts = item_path.split('/')
            if len(parts) > 2 and parts[2] not in ['root', 'bin', 'etc']:
                owner = parts[2]
                group = parts[2]

    rendered_name = _ls_render_name(display_name, perm, is_dir, color_enabled, classify)
    return f"{perm} 2 {owner} {group} {size:>5} {date_str} {rendered_name}\n"


def cmd_cd(shell, args: list) -> str:
    new_path = None
    target_display = None

    if not args:
        new_path = shell.env['HOME']
        target_display = '~'
    elif args[0] == '-':
        new_path = shell.env.get('OLDPWD', shell.env['HOME'])
    else:
        new_path = shell.normalize_path(args[0])
        target_display = args[0]

    new_path = shell.normalize_path(new_path)

    if not shell._check_read_permission(new_path):
        if new_path == '/root' and shell.username != 'root':
            return f"-bash: cd: {new_path}: Permission denied\n"

    if new_path.startswith('/etc/ssh') or new_path.startswith('/etc/ssl'):
        if shell.username != 'root':
            return f"-bash: cd: {new_path}: Permission denied\n"

    if new_path and new_path in shell.fs_state:
        shell.env['OLDPWD'] = shell.current_path
        shell.current_path = new_path
        shell.env['PWD'] = shell.current_path

        if args and args[0] == '-':
            return f"{new_path}\n"
        return ''
    else:
        display = target_display if target_display else new_path
        return f"-bash: cd: {display}: No such file or directory\n"


def cmd_cat(shell, args: list) -> str:
    if not args:
        buf = getattr(shell, '_stdin_buffer', None)
        if buf is None:
            return ""
        return str(buf)

    expanded_args = shell._expand_wildcards(args)
    output = ""
    for arg in expanded_args:
        path = shell.normalize_path(arg)

        if path in shell.fs_state:
            output += f"cat: {arg}: Is a directory\n"
            continue

        if not shell._check_read_permission(path):
            output += f"cat: {arg}: Permission denied\n"
            continue

        if path == "/dev/null":
            continue
        if path == "/dev/zero":
            output += "\x00" * 1024
            continue
        if path in ["/dev/random", "/dev/urandom"]:
            output += "".join([chr(random.randint(32, 126)) for _ in range(100)]) + "\n"
            continue

        if path.startswith("/proc/"):
            filename = path.split("/")[-1]
            proc_content = ""
            if filename == "cpuinfo":
                flags = ("fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush "
                         "dts acpi mmx fxsr sse sse2 ss ht tm pbe syscall nx pdpe1gb rdtscp lm constant_tsc "
                         "art arch_perfmon pebs bts rep_good nopl xtopology nonstop_tsc cpuid aperfmperf pni "
                         "pclmulqdq dtes64 monitor ds_cpl vmx smx est tm2 ssse3 sdbg fma cx16 xtpr pdcm pcid "
                         "sse4_1 sse4_2 x2apic movbe popcnt tsc_deadline_timer aes xsave avx f16c rdrand "
                         "lahf_lm abm 3dnowprefetch cpuid_fault epb invpcid_single pti ssbd ibrs ibpb stibp "
                         "tpr_shadow vnmi flexpriority ept vpid ept_ad fsgsbase tsc_adjust bmi1 avx2 smep "
                         "bmi2 erms invpcid mpx rdseed adx smap clflushopt intel_pt xsaveopt xsavec xgetbv1 "
                         "xsaves dtherm ida arat pln pts hwp hwp_notify hwp_act_window hwp_epp md_clear flush_l1d")
                blocks = []
                for cpu_idx in range(12):
                    core_id = cpu_idx // 2
                    blocks.append(f"""processor\t: {cpu_idx}
vendor_id\t: GenuineIntel
cpu family\t: 6
model\t\t: 158
model name\t: Intel(R) Xeon(R) E-2236 CPU @ 3.40GHz
stepping\t: 10
microcode\t: 0xca
cpu MHz\t\t: 3400.000
cache size\t: 12288 KB
physical id\t: 0
siblings\t: 12
core id\t\t: {core_id}
cpu cores\t: 6
apicid\t\t: {cpu_idx}
initial apicid\t: {cpu_idx}
fpu\t\t: yes
fpu_exception\t: yes
cpuid level\t: 22
wp\t\t: yes
flags\t\t: {flags}
bugs\t\t: cpu_meltdown spectre_v1 spectre_v2 spec_store_bypass l1tf mds swapgs itlb_multihit srbds
bogomips\t: 6800.00
clflush size\t: 64
cache_alignment\t: 64
address sizes\t: 46 bits physical, 48 bits virtual
power management:
""")
                output += "\n".join(blocks)
                continue
            if filename == "meminfo":
                mem = shell._get_mem_status()
                proc_content = f"""MemTotal:        {mem['total']} kB
MemFree:         {mem['free']} kB
MemAvailable:    {mem['available']} kB
Buffers:          {mem['buffers_cache'] // 10} kB
Cached:          {mem['buffers_cache'] * 9 // 10} kB
SwapCached:            0 kB
Active:           {mem['used'] - 200000} kB
Inactive:         {mem['free'] // 2} kB
SwapTotal:       {mem['swap_total']} kB
SwapFree:        {mem['swap_free']} kB
Shmem:             12048 kB
Slab:             134520 kB
PageTables:         4560 kB
NFS_Unstable:          0 kB
Bounce:                0 kB
HugePages_Total:       0
HugePages_Free:        0
DirectMap4k:      204800 kB
DirectMap2M:     3840000 kB
"""
            elif filename == "version":
                proc_content = f"Linux version {KERNEL_RELEASE} (buildd@bos03-amd64-046) (x86_64-linux-gnu-gcc-13 (Ubuntu 13.2.0-23ubuntu4) 13.2.0, GNU ld (GNU Binutils for Ubuntu) 2.42) {KERNEL_VERSION_STRING}\n"
            elif filename == "uptime":
                elapsed = (datetime.now() - SERVER_START_TIME).total_seconds()
                proc_content = f"{elapsed:.2f} {elapsed*0.98:.2f}\n"
            elif filename == "loadavg":
                l1, l5, l15 = shell._get_load_average()
                proc_content = f"{l1:.2f} {l5:.2f} {l15:.2f} 1/120 {os.getpid()}\n"
            elif filename == "stat":
                proc_content = "cpu  28372 0 24882 17392023 2394 0 123 0 0 0\n"
            elif filename == "mounts":
                proc_content = "/dev/sda2 / ext4 rw,relatime 0 0\n/dev/sda1 /boot/efi vfat rw,relatime 0 0\nproc /proc proc rw,relatime 0 0\nsysfs /sys sysfs rw,relatime 0 0\n"
            elif filename == "hostname":
                proc_content = HONEYPOT_IDENTITY.get("hostname", "ubuntu-server") + "\n"

            if proc_content:
                output += proc_content
                continue

        exists, content, _ = _read_virtual_file(shell, path, binary_stub=True)
        if exists:
            output += content
        else:
            output += f"cat: {arg}: No such file or directory\n"

    return output


def cmd_head(shell, args: list) -> str:
    if not args:
        return ""

    count = 10
    files = []
    i = 0
    while i < len(args):
        if args[i] == '-n' and i + 1 < len(args):
            try:
                count = int(args[i + 1])
                i += 2
                continue
            except Exception:
                pass
        elif args[i].startswith('-n'):
            try:
                count = int(args[i][2:])
                i += 1
                continue
            except Exception:
                pass
        elif not args[i].startswith('-'):
            files.append(args[i])
        i += 1

    if not files:
        return ""

    path = shell.normalize_path(files[0])
    if not shell._check_read_permission(path):
        return f"head: cannot open '{files[0]}': Permission denied\n"

    if path in shell.fs_state:
        return f"head: error reading '{files[0]}': Is a directory\n"

    exists, content, _ = _read_virtual_file(shell, path, binary_stub=True)
    if not exists:
        return f"head: cannot open '{files[0]}': No such file or directory\n"

    lines = content.split('\n')
    if lines and lines[-1] == '':
        lines.pop()

    return '\n'.join(lines[:count]) + '\n'


def cmd_tail(shell, args: list) -> str:
    if not args:
        return ""

    count = 10
    files = []
    i = 0
    while i < len(args):
        if args[i] == '-n' and i + 1 < len(args):
            try:
                count = int(args[i + 1])
                i += 2
                continue
            except Exception:
                pass
        elif args[i].startswith('-n'):
            try:
                count = int(args[i][2:])
                i += 1
                continue
            except Exception:
                pass
        elif not args[i].startswith('-'):
            files.append(args[i])
        i += 1

    if not files:
        return ""

    path = shell.normalize_path(files[0])
    if not shell._check_read_permission(path):
        return f"tail: cannot open '{files[0]}': Permission denied\n"

    if path in shell.fs_state:
        return f"tail: error reading '{files[0]}': Is a directory\n"

    exists, content, _ = _read_virtual_file(shell, path, binary_stub=True)
    if not exists:
        return f"tail: cannot open '{files[0]}': No such file or directory\n"

    lines = content.split('\n')
    if lines and lines[-1] == '':
        lines.pop()

    return '\n'.join(lines[-count:]) + '\n'


def cmd_grep(shell, args: list) -> str:
    if len(args) < 1:
        shell._last_status_explicit = 2
        return "usage: grep [OPTION]... PATTERNS [FILE]...\n"

    ignore_case = False
    show_line_no = False
    recursive = False
    invert = False
    quiet = False
    pattern = None
    files = []
    for arg in args:
        if pattern is None and arg.startswith('-'):
            if 'i' in arg:
                ignore_case = True
            if 'n' in arg:
                show_line_no = True
            if 'v' in arg:
                invert = True
            if 'q' in arg:
                quiet = True
            if 'r' in arg or arg == '-R':
                recursive = True
            continue
        if pattern is None:
            pattern = arg
            continue
        if not arg.startswith('-'):
            files.append(arg)

    if not pattern:
        shell._last_status_explicit = 2
        return ""
    if not files:
        shell._last_status_explicit = 2
        return ""

    output = ""
    matched_any = False
    had_error = False

    def _iter_files(root_path: str):
        if root_path in shell.fs_state:
            stack = [root_path]
            while stack:
                d = stack.pop()
                for name in shell.fs_state.get(d, []):
                    p = shell.normalize_path(f"{d}/{name}")
                    if p in shell.fs_state:
                        stack.append(p)
                    else:
                        yield p
        else:
            yield root_path

    def _load_content(path: str) -> str:
        if path in shell.files_content:
            return shell.files_content[path]
        if path in VIRTUAL_FILES:
            return VIRTUAL_FILES[path]
        if path.startswith('/proc/'):
            if 'cpuinfo' in path:
                return cmd_cat(shell, ['/proc/cpuinfo'])
            if 'meminfo' in path:
                return cmd_cat(shell, ['/proc/meminfo'])
        return ""

    for file in files:
        path = shell.normalize_path(file)
        targets = list(_iter_files(path)) if recursive else [path]
        for t in targets:
            if not shell._check_read_permission(t):
                had_error = True
                output += f"grep: {file}: Permission denied\n"
                continue
            exists_path, is_dir = _virtual_path_exists(shell, t)
            if not exists_path:
                had_error = True
                output += f"grep: {file}: No such file or directory\n"
                continue
            if is_dir and not recursive:
                had_error = True
                output += f"grep: {file}: Is a directory\n"
                continue
            content = _load_content(t)
            if content is None:
                continue
            lines = content.split('\n')
            for idx, line in enumerate(lines, 1):
                hay = line.lower() if ignore_case else line
                needle = pattern.lower() if ignore_case else pattern
                matched = needle in hay
                if invert:
                    matched = not matched
                if matched:
                    matched_any = True
                    if quiet:
                        shell._last_status_explicit = 0
                        return ""
                    prefix = ""
                    if recursive or len(files) > 1:
                        prefix = f"{t}:"
                    if show_line_no:
                        prefix = f"{prefix}{idx}:"
                    output += f"{prefix}{line}\n"
    if had_error:
        shell._last_status_explicit = 2
    else:
        shell._last_status_explicit = 0 if matched_any else 1
    return output


def cmd_sed(shell, args: list) -> str:
    if not args:
        return ""

    in_place = False
    no_print = False
    command = None
    input_file = None

    for arg in args:
        if arg == '-n':
            no_print = True
            continue
        if arg == '-i' or arg.startswith('-i'):
            in_place = True
            continue
        if arg.startswith('s/') or arg.startswith("'s/") or arg.startswith('"s/'):
            command = arg.replace("'", "").replace('"', '')
        elif not arg.startswith('-'):
            input_file = arg

    if not command:
        return ""

    parts = command.split('/')
    if len(parts) < 3:
        return ""

    pattern = parts[1]
    replacement = parts[2]
    global_replace = len(parts) > 3 and 'g' in parts[3]

    content = ""
    if input_file:
        path = shell.normalize_path(input_file)
        if path in shell.files_content:
            content = shell.files_content[path]
        elif path in VIRTUAL_FILES:
            content = VIRTUAL_FILES[path]

    if not content:
        return ""

    result = ""
    for line in content.split('\n'):
        if global_replace:
            new_line = line.replace(pattern, replacement)
        else:
            new_line = line.replace(pattern, replacement, 1)
        result += new_line + "\n"

    if in_place and input_file:
        shell.files_content[path] = result
        shell._save_session_state()
        return ""
    if no_print:
        return ""
    return result


def cmd_cut(shell, args: list) -> str:
    if not args:
        return ""

    delimiter = '\t'
    fields = []
    input_file = None
    i = 0
    while i < len(args):
        if args[i] == '-d' and i + 1 < len(args):
            delimiter = args[i + 1].replace("'", "").replace('"', '')
            i += 2
        elif args[i].startswith('-d'):
            delimiter = args[i][2:].replace("'", "").replace('"', '')
            i += 1
        elif args[i] == '-f' and i + 1 < len(args):
            fields = [int(x) for x in args[i + 1].split(',') if x.isdigit()]
            i += 2
        elif args[i].startswith('-f'):
            fields = [int(x) for x in args[i][2:].split(',') if x.isdigit()]
            i += 1
        elif not args[i].startswith('-'):
            input_file = args[i]
            i += 1
        else:
            i += 1

    if not fields or not input_file:
        return ""

    path = shell.normalize_path(input_file)
    content = ""
    if path in shell.files_content:
        content = shell.files_content[path]
    elif path in VIRTUAL_FILES:
        content = VIRTUAL_FILES[path]

    if not content:
        return ""

    result = ""
    for line in content.split('\n'):
        if not line:
            continue
        parts = line.split(delimiter)
        selected = []
        for f in fields:
            if f > 0 and f <= len(parts):
                selected.append(parts[f - 1])
        result += delimiter.join(selected) + "\n"

    return result


def cmd_sort(shell, args: list) -> str:
    if not args:
        return ""

    reverse = '-r' in args
    numeric = '-n' in args
    unique = '-u' in args
    key_idx = 0
    input_file = [a for a in args if not a.startswith('-')]

    if '-k' in args:
        try:
            k_idx = args.index('-k')
            key_idx = max(0, int(args[k_idx + 1]) - 1)
        except Exception:
            key_idx = 0

    if not input_file:
        return ""

    path = shell.normalize_path(input_file[0])
    content = ""
    if path in shell.files_content:
        content = shell.files_content[path]
    elif path in VIRTUAL_FILES:
        content = VIRTUAL_FILES[path]

    if not content:
        return ""

    lines = [line for line in content.split('\n') if line]
    try:
        def _key(line: str):
            parts = line.split()
            val = parts[key_idx] if key_idx < len(parts) else (parts[0] if parts else "")
            if numeric:
                try:
                    return float(val)
                except Exception:
                    return 0.0
            return val

        lines.sort(key=_key, reverse=reverse)
    except Exception:
        lines.sort(reverse=reverse)

    if unique:
        uniq_lines = []
        prev = None
        for line in lines:
            if line != prev:
                uniq_lines.append(line)
                prev = line
        lines = uniq_lines

    return '\n'.join(lines) + '\n'


def cmd_uniq(shell, args: list) -> str:
    count = '-c' in args
    input_file = [a for a in args if not a.startswith('-')]
    if not input_file:
        return ""
    path = shell.normalize_path(input_file[0])
    content = shell.files_content.get(path, VIRTUAL_FILES.get(path, ""))
    if not content:
        return ""
    lines = content.split('\n')
    result = []
    prev = None
    n = 0
    for line in lines:
        if line != prev:
            if prev is not None and count:
                result.append(f"{n:>7} {prev}")
            elif prev is not None:
                result.append(prev)
            prev = line
            n = 1
        else:
            n += 1
    if prev is not None:
        if count:
            result.append(f"{n:>7} {prev}")
        else:
            result.append(prev)
    return '\n'.join(result) + "\n"


def cmd_wc(shell, args: list) -> str:
    if not args:
        return ""
    input_file = [a for a in args if not a.startswith('-')]
    if not input_file:
        return ""
    path = shell.normalize_path(input_file[0])
    exists, content, is_binary_stub = _read_virtual_file(shell, path, binary_stub=True)
    if not exists:
        return f"wc: {input_file[0]}: No such file or directory\n"
    lines = len(content.split('\n'))
    words = len(content.split())
    chars = shell._get_file_size(path, False) if is_binary_stub else len(content)
    if '-l' in args:
        return f"{lines}\n"
    if '-w' in args:
        return f"{words}\n"
    if '-c' in args:
        return f"{chars}\n"
    return f"  {lines}  {words}  {chars} {input_file[0]}\n"


def cmd_stat(shell, args: list) -> str:
    if not args:
        return "stat: missing operand\n"
    path = shell.normalize_path(args[0])
    norm, is_dir = _virtual_path_exists(shell, path)
    if not norm:
        return f"stat: cannot stat '{args[0]}': No such file or directory\n"
    size = shell._get_file_size(path, is_dir)
    blocks = max(1, int((size + 511) / 512))
    date_str = shell._get_file_timestamp(path)
    owner, group = shell.file_owners.get(path, ("root", "root"))
    file_type = "directory" if is_dir else "regular file"

    perm = shell.file_perms.get(path, _default_virtual_perm(path, is_dir))
    def _perm_to_mode(p: str) -> str:
        if not p or len(p) < 10:
            return "0644"
        triples = [p[1:4], p[4:7], p[7:10]]
        def tri_to_digit(t):
            val = 0
            if len(t) >= 1 and t[0] == 'r': val += 4
            if len(t) >= 2 and t[1] == 'w': val += 2
            if len(t) >= 3 and t[2] == 'x': val += 1
            return str(val)
        return "0" + "".join(tri_to_digit(t) for t in triples)
    mode_str = _perm_to_mode(perm)
    inode = abs(hash(path)) % 20000000 + 100000
    device_major = 8
    device_minor = 1
    return f'''  File: {args[0]}
  Size: {size}        Blocks: {blocks:<10} IO Block: 4096   {file_type}
Device: {device_major:02x}{device_minor:02x}h/{device_major*256+device_minor}d    Inode: {inode}     Links: 1
Access: ({mode_str}/{perm})  Uid: ({owner:>5}/  {owner})   Gid: ({group:>5}/  {group})
Access: {date_str}
Modify: {date_str}
Change: {date_str}
 Birth: -
'''


def cmd_base64(shell, args: list) -> str:
    import base64 as b64
    decode = '-d' in args
    input_file = [a for a in args if not a.startswith('-')]
    if not input_file:
        return ""
    path = shell.normalize_path(input_file[0])
    exists, content, is_binary_stub = _read_virtual_file(shell, path, binary_stub=True)
    if not exists:
        return ""
    try:
        if decode:
            return b64.b64decode(content.strip()).decode('utf-8') + '\n'
        payload = content.encode('latin-1', errors='ignore') if is_binary_stub else content.encode()
        return b64.b64encode(payload).decode() + '\n'
    except Exception:
        return "base64: invalid input\n"


def cmd_md5sum(shell, args: list) -> str:
    import hashlib
    if not args:
        return ""
    path = shell.normalize_path(args[0])
    exists, content, is_binary_stub = _read_virtual_file(shell, path, binary_stub=True)
    if not exists:
        return f"md5sum: {args[0]}: No such file or directory\n"
    m = hashlib.md5()
    payload = content.encode('latin-1', errors='ignore') if is_binary_stub else content.encode('utf-8')
    m.update(payload)
    return f"{m.hexdigest()}  {args[0]}\n"


def cmd_sudo(shell, args: list) -> str:
    """模拟 sudo 提权执行。"""
    if not args:
        return "usage: sudo -h | -K | -k | -V | -v | -l | -L | -P | [-A] [-b] [-C fd] [-g group] [-H] [-p prompt] [-S] [-u user] command\n"

    if shell.username not in ['root', 'ubuntu']:
        return f"{shell.username} is not in the sudoers file.  This incident will be reported.\n"

    # sudo -k 清理当前 TTY 缓存；sudo -K 清理当前用户全部 TTY 缓存
    if args[0] == '-k':
        if hasattr(shell, '_clear_sudo_cache'):
            shell._clear_sudo_cache(shell.username)
        return ""
    if args[0] == '-K':
        if hasattr(shell, '_clear_sudo_cache_all_tty'):
            shell._clear_sudo_cache_all_tty(shell.username)
        elif hasattr(shell, '_clear_sudo_cache'):
            shell._clear_sudo_cache(shell.username)
        return ""

    # sudo -v 刷新或验证缓存
    if args[0] == '-v':
        if shell.username == 'root':
            return ""
        if hasattr(shell, '_sudo_cache_valid') and shell._sudo_cache_valid(shell.username):
            shell._touch_sudo_cache(shell.username)
            return ""
        shell.interactive_state = {
            'func': shell._sudo_authenticate,
            'args': {'mode': 'noop', 'user': shell.username},
            'echo': False,
            'prompt': ''
        }
        return f"[sudo] password for {shell.username}: "

    # root 直接执行，不触发口令校验
    if shell.username == 'root':
        return shell.execute_command(" ".join(args), record_history=False)

    # 缓存有效时直接提权执行
    if hasattr(shell, '_sudo_cache_valid') and shell._sudo_cache_valid(shell.username):
        old_user = shell.username
        shell.username = 'root'
        try:
            cmd = " ".join(args)
            logger.info(f"[SUDO] 用户 {old_user} 使用缓存提权执行: {cmd}")
            shell._touch_sudo_cache(old_user)
            return shell.execute_command(cmd, record_history=False)
        finally:
            shell.username = old_user

    shell.interactive_state = {
        'func': shell._sudo_authenticate,
        'args': {'mode': 'exec', 'user': shell.username, 'cmd': args},
        'echo': False,
        'prompt': ''
    }
    return f"[sudo] password for {shell.username}: "


def cmd_id(shell, args: list) -> str:
    target_user = args[0] if args else shell.username
    identity = _resolve_user_identity(shell, target_user)
    if not identity:
        shell._last_status_explicit = 1
        return f"id: '{target_user}': no such user\n"
    shell._last_status_explicit = 0
    group_text = ",".join(
        f"{group_id}({group_name})" for group_id, group_name in identity['groups']
    )
    return (
        f"uid={identity['uid']}({identity['user']}) "
        f"gid={identity['gid']}({identity['primary_group']}) "
        f"groups={group_text}\n"
    )


def cmd_ss(shell, args: list) -> str:
    show_listen = _arg_has_short_option(args, '-l')
    show_tcp = _arg_has_short_option(args, '-t')
    show_udp = _arg_has_short_option(args, '-u')
    show_proc = _arg_has_short_option(args, '-p')
    if not (show_tcp or show_udp):
        show_tcp = True

    header = "State      Recv-Q Send-Q Local Address:Port               Peer Address:Port"
    if show_proc:
        header += "              Process"
    header += "\n"
    output = header

    ensure_service_state(shell)
    ssh_running = _service_running(shell, "ssh")
    resolved_running = _service_running(shell, "systemd-resolved")
    sshd_pid, _ = _service_pid_cmd(shell, "ssh")
    resolved_pid, _ = _service_pid_cmd(shell, "systemd-resolved")
    sshd_pid = sshd_pid or "512"
    resolved_pid = resolved_pid or "720"

    def _fmt(line: str, proc: str = "") -> str:
        if show_proc:
            return f"{line} {proc}\n"
        return f"{line}\n"

    if show_tcp and ssh_running:
        if not show_listen:
            output += _fmt(
                f"ESTAB      0      0      {HONEYPOT_IDENTITY['server_ip']}:22                 {shell.client_ip}:{getattr(shell,'client_port',54321)}"
            )
        else:
            output += _fmt(
                "LISTEN     0      128          0.0.0.0:22                      0.0.0.0:*",
                f"users:((\"sshd\",pid={sshd_pid},fd=3))"
            )
            output += _fmt(
                "LISTEN     0      128             [::]:22                         [::]:*",
                f"users:((\"sshd\",pid={sshd_pid},fd=4))"
            )
    if show_udp and resolved_running:
        output += _fmt(
            "UNCONN     0      0        127.0.0.53%lo:53                       0.0.0.0:*",
            f"users:((\"systemd-resolve\",pid={resolved_pid},fd=13))"
        )

    return output


def cmd_uname(shell, args: list) -> str:
    if _arg_has_short_option(args, '-a'):
        return f"Linux {shell.hostname} {KERNEL_RELEASE} {KERNEL_VERSION_STRING} x86_64 x86_64 x86_64 GNU/Linux\n"
    if _arg_has_short_option(args, '-r'):
        return f"{KERNEL_RELEASE}\n"
    if _arg_has_short_option(args, '-v'):
        return f"{KERNEL_VERSION_STRING}\n"
    if _arg_has_short_option(args, '-m'):
        return "x86_64\n"
    if _arg_has_short_option(args, '-n'):
        return f"{shell.hostname}\n"
    if _arg_has_short_option(args, '-o'):
        return "GNU/Linux\n"
    if _arg_has_short_option(args, '-s'):
        return "Linux\n"
    if _arg_has_short_option(args, '-p') or _arg_has_short_option(args, '-i'):
        return "x86_64\n"
    return "Linux\n"


def cmd_hostname(shell, args: list) -> str:
    if '/etc/hostname' in shell.files_content:
        return shell.files_content['/etc/hostname'].strip() + '\n'
    if '/etc/hostname' in VIRTUAL_FILES:
        return VIRTUAL_FILES['/etc/hostname'].strip() + '\n'
    return shell.hostname + '\n'


def cmd_hostnamectl(shell, args: list) -> str:
    hostname = cmd_hostname(shell, []).strip() or shell.hostname or HONEYPOT_IDENTITY.get('hostname', 'ubuntu-server')
    if args and args[0] == '--static':
        return hostname + '\n'
    return f''' Static hostname: {hostname}
       Icon name: computer-vm
         Chassis: vm
      Machine ID: 9d3ad1f35a8548ec8a7f4d7b1b0f6f21
         Boot ID: 2c8dcf7b1bdb4cb78174db35f8fdf9c8
  Virtualization: kvm
 Operating System: Ubuntu 24.04.2 LTS
          Kernel: Linux {KERNEL_RELEASE}
    Architecture: x86-64
 Hardware Vendor: QEMU
  Hardware Model: Standard PC (Q35 + ICH9, 2009)
'''


def cmd_ip(shell, args: list) -> str:
    if not args:
        return "Usage: ip [ OPTIONS ] OBJECT { COMMAND }\n"

    if args[0] == '-br' and len(args) > 1 and args[1] in ['addr', 'a', 'address']:
        server_ip = HONEYPOT_IDENTITY.get('server_ip', '10.0.12.10')
        return f'''lo               UNKNOWN        127.0.0.1/8 ::1/128
eth0             UP             {server_ip}/24
'''

    if args[0] in ['addr', 'a', 'address']:
        server_ip = HONEYPOT_IDENTITY.get('server_ip', '10.0.12.10')
        mac_address = str(getattr(shell, 'mac_address', '52:54:00:12:34:56') or '52:54:00:12:34:56')
        mac_parts = mac_address.split(':')
        ipv6_suffix = f"{mac_parts[0]}{mac_parts[1]}:{mac_parts[2]}ff:fe{mac_parts[3]}:{mac_parts[4]}{mac_parts[5]}"
        ipv6_ll = f"fe80::{ipv6_suffix}"

        return f'''1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether {mac_address} brd ff:ff:ff:ff:ff:ff
    inet {server_ip}/24 brd {server_ip.rsplit('.', 1)[0]}.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 {ipv6_ll}/64 scope link
       valid_lft forever preferred_lft forever
'''

    if args[0] in ['route', 'r']:
        server_ip = HONEYPOT_IDENTITY.get('server_ip', '10.0.12.10')
        gateway = server_ip.rsplit('.', 1)[0] + '.1'
        return f'''default via {gateway} dev eth0 proto static
{gateway.rsplit('.', 1)[0]}.0/24 dev eth0 proto kernel scope link src {server_ip}
'''

    if args[0] in ['link', 'l']:
        mac_address = str(getattr(shell, 'mac_address', '52:54:00:12:34:56') or '52:54:00:12:34:56')
        return f'''1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000
    link/ether {mac_address} brd ff:ff:ff:ff:ff:ff
'''

    if args[0] in ['neigh', 'n', 'neighbour']:
        server_ip = HONEYPOT_IDENTITY.get('server_ip', '10.0.12.10')
        gateway = server_ip.rsplit('.', 1)[0] + '.1'
        attacker = shell.client_ip

        return f'''{gateway} dev eth0 lladdr 50:54:00:02:23:45 REACHABLE
{attacker} dev eth0 lladdr 00:0c:29:1a:2b:3c STALE
'''

    return "Usage: ip [ OPTIONS ] OBJECT { COMMAND }\n"


def cmd_ps(shell, args: list) -> str:
    show_all = False
    full_format = False
    mode_aux = False

    args_str = "".join(args)
    if 'aux' in args_str or (('a' in args_str) and ('u' in args_str) and ('x' in args_str)):
        mode_aux = True
        show_all = True
    else:
        if 'e' in args_str or 'a' in args_str:
            show_all = True
        if 'f' in args_str or 'u' in args_str:
            full_format = True

    if not hasattr(shell, 'processes') or not shell.processes:
        shell._init_processes()

    shell._tick_process_times()

    output = ""
    if mode_aux:
        output += "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
    elif full_format:
        output += "UID          PID    PPID  C STIME TTY          TIME CMD\n"
    else:
        output += "    PID TTY          TIME CMD\n"

    active_procs = []
    for pid, info in shell.processes.items():
        if pid in shell.killed_pids:
            continue

        is_tty = ('bash' in info['cmd'] or 'ps' in info['cmd'])

        # 无参数时仅显示当前终端相关进程，贴近真实 ps 行为
        if not show_all and not is_tty:
            continue

        active_procs.append((pid, info))

    ps_pid = str(random.randint(3000, 9000))
    ps_cmd = 'ps' if not args else ('ps ' + ' '.join(args))
    active_procs.append((ps_pid, {'user': shell.username, 'ppid': shell.shell_pid, 'cmd': ps_cmd, 'port': None}))

    if mode_aux or 'u' in args_str:
        active_procs.sort(key=lambda x: x[1].get('cpu_pct', 0.0), reverse=True)
    else:
        active_procs.sort(key=lambda x: int(x[0]) if x[0].isdigit() else 0)

    def _fmt_time(seconds: float) -> str:
        if seconds < 0:
            seconds = 0
        s = int(seconds)
        h = s // 3600
        m = (s % 3600) // 60
        sec = s % 60
        return f"{h:02d}:{m:02d}:{sec:02d}"

    def _fmt_stime(dt):
        if not isinstance(dt, datetime):
            return "Jan01"
        now = datetime.now()
        if (now - dt).days >= 1:
            return dt.strftime("%b%d")
        return dt.strftime("%H:%M")

    mem_total = shell._get_mem_status().get('total', 1024000)

    for pid, info in active_procs:
        user = info['user']
        ppid = info['ppid']
        cmd = info['cmd']
        stime = _fmt_stime(info.get('start_time'))

        tty = "?"
        if 'bash' in cmd or 'ps' in cmd:
            tty = _shell_tty_label(shell)

        time_str = _fmt_time(info.get('cpu_time', 0.0))

        cpu_pct = info.get('cpu_pct', 0.0)
        mem_pct = info.get('mem_pct', 0.0)
        rss_kb = int(mem_total * (mem_pct / 100.0))
        if rss_kb <= 0:
            rss_kb = random.randint(1024, 8192)
        vsz_kb = rss_kb * 3 + random.randint(1024, 16384)
        stat = "Ss" if user == 'root' else "S"

        cpu_col = f"{int(cpu_pct):>2}"
        if mode_aux:
            output += f"{user:<8} {pid:>5} {cpu_pct:>4.1f} {mem_pct:>4.1f} {vsz_kb:>6} {rss_kb:>5} {tty:<8} {stat:<4} {stime:<6} {time_str:>8} {cmd}\n"
        elif full_format:
            output += f"{user:<8} {pid:>6} {ppid:>7} {cpu_col} {stime:<5} {tty:<8} {time_str:>8} {cmd}\n"
        else:
            display_cmd = cmd.lstrip('-')
            output += f"{pid:>5} {tty:<7} {time_str:>8} {display_cmd}\n"

    return output


def cmd_kill(shell, args: list) -> str:
    if not args:
        return "kill: usage: kill [-s sigspec | -n signum | -sigspec] pid | jobspec ... or kill -l [sigspec]\n"

    pid = args[-1]
    if pid.startswith('-'):
        pass

    if pid == getattr(shell, 'shell_pid', None):
        return "logout\n"

    shell.killed_pids.add(pid)
    ensure_service_state(shell)
    for service_key in list(getattr(shell, "services_state", {}).keys()):
        state = shell.services_state.get(service_key, {})
        if str(state.get("pid") or "") == str(pid):
            _set_service_running(shell, service_key, False, save=False)
            break
    try:
        shell._save_session_state()
    except Exception:
        pass
    return ""


def cmd_service(shell, args: list) -> str:
    if not args:
        return "Usage: service <option> | --status-all | [ service_name [ command | --full-restart ] ]\n"

    service_name = args[0]
    service_key = _normalize_service_name(service_name)
    action = args[1] if len(args) > 1 else 'status'
    ensure_service_state(shell)
    if not _service_exists(service_key):
        return f"{service_name}: unrecognized service\n"
    is_running = _service_running(shell, service_key)

    if action == 'status':
        if is_running:
            return f" * {service_key} is running\n"
        return f" * {service_key} is not running\n"

    if action == 'stop':
        if shell.username != 'root':
            return "stop: Operation not permitted\n"
        _set_service_running(shell, service_key, False)
        return f" * Stopping {service_key} \n"

    if action == 'start':
        if shell.username != 'root':
            return "start: Operation not permitted\n"
        _set_service_running(shell, service_key, True)
        return f" * Starting {service_key} \n"

    if action == 'restart':
        if shell.username != 'root':
            return "restart: Operation not permitted\n"
        _set_service_running(shell, service_key, False)
        _set_service_running(shell, service_key, True)
        return f" * Restarting {service_key} \n"

    return ""


def cmd_sshd(shell, args: list) -> str:
    version = "OpenSSH_9.6p1 Ubuntu-3ubuntu13.8, OpenSSL 3.0.13 30 Jan 2024"
    if not args:
        return "sshd re-exec requires execution with an absolute path\n"

    filtered_args = []
    i = 0
    while i < len(args):
        arg = str(args[i] or '').strip()
        if arg == '-C' and i + 1 < len(args):
            i += 2
            continue
        filtered_args.append(arg)
        i += 1

    if '-V' in filtered_args or '--version' in filtered_args:
        return version + "\n"
    if '-t' in filtered_args:
        return ""
    if '-T' in filtered_args:
        hostname = HONEYPOT_IDENTITY.get('hostname', 'ubuntu-server')
        return f"""port 22
addressfamily any
listenaddress 0.0.0.0:22
listenaddress [::]:22
usepam yes
permitrootlogin yes
passwordauthentication yes
pubkeyauthentication yes
permitemptypasswords no
challengeresponseauthentication no
kerberosauthentication no
gssapiauthentication no
x11forwarding yes
printmotd no
printlastlog yes
tcpkeepalive yes
permittty yes
allowtcpforwarding yes
allowagentforwarding yes
gatewayports no
clientaliveinterval 0
clientalivecountmax 3
pidfile /run/sshd.pid
authorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2
versionaddendum none
banner none
acceptenv LANG LC_*
loglevel INFO
syslogfacility AUTH
usedns no
hostkeyagent none
hostcertificate none
hostkey /etc/ssh/ssh_host_rsa_key
hostkey /etc/ssh/ssh_host_ecdsa_key
hostkey /etc/ssh/ssh_host_ed25519_key
hostbasedauthentication no
ignoreuserknownhosts no
ignoreRhosts yes
streamlocalbindunlink no
rekeylimit default none
modulifile /etc/ssh/moduli
authenticationmethods any
persourcemaxstartups none
persourcenetblocksize 32:128
match all
"""
    return f"sshd: no hostkeys available -- exiting.\n"


def cmd_ssh(shell, args: list) -> str:
    if not args:
        return "usage: ssh [-46AaCfGgKkMNnqsTtVvXxYy] [-B bind_interface] [-b bind_address] [-c cipher_spec] [-D [bind_address:]port] [-E log_file] [-e escape_char] [-F configfile] [-I pkcs11] [-i identity_file] [-J [user@]host[:port]] [-L address] [-l login_name] [-m mac_spec] [-O ctl_cmd] [-o option] [-p port] [-Q query_option] [-R address] [-S ctl_path] [-W host:port] [-w local_tun[:remote_tun]] destination [command]\n"

    dest = args[-1]
    for arg in args:
        if not arg.startswith('-') and '@' in arg:
            dest = arg.split('@')[1]
            break
        if not arg.startswith('-'):
            dest = arg

    logger.info(f"[SSH Pivot] {shell.client_ip} 尝试 SSH 连接到 {dest}")
    log_event_activity(shell.client_ip, 'SSH_PIVOT', f"Target: {dest}")

    if dest in ['localhost', '127.0.0.1', HONEYPOT_IDENTITY.get('server_ip'), HONEYPOT_IDENTITY.get('hostname')]:
        return "Permission denied (publickey,password).\n"

    if dest in ['db-server', '10.0.12.50', 'backup-server', '10.0.12.51']:
        time.sleep(1.0)
        return f"root@{dest}: Permission denied (publickey,password).\n"

    time.sleep(3.0)
    return f"ssh: connect to host {dest} port 22: Connection timed out\n"


def cmd_exit(shell, args: list) -> str:
    if shell.user_stack:
        prev_state = shell.user_stack.pop()
        shell.username = prev_state['username']
        shell.env = prev_state['env']
        shell.current_path = prev_state['current_path']
        shell.env['PWD'] = shell.current_path
        if prev_state.get('kind') == 'su':
            return "logout\n"
        return ""

    return '__EXIT__'


def cmd_who(shell, args: list) -> str:
    entry = _current_login_entry(shell)
    login_at = _login_entry_started_at(shell, entry)
    now = login_at.strftime('%Y-%m-%d %H:%M')
    username = str((entry or {}).get('user') or shell.username)
    client_ip = str((entry or {}).get('ip') or shell.client_ip)
    tty = _login_entry_tty(shell, entry)
    return f"{username}     {tty:<12}{now} ({client_ip})\n"


def cmd_w(shell, args: list) -> str:
    header = shell._cmd_uptime([]).strip()
    entry = _current_login_entry(shell)
    login_at = _login_entry_started_at(shell, entry)
    login_str = login_at.strftime('%H:%M')
    username = str((entry or {}).get('user') or shell.username)
    client_ip = str((entry or {}).get('ip') or shell.client_ip)
    tty = _login_entry_tty(shell, entry)
    return f'''{header}
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
{username:<8} {tty:<8} {client_ip:<15} {login_str}    1.00s  0.10s  0.00s -bash
'''


def cmd_last(shell, args: list) -> str:
    limit = 10
    user_filter = None
    i = 0
    while i < len(args):
        arg = str(args[i] or '').strip()
        if arg == '-n' and i + 1 < len(args):
            try:
                limit = max(1, min(int(args[i + 1]), 50))
            except Exception:
                pass
            i += 2
            continue
        if arg.startswith('-n') and len(arg) > 2:
            try:
                limit = max(1, min(int(arg[2:]), 50))
            except Exception:
                pass
            i += 1
            continue
        if not arg.startswith('-') and user_filter is None:
            user_filter = arg
        i += 1

    rows = []
    login_history = getattr(shell, 'login_history', [])
    if isinstance(login_history, list):
        visible_index = 0
        for entry in login_history:
            if not isinstance(entry, dict):
                continue
            login_at = entry.get('login_at')
            if not isinstance(login_at, datetime):
                continue
            user = str(entry.get('user') or shell.username)
            if user_filter and user != user_filter:
                continue
            logout_at = entry.get('logout_at')
            if not isinstance(logout_at, datetime):
                logout_at = None
            ip_addr = str(entry.get('ip') or shell.client_ip)
            tty = _login_entry_tty(shell, entry, visible_index)
            login_stamp = _format_last_login_stamp(login_at)
            if logout_at is None:
                tail = "still logged in"
            else:
                tail = f"- {logout_at:%H:%M}  {_format_last_duration(login_at, logout_at)}"
            rows.append(f"{user:<8} {tty:<12} {ip_addr:<15} {login_stamp}   {tail}")
            visible_index += 1
            if len(rows) >= limit:
                break
    if not rows:
        now = datetime.now()
        if not user_filter or user_filter == shell.username:
            rows.append(f"{shell.username:<8} {_shell_tty_label(shell):<12} {shell.client_ip:<15} {_format_last_login_stamp(now)}   still logged in")
        oldest = now
    else:
        oldest_candidates = [
            entry.get('login_at')
            for entry in login_history
            if isinstance(entry, dict)
            and isinstance(entry.get('login_at'), datetime)
            and (not user_filter or str(entry.get('user') or shell.username) == user_filter)
        ]
        oldest = min(oldest_candidates) if oldest_candidates else datetime.now()
    rows.append("")
    rows.append(f"wtmp begins {_format_last_wtmp_stamp(oldest)}")
    return '\n'.join(rows) + '\n'


def cmd_free(shell, args: list) -> str:
    mem = shell._get_mem_status()

    def fmt(val, unit_div=1, suffix=""):
        if unit_div == 1:
            return str(val)
        v = val / unit_div
        if v >= 10:
            return f"{int(v)}{suffix}"
        return f"{v:.1f}{suffix}"

    if '-h' in args:
        return f'''              total        used        free      shared  buff/cache   available
Mem:           {fmt(mem['total']*1024, 1024**3, "Gi"):>5}       {fmt(mem['used']*1024, 1024**3, "Gi"):>5}       {fmt(mem['free']*1024, 1024**3, "Gi"):>5}        {fmt(mem['shared']*1024, 1024**2, "Mi"):>4}       {fmt(mem['buffers_cache']*1024, 1024**3, "Gi"):>5}       {fmt(mem['available']*1024, 1024**3, "Gi"):>5}
Swap:          {fmt(mem['swap_total']*1024, 1024**3, "Gi"):>5}          0B       {fmt(mem['swap_free']*1024, 1024**3, "Gi"):>5}
'''
    if '-m' in args:
        return f'''              total        used        free      shared  buff/cache   available
Mem:           {mem['total']//1024:>4}        {mem['used']//1024:>4}        {mem['free']//1024:>4}          {mem['shared']//1024:>2}        {mem['buffers_cache']//1024:>4}        {mem['available']//1024:>4}
Swap:          {mem['swap_total']//1024:>4}           0        {mem['swap_free']//1024:>4}
'''
    return f'''              total        used        free      shared  buff/cache   available
Mem:        {mem['total']:>10}  {mem['used']:>10}  {mem['free']:>10}       {mem['shared']:>5}     {mem['buffers_cache']:>9}     {mem['available']:>9}
Swap:       {mem['swap_total']:>10}           0     {mem['swap_free']:>10}
'''


def cmd_df(shell, args: list) -> str:
    disk = shell._get_disk_status()

    total_k = disk['total']
    used_k = disk['used']
    avail_k = disk['available']
    use_pct = disk['use_percent']

    if '-h' in args:
        def to_h(k):
            if k > 1024*1024:
                return f"{k/(1024*1024):.0f}G"
            if k > 1024:
                return f"{k/1024:.0f}M"
            return f"{k}K"

        return f'''Filesystem      Size  Used Avail Use% Mounted on
tmpfs           394M  2.8M  391M   1% /run
/dev/sda2        {to_h(total_k):>3}   {to_h(used_k):>3}   {to_h(avail_k):>3}  {use_pct} /
tmpfs           2.0G     0  2.0G   0% /dev/shm
tmpfs           5.0M     0  5.0M   0% /run/lock
/dev/sda1       511M  6.1M  505M   2% /boot/efi
'''
    return f'''Filesystem     1K-blocks     Used Available Use% Mounted on
tmpfs               402468     2828    399640   1% /run
/dev/sda2         {total_k:>8} {used_k:>8}  {avail_k:>8}  {use_pct} /
tmpfs              2015232        0   2015232   0% /dev/shm
tmpfs                 5120        0      5120   0% /run/lock
/dev/sda1           523248     6216    517032   2% /boot/efi
'''


def cmd_clear(shell, args: list) -> str:
    return '\033[2J\033[H'


def cmd_more(shell, args: list) -> str:
    return cmd_cat(shell, args)


def cmd_less(shell, args: list) -> str:
    return cmd_cat(shell, args)


def cmd_tar(shell, args: list) -> str:
    args_str = ''.join(args)
    if 'x' in args or '-x' in args or 'x' in args_str:
        target = "archive"
        for arg in args:
            if arg.endswith('.tar.gz') or arg.endswith('.tgz') or arg.endswith('.tar'):
                target = arg

        if target.endswith('.tar.gz'):
            dir_name = target[:-7]
        elif target.endswith('.tgz'):
            dir_name = target[:-4]
        elif target.endswith('.tar'):
            dir_name = target[:-4]
        else:
            dir_name = target.split('.')[0]

        out = ""
        if 'v' in args_str:
            out = f"{dir_name}/\n"

        path = shell.normalize_path(dir_name)
        if path not in shell.fs_state:
            shell.fs_state[path] = []

        shell.file_perms[path] = "drwxr-xr-x"
        shell.file_owners[path] = (shell.username, shell.username)
        shell.file_sizes[path] = 4096
        shell.file_timestamps[path] = datetime.now()

        parent = os.path.dirname(path)
        if os.path.basename(path) not in shell.fs_state.get(parent, []):
            if parent in shell.fs_state:
                shell.fs_state[parent].append(os.path.basename(path))

        return out

    if 'c' in args or '-c' in args:
        return ""

    return "tar: must specify one of -c, -r, -t, -u, -x\n"


def cmd_history(shell, args: list) -> str:
    if '-c' in args:
        shell.history = []
        if hasattr(shell, '_save_session_state'):
            shell._save_session_state()
        return ""

    output = ""
    for i, cmd in enumerate(shell.history, 1):
        output += f" {i:>4}  {cmd}\n"
    return output


def cmd_env(shell, args: list) -> str:
    return '\n'.join([f"{k}={v}" for k, v in shell.env.items()]) + '\n'


def cmd_export(shell, args: list) -> str:
    if not args:
        return cmd_env(shell, [])
    for arg in args:
        if '=' in arg:
            key, value = arg.split('=', 1)
            shell.env[key] = value
        else:
            shell.env.setdefault(arg, "")
    return ''


def cmd_bash(shell, args: list) -> str:
    if not args or (args and args[0].startswith('-') and args[0] != '-c'):
        shell.user_stack.append({
            'username': shell.username,
            'env': shell.env.copy(),
            'current_path': shell.current_path,
            'kind': 'bash'
        })
        try:
            lvl = int(shell.env.get('SHLVL', '1'))
        except Exception:
            lvl = 1
        shell.env['SHLVL'] = str(lvl + 1)
        shell.env['SHELL'] = '/bin/bash'
        return ""

    if args[0] == '-c':
        if len(args) < 2:
            return "bash: -c: option requires an argument\n"

        full_cmd = " ".join(args[1:])
        if full_cmd.startswith('"') and full_cmd.endswith('"'):
            full_cmd = full_cmd[1:-1]
        elif full_cmd.startswith("'") and full_cmd.endswith("'"):
            full_cmd = full_cmd[1:-1]

        return shell._execute_single_command(full_cmd)

    return ""


def cmd_sh(shell, args: list) -> str:
    if not args or (args and args[0].startswith('-') and args[0] != '-c'):
        shell.user_stack.append({
            'username': shell.username,
            'env': shell.env.copy(),
            'current_path': shell.current_path,
            'kind': 'bash'
        })
        try:
            lvl = int(shell.env.get('SHLVL', '1'))
        except Exception:
            lvl = 1
        shell.env['SHLVL'] = str(lvl + 1)
        shell.env['SHELL'] = '/bin/sh'
        return ""
    return cmd_bash(shell, args)


def cmd_apt(shell, args: list) -> str:
    if shell.username != 'root':
        return "E: Could not open lock file /var/lib/dpkg/lock-frontend - open (13: Permission denied)\n"

    sub = args[0] if args else 'update'
    if sub in ('--version', '-V', '-v', 'version'):
        return "apt 2.7.14 (amd64)\n"
    time.sleep(random.uniform(2.0, 4.0))
    if sub in ['install', 'upgrade', 'full-upgrade', 'dist-upgrade']:
        pkg = 'unknown'
        for a in args[1:]:
            if not a.startswith('-'):
                pkg = a
                break
        return ("Reading package lists... Done\n"
                "Building dependency tree... Done\n"
                "Reading state information... Done\n"
                "E: Unable to locate package {pkg}\n").format(pkg=pkg)
    return "Err:1 http://archive.ubuntu.com/ubuntu noble InRelease\n  Temporary failure resolving 'archive.ubuntu.com'\nE: Failed to fetch http://archive.ubuntu.com/ubuntu/dists/noble/InRelease  Temporary failure resolving 'archive.ubuntu.com'\nE: Some index files failed to download. They have been ignored, or old ones used instead.\n"


def cmd_unminimize(shell, args: list) -> str:
    if shell.username != 'root':
        return "This command can only be run as root.\n"

    output = "This system has been minimized by removing packages and content that are\n"
    output += "not required on a system that users do not log into.\n\n"
    output += "This script will restore this content. This will take a few minutes.\n\n"
    output += "Would you like to continue? [y/N] "

    shell.interactive_state = {
        'func': shell._unminimize_confirm,
        'args': args,
        'echo': True,
        'prompt': ''
    }
    return output


def cmd_apt_get(shell, args: list) -> str:
    return cmd_apt(shell, args)


def cmd_wget(shell, args: list) -> str:
    if not args:
        return "wget: missing URL\nUsage: wget [OPTION]... [URL]...\n"

    url = args[-1]
    for arg in args:
        if not arg.startswith('-'):
            url = arg

    domain = url.split('/')[2] if '//' in url else url.split('/')[0]
    domain_only = domain.split(':')[0]

    logger.info(f"[Wget] {shell.client_ip} 请求 {url}")
    log_event_activity(shell.client_ip, 'WGET', f"URL: {url}")

    is_ip = domain_only.replace('.', '').isdigit()
    is_private = False
    if is_ip:
        if (domain_only.startswith('192.168.') or
            domain_only.startswith('10.') or
            domain_only.startswith('127.') or
            (domain_only.startswith('172.') and 16 <= int(domain_only.split('.')[1]) <= 31)):
            is_private = True
    elif domain_only == 'localhost':
        is_private = True

    time.sleep(1.0)
    date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    if is_private:
        return f"--{date}--  {url}\nConnecting to {domain}... failed: Connection refused.\n"
    return f"--{date}--  {url}\nResolving {domain_only}... failed: Temporary failure in name resolution.\nwget: unable to resolve host address '{domain_only}'\n"


def cmd_lscpu(shell, args: list) -> str:
    return '''Architecture:            x86_64
  CPU op-mode(s):        32-bit, 64-bit
  Address sizes:         46 bits physical, 48 bits virtual
  Byte Order:            Little Endian
CPU(s):                  12
  On-line CPU(s) list:   0-11
Vendor ID:               GenuineIntel
  Model name:            Intel(R) Xeon(R) E-2236 CPU @ 3.40GHz
    CPU family:          6
    Model:               158
    Thread(s) per core:  2
    Core(s) per socket:  6
    Socket(s):           1
    Stepping:            10
    CPU max MHz:         4800.0000
    CPU min MHz:         800.0000
    BogoMIPS:            6800.00
Caches (sum of all):
  L1d:                   192 KiB (6 instances)
  L1i:                   192 KiB (6 instances)
  L2:                    1.5 MiB (6 instances)
  L3:                    12 MiB (1 instance)
Vulnerabilities:
  Itlb multihit:         KVM: Mitigation: VMX disabled
  L1tf:                  Mitigation; PTE Inversion; VMX conditional cache flushes, SMT disabled
  Mds:                   Mitigation; Clear CPU buffers; SMT disabled
  Meltdown:              Mitigation; PTI
  Spec store bypass:     Mitigation; Speculative Store Bypass disabled via prctl and seccomp
  Spectre v1:            Mitigation; usercopy/swapgs barriers and __user pointer sanitization
  Spectre v2:            Mitigation; Retpolines, IBPB conditional, IBRS_FW, RSB filling
  Srbds:                 Mitigation; Microcode
  Tsx async abort:       Mitigation; TSX disabled
'''


def cmd_systemctl(shell, args: list) -> str:
    def _color_enabled() -> bool:
        try:
            flag = str(shell.env.get('SSH_COLOR', '1')).strip().lower()
            if flag in ('0', 'false', 'no', 'off'):
                return False
            term = str(shell.env.get('TERM', '') or '').strip().lower()
            return term not in ('', 'dumb')
        except Exception:
            return False

    def _status_dot(state: str) -> str:
        dot = "●"
        if not _color_enabled():
            return dot
        s = (state or '').lower()
        if 'active (running)' in s:
            return "\x1b[1;32m●\x1b[0m"
        if 'failed' in s or 'inactive' in s:
            return "\x1b[1;31m●\x1b[0m"
        if 'activating' in s or 'deactivating' in s:
            return "\x1b[1;33m●\x1b[0m"
        return dot

    def _color_state(state: str) -> str:
        if not _color_enabled():
            return state
        s = (state or '').lower()
        if 'active (running)' in s:
            return f"\x1b[1;32m{state}\x1b[0m"
        if 'failed' in s or 'inactive' in s:
            return f"\x1b[1;31m{state}\x1b[0m"
        if 'activating' in s or 'deactivating' in s:
            return f"\x1b[1;33m{state}\x1b[0m"
        return state
    if not args:
        now = datetime.now().strftime('%a %Y-%m-%d %H:%M:%S UTC')
        return f"""   State: running
    Jobs: 0 queued
  Failed: 0 units
   Since: {now}
  CGroup: /system.slice
          ├─sshd.service
          ├─cron.service
          └─rsyslog.service
"""

    cmd = args[0]
    service = args[1] if len(args) > 1 else ""
    ensure_service_state(shell)

    if cmd in ['list-units', 'list-units --type=service', '--type=service', '--type=service', '--state=running']:
        rows = []
        for key in ['cron', 'rsyslog', 'ssh', 'systemd-journald', 'systemd-resolved']:
            active = _service_running(shell, key)
            active_col = "active" if active else "inactive"
            sub = "running" if active else "dead"
            desc = _SERVICE_DESCRIPTIONS.get(key, key)
            rows.append(f"{key}.service".ljust(20) + f" loaded {active_col:<6} {sub:<7} {desc}")
        return "UNIT                LOAD   ACTIVE SUB     DESCRIPTION\n" + "\n".join(rows) + "\n"

    if cmd == 'status':
        boot_time = HONEYPOT_IDENTITY.get('boot_time') or datetime.now()
        boot_str = boot_time.strftime('%a %Y-%m-%d %H:%M:%S UTC')
        delta = datetime.now() - boot_time
        if delta.days >= 7:
            weeks = delta.days // 7
            days = delta.days % 7
            if days == 0:
                ago_str = f"{weeks} weeks ago"
            elif days == 1:
                ago_str = f"{weeks} weeks 1 day ago"
            else:
                ago_str = f"{weeks} weeks {days} days ago"
        else:
            if delta.days == 1:
                ago_str = "1 day ago"
            else:
                ago_str = f"{delta.days} days ago"

        if service in ['ssh', 'sshd', 'ssh.service']:
            pid, cmdline = _service_pid_cmd(shell, "ssh")
            running = _service_running(shell, "ssh")
            state = "active (running)" if running else "inactive (dead)"
            dot = _status_dot(state)
            state_col = _color_state(state)
            # 组织接近 systemctl 的输出格式
            import hashlib
            inv_seed = f"{boot_str}|{pid or '-'}|{shell.hostname}"
            invocation = hashlib.md5(inv_seed.encode('utf-8', errors='ignore')).hexdigest()
            pre_pid = None
            try:
                pre_pid = int(pid) - 2 if pid and str(pid).isdigit() else random.randint(1100, 1400)
            except Exception:
                pre_pid = random.randint(1100, 1400)
            tasks_limit = 3922
            mem_val = 7.2
            mem_peak = 10.2
            cpu_ms = 262

            # 附加最近 sshd 日志（取自 auth.log）
            auth_log = shell.files_content.get('/var/log/auth.log', VIRTUAL_FILES.get('/var/log/auth.log', '')).strip()
            log_lines = []
            if auth_log:
                for line in auth_log.split('\n'):
                    if 'sshd' in line:
                        log_lines.append(line)
            tail = log_lines[-8:] if log_lines else []
            fmt_tail = []
            for l in tail:
                # 输出时统一使用 sshd-session[...] 形态
                fmt_tail.append(l.replace('sshd[', 'sshd-session['))
            tail_block = ("\n" + "\n".join(fmt_tail) + "\n") if fmt_tail else ""

            return f'''{dot} ssh.service - OpenBSD Secure Shell server
     Loaded: loaded (/usr/lib/systemd/system/ssh.service; disabled; preset: enabled)
     Active: {state_col} since {boot_str}; {ago_str}
 Invocation: {invocation}
TriggeredBy: {_status_dot('active (running)')} ssh.socket
       Docs: man:sshd(8)
             man:sshd_config(5)
    Process: {pre_pid} ExecStartPre=/usr/sbin/sshd -t (code=exited, status=0/SUCCESS)
   Main PID: {pid or '-'} (sshd)
      Tasks: 1 (limit: {tasks_limit})
     Memory: {mem_val:.1f}M (peak: {mem_peak:.1f}M)
        CPU: {cpu_ms}ms
     CGroup: /system.slice/ssh.service
             └─{pid or '-'} "sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups"
{tail_block}'''
        if service in ['cron', 'cron.service']:
            pid, cmdline = _service_pid_cmd(shell, "cron")
            running = _service_running(shell, "cron")
            state = "active (running)" if running else "inactive (dead)"
            dot = _status_dot(state)
            state_col = _color_state(state)
            return f'''{dot} cron.service - Regular background program processing daemon
   Loaded: loaded (/lib/systemd/system/cron.service; enabled; vendor preset: enabled)
   Active: {state_col} since {boot_str}; {ago_str}
     Docs: man:cron(8)
           man:cron_config(5)
 Main PID: {pid or '-'} (cron)
    Tasks: 1 (limit: 4677)
   Memory: 1.2M
   CGroup: /system.slice/cron.service
           └─{pid or '-'} {cmdline or '/usr/sbin/cron -f'}
'''
        if service in ['rsyslog', 'rsyslog.service']:
            pid, cmdline = _service_pid_cmd(shell, "rsyslog")
            running = _service_running(shell, "rsyslog")
            state = "active (running)" if running else "inactive (dead)"
            dot = _status_dot(state)
            state_col = _color_state(state)
            return f'''{dot} rsyslog.service - System Logging Service
   Loaded: loaded (/lib/systemd/system/rsyslog.service; enabled; vendor preset: enabled)
   Active: {state_col} since {boot_str}; {ago_str}
     Docs: man:rsyslogd(8)
           https://www.rsyslog.com/doc/
 Main PID: {pid or '-'} (rsyslogd)
    Tasks: 4 (limit: 4677)
   Memory: 4.8M
   CGroup: /system.slice/rsyslog.service
           └─{pid or '-'} {cmdline or '/usr/sbin/rsyslogd -n -iNONE'}
'''
        if service in ['systemd-journald', 'systemd-journald.service']:
            pid, cmdline = _service_pid_cmd(shell, "systemd-journald")
            running = _service_running(shell, "systemd-journald")
            state = "active (running)" if running else "inactive (dead)"
            dot = _status_dot(state)
            state_col = _color_state(state)
            return f'''{dot} systemd-journald.service - Journal Service
   Loaded: loaded (/lib/systemd/system/systemd-journald.service; static)
   Active: {state_col} since {boot_str}; {ago_str}
 Main PID: {pid or '-'} (systemd-journald)
    Tasks: 1 (limit: 4677)
   Memory: 2.1M
   CGroup: /system.slice/systemd-journald.service
           └─{pid or '-'} {cmdline or '/lib/systemd/systemd-journald'}
'''
        if service in ['systemd-resolved', 'systemd-resolved.service']:
            pid, cmdline = _service_pid_cmd(shell, "systemd-resolved")
            running = _service_running(shell, "systemd-resolved")
            state = "active (running)" if running else "inactive (dead)"
            dot = _status_dot(state)
            state_col = _color_state(state)
            return f'''{dot} systemd-resolved.service - Network Name Resolution
   Loaded: loaded (/lib/systemd/system/systemd-resolved.service; enabled; vendor preset: enabled)
   Active: {state_col} since {boot_str}; {ago_str}
 Main PID: {pid or '-'} (systemd-resolved)
    Tasks: 1 (limit: 4677)
   Memory: 2.9M
   CGroup: /system.slice/systemd-resolved.service
           └─{pid or '-'} {cmdline or '/lib/systemd/systemd-resolved'}
'''
        if service in ['systemd-timesyncd', 'systemd-timesyncd.service']:
            pid, cmdline = _service_pid_cmd(shell, "systemd-timesyncd")
            running = _service_running(shell, "systemd-timesyncd")
            state = "active (running)" if running else "inactive (dead)"
            dot = _status_dot(state)
            state_col = _color_state(state)
            return f'''{dot} systemd-timesyncd.service - Network Time Synchronization
   Loaded: loaded (/lib/systemd/system/systemd-timesyncd.service; enabled; vendor preset: enabled)
   Active: {state_col} since {boot_str}; {ago_str}
 Main PID: {pid or '-'} (systemd-timesyncd)
    Tasks: 1 (limit: 4677)
   Memory: 1.4M
   CGroup: /system.slice/systemd-timesyncd.service
           └─{pid or '-'} {cmdline or '/lib/systemd/systemd-timesyncd'}
'''
        if service in ['systemd-networkd', 'systemd-networkd.service', 'networking', 'networking.service']:
            pid, cmdline = _service_pid_cmd(shell, "systemd-networkd")
            running = _service_running(shell, "systemd-networkd")
            state = "active (running)" if running else "inactive (dead)"
            dot = _status_dot(state)
            state_col = _color_state(state)
            return f'''{dot} systemd-networkd.service - Network Service
   Loaded: loaded (/lib/systemd/system/systemd-networkd.service; enabled; vendor preset: enabled)
   Active: {state_col} since {boot_str}; {ago_str}
 Main PID: {pid or '-'} (systemd-networkd)
    Tasks: 1 (limit: 4677)
   Memory: 2.2M
   CGroup: /system.slice/systemd-networkd.service
           └─{pid or '-'} {cmdline or '/lib/systemd/systemd-networkd'}
'''
        if service in ['dbus', 'dbus.service']:
            pid, cmdline = _service_pid_cmd(shell, "dbus")
            running = _service_running(shell, "dbus")
            state = "active (running)" if running else "inactive (dead)"
            dot = _status_dot(state)
            state_col = _color_state(state)
            return f'''{dot} dbus.service - D-Bus System Message Bus
   Loaded: loaded (/lib/systemd/system/dbus.service; static)
   Active: {state_col} since {boot_str}; {ago_str}
 Main PID: {pid or '-'} (dbus-daemon)
    Tasks: 1 (limit: 4677)
   Memory: 1.6M
   CGroup: /system.slice/dbus.service
           └─{pid or '-'} {cmdline or '/usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation'}
'''
        if service in ['ufw', 'ufw.service']:
            pid, cmdline = _service_pid_cmd(shell, "ufw")
            running = _service_running(shell, "ufw")
            state = "active (exited)" if running else "inactive (dead)"
            dot = _status_dot(state)
            state_col = _color_state(state)
            return f'''{dot} ufw.service - Uncomplicated firewall
   Loaded: loaded (/lib/systemd/system/ufw.service; enabled; vendor preset: enabled)
   Active: {state_col} since {boot_str}; {ago_str}
 Main PID: {pid or '-'} (code=exited, status=0/SUCCESS)
   CGroup: /system.slice/ufw.service
'''
        if service in ['apparmor', 'apparmor.service']:
            pid, cmdline = _service_pid_cmd(shell, "apparmor")
            running = _service_running(shell, "apparmor")
            state = "active (exited)" if running else "inactive (dead)"
            dot = _status_dot(state)
            state_col = _color_state(state)
            return f'''{dot} apparmor.service - Load AppArmor profiles
   Loaded: loaded (/lib/systemd/system/apparmor.service; enabled; vendor preset: enabled)
   Active: {state_col} since {boot_str}; {ago_str}
 Main PID: {pid or '-'} (code=exited, status=0/SUCCESS)
   CGroup: /system.slice/apparmor.service
'''
        if service in ['systemd-logind', 'systemd-logind.service']:
            pid, cmdline = _service_pid_cmd(shell, "systemd-logind")
            running = _service_running(shell, "systemd-logind")
            state = "active (running)" if running else "inactive (dead)"
            dot = _status_dot(state)
            state_col = _color_state(state)
            return f'''{dot} systemd-logind.service - User Login Management
   Loaded: loaded (/lib/systemd/system/systemd-logind.service; static)
   Active: {state_col} since {boot_str}; {ago_str}
 Main PID: {pid or '-'} (systemd-logind)
    Tasks: 1 (limit: 4677)
   Memory: 1.9M
   CGroup: /system.slice/systemd-logind.service
           └─{pid or '-'} {cmdline or '/lib/systemd/systemd-logind'}
'''
        if service in ['nginx', 'mysql', 'docker', 'apache2']:
            return f'''Unit {service}.service could not be found.
Loaded: not-found (Reason: No such file or directory)
Active: inactive (dead)
'''

        return f'''Unit {service} could not be found.
Loaded: not-found (Reason: No such file or directory)
Active: inactive (dead)
'''

    if cmd in ['start', 'stop', 'restart', 'reload', 'enable', 'disable']:
        if shell.username != 'root':
            return f"==== AUTHENTICATING FOR org.freedesktop.systemd1.manage-units ===\nAuthentication is required to manage system services or units.\nAuthenticating as: {shell.username}\nPassword: \npolkit-agent-helper-1: pam_authenticate failed: Authentication failure\n==== AUTHENTICATION FAILED ===\nFailed to {cmd} {service}.service: Access denied\nSee system logs and 'systemctl status {service}.service' for details.\n"
        service_key = _normalize_service_name(service)
        if not _service_exists(service_key):
            return f"Failed to {cmd} {service}.service: Unit {service}.service not found.\n"
        if cmd == 'start':
            _set_service_running(shell, service_key, True)
        elif cmd == 'stop':
            _set_service_running(shell, service_key, False)
        elif cmd == 'restart':
            _set_service_running(shell, service_key, False)
            _set_service_running(shell, service_key, True)
        elif cmd == 'reload':
            now_ts = datetime.now().strftime("%b %d %H:%M:%S")
            host = HONEYPOT_IDENTITY.get("hostname")
            _append_service_log(shell, service_key, f"{now_ts} {host} systemd[1]: Reloaded {_SERVICE_DESCRIPTIONS.get(service_key, service_key)}.")
            try:
                shell._save_session_state()
            except Exception:
                pass
        return ""

    return ""


def cmd_sysctl(shell, args: list) -> str:
    if not hasattr(shell, '_sysctl_state') or not isinstance(shell._sysctl_state, dict):
        shell._sysctl_state = {
            'fs.file-max': '1048576',
            'kernel.hostname': HONEYPOT_IDENTITY.get('hostname', 'ubuntu-server'),
            'kernel.osrelease': KERNEL_RELEASE,
            'kernel.randomize_va_space': '2',
            'net.ipv4.conf.all.rp_filter': '1',
            'net.ipv4.ip_forward': '0',
            'net.ipv4.tcp_syncookies': '1',
            'vm.swappiness': '60',
        }

    if not args or args[0] in ('-a', '--all'):
        lines = [f"{key} = {value}" for key, value in sorted(shell._sysctl_state.items())]
        return '\n'.join(lines) + '\n'

    if args[0] == '-w':
        if len(args) < 2 or '=' not in args[1]:
            return "sysctl: invalid syntax, continuing...\n"
        key, value = args[1].split('=', 1)
        key = key.strip()
        value = value.strip()
        if shell.username != 'root':
            return f"sysctl: permission denied on key '{key}'\n"
        shell._sysctl_state[key] = value
        return f"{key} = {value}\n"

    lines = []
    for key in args:
        if key.startswith('-'):
            continue
        value = shell._sysctl_state.get(key)
        if value is None:
            lines.append(f"sysctl: cannot stat /proc/sys/{key.replace('.', '/')}: No such file or directory")
        else:
            lines.append(f"{key} = {value}")
    return '\n'.join(lines) + ('\n' if lines else '')


def cmd_ufw(shell, args: list) -> str:
    if not hasattr(shell, '_ufw_enabled'):
        shell._ufw_enabled = True

    if not args or args[0] == 'status':
        status = 'active' if shell._ufw_enabled else 'inactive'
        if not shell._ufw_enabled:
            return "Status: inactive\n"
        return (
            f"Status: {status}\n\n"
            "To                         Action      From\n"
            "--                         ------      ----\n"
            "22/tcp                     ALLOW       Anywhere\n"
            "80/tcp                     ALLOW       Anywhere\n"
            "22/tcp (v6)                ALLOW       Anywhere (v6)\n"
            "80/tcp (v6)                ALLOW       Anywhere (v6)\n"
        )

    if args[:2] == ['app', 'list']:
        return "Available applications:\n  OpenSSH\n"

    action = args[0]
    if action in {'enable', 'disable', 'reload'}:
        if shell.username != 'root':
            return "ERROR: You need to be root to run this script\n"
        if action == 'enable':
            shell._ufw_enabled = True
            return "Firewall is active and enabled on system startup\n"
        if action == 'disable':
            shell._ufw_enabled = False
            return "Firewall stopped and disabled on system startup\n"
        return "Firewall reloaded\n"

    return f"ufw: unknown command: {action}\n"


def cmd_visudo(shell, args: list) -> str:
    if shell.username != 'root':
        return "visudo: /etc/sudoers: Permission denied\n"
    if '-c' in args:
        return "/etc/sudoers: parsed OK\n/etc/sudoers.d/README: parsed OK\n"
    return "visudo: /etc/sudoers.tmp unchanged\n"


def cmd_journalctl(shell, args: list) -> str:
    ensure_service_state(shell)
    unit = None
    follow = '-f' in args
    if '-u' in args:
        try:
            idx = args.index('-u')
            unit = args[idx + 1] if idx + 1 < len(args) else None
        except Exception:
            unit = None

    auth_log = shell.files_content.get('/var/log/auth.log', VIRTUAL_FILES.get('/var/log/auth.log', '')).strip()
    auth_lines = [l for l in auth_log.split('\n') if l]
    lines = []

    unit_key = _normalize_service_name(unit) if unit else ""
    if unit:
        if not _service_exists(unit_key):
            return "-- No entries --\n"
        lines.extend(shell.service_logs.get(unit_key, []))
        if unit_key == 'ssh':
            lines.extend([l for l in auth_lines if 'sshd' in l])
    else:
        # 未指定 unit：展示系统服务日志 + SSH 认证日志
        for key in ['systemd-journald', 'systemd-resolved', 'cron', 'rsyslog', 'ssh']:
            lines.extend(shell.service_logs.get(key, []))
        lines.extend(auth_lines[-20:])

    tail_n = 10
    if '-n' in args:
        try:
            n_idx = args.index('-n')
            tail_n = int(args[n_idx + 1])
        except Exception:
            pass

    tail_lines = lines[-tail_n:] if tail_n > 0 else lines
    if not tail_lines:
        return "-- No entries --\n"

    boot_time = HONEYPOT_IDENTITY.get('boot_time') or datetime.now()
    header = f"-- Logs begin at {boot_time.strftime('%a %Y-%m-%d %H:%M:%S')}, end at {datetime.now().strftime('%a %Y-%m-%d %H:%M:%S')}. --\n"
    body = "\n".join(tail_lines) + "\n"

    if '-xe' in args:
        now = datetime.now().strftime('%b %d %H:%M:%S')
        body += (
            f"{now} {HONEYPOT_IDENTITY.get('hostname')} systemd[1]: Failed to start Example Service.\n"
            f"{now} {HONEYPOT_IDENTITY.get('hostname')} systemd[1]: example.service: Unit entered failed state.\n"
            f"{now} {HONEYPOT_IDENTITY.get('hostname')} systemd[1]: example.service: Failed with result 'exit-code'.\n"
        )
    if follow:
        body += "-- Journal file is active; follow mode stopped.\n"
    return header + body


def cmd_date(shell, args: list) -> str:
    return datetime.now().strftime("%a %b %d %H:%M:%S UTC %Y") + "\n"


def cmd_uptime(shell, args: list) -> str:
    now = datetime.now()
    boot_time = HONEYPOT_IDENTITY.get('boot_time') or now
    delta = now - boot_time
    days = delta.days
    seconds = delta.seconds
    hours = seconds // 3600
    minutes = (seconds % 3600) // 60

    time_str = now.strftime("%H:%M:%S")
    up_str = f"{days} days, {hours}:{minutes:02d}"
    if days == 0:
        if hours == 0:
            up_str = f"{minutes} min"
        else:
            up_str = f"{hours}:{minutes:02d}"

    l1, l5, l15 = shell._get_load_average()

    return f" {time_str} up {up_str},  1 user,  load average: {l1:.2f}, {l5:.2f}, {l15:.2f}\n"


def cmd_lsb_release(shell, args: list) -> str:
    if '-a' in args:
        return '''No LSB modules are available.
Distributor ID:	Ubuntu
Description:	Ubuntu 24.04.2 LTS
Release:	24.04
Codename:	noble
'''
    if '-d' in args:
        return "Description:\tUbuntu 24.04.2 LTS\n"
    if '-r' in args:
        return "Release:\t24.04\n"
    if '-c' in args:
        return "Codename:\tnoble\n"
    return "Usage: lsb_release [options]\n"


def cmd_top(shell, args: list) -> str:
    now = datetime.now()
    boot_time = HONEYPOT_IDENTITY.get('boot_time') or now
    delta = now - boot_time
    days = delta.days
    hours = delta.seconds // 3600
    mins = (delta.seconds % 3600) // 60
    time_str = now.strftime('%H:%M:%S')

    if not hasattr(shell, 'processes') or not shell.processes:
        shell._init_processes()
    shell._tick_process_times()
    perf = shell._get_perf_state()
    l1, l5, l15 = perf['load']
    cpu = perf['cpu']
    mem = perf['mem']

    mem_total = mem['total'] / 1024
    mem_free = mem['free'] / 1024
    mem_used = mem['used'] / 1024
    mem_cache = mem['buffers_cache'] / 1024
    swap_total = mem['swap_total'] / 1024
    swap_free = mem['swap_free'] / 1024

    active = [(pid, info) for pid, info in shell.processes.items() if pid not in shell.killed_pids]
    active.sort(key=lambda x: x[1].get('cpu_pct', 0.0), reverse=True)
    top_list = active[:5]

    lines = []
    for pid, info in top_list:
        cmd = info.get('cmd', 'bash')
        user = info.get('user', 'root')
        cpu_pct = info.get('cpu_pct', 0.0)
        mem_pct = info.get('mem_pct', 0.0)
        time_val = info.get('cpu_time', 0.0)
        lines.append(f"{pid:>5} {user:<8} 20   0   15000   4500   3200 S  {cpu_pct:>4.1f}  {mem_pct:>4.1f}   {time_val:>6.2f} {cmd}")

    proc_lines = "\n".join(lines)
    total_tasks = max(20, len(active) + 5)
    sleeping = max(0, total_tasks - 1)
    return f'''top - {time_str} up {days} days, {hours:2d}:{mins:02d},  1 user,  load average: {l1:.2f}, {l5:.2f}, {l15:.2f}
Tasks:  {total_tasks:2d} total,   1 running,  {sleeping:2d} sleeping,   0 stopped,   0 zombie
%Cpu(s):  {cpu['user']:.1f} us,  {cpu['sys']:.1f} sy,  0.0 ni, {cpu['idle']:.1f} id,  {cpu['wa']:.1f} wa,  0.0 hi,  0.0 si,  0.0 st
MiB Mem :   {mem_total:6.1f} total,   {mem_free:6.1f} free,   {mem_used:6.1f} used,   {mem_cache:6.1f} buff/cache
MiB Swap:   {swap_total:6.1f} total,   {swap_free:6.1f} free,     0.0 used.   {(mem_free + mem_cache):6.1f} avail Mem

  PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND
{proc_lines}
'''


def cmd_mkdir(shell, args: list) -> str:
    if not args:
        return "mkdir: missing operand\n"

    parents = False
    targets = []
    parse_options = True
    for arg in args:
        if parse_options and arg == '--':
            parse_options = False
            continue
        if parse_options and arg.startswith('-') and arg != '-':
            for flag in arg[1:]:
                if flag == 'p':
                    parents = True
                else:
                    return f"mkdir: invalid option -- '{flag}'\n"
            continue
        targets.append(arg)

    if not targets:
        return "mkdir: missing operand\n"

    for raw_target in targets:
        target_path = shell.normalize_path(raw_target)

        if not shell._check_write_permission(target_path):
            return f"mkdir: cannot create directory '{raw_target}': Permission denied\n"

        parent_dir = os.path.dirname(target_path)
        new_dir_name = os.path.basename(target_path)

        if parents:
            parts = [part for part in target_path.split('/') if part]
            current = ""
            for part in parts:
                current += f"/{part}"
                p_dir = os.path.dirname(current) or '/'
                c_name = os.path.basename(current)
                if p_dir not in shell.fs_state:
                    return f"mkdir: cannot create directory '{raw_target}': No such file or directory\n"
                if current not in shell.fs_state:
                    if c_name not in shell.fs_state[p_dir]:
                        shell.fs_state[p_dir].append(c_name)
                    shell.fs_state[current] = []
                    shell.file_owners[current] = (shell.username, shell.username)
                    shell.file_perms[current] = "drwxr-xr-x"
                    shell.file_timestamps[current] = datetime.now()
                    shell.file_sizes[current] = 4096
            continue

        if parent_dir not in shell.fs_state:
            return f"mkdir: cannot create directory '{raw_target}': No such file or directory\n"

        if target_path in shell.fs_state or new_dir_name in shell.fs_state[parent_dir]:
            return f"mkdir: cannot create directory '{raw_target}': File exists\n"

        shell.fs_state[parent_dir].append(new_dir_name)
        shell.fs_state[target_path] = []
        shell.file_owners[target_path] = (shell.username, shell.username)
        shell.file_perms[target_path] = "drwxr-xr-x"
        shell.file_timestamps[target_path] = datetime.now()
        shell.file_sizes[target_path] = 4096

    shell._save_session_state()
    return ''


def cmd_touch(shell, args: list) -> str:
    if not args:
        return "touch: missing file operand\n"

    for arg in args:
        target_path = shell.normalize_path(arg)

        if not shell._check_write_permission(target_path):
            return f"touch: cannot touch '{arg}': Permission denied\n"

        parent_dir = os.path.dirname(target_path)
        file_name = os.path.basename(target_path)

        if parent_dir not in shell.fs_state:
            return f"touch: cannot touch '{arg}': No such file or directory\n"

        if file_name not in shell.fs_state[parent_dir]:
            shell.fs_state[parent_dir].append(file_name)
            shell.files_content[target_path] = ""
            shell.file_owners[target_path] = (shell.username, shell.username)
            shell.file_perms[target_path] = "-rw-r--r--"

        shell.file_timestamps[target_path] = datetime.now()
        if target_path not in shell.file_sizes:
            shell.file_sizes[target_path] = 0

    shell._save_session_state()
    return ''


def cmd_cp(shell, args: list) -> str:
    recursive = '-r' in args or '-R' in args or '-a' in args
    sources = [a for a in args if not a.startswith('-')]
    if len(sources) < 2:
        return "cp: missing file operand\n"

    dest = sources[-1]
    src_list = sources[:-1]
    dest_path = shell.normalize_path(dest)

    is_dest_dir = dest_path in shell.fs_state

    if len(src_list) > 1 and not is_dest_dir:
        return f"cp: target '{dest}' is not a directory\n"

    output = ""
    for src in src_list:
        src_path = shell.normalize_path(src)
        src_name = os.path.basename(src_path)

        if src_path not in shell.files_content and src_path not in shell.fs_state:
            output += f"cp: cannot stat '{src}': No such file or directory\n"
            continue

        if is_dest_dir:
            target_path = f"{dest_path}/{src_name}" if dest_path != '/' else f"/{src_name}"
        else:
            target_path = dest_path

        if src_path in shell.fs_state:
            if not recursive:
                output += f"cp: -r not specified; omitting directory '{src}'\n"
                continue
            shell._copy_recursive(src_path, target_path)
        else:
            shell._copy_file(src_path, target_path)

    shell._save_session_state()
    return output


def cmd_mv(shell, args: list) -> str:
    sources = [a for a in args if not a.startswith('-')]
    if len(sources) < 2:
        return "mv: missing file operand\n"

    dest = sources[-1]
    src_list = sources[:-1]
    dest_path = shell.normalize_path(dest)
    is_dest_dir = dest_path in shell.fs_state

    if len(src_list) > 1 and not is_dest_dir:
        return f"mv: target '{dest}' is not a directory\n"

    output = ""
    for src in src_list:
        src_path = shell.normalize_path(src)
        src_name = os.path.basename(src_path)

        if src_path not in shell.files_content and src_path not in shell.fs_state:
            output += f"mv: cannot stat '{src}': No such file or directory\n"
            continue

        if is_dest_dir:
            target_path = f"{dest_path}/{src_name}" if dest_path != '/' else f"/{src_name}"
        else:
            target_path = dest_path

        if src_path == target_path:
            output += f"mv: '{src}' and '{dest}' are the same file\n"
            continue

        if src_path in shell.fs_state:
            shell._copy_recursive(src_path, target_path, keep_metadata=True)
            shell._delete_recursive(src_path)
        else:
            shell._copy_file(src_path, target_path, keep_metadata=True)
            if src_path in shell.files_content:
                del shell.files_content[src_path]
            if src_path in shell.file_timestamps:
                del shell.file_timestamps[src_path]
            if src_path in shell.file_perms:
                del shell.file_perms[src_path]
            if src_path in shell.file_owners:
                del shell.file_owners[src_path]
            if src_path in shell.file_sizes:
                del shell.file_sizes[src_path]

            sp = os.path.dirname(src_path)
            sn = os.path.basename(src_path)
            if sp in shell.fs_state and sn in shell.fs_state[sp]:
                shell.fs_state[sp].remove(sn)

    shell._save_session_state()
    return output


def cmd_rm(shell, args: list) -> str:
    recursive = '-r' in args or '-rf' in args
    force = '-f' in args or '-rf' in args

    targets = [a for a in args if not a.startswith('-')]
    if not targets and not force:
        return "rm: missing operand\n"

    output = ""
    for arg in targets:
        path = shell.normalize_path(arg)
        parent = os.path.dirname(path)
        name = os.path.basename(path)

        if path == '/':
            output += "rm: it is dangerous to operate recursively on '/'\n"
            continue

        if not shell._check_write_permission(path):
            output += f"rm: cannot remove '{arg}': Permission denied\n"
            continue

        if parent in shell.fs_state and name in shell.fs_state[parent]:
            if path in shell.fs_state:
                if recursive:
                    shell._delete_recursive(path)
                else:
                    output += f"rm: cannot remove '{name}': Is a directory\n"
                    continue
            else:
                if path in shell.files_content:
                    del shell.files_content[path]
                if path in shell.file_timestamps:
                    del shell.file_timestamps[path]
                if path in shell.file_perms:
                    del shell.file_perms[path]
                if path in shell.file_owners:
                    del shell.file_owners[path]
                if path in shell.file_sizes:
                    del shell.file_sizes[path]

            if name in shell.fs_state[parent]:
                shell.fs_state[parent].remove(name)
        elif not force:
            output += f"rm: cannot remove '{arg}': No such file or directory\n"

    shell._save_session_state()
    return output


def cmd_chmod(shell, args: list) -> str:
    if len(args) < 2:
        return "chmod: missing operand\n"

    mode = args[0]
    target = args[1]
    path = shell.normalize_path(target)

    if path not in shell.fs_state and path not in shell.files_content:
        return f"chmod: cannot access '{target}': No such file or directory\n"

    if shell.username != 'root':
        owner, _ = shell.file_owners.get(path, ('root', 'root'))
        if shell.username != owner:
            return f"chmod: changing permissions of '{target}': Operation not permitted\n"

    perm_str = ""
    is_dir = path in shell.fs_state
    entry_type = 'd' if is_dir else '-'

    if mode.isdigit() and (len(mode) == 3 or (len(mode) == 4 and mode.startswith('0'))):
        if len(mode) == 4 and mode.startswith('0'):
            mode = mode[1:]
        mapping = {
            '0': '---', '1': '--x', '2': '-w-', '3': '-wx',
            '4': 'r--', '5': 'r-x', '6': 'rw-', '7': 'rwx'
        }
        perm_str = entry_type + mapping.get(mode[0], '---') + mapping.get(mode[1], '---') + mapping.get(mode[2], '---')
        shell.file_perms[path] = perm_str
        shell._save_session_state()
        return ''

    if mode == '+x':
        current = shell.file_perms.get(path, entry_type + "rw-r--r--")
        new_perm = list(current)
        for i in [3, 6, 9]:
            if i < len(new_perm):
                new_perm[i] = 'x'
        shell.file_perms[path] = "".join(new_perm)
        shell._save_session_state()
        return ''

    if any(op in mode for op in ['+', '-']) and any(u in mode for u in ['u', 'g', 'o', 'a']):
        current = shell.file_perms.get(path, entry_type + "rw-r--r--")
        new_perm = list(current)
        who, rest = mode.split('+', 1) if '+' in mode else mode.split('-', 1)
        op = '+' if '+' in mode else '-'
        perms = rest
        targets = []
        if 'a' in who or who == '':
            targets = [1, 4, 7]
        else:
            if 'u' in who: targets.append(1)
            if 'g' in who: targets.append(4)
            if 'o' in who: targets.append(7)
        for t in targets:
            if 'r' in perms:
                new_perm[t] = 'r' if op == '+' else '-'
            if 'w' in perms:
                new_perm[t+1] = 'w' if op == '+' else '-'
            if 'x' in perms:
                new_perm[t+2] = 'x' if op == '+' else '-'
        shell.file_perms[path] = "".join(new_perm)
        shell._save_session_state()
        return ''

    return f"chmod: invalid mode: '{mode}'\n"


def cmd_chown(shell, args: list) -> str:
    if len(args) < 2:
        return "chown: missing operand\n"

    if shell.username != 'root':
        return "chown: changing ownership of '{}': Operation not permitted\n".format(args[1])

    owner_spec = args[0]
    target = args[1]
    path = shell.normalize_path(target)

    if ':' in owner_spec:
        user, group = owner_spec.split(':', 1)
    else:
        user, group = owner_spec, owner_spec

    if path in shell.fs_state or path in shell.files_content or path in VIRTUAL_FILES:
        shell.file_owners[path] = (user, group)
        shell._save_session_state()
        return ""

    return f"chown: cannot access '{target}': No such file or directory\n"


def cmd_which(shell, args: list) -> str:
    if not args:
        shell._last_status_explicit = 1
        return ""
    resolved = _find_command_in_path(shell, args[0])
    if resolved:
        shell._last_status_explicit = 0
        return f"{resolved}\n"
    shell._last_status_explicit = 1
    return ""


def _cmd_python_common(shell, args: list, binary_name: str) -> str:
    version = "Python 3.12.3"
    if not args:
        shell._last_status_explicit = 0
        return f"{version}\n"

    first = str(args[0] or '').strip()
    if first in ('--version', '-V'):
        shell._last_status_explicit = 0
        return f"{version}\n"

    if first == '-c':
        shell._last_status_explicit = 0
        return ""

    if first == '-m' and len(args) > 1:
        shell._last_status_explicit = 0
        return ""

    if first == '-':
        shell._last_status_explicit = 0
        return ""

    if first.startswith('-'):
        shell._last_status_explicit = 2
        return f"usage: {binary_name} [option] ... [-c cmd | -m mod | file | -] [arg] ...\n"

    shell._last_status_explicit = 0
    return ""


def cmd_python3(shell, args: list) -> str:
    return _cmd_python_common(shell, args, 'python3')


def cmd_python(shell, args: list) -> str:
    return _cmd_python_common(shell, args, 'python')


def cmd_poweroff(shell, args: list) -> str:
    if shell.username != 'root':
        return "poweroff: Need to be root\n"
    return "__POWEROFF__"


def cmd_halt(shell, args: list) -> str:
    if shell.username != 'root':
        return "halt: Need to be root\n"
    return "__REBOOT__"


def cmd_shutdown(shell, args: list) -> str:
    if shell.username != 'root':
        return "shutdown: Need to be root\n"
    if args and '-c' in args:
        if getattr(shell, 'shutdown_deadline', None):
            shell.shutdown_deadline = None
            if hasattr(shell, '_save_session_state'):
                shell._save_session_state()
            return "Shutdown cancelled.\n"
        return "shutdown: no shutdown is running.\n"
    now = datetime.utcnow()
    target = now + timedelta(minutes=5)
    msg = f"Shutdown scheduled for {target.strftime('%a %Y-%m-%d %H:%M:%S')} UTC, use 'shutdown -c' to cancel.\n"
    # 与提示一致：5 分钟后触发关机
    shell.shutdown_deadline = time.time() + 300
    if hasattr(shell, '_save_session_state'):
        shell._save_session_state()
    return f"__SHUTDOWN__\n{msg}"


def cmd_reboot(shell, args: list) -> str:
    if shell.username != 'root':
        return "reboot: Need to be root\n"
    return "__REBOOT__"


def cmd_find(shell, args: list) -> str:
    search_root = '.'
    name_pattern = '*'

    i = 0
    while i < len(args):
        arg = args[i]
        if arg == '-name' and i + 1 < len(args):
            name_pattern = args[i + 1].replace('"', '').replace("'", "")
            i += 2
        elif not arg.startswith('-'):
            search_root = arg
            i += 1
        else:
            i += 1

    search_root = shell.normalize_path(search_root)

    found_paths = []

    for dir_path, files in shell.fs_state.items():
        if dir_path == search_root or dir_path.startswith(search_root.rstrip('/') + '/'):
            for f in files:
                full_path = os.path.join(dir_path, f).replace('\\', '/')
                if fnmatch.fnmatch(f, name_pattern):
                    found_paths.append(full_path)

    bait_files = [
        '/etc/passwd', '/etc/shadow', '/etc/ssh/sshd_config',
        '/var/log/auth.log', '/var/log/syslog'
    ]
    for bait in bait_files:
        if bait.startswith(search_root) and fnmatch.fnmatch(os.path.basename(bait), name_pattern):
            if bait not in found_paths:
                found_paths.append(bait)

    if found_paths:
        found_paths.sort()
        return '\n'.join(found_paths) + '\n'

    return ""


def cmd_dmesg(shell, args: list) -> str:
    if shell.username != 'root':
        return "dmesg: read kernel buffer failed: Operation not permitted\n"

    return f'''[    0.000000] Linux version {KERNEL_RELEASE} (buildd@bos03-amd64-046) (x86_64-linux-gnu-gcc-13 (Ubuntu 13.2.0-23ubuntu4) 13.2.0, GNU ld (GNU Binutils for Ubuntu) 2.42) {KERNEL_VERSION_STRING}
[    0.000000] Command line: BOOT_IMAGE=/boot/vmlinuz-{KERNEL_RELEASE} root=UUID=a1b2c3d4-e5f6-7890-abcd-ef1234567890 ro quiet splash
[    0.000000] BIOS-provided physical RAM map:
[    0.000000] BIOS-e820: [mem 0x0000000000000000-0x000000000009fbff] usable
[    0.000000] BIOS-e820: [mem 0x0000000000100000-0x00000000bfffffff] usable
[    0.000000] NX (Execute Disable) protection: active
[    0.000000] SMBIOS 2.8 present.
[    0.000000] DMI: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.15.0-1 04/01/2014
[    0.524789] smpboot: CPU0: Intel(R) Xeon(R) E-2236 CPU @ 3.40GHz (family: 0x6, model: 0x9e, stepping: 0xa)
[    0.725000] Spectre V1 : Mitigation: usercopy/swapgs barriers
[    0.725000] Spectre V2 : Mitigation: Retpolines
[    0.725000] MDS: Mitigation: Clear CPU buffers
[    1.034567] NET: Registered protocol family 2
[    1.234567] e1000 0000:00:03.0 eth0: Intel(R) PRO/1000 Network Connection
[    1.534567] e1000 0000:00:03.0 eth0: link up
[    2.134567] EXT4-fs (sda1): mounted filesystem with ordered data mode
'''


def cmd_su(shell, args: list) -> str:
    """模拟 su 切换用户"""
    target_user = 'root'
    if args:
        target_user = args[0]
        if target_user == '-':
            if len(args) > 1:
                target_user = args[1]
            else:
                target_user = 'root'

    if target_user == shell.username:
        return ""

    if shell.username == 'root':
        _su_perform_switch(shell, target_user, args)
        return ""

    target_prompt = "Password: "
    shell.interactive_state = {
        'func': su_authenticate,
        'args': {'shell': shell, 'target_user': target_user, 'args': args},
        'echo': False
    }
    return target_prompt


def _su_perform_switch(shell, target_user, args):
    """执行切换逻辑 (抽取为公共方法)"""
    shell.user_stack.append({
        'username': shell.username,
        'env': shell.env.copy(),
        'current_path': shell.current_path,
        'kind': 'su'
    })

    logger.info(f"[SU] 用户 {shell.username} 切换到了 {target_user}")

    shell.username = target_user
    shell.env['USER'] = target_user
    shell.env['HOME'] = f'/home/{target_user}' if target_user != 'root' else '/root'

    if args and args[0] == '-':
        shell.current_path = shell.env['HOME']
        shell.env['PWD'] = shell.current_path


def su_authenticate(password, context):
    shell = context['shell']
    target_user = context['target_user']
    if not password:
        shell.interactive_state = None
        return "su: Authentication failure\n"

    shadow_content = shell.files_content.get('/etc/shadow', VIRTUAL_FILES.get('/etc/shadow', ''))

    authenticated = False
    user_found = target_user in SSH_CREDENTIALS
    current_login_password = SSH_CREDENTIALS.get(target_user)
    if current_login_password is not None and password == current_login_password:
        authenticated = True

    for line in shadow_content.split('\n'):
        if line.startswith(f"{target_user}:"):
            user_found = True
            parts = line.split(':')
            if len(parts) > 1:
                hash_str = parts[1]
                hash_parts = hash_str.split('$')
                if len(hash_parts) >= 4 and hash_parts[1] == '6':
                    salt = hash_parts[2]
                    stored_hash = hash_parts[3]
                    import hashlib
                    calc_hash = hashlib.sha512((salt + password).encode()).hexdigest()
                    if calc_hash == stored_hash:
                        authenticated = True

                if not authenticated and ('GR@.S3Rv3R' in hash_str or 'B2c3D4e5F6g7' in hash_str):
                    authenticated = True
                elif (hash_str == '!' or hash_str == '*') and not (
                    current_login_password is not None and password == current_login_password
                ):
                    authenticated = False

            break

    if not user_found:
        time.sleep(2)
        shell.interactive_state = None
        return f"su: user {target_user} does not exist\n"

    if not authenticated:
        time.sleep(2)
        shell.interactive_state = None
        return "su: Authentication failure\n"

    log_event_activity(shell.client_ip, 'SU_LOGIN', f"User: {shell.username} -> {target_user} Password: {password} (Success)")

    args = context.get('args', [])
    _su_perform_switch(shell, target_user, args)

    shell.interactive_state = None
    if hasattr(shell, '_save_session_state'):
        shell._save_session_state()
    return ""


def cmd_passwd(shell, args: list) -> str:
    """交互式修改密码"""
    user = args[0] if args else shell.username

    if user != shell.username and shell.username != 'root':
        return f"passwd: You may not view or modify password information for {user}.\n"

    return passwd_start(shell, user)


def passwd_start(shell, target_user: str) -> str:
    if shell.username != 'root':
        shell.interactive_state = {
            'func': passwd_check_current,
            'args': {'shell': shell, 'target': target_user, 'tries': 0},
            'prompt': "Current password: ",
            'echo': False,
            'on_interrupt': "passwd: Authentication token manipulation error\npasswd: password unchanged\n"
        }
        return f"Changing password for {target_user}.\nCurrent password: "

    return passwd_ask_new(shell, target_user)


def passwd_check_current(password: str, context: dict) -> str:
    shell = context['shell']
    log_event_activity(shell.client_ip, 'PASSWD_GUESS', f"User: {shell.username} OldPassword: {password}")
    logger.critical(f"[凭证] 用户 {shell.username} 修改密码，旧密码: {password}")

    expected = SSH_CREDENTIALS.get(shell.username)
    if (not expected) or (password != expected):
        shell.interactive_state = None
        return "passwd: Authentication token manipulation error\npasswd: password unchanged\n"

    return passwd_ask_new(shell, context['target'])


def passwd_ask_new(shell, target_user: str) -> str:
    shell.interactive_state = {
        'func': passwd_get_new,
        'args': {'shell': shell, 'target': target_user},
        'prompt': "New password: ",
        'echo': False,
        'on_interrupt': "passwd: Authentication token manipulation error\npasswd: password unchanged\n"
    }
    return "New password: "


def passwd_get_new(password: str, context: dict) -> str:
    shell = context['shell']
    if len(password) < 1:
        return "passwd: password must not be empty\n" + passwd_ask_new(shell, context['target'])

    context['new_pass'] = password
    shell.interactive_state = {
        'func': passwd_confirm_new,
        'args': context,
        'prompt': "Retype new password: ",
        'echo': False,
        'on_interrupt': "passwd: Authentication token manipulation error\npasswd: password unchanged\n"
    }
    return "Retype new password: "


def passwd_confirm_new(password: str, context: dict) -> str:
    shell = context['shell']
    if password != context['new_pass']:
        shell.interactive_state = None
        return "Sorry, passwords do not match.\npasswd: Authentication token manipulation error\npasswd: password unchanged\n"

    target = context['target']
    logger.critical(f"[凭证] 用户 {target} 密码被修改为: {context['new_pass']}")
    log_event_activity(shell.client_ip, 'PASSWD_CHANGE', f"Target: {target} NewPassword: {context['new_pass']}")

    shadow_content = shell.files_content.get('/etc/shadow', VIRTUAL_FILES.get('/etc/shadow', ''))
    lines = shadow_content.split('\n')
    new_lines = []
    found = False
    for line in lines:
        if line.startswith(f"{target}:"):
            parts = line.split(':')
            import secrets
            import hashlib
            salt = secrets.token_hex(8)
            h = hashlib.sha512((salt + password).encode()).hexdigest()
            parts[1] = f"$6${salt}${h}"
            new_lines.append(':'.join(parts))
            found = True
        else:
            new_lines.append(line)

    if not found:
        import secrets
        import hashlib
        salt = secrets.token_hex(8)
        h = hashlib.sha512((salt + password).encode()).hexdigest()
        entry = f"{target}:$6${salt}${h}:19700:0:99999:7:::"
        new_lines.append(entry)

    shell.files_content['/etc/shadow'] = '\n'.join(new_lines)
    shell.file_timestamps['/etc/shadow'] = datetime.now()
    shell.file_sizes['/etc/shadow'] = len(shell.files_content['/etc/shadow'])
    SSH_CREDENTIALS[target] = context['new_pass']

    shell.interactive_state = None
    if hasattr(shell, '_save_session_state'):
        shell._save_session_state()
    return "passwd: password updated successfully\n"


def cmd_useradd(shell, args: list) -> str:
    if not args:
        return "useradd: missing operand\n"

    username = args[-1]
    passwd_content = shell.files_content.get('/etc/passwd', VIRTUAL_FILES.get('/etc/passwd', ''))
    if f"{username}:" in passwd_content:
        return f"useradd: user '{username}' already exists\n"

    uid = 1001
    for line in passwd_content.split('\n'):
        if line and ':' in line:
            parts = line.split(':')
            if len(parts) > 2 and parts[2].isdigit():
                u = int(parts[2])
                if u >= 1000 and u < 60000:
                    uid = max(uid, u + 1)

    gid = uid
    home_dir = f"/home/{username}"
    user_shell = "/bin/bash"

    entry = f"{username}:x:{uid}:{gid}::/home/{username}:{user_shell}"
    if '/etc/passwd' in shell.files_content:
        shell.files_content['/etc/passwd'] += f"{entry}\n"
    else:
        shell.files_content['/etc/passwd'] = passwd_content + f"\n{entry}\n"

    shadow_entry = f"{username}:!:19700:0:99999:7:::"
    shadow_content = shell.files_content.get('/etc/shadow', VIRTUAL_FILES.get('/etc/shadow', ''))
    if '/etc/shadow' in shell.files_content:
        shell.files_content['/etc/shadow'] += f"{shadow_entry}\n"
    else:
        shell.files_content['/etc/shadow'] = shadow_content + f"\n{shadow_entry}\n"

    # 同步 /etc/group
    group_content = shell.files_content.get('/etc/group', VIRTUAL_FILES.get('/etc/group', ''))
    group_line = f"{username}:x:{gid}:"
    if f"{username}:" not in group_content:
        if '/etc/group' in shell.files_content:
            shell.files_content['/etc/group'] += f"{group_line}\n"
        else:
            shell.files_content['/etc/group'] = group_content + f"\n{group_line}\n"

    # 同步 /etc/gshadow
    gshadow_content = shell.files_content.get('/etc/gshadow', VIRTUAL_FILES.get('/etc/gshadow', ''))
    gshadow_line = f"{username}:!::"
    if f"{username}:" not in gshadow_content:
        if '/etc/gshadow' in shell.files_content:
            shell.files_content['/etc/gshadow'] += f"{gshadow_line}\n"
        else:
            shell.files_content['/etc/gshadow'] = gshadow_content + f"\n{gshadow_line}\n"

    home_dir = f"/home/{username}"
    parent = os.path.dirname(home_dir)
    if home_dir not in shell.fs_state:
        shell.fs_state[home_dir] = []
        if parent in shell.fs_state and os.path.basename(home_dir) not in shell.fs_state[parent]:
            shell.fs_state[parent].append(os.path.basename(home_dir))

    now = datetime.now()
    shell.file_owners[home_dir] = (username, username)
    shell.file_perms[home_dir] = "drwxr-xr-x"
    shell.file_timestamps[home_dir] = now
    shell.file_sizes[home_dir] = 4096

    metadata_targets = ('/etc/passwd', '/etc/shadow', '/etc/group', '/etc/gshadow')
    for path in metadata_targets:
        if path in shell.files_content:
            shell.file_timestamps[path] = now
            shell.file_sizes[path] = len(shell.files_content[path])

    if parent in shell.fs_state:
        shell.file_timestamps[parent] = now
        shell.file_sizes[parent] = 4096

    if hasattr(shell, '_save_session_state'):
        shell._save_session_state()

    return ""


def cmd_groupadd(shell, args: list) -> str:
    if shell.username != 'root':
        return "groupadd: Permission denied.\ngroupadd: cannot lock /etc/group; try again later.\n"
    if not args:
        return "groupadd: missing operand\nTry 'groupadd --help' for more information.\n"

    group_name = str(args[-1] or '').strip()
    if not group_name:
        return "groupadd: invalid group name ''\n"

    group_content = _read_virtual_account_file(shell, '/etc/group')
    if any(line.startswith(f"{group_name}:") for line in group_content.splitlines()):
        return f"groupadd: group '{group_name}' already exists\n"

    next_gid = 1001
    for line in group_content.splitlines():
        parts = line.split(':')
        if len(parts) > 2 and parts[2].isdigit():
            gid = int(parts[2])
            if 1000 <= gid < 60000:
                next_gid = max(next_gid, gid + 1)

    group_line = f"{group_name}:x:{next_gid}:"
    gshadow_line = f"{group_name}:!::"
    shell.files_content['/etc/group'] = (group_content.rstrip('\n') + '\n' + group_line + '\n').lstrip('\n')
    gshadow_content = _read_virtual_account_file(shell, '/etc/gshadow')
    shell.files_content['/etc/gshadow'] = (gshadow_content.rstrip('\n') + '\n' + gshadow_line + '\n').lstrip('\n')

    now = datetime.now()
    for path in ('/etc/group', '/etc/gshadow'):
        shell.file_timestamps[path] = now
        shell.file_sizes[path] = len(shell.files_content[path])

    if hasattr(shell, '_save_session_state'):
        shell._save_session_state()
    return ""


def cmd_usermod(shell, args: list) -> str:
    if shell.username != 'root':
        return "usermod: Permission denied.\nusermod: cannot lock /etc/passwd; try again later.\n"
    if not args:
        return "usermod: no changes\n"

    append_groups = False
    group_spec = None
    login_shell = None
    new_home = None
    move_home = False
    target_user = None

    i = 0
    while i < len(args):
        arg = str(args[i] or '').strip()
        if arg == '-a':
            append_groups = True
        elif arg == '-aG':
            append_groups = True
            if i + 1 < len(args):
                group_spec = str(args[i + 1] or '').strip()
                i += 1
        elif arg == '-G' and i + 1 < len(args):
            group_spec = str(args[i + 1] or '').strip()
            i += 1
        elif arg.startswith('-G') and len(arg) > 2:
            group_spec = arg[2:].strip()
        elif arg == '-s' and i + 1 < len(args):
            login_shell = str(args[i + 1] or '').strip()
            i += 1
        elif arg.startswith('-s') and len(arg) > 2:
            login_shell = arg[2:].strip()
        elif arg == '-d' and i + 1 < len(args):
            new_home = str(args[i + 1] or '').strip()
            i += 1
        elif arg.startswith('-d') and len(arg) > 2:
            new_home = arg[2:].strip()
        elif arg == '-m':
            move_home = True
        elif not arg.startswith('-'):
            target_user = arg
        i += 1

    if not target_user:
        return "usermod: no changes\n"

    identity = _resolve_user_identity(shell, target_user)
    if not identity:
        return f"usermod: user '{target_user}' does not exist\n"

    if group_spec is not None:
        requested_groups = [name.strip() for name in group_spec.split(',') if name.strip()]
        existing_group_names = {
            line.split(':')[0]
            for line in _list_account_lines(shell, '/etc/group')
            if ':' in line
        }
        missing = [name for name in requested_groups if name not in existing_group_names]
        if missing:
            return f"usermod: group '{missing[0]}' does not exist\n"

    now = datetime.now()
    passwd_lines = _list_account_lines(shell, '/etc/passwd')
    updated_passwd = []
    current_home = None
    for line in passwd_lines:
        parts = line.split(':')
        if len(parts) < 7 or parts[0] != target_user:
            updated_passwd.append(line)
            continue
        current_home = parts[5]
        if login_shell:
            parts[6] = login_shell
        if new_home:
            parts[5] = new_home
        updated_passwd.append(':'.join(parts))
    _write_virtual_text(shell, '/etc/passwd', '\n'.join(updated_passwd) + '\n', now)

    if new_home and current_home and move_home:
        _rename_virtual_home(shell, current_home, new_home)

    if group_spec is not None:
        requested_groups = [name.strip() for name in group_spec.split(',') if name.strip()]
        group_lines = _list_account_lines(shell, '/etc/group')
        gshadow_lines = _list_account_lines(shell, '/etc/gshadow')

        new_group_lines = []
        for line in group_lines:
            parts = line.split(':')
            while len(parts) < 4:
                parts.append('')
            group_name = parts[0]
            members = [member.strip() for member in parts[3].split(',') if member.strip()]
            if append_groups:
                if group_name in requested_groups and target_user not in members:
                    members.append(target_user)
            else:
                members = [member for member in members if member != target_user]
                if group_name in requested_groups:
                    members.append(target_user)
            new_group_lines.append(_replace_group_line_members(':'.join(parts[:4]), members))

        new_gshadow_lines = []
        for line in gshadow_lines:
            parts = line.split(':')
            while len(parts) < 4:
                parts.append('')
            group_name = parts[0]
            admins = [member.strip() for member in parts[2].split(',') if member.strip()]
            members = [member.strip() for member in parts[3].split(',') if member.strip()]
            if append_groups:
                if group_name in requested_groups and target_user not in members:
                    members.append(target_user)
            else:
                members = [member for member in members if member != target_user]
                if group_name in requested_groups:
                    members.append(target_user)
            parts[2] = ','.join(admins)
            parts[3] = ','.join(dict.fromkeys(member for member in members if member))
            new_gshadow_lines.append(':'.join(parts[:4]))

        _write_virtual_text(shell, '/etc/group', '\n'.join(new_group_lines) + '\n', now)
        _write_virtual_text(shell, '/etc/gshadow', '\n'.join(new_gshadow_lines) + '\n', now)

    _persist_account_files(shell, now)
    return ""


def cmd_deluser(shell, args: list) -> str:
    if shell.username != 'root':
        return "deluser: Only root may remove a user or group from the system.\n"
    if not args:
        return "deluser: Specify a user to remove.\n"

    remove_home = '--remove-home' in args
    target_user = None
    for arg in args:
        text = str(arg or '').strip()
        if text and not text.startswith('-'):
            target_user = text
    if not target_user:
        return "deluser: Specify a user to remove.\n"
    if target_user == 'root':
        return "deluser: `/usr/sbin/deluser root' will not remove the root account.\n"

    identity = _resolve_user_identity(shell, target_user)
    if not identity:
        return f"deluser: The user `{target_user}' does not exist.\n"

    now = datetime.now()
    for path in ('/etc/passwd', '/etc/shadow'):
        lines = [
            line for line in _list_account_lines(shell, path)
            if not line.startswith(f"{target_user}:")
        ]
        _write_virtual_text(shell, path, ('\n'.join(lines) + '\n') if lines else '', now)

    group_lines = []
    for line in _list_account_lines(shell, '/etc/group'):
        parts = line.split(':')
        while len(parts) < 4:
            parts.append('')
        group_name = parts[0]
        group_id = parts[2]
        if group_name == target_user and group_id == identity['gid']:
            continue
        members = [member.strip() for member in parts[3].split(',') if member.strip() and member.strip() != target_user]
        group_lines.append(_replace_group_line_members(':'.join(parts[:4]), members))
    _write_virtual_text(shell, '/etc/group', ('\n'.join(group_lines) + '\n') if group_lines else '', now)

    gshadow_lines = []
    for line in _list_account_lines(shell, '/etc/gshadow'):
        parts = line.split(':')
        while len(parts) < 4:
            parts.append('')
        if parts[0] == target_user:
            continue
        admins = [member.strip() for member in parts[2].split(',') if member.strip() and member.strip() != target_user]
        members = [member.strip() for member in parts[3].split(',') if member.strip() and member.strip() != target_user]
        parts[2] = ','.join(admins)
        parts[3] = ','.join(members)
        gshadow_lines.append(':'.join(parts[:4]))
    _write_virtual_text(shell, '/etc/gshadow', ('\n'.join(gshadow_lines) + '\n') if gshadow_lines else '', now)

    if remove_home:
        _remove_virtual_tree(shell, f"/home/{target_user}")

    _persist_account_files(shell, now)
    return f"Removing user `{target_user}' ...\nDone.\n"



