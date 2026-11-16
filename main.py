# -*- coding: utf-8 -*-
"""
蜜罐系统统一启动入口
功能：
1. 统一管理 SSH、Web、Dashboard 三个服务进程
2. 实时流式监控子服务日志，防止管道阻塞
3. 异常退出实时告警与错误回显
4. 服务自动重启机制，防止单点故障
5. 端口残留自动清理，以及 --stop / --restart / --status 运维命令
"""
import argparse
import json
import subprocess
import time
import os
import sys
import signal
import socket
import threading
from typing import Dict, List, Optional
from collections import defaultdict
from utils.logger import setup_logger
from app_config import env_bool as _env_bool, env_float as _env_float, env_int as _env_int, env_str as _env_str, is_production as _config_is_production

try:  # 端口归属识别与进程树清理（requirements.txt 已声明 psutil）
    import psutil
except ImportError:  # pragma: no cover - 缺依赖时退化为系统命令
    psutil = None

# 添加项目根目录到路径
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

# 主控制器日志（仅文件输出，避免与控制台主流程重复）
logger = setup_logger('main', 'main.log', console_output=False)

# 运行时状态文件：记录主进程 PID、子服务 PID 与实际停止标记路径
LOG_DIR = os.path.join(BASE_DIR, 'logs')
RUNTIME_STATE_FILE = os.path.join(LOG_DIR, 'honeypot.runtime.json')
DEFAULT_STOP_FILE = os.path.join(LOG_DIR, 'honeypot.stop')

# ============================================
# 服务配置
# ============================================
SERVICES: List[Dict] = [
    {
        'name': 'SSH蜜罐',
        'script': os.path.join('ssh_honeypot', 'server.py'),
        'host': _env_str('SSH_HOST', '0.0.0.0'),
        'port': _env_int('SSH_PORT', 2222, 1, 65535),
        'description': 'SSH 终端交互与行为审计',
        'color': '\033[93m',  # 黄色
        'short': 'SSH'
    },
    {
        'name': 'Web蜜罐',
        'script': os.path.join('web_honeypot', 'server.py'),
        'host': _env_str('WEB_HOST', '0.0.0.0'),
        'port': _env_int('WEB_PORT', 5000, 1, 65535),
        'description': 'Web 业务模拟与攻击诱捕',
        'color': '\033[92m',  # 绿色
        'short': 'Web'
    },
    {
        'name': '管理端',
        'script': os.path.join('dashboard', 'server.py'),
        'host': _env_str('DASHBOARD_HOST', '127.0.0.1'),
        'port': _env_int('DASHBOARD_PORT', 5001, 1, 65535),
        'description': '态势感知可视化大屏',
        'color': '\033[94m',  # 蓝色
        'short': 'Dash'
    },
]

# ============================================
# 多协议扩展服务（可通过 honeypot.ini / 环境变量启停）
# 数据库蜜罐一个进程同时监听 MySQL / Redis 两个端口；
# 'port' 取 MySQL 端口用于端口检查与汇总展示，Redis 端口在其描述中标注。
# ============================================
if _env_bool('DB_HONEYPOT_ENABLED', True):
    _db_host = _env_str('DB_HONEYPOT_HOST', '0.0.0.0')
    _mysql_port = _env_int('MYSQL_PORT', 13306, 1, 65535)
    _redis_port = _env_int('REDIS_PORT', 16379, 1, 65535)
    SERVICES.append({
        'name': '数据库蜜罐',
        'script': os.path.join('db_honeypot', 'server.py'),
        'host': _db_host,
        'port': _mysql_port,
        'redis_port': _redis_port,
        'description': f'MySQL({_mysql_port}) / Redis({_redis_port}) 协议诱捕',
        'color': '\033[95m',  # 紫色
        'short': 'DB'
    })

if _env_bool('FILE_HONEYPOT_ENABLED', True):
    SERVICES.append({
        'name': '文件共享蜜罐',
        'script': os.path.join('file_honeypot', 'server.py'),
        'host': _env_str('FTP_HOST', '0.0.0.0'),
        'port': _env_int('FTP_PORT', 2121, 1, 65535),
        'description': 'FTP 协议诱捕（SMB 为后续阶段）',
        'color': '\033[96m',  # 青色
        'short': 'FTP'
    })

if _env_bool('REMOTE_HONEYPOT_ENABLED', True):
    SERVICES.append({
        'name': '远程管理蜜罐',
        'script': os.path.join('remote_honeypot', 'server.py'),
        'host': _env_str('TELNET_HOST', '0.0.0.0'),
        'port': _env_int('TELNET_PORT', 2223, 1, 65535),
        'description': 'Telnet(IoT) 协议诱捕（RDP 为后续阶段）',
        'color': '\033[90m',  # 灰色
        'short': 'Telnet'
    })

# ============================================
# 请求级 AI 攻击检测服务（外部模型目录，可选）
# 与 honeypot.ini [ai] 配合：服务监听 host:port，蜜罐按 [ai] url 调用。
# ============================================
if _env_bool('AI_DETECT_ENABLED', False):
    _aid_path = _env_str('AI_DETECT_PATH', '').strip()
    _aid_dir = _aid_path if os.path.isabs(_aid_path) else os.path.join(BASE_DIR, _aid_path)
    if not _aid_path or not os.path.isdir(_aid_dir):
        print(f"  ! AI_DETECT_ENABLED 已启用但模型目录无效: {_aid_dir or '(未配置 AI_DETECT_PATH)'}")
    else:
        _aid_host = _env_str('AI_DETECT_HOST', '127.0.0.1') or '127.0.0.1'
        _aid_port = _env_int('AI_DETECT_PORT', 8003, 1, 65535)
        _aid_python = _env_str('AI_DETECT_PYTHON', '').strip()
        if not _aid_python:
            _venv_python = (
                os.path.join(_aid_dir, '.venv', 'Scripts', 'python.exe')
                if sys.platform == 'win32'
                else os.path.join(_aid_dir, '.venv', 'bin', 'python')
            )
            _aid_python = _venv_python if os.path.exists(_venv_python) else sys.executable
        SERVICES.append({
            'name': 'AI攻击检测',
            'script': '',
            'cwd': _aid_dir,
            'python': _aid_python,
            'args': ['-m', 'uvicorn', 'src.api:app', '--host', _aid_host, '--port', str(_aid_port)],
            'host': _aid_host,
            'port': _aid_port,
            'description': '请求级攻击检测模型（规则 + ai_points 融合）',
            'color': '\033[96m',  # 青色
            'short': 'AI-DET'
        })

# ============================================
# round 9 合并：团队数据中心 / AI 推理网关
# 两者均为独立 JSON 配置的子进程，默认关闭；
# 仅在 enabled 且配置文件存在时注册。
# ============================================
def _load_service_endpoint(config_path):
    """读取子服务 JSON 配置中的 host/port，失败返回 (None, None)。"""
    try:
        import json as _json
        with open(config_path, 'r', encoding='utf-8-sig') as fh:
            cfg = _json.load(fh)
        return str(cfg.get('host', '127.0.0.1')), int(cfg.get('port', 0))
    except Exception:
        return None, None

if _env_bool('TEAM_CENTER_ENABLED', False):
    _tc_config = _env_str('TEAM_CENTER_CONFIG', os.path.join('deployment', 'center', 'center.json'))
    _tc_path = _tc_config if os.path.isabs(_tc_config) else os.path.join(BASE_DIR, _tc_config)
    if os.path.exists(_tc_path):
        _tc_host, _tc_port = _load_service_endpoint(_tc_path)
        if _tc_port:
            SERVICES.append({
                'name': '团队数据中心',
                'script': os.path.join('scripts', 'team_center.py'),
                'args': ['serve', '--config', _tc_path],
                'host': _tc_host,
                'port': _tc_port,
                'description': '多设备证据汇聚与协作中心（独立登录）',
                'color': '\033[92m',  # 亮绿
                'short': 'Team'
            })
    else:
        print(f"  ! TEAM_CENTER_ENABLED 已启用但配置不存在: {_tc_path}（先运行 python scripts/team_center.py init 初始化）")

if _env_bool('AI_GATEWAY_ENABLED', False):
    _gw_config = _env_str('AI_GATEWAY_CONFIG', os.path.join('deployment', 'gateway', 'gateway.json'))
    _gw_path = _gw_config if os.path.isabs(_gw_config) else os.path.join(BASE_DIR, _gw_config)
    if os.path.exists(_gw_path):
        _gw_host, _gw_port = _load_service_endpoint(_gw_path)
        if _gw_port:
            SERVICES.append({
                'name': 'AI推理网关',
                'script': os.path.join('ai_gateway', 'server.py'),
                'args': ['--config', _gw_path],
                'host': _gw_host,
                'port': _gw_port,
                'description': '多成员共享 AI 推理队列',
                'color': '\033[96m',  # 青色
                'short': 'AI-GW'
            })
    else:
        print(f"  ! AI_GATEWAY_ENABLED 已启用但配置不存在: {_gw_path}")

# 颜色常量
RESET = '\033[0m'
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
CYAN = '\033[96m'
BOLD = '\033[1m'
GRAY = '\033[90m'

# 全局进程字典
processes: Dict[str, subprocess.Popen] = {}
process_services: Dict[str, Dict] = {}
threads: List[threading.Thread] = []
shutdown_flag = False
print_lock = threading.Lock()

# 服务重启配置
MAX_RESTART_ATTEMPTS = _env_int('MAX_RESTART_ATTEMPTS', 5, 0, 100)  # 最大重启尝试次数
RESTART_DELAY = _env_float('RESTART_DELAY', 3.0, 0.0, 300.0)  # 重启延迟（秒）

# 端口残留清理：启动时若发现上一次运行的本项目进程仍占用端口，自动停止旧实例后重启
AUTO_CLEAN_STALE_PORTS = _env_bool('HONEYPOT_AUTO_CLEAN_PORTS', True)
# 请求旧实例优雅退出的最长等待时间（超过后强制结束进程树）
STOP_WAIT_SECONDS = _env_float('HONEYPOT_STOP_WAIT', 8.0, 0.5, 120.0)
# 端口释放等待时间
PORT_FREE_WAIT_SECONDS = _env_float('HONEYPOT_PORT_FREE_WAIT', 8.0, 0.5, 120.0)

# 服务状态跟踪
service_status = defaultdict(dict)

# 控制是否在控制台打印“凭证初始化”日志
SHOW_CREDENTIAL_LOGS = _env_bool('SHOW_CREDENTIAL_LOGS', False)
# 控制启动汇总是否展示 Web/SSH 凭证（默认展示，便于演示）
SHOW_SUMMARY_CREDS = _env_bool('SHOW_SUMMARY_CREDS', True)
# 控制汇总等待凭证的时间（秒），即使传 inf 也会限制在 SUMMARY_CRED_WAIT_MAX 内，避免启动卡死
SUMMARY_CRED_WAIT_MAX = _env_float('SUMMARY_CRED_WAIT_MAX', 15.0, 1.0, 300.0)
_raw_wait = _env_str('SUMMARY_CRED_WAIT', '2').strip().lower()
if _raw_wait in ('-1', 'inf', 'infinite'):
    SUMMARY_CRED_WAIT = SUMMARY_CRED_WAIT_MAX
else:
    try:
        SUMMARY_CRED_WAIT = min(max(0.0, float(_raw_wait)), SUMMARY_CRED_WAIT_MAX)
    except ValueError:
        SUMMARY_CRED_WAIT = 2.0

# ============================================
# 启动横幅
# ============================================
BANNER = f"""
{CYAN}{BOLD}
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║    ██╗  ██╗ ██████╗ ███╗   ██╗███████╗██╗   ██╗███████╗  ██████╗ ████████╗   ║
║    ██║  ██║██╔═══██╗████╗  ██║██╔════╝╚██╗ ██╔╝██╔══██╗██╔═══██╗╚══██╔══╝    ║
║    ███████║██║   ██║██╔██╗ ██║█████╗   ╚████╔╝ ██████╔╝██║   ██║   ██║       ║
║    ██╔══██║██║   ██║██║╚██╗██║██╔══╝    ╚██╔╝  ██╔═══╝ ██║   ██║   ██║       ║
║    ██║  ██║╚██████╔╝██║ ╚████║███████╗   ██║   ██║     ╚██████╔╝   ██║       ║
║    ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝      ╚═════╝    ╚═╝       ║
║                                                                              ║
║                        {YELLOW}网络威胁态势感知与蜜罐诱捕系统{CYAN}                        ║
║                   {RESET}{CYAN}Cyber Threat Awareness & Honeypot System{BOLD}                   ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
{RESET}
"""

def print_banner():
    """打印启动 Banner"""
    safe_print(BANNER)

def safe_print(*args, **kwargs):
    """线程安全打印，避免多线程日志输出错乱"""
    with print_lock:
        print(*args, **kwargs)

def _is_production_env() -> bool:
    return _config_is_production()


def _is_running_under_systemd() -> bool:
    """
    判断当前是否运行在 systemd 托管环境。
    在 systemd 下会注入 INVOCATION_ID/JOURNAL_STREAM/NOTIFY_SOCKET 等变量。
    """
    return bool(
        os.environ.get('INVOCATION_ID')
        or os.environ.get('JOURNAL_STREAM')
        or os.environ.get('NOTIFY_SOCKET')
    )


def check_port(port: int, host: str = '0.0.0.0') -> bool:
    """检查端口是否被占用"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if sys.platform == 'win32' and hasattr(socket, 'SO_EXCLUSIVEADDRUSE'):
                s.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            else:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((host, port))
            return True
    except Exception:
        return False

def _service_ports_of(service: Dict) -> List[int]:
    """返回单个服务需要占用的全部 TCP 端口（DB 蜜罐含 MySQL + Redis）。"""
    ports = [int(service['port'])]
    if service.get('redis_port'):
        ports.append(int(service['redis_port']))
    return ports


def _service_port_numbers() -> List[int]:
    """返回所有服务端口（去重、保持顺序）。"""
    ports: List[int] = []
    for service in SERVICES:
        for port in _service_ports_of(service):
            if port not in ports:
                ports.append(port)
    return ports


def _stop_file_path() -> str:
    """外部停止标记路径，可用 HONEYPOT_STOP_FILE 覆盖。"""
    return os.environ.get('HONEYPOT_STOP_FILE') or DEFAULT_STOP_FILE


def _remove_file(path: str) -> None:
    try:
        if path and os.path.exists(path):
            os.remove(path)
    except OSError:
        pass


def _pid_exists(pid: Optional[int]) -> bool:
    if not pid:
        return False
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return False
    if psutil is not None:
        try:
            return psutil.pid_exists(pid)
        except Exception:
            return False
    try:
        os.kill(pid, 0)
        return True
    except Exception:
        return False


def _read_runtime_state() -> Dict:
    """读取上一次运行留下的运行时状态（不存在或损坏时返回空字典）。"""
    try:
        with open(RUNTIME_STATE_FILE, 'r', encoding='utf-8') as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_runtime_state() -> None:
    """持久化主进程 / 子服务 PID，供下次启动或 --stop 定位残留进程。"""
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        payload = {
            'pid': os.getpid(),
            'started_at': time.time(),
            'base_dir': BASE_DIR,
            'stop_file': _stop_file_path(),
            'services': {
                name: (process.pid if process is not None else None)
                for name, process in processes.items()
            },
            'ports': _service_port_numbers(),
        }
        tmp_path = RUNTIME_STATE_FILE + '.tmp'
        with open(tmp_path, 'w', encoding='utf-8') as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)
        os.replace(tmp_path, RUNTIME_STATE_FILE)
    except Exception as exc:
        logger.debug(f"保存运行时状态失败: {exc}")


def _clear_runtime_state() -> None:
    _remove_file(RUNTIME_STATE_FILE)


def _process_cmdline(pid: Optional[int]) -> List[str]:
    if not pid or psutil is None:
        return []
    try:
        return list(psutil.Process(int(pid)).cmdline())
    except Exception:
        return []


def _project_script_paths() -> set:
    paths = set()
    for service in SERVICES:
        script = service.get('script')
        if not script:
            continue
        paths.add(os.path.normcase(os.path.abspath(os.path.join(BASE_DIR, script))))
    return paths


def _is_project_service_process(pid: Optional[int]) -> bool:
    """判断 PID 是否是本项目的子服务进程（按启动脚本绝对路径匹配）。"""
    if not pid:
        return False
    scripts = _project_script_paths()
    if not scripts:
        return False
    for arg in _process_cmdline(pid):
        if not arg or arg.startswith('-'):
            continue
        try:
            if os.path.normcase(os.path.abspath(arg)) in scripts:
                return True
        except (OSError, ValueError):
            continue
    return False


def _is_supervisor_process(pid: Optional[int]) -> bool:
    """判断 PID 是否是本项目的 main.py 主进程（含 venv 启动器）。"""
    if not pid or not _pid_exists(pid) or int(pid) == os.getpid() or psutil is None:
        return False
    try:
        proc = psutil.Process(int(pid))
        cwd = os.path.normcase(os.path.abspath(proc.cwd()))
        if cwd != os.path.normcase(BASE_DIR):
            return False
        main_path = os.path.normcase(os.path.abspath(__file__))
        for arg in proc.cmdline()[1:]:
            if not arg or arg.startswith('-'):
                continue
            if os.path.normcase(os.path.abspath(os.path.join(cwd, arg))) == main_path:
                return True
    except Exception:
        return False
    return False


def _find_supervisor_pids(service_pids: set) -> set:
    """沿子服务进程的父链向上找到 main.py 主进程 PID。"""
    supervisors = set()
    if psutil is None:
        return supervisors
    for pid in service_pids:
        try:
            parents = psutil.Process(int(pid)).parents()
        except Exception:
            continue
        for parent in parents:
            if _is_supervisor_process(parent.pid):
                supervisors.add(parent.pid)
    return supervisors


def _port_owner_map() -> Dict[int, Optional[int]]:
    """返回当前 TCP LISTEN 端口到进程 PID 的快照。"""
    owners: Dict[int, Optional[int]] = {}
    if psutil is None:
        return owners
    try:
        connections = psutil.net_connections(kind='inet')
    except Exception:
        return owners
    for conn in connections:
        if conn.status != psutil.CONN_LISTEN or not conn.laddr:
            continue
        try:
            port = int(conn.laddr.port)
        except (TypeError, ValueError):
            continue
        if conn.pid:
            owners[port] = int(conn.pid)
        else:
            owners.setdefault(port, None)
    return owners


def _describe_owner(pid: Optional[int]) -> str:
    """生成占用端口的进程描述，便于用户判断是旧实例还是外部程序。"""
    if not pid:
        return '未知进程（无法读取占用者 PID）'
    if psutil is None:
        return f'PID {pid}'
    try:
        proc = psutil.Process(int(pid))
        name = proc.name()
        cmdline = ' '.join(proc.cmdline()).strip()
        if len(cmdline) > 120:
            cmdline = cmdline[:117] + '...'
        return f'{name} (PID {pid}) {cmdline}'.strip()
    except Exception:
        return f'PID {pid}'


def _scan_port_conflicts() -> List[Dict]:
    """检查所有服务端口，返回被占用端口的详细信息。"""
    owners = _port_owner_map()
    conflicts: List[Dict] = []
    for service in SERVICES:
        for port in _service_ports_of(service):
            if check_port(port, service.get('host', '0.0.0.0')):
                continue
            pid = owners.get(port)
            conflicts.append({
                'service': service,
                'port': port,
                'pid': pid,
                'ours': _is_project_service_process(pid),
            })
    return conflicts


def _print_port_scan(conflicts: List[Dict]) -> None:
    """按服务分组打印端口检查结果。"""
    conflict_by_port = {item['port']: item for item in conflicts}
    for service in SERVICES:
        name = service['name']
        color = service['color']
        for port in _service_ports_of(service):
            conflict = conflict_by_port.get(port)
            if conflict is None:
                safe_print(f"  {GREEN}√{RESET} 端口 {BOLD}{port}{RESET} 可用 ({color}{name}{RESET})")
            else:
                safe_print(
                    f"  {RED}×{RESET} 端口 {BOLD}{port}{RESET} 已被占用 "
                    f"({color}{name}{RESET}) <- {_describe_owner(conflict['pid'])}"
                )


def _terminate_process_tree(pid: Optional[int], timeout: float = 3.0) -> bool:
    """结束 PID 及其全部子进程；兼容 venv 启动器 -> 真实解释器 -> 服务的多级进程链。"""
    if not pid or int(pid) == os.getpid():
        return False
    pid = int(pid)
    if psutil is not None:
        try:
            root = psutil.Process(pid)
        except Exception:
            return False
        processes_to_stop = [root]
        try:
            processes_to_stop.extend(root.children(recursive=True))
        except Exception:
            pass
        for proc in processes_to_stop:
            try:
                proc.terminate()
            except Exception:
                pass
        try:
            _, alive = psutil.wait_procs(processes_to_stop, timeout=max(0.1, float(timeout)))
        except Exception:
            alive = []
        for proc in alive:
            try:
                proc.kill()
            except Exception:
                pass
        try:
            psutil.wait_procs(alive, timeout=2.0)
        except Exception:
            pass
        return True
    # psutil 不可用时的兜底实现
    try:
        if sys.platform == 'win32':
            subprocess.run(
                ['taskkill', '/F', '/T', '/PID', str(pid)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=timeout + 2.0,
            )
        else:
            os.kill(pid, signal.SIGTERM)
        return True
    except Exception:
        return False


def _wait_ports_free(ports: List[int], timeout: float) -> bool:
    deadline = time.time() + max(0.0, float(timeout))
    while True:
        remaining = [port for port in ports if not check_port(port, '0.0.0.0')]
        if not remaining:
            return True
        if time.time() >= deadline:
            return False
        time.sleep(0.25)


def _kill_remaining_project_services(expected_ports: Optional[List[int]] = None) -> bool:
    """清理所有仍占用本项目端口的残留子进程（含 launcher 已退出的孤儿进程）。"""
    ports = _service_port_numbers() if expected_ports is None else list(expected_ports)
    if not ports:
        return True
    killed = set()
    deadline = time.time() + max(1.0, PORT_FREE_WAIT_SECONDS)
    while time.time() < deadline:
        owners = _port_owner_map()
        remaining = set()
        for port in ports:
            pid = owners.get(port)
            if pid and _is_project_service_process(pid):
                remaining.add(pid)
        if not remaining:
            return True
        for pid in sorted(remaining - killed):
            logger.info(f"清理残留服务进程 PID={pid}")
            _terminate_process_tree(pid)
            killed.add(pid)
        time.sleep(0.25)
    return False


def stop_running_instance(wait_seconds: Optional[float] = None, verbose: bool = True) -> bool:
    """停止上一次运行留下的本项目实例。

    返回 True 表示确实发现并处理了残留进程；False 表示当前没有本项目实例在运行。
    """
    wait_seconds = STOP_WAIT_SECONDS if wait_seconds is None else wait_seconds
    ports = _service_port_numbers()
    owners = _port_owner_map()
    running_pids = set()
    for port in ports:
        pid = owners.get(port)
        if pid and _is_project_service_process(pid):
            running_pids.add(int(pid))

    state = _read_runtime_state()
    supervisor_pids = set(_find_supervisor_pids(running_pids))
    state_pid = state.get('pid')
    if state_pid and _pid_exists(state_pid) and _is_supervisor_process(state_pid):
        supervisor_pids.add(int(state_pid))

    if not running_pids and not supervisor_pids:
        return False

    stop_file = str(state.get('stop_file') or _stop_file_path())
    try:
        os.makedirs(os.path.dirname(stop_file), exist_ok=True)
        with open(stop_file, 'w', encoding='utf-8') as fh:
            fh.write(str(os.getpid()))
    except Exception as exc:
        logger.warning(f"写入停止标记失败 ({stop_file}): {exc}")

    if verbose:
        detail = ', '.join(str(pid) for pid in sorted(supervisor_pids | running_pids))
        safe_print(f"  {YELLOW}检测到上一次运行仍在占用端口，正在停止旧实例 (PID: {detail})...{RESET}")

    # 先给旧实例一个优雅退出的机会（新版本会轮询停止标记）
    if supervisor_pids:
        deadline = time.time() + max(0.0, float(wait_seconds))
        while time.time() < deadline:
            if not any(_pid_exists(pid) for pid in supervisor_pids):
                break
            time.sleep(0.2)

    # 再按进程树强制清理：先主进程，避免监控逻辑把服务重新拉起
    for pid in sorted(supervisor_pids):
        if _pid_exists(pid):
            logger.info(f"强制停止旧主进程 PID={pid}")
            _terminate_process_tree(pid)
    for pid in sorted(running_pids):
        if _pid_exists(pid):
            logger.info(f"停止残留服务进程 PID={pid}")
            _terminate_process_tree(pid)

    # 只等待被本项目进程占用的端口，避免外部程序占用时白等
    our_ports = [
        port for port in ports
        if owners.get(port) and _is_project_service_process(owners.get(port))
    ]
    _kill_remaining_project_services(our_ports)
    _wait_ports_free(our_ports, PORT_FREE_WAIT_SECONDS)

    _remove_file(stop_file)
    _clear_runtime_state()
    if verbose:
        safe_print(f"  {GREEN}旧实例已停止{RESET}")
    return True


def _stop_requested() -> bool:
    return os.path.exists(_stop_file_path())


def check_all_ports(auto_clean: Optional[bool] = None) -> bool:
    """检查所有服务端口是否可用；本项目旧实例占用时自动清理后重试。"""
    if auto_clean is None:
        auto_clean = AUTO_CLEAN_STALE_PORTS
    safe_print(f"\n{BOLD}[1/3] 检查端口占用情况...{RESET}\n")

    conflicts = _scan_port_conflicts()
    _print_port_scan(conflicts)
    if not conflicts:
        safe_print()
        return True

    ours = [item for item in conflicts if item['ours']]
    if ours and auto_clean:
        if stop_running_instance():
            conflicts = _scan_port_conflicts()
            safe_print()
            safe_print(f"{BOLD}[1/3] 清理后端口检查...{RESET}\n")
            _print_port_scan(conflicts)
            if not conflicts:
                safe_print()
                return True

    for item in conflicts:
        service = item['service']
        owner_kind = '本项目旧进程' if item['ours'] else '外部程序'
        safe_print(
            f"  {RED}端口 {item['port']} 被{owner_kind}占用{RESET} "
            f"({service['name']}): {_describe_owner(item['pid'])}"
        )
    if any(item['ours'] for item in conflicts) and not auto_clean:
        safe_print(
            f"  {YELLOW}提示:{RESET} 可用 {BOLD}python main.py --stop{RESET} 停止旧实例，"
            f"或去掉 --no-auto-clean 重新启动。"
        )
    safe_print()
    return False


def _detect_local_ipv4() -> str:
    """检测本机首选 IPv4，用于 0.0.0.0 监听时的访问地址展示。"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            # 不会真正发包，只用于让系统选择默认出口网卡
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            if ip and not ip.startswith("127."):
                return ip
    except Exception:
        pass
    try:
        ip = socket.gethostbyname(socket.gethostname())
        if ip:
            return ip
    except Exception:
        pass
    return "127.0.0.1"


def _resolve_display_host(bind_host: str) -> str:
    """将监听地址转换为更适合展示的访问地址。"""
    h = str(bind_host or "").strip()
    if h in ("", "0.0.0.0", "::", "[::]"):
        return _detect_local_ipv4()
    if h.lower() == "localhost":
        return "127.0.0.1"
    return h

# 启动完成事件
startup_event = threading.Event()
# 运行期捕获到的凭证
CAPTURED_CREDS = defaultdict(list)

def log_streamer(pipe, service_short_name, color):
    """读取子进程输出流并打印到控制台"""
    log_buffer = []  # 启动期间的日志缓冲
    cred_block_active = False

    try:
        # text=True 模式下，line 已是字符串
        for line in iter(pipe.readline, ''):
            if not line:
                break

            line_str = line.strip()
            if not line_str:
                continue

            # 捕获随机生成的凭证（仅来自标准输出前缀）
            # 格式: CRED::username::password
            if line_str.startswith("CRED::"):
                try:
                    parts = line_str.split("::", 2)
                    if len(parts) == 3:
                        user_part = parts[1].strip()
                        pass_part = parts[2].strip()
                        if user_part and pass_part:
                            CAPTURED_CREDS[service_short_name].append(f"{user_part}/{pass_part}")
                except Exception:
                    pass
                continue

            # 过滤 Flask/Werkzeug 启动噪声
            if any(x in line_str for x in [
                "* Serving Flask app",
                "* Debug mode",
                "WARNING: This is a development server",
                "Use a production WSGI server"
            ]):
                continue

            # 凭证初始化日志过滤（控制台不再重复展示）
            is_cred_header = "凭证初始化" in line_str
            is_cred_user_line = ("用户:" in line_str and "| 密码:" in line_str)
            is_separator = line_str.strip().strip('=') == ''

            if is_cred_header:
                cred_block_active = True

            is_cred_line = is_cred_header or is_cred_user_line or (cred_block_active and is_separator)

            # 结束凭证块
            if cred_block_active and is_separator and not is_cred_header:
                cred_block_active = False

            if (not SHOW_CREDENTIAL_LOGS) and is_cred_line:
                continue

            formatted_log = f"{color}[{service_short_name}]{RESET} {line_str}"

            # 如果启动还没完成，先存入缓冲
            if not startup_event.is_set():
                log_buffer.append(formatted_log)
            else:
                # 启动完成后，统一加锁输出，避免多线程输出交叉
                with print_lock:
                    if log_buffer:
                        for buffered_log in log_buffer:
                            print(buffered_log)
                        log_buffer = [] # 清空
                    print(formatted_log)

    except ValueError:
        pass
    finally:
        # 进程提前退出时，确保把缓冲日志刷出来，避免启动失败无任何提示
        # 但在正常停服流程中不刷缓冲，避免输出插队
        if log_buffer and not shutdown_flag:
            with print_lock:
                for buffered_log in log_buffer:
                    print(buffered_log)
            log_buffer = []

def wait_for_summary_creds() -> None:
    """等待子服务输出凭证到 stdout，便于汇总展示"""
    if not SHOW_SUMMARY_CREDS:
        return
    deadline = time.time() + max(0.0, float(SUMMARY_CRED_WAIT))
    target_pairs = [
        (name, svc.get('short'))
        for name, svc in process_services.items()
        if svc.get('short') in ('SSH', 'Web', 'DB', 'FTP', 'Telnet')
    ]
    targets = {short for _, short in target_pairs}
    if not targets:
        return
    while time.time() < deadline:
        missing = [t for t in targets if not CAPTURED_CREDS.get(t)]
        if not missing:
            return
        alive_missing = set()
        for name, short in target_pairs:
            proc = processes.get(name)
            if short in missing and proc and proc.poll() is None:
                alive_missing.add(short)
        if not alive_missing:
            return
        time.sleep(0.05)

def start_service(service: Dict, restart: bool = False) -> Optional[subprocess.Popen]:
    """启动单个服务（支持外部目录 + 独立解释器的子服务）"""
    service_name = service['name']
    script_rel = service.get('script') or ''
    script_path = os.path.join(BASE_DIR, script_rel) if script_rel else ''

    if script_rel and not os.path.exists(script_path):
        logger.error(f"脚本文件不存在: {script_path}")
        return None

    workdir = service.get('cwd') or BASE_DIR
    interpreter = service.get('python') or sys.executable

    if not restart:
        port = service.get('port', 0)
        host = service.get('host', '0.0.0.0')
        if not check_port(port, host):
            logger.error(f"端口 {port} 被占用，无法启动 {service_name}")
            return None
    else:
        # 重启前清理该服务可能残留的孤儿进程（venv 启动器退出后真实解释器仍可能占用端口）
        service_ports = _service_ports_of(service)
        for port in service_ports:
            if check_port(port, service.get('host', '0.0.0.0')):
                continue
            owner_pid = _port_owner_map().get(port)
            if owner_pid and _is_project_service_process(owner_pid):
                logger.warning(f"重启 {service_name} 前清理端口 {port} 的残留进程 PID={owner_pid}")
                _terminate_process_tree(owner_pid)
        _wait_ports_free(service_ports, 3.0)

    try:
        # 通过环境变量避免子进程输出乱码
        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        env["EMIT_CREDENTIAL_LINES"] = "1" if SHOW_SUMMARY_CREDS else "0"
        if "HONEYPOT_CONFIG" in os.environ:
            env["HONEYPOT_CONFIG"] = os.environ["HONEYPOT_CONFIG"]

        # 构建启动命令
        cmd = [interpreter, "-u", script_path] if script_path else [interpreter]

        if service.get('args'):
            # 自定义参数模式（如 team_center serve --config / gateway --config）
            cmd.extend(service['args'])
        else:
            # 传递端口参数
            port = service.get('port')
            if port:
                cmd.extend(["--port", str(port)])

            # 传递监听地址参数
            host = service.get('host')
            if host:
                cmd.extend(["--host", str(host)])

        creationflags = 0
        startupinfo = None
        if sys.platform == 'win32':
            creationflags = subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        process = subprocess.Popen(
            cmd, # 使用构建好的带参数命令
            cwd=workdir,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True, # 文本模式，自动解码
            encoding='utf-8',
            errors='replace',
            env=env,
            creationflags=creationflags,
            startupinfo=startupinfo
        )

        t = threading.Thread(target=log_streamer, args=(process.stdout, service['short'], service['color']), daemon=True)
        t.start()
        threads.append(t)

        service_status[service_name]['status'] = 'running'
        service_status[service_name]['pid'] = process.pid
        if restart:
            service_status[service_name]['last_restart'] = time.time()
        else:
            service_status[service_name]['last_start'] = time.time()
            service_status[service_name]['restart_count'] = 0

        return process
    except Exception as e:
        logger.error(f"启动 {service_name} 失败: {e}")
        return None

def start_all_services():
    """启动所有服务"""
    global processes, process_services
    safe_print(f"{BOLD}[2/3] 启动服务进程...{RESET}\n")

    for service in SERVICES:
        name = service['name']
        color = service['color']
        port = service['port']
        safe_print(f"  {YELLOW}○{RESET} 正在启动 {color}{name}{RESET} (端口 {port})...", end='', flush=True)

        process = start_service(service)

        # 换行，以便日志接在下面
        safe_print()

        if process:
            processes[name] = process
            process_services[name] = service
            time.sleep(0.5)
            if process.poll() is None:
                safe_print(f"  {GREEN}√{RESET} 已启动 {color}{name}{RESET} (PID: {process.pid})")
            else:
                safe_print(f"  {RED}×{RESET} 启动失败 {color}{name}{RESET} (立即退出)")
                logger.error(f"{name} 启动失败")
        else:
            safe_print(f"\r  {RED}✗{RESET} 启动失败 {color}{name}{RESET}")
    _save_runtime_state()
    safe_print()

def _probe_external_ai():
    """探活外部（Docker）AI 检测服务。

    返回 (ok, detail)；未启用时返回 None。只用于启动提示，失败不阻塞启动。
    """
    if not _env_bool('AI_XSS_ENABLED', False):
        return None

    detect_url = _env_str(
        'AI_XSS_URL', 'http://127.0.0.1:8000/api/v1/detect'
    ).strip() or 'http://127.0.0.1:8000/api/v1/detect'
    info_url = _env_str(
        'AI_XSS_INFO_URL', 'http://127.0.0.1:8000/model/info'
    ).strip() or 'http://127.0.0.1:8000/model/info'

    if '/api/' in detect_url:
        base_url = detect_url.split('/api/', 1)[0].rstrip('/')
    else:
        base_url = detect_url.rstrip('/')
    health_url = base_url + '/health'

    try:
        import requests
        response = requests.get(health_url, timeout=1.2)
        response.raise_for_status()
        health = response.json() or {}
        if not health.get('model_loaded'):
            return False, '服务可达但模型未加载'

        info = {}
        try:
            info_response = requests.get(info_url, timeout=0.8)
            if info_response.ok:
                info = info_response.json() or {}
        except Exception:
            info = {}

        version = str(info.get('version') or '').strip()
        trained_at = str(info.get('trained_at') or '').strip()
        detail = '在线'
        if version:
            detail += f'｜模型 {version}'
        if trained_at:
            detail += f'（{trained_at}）'
        return True, detail
    except Exception as exc:
        return False, f'不可达（{str(exc)[:80]}），将回退纯规则'


def print_service_summary():
    """打印服务访问地址汇总"""
    # 先等一小会儿抓取凭证，避免汇总里空白
    wait_for_summary_creds()

    safe_print(f"{BOLD}[3/3] 服务访问地址汇总{RESET}")
    safe_print(f"  {BOLD}{'─' * 60}{RESET}")

    for service in SERVICES:
        name = service['name']
        color = service['color']
        port = service['port']
        bind_host = service.get('host', '0.0.0.0')
        display_host = _resolve_display_host(bind_host)
        short = service['short']
        desc = service['description']

        # 各服务的访问入口（按 short 数据驱动，避免新增协议时漏配）
        if short == 'SSH':
            urls = [f"ssh root@{display_host} -p {port}"]
        elif short == 'Web':
            urls = [
                f"http://{display_host}:{port}",
                f"http://{display_host}:{port}/admin",
            ]
        elif short == 'Dash':
            urls = [f"http://{display_host}:{port}/dashboard"]
        elif short == 'DB':
            _redis_port = service.get('redis_port', 16379)
            urls = [
                f"mysql -h {display_host} -P {port} -u root -p",
                f"redis-cli -h {display_host} -p {_redis_port}",
            ]
        elif short == 'FTP':
            urls = [
                f"ftp://{display_host}:{port}/",
                f"ftp {display_host} {port}",
            ]
        elif short == 'Telnet':
            urls = [f"telnet {display_host} {port}"]
        elif short == 'Team':
            urls = [f"http://{display_host}:{port}/"]
        elif short == 'AI-GW':
            urls = [f"http://{display_host}:{port}/v1/status"]
        elif short == 'AI-DET':
            urls = [
                f"http://{display_host}:{port}/health",
                f"http://{display_host}:{port}/model/info",
            ]
        else:
            urls = [f"{display_host}:{port}"]

        # 凭证展示（管理端使用 [admin] 配置，不在此展示诱饵凭证）
        creds_lines = []
        if short != 'Dash':
            if not SHOW_SUMMARY_CREDS:
                creds_lines = [f"{GRAY}凭证已隐藏{RESET}"]
            else:
                creds_list = CAPTURED_CREDS.get(short, [])
                if creds_list:
                    max_u_len = max(len(c.split('/')[0]) for c in creds_list)
                    for c in creds_list:
                        u, p = c.split('/')
                        creds_lines.append(f"{BOLD}{u:<{max_u_len}}{RESET} : {BOLD}{p}{RESET}")

        # 统一的服务标题格式
        safe_print(f"  {color}> [{name}]{RESET} {desc}")
        for entry_url in urls:
            safe_print(f"    {CYAN}{entry_url}{RESET}")

        # 输出凭证信息
        if creds_lines:
            if len(creds_lines) == 1 and creds_lines[0].startswith(GRAY):
                safe_print(f"    {creds_lines[0]}")
            else:
                safe_print("    凭证列表:")
                for line in creds_lines:
                    safe_print(f"      {line}")

        safe_print()

    # 外部 AI 检测服务（Docker）不在 SERVICES 中托管，单独探活并提示
    probe = _probe_external_ai()
    if probe is not None:
        ai_ok, ai_detail = probe
        ai_url = _env_str(
            'AI_XSS_URL', 'http://127.0.0.1:8000/api/v1/detect'
        ).strip() or 'http://127.0.0.1:8000/api/v1/detect'
        ai_color = GREEN if ai_ok else YELLOW
        safe_print(
            f"  {ai_color}> [AI攻击检测·Docker]{RESET} "
            "请求级攻击检测模型（规则 + ai_points 融合）"
        )
        safe_print(f"    {CYAN}{ai_url}{RESET}")
        safe_print(f"    状态: {ai_color}{ai_detail}{RESET}")
        safe_print()

    safe_print(f"  {BOLD}{'─' * 60}{RESET}")
    if _is_running_under_systemd():
        service_name = str(os.environ.get('SYSTEMD_SERVICE_NAME', 'honeypot')).strip() or 'honeypot'
        safe_print(
            f"\n  {YELLOW}提示:{RESET} 当前为 systemd 托管。"
            f"停止: {BOLD}sudo systemctl stop {service_name}{RESET}，"
            f"日志: {BOLD}sudo journalctl -u {service_name} -f -o cat{RESET}\n"
        )
    else:
        safe_print(f"\n  {YELLOW}提示:{RESET} 日志已实时输出到下方控制台，按 {BOLD}Ctrl+C{RESET} 停止所有服务\n")
    safe_print(f"{BOLD}=== 系统运行日志 ==={RESET}\n")

    # 打印完毕后，允许日志开始流动
    startup_event.set()

def signal_handler(signum, frame):
    raise KeyboardInterrupt

def shutdown_all_services():
    """关闭所有服务进程（连同 venv 启动器派生的真实解释器一起结束）"""
    global processes, shutdown_flag
    shutdown_flag = True
    safe_print(f"\n\n{YELLOW}[系统] 正在停止所有服务...{RESET}")

    for name, process in list(processes.items()):
        if not process:
            continue
        safe_print(f"  关闭 {name}...", end=' ')
        try:
            if process.poll() is None and sys.platform == 'win32':
                try:
                    process.send_signal(signal.CTRL_BREAK_EVENT)
                except Exception:
                    pass
            _terminate_process_tree(process.pid)
            safe_print(f"{GREEN}OK{RESET}")
        except Exception as exc:
            logger.warning(f"关闭 {name} 失败: {exc}")
            safe_print(f"{RED}Fail{RESET}")

    # 兜底：清理 launcher 已退出但真实服务仍在监听端口的孤儿进程
    _kill_remaining_project_services()

    processes.clear()
    _clear_runtime_state()
    _remove_file(_stop_file_path())
    safe_print(f"{GREEN}所有服务已安全停止。{RESET}")

def monitor_processes():
    """监控子进程状态；检测到外部停止标记时退出主循环。"""
    while True:
        time.sleep(2)

        # 外部停止请求必须优先于重启判断：否则进程退出会被立即拉起，--stop 永远停不下来
        if _stop_requested():
            safe_print(f"\n{YELLOW}[系统] 收到外部停止请求，正在关闭所有服务...{RESET}")
            return

        if not processes:
            break

        for name, process in list(processes.items()):
            if process.poll() is not None:
                service_info = process_services.get(name, {})
                returncode = process.returncode
                # 记录退出状态
                status = service_status.get(name, {})
                status['exit_code'] = returncode

                # 检查重启
                restart_count = status.get('restart_count', 0)
                if restart_count < MAX_RESTART_ATTEMPTS:
                    safe_print(f"\n{YELLOW}[警告] {name} 意外退出 (Code: {returncode})，正在尝试重启...{RESET}")

                    # 启动新进程
                    if RESTART_DELAY > 0:
                        time.sleep(RESTART_DELAY)
                    new_process = start_service(service_info, restart=True)
                    if new_process:
                        processes[name] = new_process
                        _save_runtime_state()
                        status['restart_count'] = restart_count + 1
                        safe_print(f"{GREEN}[系统] {name} 重启成功 (PID: {new_process.pid}){RESET}")
                    else:
                        safe_print(f"{RED}[错误] {name} 重启失败{RESET}")
                        status['restart_count'] = restart_count + 1
                else:
                    if status.get('status') != 'failed':
                        safe_print(f"\n{RED}[严重错误] {name} 达到最大重启次数，停止重启{RESET}")
                        status['status'] = 'failed'


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        prog='main.py',
        description='网络威胁态势感知与蜜罐诱捕系统统一启动入口',
    )
    action = parser.add_mutually_exclusive_group()
    action.add_argument('--stop', action='store_true', help='停止正在运行的蜜罐实例并释放端口')
    action.add_argument('--restart', action='store_true', help='先停止旧实例，再重新启动')
    action.add_argument('--status', action='store_true', help='查看各服务端口与进程状态')
    parser.add_argument(
        '--no-auto-clean',
        action='store_true',
        help='端口被本项目上一次运行的进程占用时，不自动停止旧实例',
    )
    return parser.parse_args(argv)


def cmd_status() -> int:
    """打印端口与服务状态，不启动也不停止任何进程。"""
    safe_print(f"\n{BOLD}蜜罐服务状态{RESET}\n")
    owners = _port_owner_map()
    all_running = True
    for service in SERVICES:
        for port in _service_ports_of(service):
            host = service.get('host', '0.0.0.0')
            if check_port(port, host):
                safe_print(f"  {RED}×{RESET} [{service['name']}] 端口 {BOLD}{port}{RESET}: 未监听")
                all_running = False
                continue
            pid = owners.get(port)
            if pid and _is_project_service_process(pid):
                label = f"{GREEN}本项目{RESET}"
            else:
                label = f"{YELLOW}外部进程{RESET}"
                all_running = False
            safe_print(
                f"  {GREEN}√{RESET} [{service['name']}] 端口 {BOLD}{port}{RESET}: "
                f"监听中 <- {label} {_describe_owner(pid)}"
            )

    state = _read_runtime_state()
    supervisor_pid = state.get('pid')
    service_pids = {
        owners.get(port) for port in _service_port_numbers()
        if owners.get(port) and _is_project_service_process(owners.get(port))
    }
    detected_supervisors = sorted(_find_supervisor_pids(service_pids))
    if supervisor_pid and _pid_exists(supervisor_pid) and _is_supervisor_process(supervisor_pid):
        safe_print(f"\n  主进程: PID {supervisor_pid} 运行中")
    elif detected_supervisors:
        safe_print(f"\n  主进程: PID {', '.join(str(pid) for pid in detected_supervisors)} 运行中")
    else:
        safe_print("\n  主进程: 未运行")

    conflicts = _scan_port_conflicts()
    foreign = [item for item in conflicts if not item['ours']]
    if foreign:
        safe_print(f"\n  {YELLOW}以下端口被外部程序占用:{RESET}")
        for item in foreign:
            safe_print(f"    端口 {item['port']} <- {_describe_owner(item['pid'])}")
    safe_print()
    return 0 if all_running else 1


def cmd_stop() -> int:
    """停止本项目正在运行的实例，并报告仍被外部程序占用的端口。"""
    stopped = stop_running_instance()
    if stopped:
        safe_print(f"\n{GREEN}蜜罐服务已停止，端口已释放。{RESET}")
    else:
        safe_print(f"\n{YELLOW}没有检测到正在运行的本项目实例。{RESET}")

    conflicts = _scan_port_conflicts()
    own_left = [item for item in conflicts if item['ours']]
    for item in own_left:
        safe_print(
            f"  {RED}端口 {item['port']} 仍被本项目进程占用: "
            f"{_describe_owner(item['pid'])}{RESET}"
        )
    foreign = [item for item in conflicts if not item['ours']]
    for item in foreign:
        safe_print(
            f"  {YELLOW}端口 {item['port']} 仍被外部程序占用: "
            f"{_describe_owner(item['pid'])}{RESET}"
        )
    safe_print()
    return 1 if own_left else 0


def main(argv=None):
    args = parse_args(argv)
    if args.status:
        sys.exit(cmd_status())
    if args.stop:
        sys.exit(cmd_stop())
    if args.restart:
        stop_running_instance()

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    if sys.platform == 'win32':
        try: signal.signal(signal.SIGBREAK, signal_handler)
        except AttributeError: pass

    # 清掉上一次可能残留的停止标记，避免刚启动就被误停
    _remove_file(_stop_file_path())

    os.system('') # Enable ANSI
    print_banner()
    # 启动自检：打印数据库模式
    try:
        from app_config import config as app_config
        env_key = 'production' if _is_production_env() else 'development'
        safe_print(f"{CYAN}{BOLD}[ENV]{RESET} {env_key}")
        logger.info(f"运行环境: {env_key}")
        conf = app_config[env_key]
        db_type = str(getattr(conf, 'DB_TYPE', 'sqlite')).lower()
        if db_type == 'mysql':
            msg = f"MySQL  {conf.DB_USER}@{conf.DB_HOST}:{conf.DB_PORT}/{conf.DB_NAME}"
        else:
            db_path = getattr(conf, 'DB_PATH', os.path.join(BASE_DIR, 'database', 'event_logs.db'))
            msg = f"SQLite {db_path}"
        safe_print(f"{CYAN}{BOLD}[DB]{RESET} {msg}")
        logger.info(msg)
    except Exception as e:
        logger.debug(f"数据库配置读取失败: {e}")
    logger.info("=" * 45)
    logger.info("蜜罐系统启动中...")

    if not check_all_ports(auto_clean=not args.no_auto_clean):
        safe_print(
            f"{RED}{BOLD}错误: 部分端口被外部程序占用。{RESET}\n"
            f"  请关闭占用程序，或修改 honeypot.ini 中对应服务的 port 后重试；\n"
            f"  也可运行 {BOLD}python main.py --status{RESET} 查看占用者。"
        )
        sys.exit(1)

    start_all_services()

    if not processes:
        safe_print(f"{RED}{BOLD}错误: 所有服务均启动失败，系统退出。{RESET}")
        sys.exit(1)

    try:
        print_service_summary()
        _save_runtime_state()
        logger.info("所有服务已启动，系统运行中")
        monitor_processes()
    except KeyboardInterrupt:
        pass
    finally:
        shutdown_all_services()

if __name__ == '__main__':
    main()

