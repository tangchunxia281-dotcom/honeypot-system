# -*- coding: utf-8 -*-
"""
蜜罐系统统一启动入口
功能：
1. 统一管理 SSH、Web、Dashboard 三个服务进程
2. 实时流式监控子服务日志，防止管道阻塞
3. 异常退出实时告警与错误回显
4. 服务自动重启机制，防止单点故障
"""
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

# 添加项目根目录到路径
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

# 主控制器日志（仅文件输出，避免与控制台主流程重复）
logger = setup_logger('main', 'main.log', console_output=False)

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

def check_all_ports() -> bool:
    """检查所有服务端口是否可用"""
    safe_print(f"\n{BOLD}[启动检查] 检查端口占用情况...{RESET}\n")
    all_available = True
    for service in SERVICES:
        port = service['port']
        host = service.get('host', '0.0.0.0')
        name = service['name']
        color = service['color']
        if check_port(port, host):
            safe_print(f"  {GREEN}√{RESET} 端口 {BOLD}{port}{RESET} 可用 ({color}{name}{RESET})")
        else:
            safe_print(f"  {RED}×{RESET} 端口 {BOLD}{port}{RESET} 已被占用 ({color}{name}{RESET})")
            all_available = False
    safe_print()
    return all_available


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
        if svc.get('short') in ('SSH', 'Web')
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
    """启动单个服务"""
    script_path = os.path.join(BASE_DIR, service['script'])
    service_name = service['name']

    if not os.path.exists(script_path):
        logger.error(f"脚本文件不存在: {script_path}")
        return None

    if not restart:
        port = service.get('port', 0)
        host = service.get('host', '0.0.0.0')
        if not check_port(port, host):
            logger.error(f"端口 {port} 被占用，无法启动 {service_name}")
            return None

    try:
        # 通过环境变量避免子进程输出乱码
        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        env["EMIT_CREDENTIAL_LINES"] = "1" if SHOW_SUMMARY_CREDS else "0"
        if "HONEYPOT_CONFIG" in os.environ:
            env["HONEYPOT_CONFIG"] = os.environ["HONEYPOT_CONFIG"]

        # 构建启动命令
        cmd = [sys.executable, "-u", script_path]

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
            cwd=BASE_DIR,
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
    safe_print(f"{BOLD}[启动服务] 启动服务进程...{RESET}\n")

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
    safe_print()

def print_service_summary():
    """打印服务访问地址汇总"""
    # 先等一小会儿抓取凭证，避免汇总里空白
    wait_for_summary_creds()

    safe_print(f"{BOLD}[访问汇总] 服务访问地址汇总{RESET}")
    safe_print(f"  {BOLD}{'─' * 60}{RESET}")

    for service in SERVICES:
        name = service['name']
        color = service['color']
        port = service['port']
        bind_host = service.get('host', '0.0.0.0')
        display_host = _resolve_display_host(bind_host)
        short = service['short']
        desc = service['description']

        if 'SSH' in name:
            url = f"ssh root@{display_host} -p {port}"
            if not SHOW_SUMMARY_CREDS:
                creds = f"{GRAY}凭证已隐藏{RESET}"
            else:
                creds_list = CAPTURED_CREDS.get(short, [])
                if creds_list:
                    creds_lines = []
                    # 计算用户名列宽用于对齐
                    max_u_len = max(len(c.split('/')[0]) for c in creds_list)

                    for c in creds_list:
                        u, p = c.split('/')
                        # 对齐显示: root   : 111111
                        creds_lines.append(f"{BOLD}{u:<{max_u_len}}{RESET} : {BOLD}{p}{RESET}")

                    if len(creds_lines) == 1:
                         creds = f"测试: {creds_lines[0]}"
                    else:
                         creds = f"凭证列表:"
                         for line in creds_lines:
                             creds += f"\n      {line}"
                else:
                    creds = f"{GRAY}暂无凭证{RESET}"

        elif name == 'Web蜜罐':
            url = f"http://{display_host}:{port}"
            if not SHOW_SUMMARY_CREDS:
                creds = f"{GRAY}凭证已隐藏{RESET}"
            else:
                creds_list = CAPTURED_CREDS.get(short, [])
                if creds_list:
                    creds_lines = []
                    max_u_len = max(len(c.split('/')[0]) for c in creds_list)

                    for c in creds_list:
                        u, p = c.split('/')
                        creds_lines.append(f"{BOLD}{u:<{max_u_len}}{RESET} : {BOLD}{p}{RESET}")

                    if len(creds_lines) == 1:
                         creds = f"测试: {creds_lines[0]}"
                    else:
                         creds = f"凭证列表:"
                         for line in creds_lines:
                             creds += f"\n      {line}"
                else:
                    creds = f"{GRAY}暂无凭证{RESET}"

        elif name == '管理端':
            url = f"http://{display_host}:{port}/dashboard"
            creds = ""

        # 统一的服务标题格式
        safe_print(f"  {color}> [{name}]{RESET} {desc}")
        safe_print(f"    {CYAN}{url}{RESET}")
        if name == 'Web蜜罐':
            safe_print(f"    {CYAN}http://{display_host}:{port}/admin{RESET}")

        # 输出凭证信息
        if creds:
            safe_print(f"    {creds}")

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
    """关闭所有服务进程"""
    global processes, shutdown_flag
    shutdown_flag = True
    safe_print(f"\n\n{YELLOW}[系统] 正在停止所有服务...{RESET}")

    for name, process in processes.items():
        if process and process.poll() is None:
            safe_print(f"  关闭 {name}...", end=' ')
            try:
                if sys.platform == 'win32':
                    try:
                        process.send_signal(signal.CTRL_BREAK_EVENT)
                        time.sleep(1)
                    except Exception:
                        pass
                process.terminate()
                try:
                    process.wait(timeout=2)
                    safe_print(f"{GREEN}OK{RESET}")
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                    safe_print(f"{RED}Kill{RESET}")
            except Exception as e:
                safe_print(f"{RED}Fail{RESET}")

    processes.clear()
    safe_print(f"{GREEN}所有服务已安全停止。{RESET}")

def monitor_processes():
    """监控子进程状态"""
    while True:
        time.sleep(2)
        if not processes: break

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
                        status['restart_count'] = restart_count + 1
                        safe_print(f"{GREEN}[系统] {name} 重启成功 (PID: {new_process.pid}){RESET}")
                    else:
                        safe_print(f"{RED}[错误] {name} 重启失败{RESET}")
                        status['restart_count'] = restart_count + 1
                else:
                    if status.get('status') != 'failed':
                        safe_print(f"\n{RED}[严重错误] {name} 达到最大重启次数，停止重启{RESET}")
                        status['status'] = 'failed'

def main():
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    if sys.platform == 'win32':
        try: signal.signal(signal.SIGBREAK, signal_handler)
        except AttributeError: pass

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


    if not check_all_ports():
        safe_print(f"{RED}{BOLD}错误: 部分端口被占用，请先释放端口后重试{RESET}")
        sys.exit(1)

    start_all_services()

    if not processes:
        safe_print(f"{RED}{BOLD}错误: 所有服务均启动失败，系统退出。{RESET}")
        sys.exit(1)

    try:
        print_service_summary()
        logger.info("所有服务已启动，系统运行中")
        monitor_processes()
    except KeyboardInterrupt:
        pass
    finally:
        shutdown_all_services()

if __name__ == '__main__':
    main()

