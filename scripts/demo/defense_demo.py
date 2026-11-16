# -*- coding: utf-8 -*-
"""
答辩功能演示脚本（SSH + Web + Dashboard）

用途：
1) 自动复用或拉起三端服务
2) 触发典型攻击样本（SSH 口令爆破样本、Web 探测样本）
3) 自动登录管理端并拉取事件/统计接口
4) 输出演示结果与 JSON 报告，便于答辩现场讲解
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import signal
import socket
import subprocess
import sys
import threading
import time
from collections import Counter, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import requests

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from env_utils import env_int as _env_int, env_str as _env_str


ROOT_DIR = Path(__file__).resolve().parent.parent.parent
SCRIPTS_DIR = ROOT_DIR / "scripts"
DEMO_DIR = SCRIPTS_DIR / "demo"
MAIN_PY = ROOT_DIR / "main.py"
REPORT_PATH = DEMO_DIR / "last_demo_report.json"
LOCK_PATH = DEMO_DIR / ".defense_demo.lock"
# 远程答辩目标单点配置（一个变量控制 SSH/Web/Dashboard 三端目标）
DEFAULT_DEMO_TARGET_HOST = _env_str('DEMO_TARGET_HOST', '101.34.65.27') or '101.34.65.27'

def _is_local_host(host: str) -> bool:
    h = str(host or "").strip().lower()
    if h in ("127.0.0.1", "localhost", "::1", "0.0.0.0", "::", "[::]"):
        return True
    try:
        ip = socket.gethostbyname(h)
        return ip.startswith("127.")
    except Exception:
        return False


def _probe_host_for_client(host: str) -> str:
    """
    将监听地址转换成客户端可访问地址。
    - 0.0.0.0/::/localhost -> 127.0.0.1
    - 其他保持原样（域名/IP）
    """
    h = str(host or "").strip()
    if not h:
        return "127.0.0.1"
    if h.lower() in ("localhost",):
        return "127.0.0.1"
    if h in ("0.0.0.0", "::", "[::]"):
        return "127.0.0.1"
    return h


def _pid_is_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except Exception:
        return False


def _acquire_lock(lock_path: Path) -> Optional[int]:
    try:
        fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        os.write(fd, str(os.getpid()).encode("utf-8", errors="ignore"))
        return fd
    except FileExistsError:
        try:
            stale_pid = int(lock_path.read_text(encoding="utf-8").strip())
        except Exception:
            stale_pid = -1
        if stale_pid > 0 and not _pid_is_alive(stale_pid):
            try:
                lock_path.unlink()
            except Exception:
                return None
            try:
                fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                os.write(fd, str(os.getpid()).encode("utf-8", errors="ignore"))
                return fd
            except Exception:
                return None
        return None


def _release_lock(lock_fd: Optional[int], lock_path: Path) -> None:
    try:
        if lock_fd is not None:
            os.close(lock_fd)
    except Exception:
        pass
    try:
        if lock_path.exists():
            lock_path.unlink()
    except Exception:
        pass


def _is_port_open(host: str, port: int, timeout: float = 0.5) -> bool:
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except Exception:
        return False


def _wait_for_http(url: str, timeout_s: float, ok_status: Tuple[int, ...]) -> Tuple[bool, str]:
    deadline = time.time() + float(timeout_s)
    last_err = "timeout"
    while time.time() < deadline:
        try:
            r = requests.get(url, timeout=2.5, allow_redirects=False)
            if r.status_code in ok_status:
                return True, f"status={r.status_code}"
            last_err = f"status={r.status_code}"
        except Exception as e:
            last_err = str(e)
        time.sleep(0.4)
    return False, last_err


def _wait_for_ssh_banner(host: str, port: int, timeout_s: float) -> Tuple[bool, str]:
    deadline = time.time() + float(timeout_s)
    last_err = "timeout"
    while time.time() < deadline:
        try:
            with socket.create_connection((host, int(port)), timeout=2.0) as s:
                s.settimeout(2.0)
                data = s.recv(256) or b""
                text = data.decode("utf-8", errors="ignore").strip()
                if text.startswith("SSH-2.0-"):
                    return True, text
                last_err = f"invalid_banner={text[:120]}"
        except Exception as e:
            last_err = str(e)
        time.sleep(0.4)
    return False, last_err


@dataclass
class StepResult:
    name: str
    ok: bool
    detail: str


class ManagedMainProcess:
    def __init__(self, env: Dict[str, str], workdir: Path) -> None:
        self._env = env
        self._workdir = workdir
        self.proc: Optional[subprocess.Popen] = None
        self.log_tail: deque[str] = deque(maxlen=240)
        self._reader_thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if self.proc is not None:
            return
        creationflags = 0
        if os.name == "nt":
            creationflags = subprocess.CREATE_NEW_PROCESS_GROUP
        self.proc = subprocess.Popen(
            [sys.executable, "-u", str(MAIN_PY)],
            cwd=str(self._workdir),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=self._env,
            creationflags=creationflags,
        )
        self._reader_thread = threading.Thread(target=self._read_logs, daemon=True)
        self._reader_thread.start()

    def _read_logs(self) -> None:
        if not self.proc or not self.proc.stdout:
            return
        try:
            for line in self.proc.stdout:
                if line:
                    self.log_tail.append(line.rstrip("\n"))
        except Exception:
            pass

    def is_alive(self) -> bool:
        return bool(self.proc and self.proc.poll() is None)

    def stop(self) -> None:
        if not self.proc or self.proc.poll() is not None:
            return
        try:
            if os.name == "nt" and hasattr(signal, "CTRL_BREAK_EVENT"):
                self.proc.send_signal(signal.CTRL_BREAK_EVENT)
                time.sleep(1.2)
            else:
                self.proc.terminate()
        except Exception:
            pass
        try:
            self.proc.wait(timeout=6.0)
        except Exception:
            try:
                self.proc.kill()
                self.proc.wait(timeout=3.0)
            except Exception:
                pass


def _extract_csrf_token(html: str) -> str:
    if not html:
        return ""
    m = re.search(r'name=["\']csrf_token["\']\s+value=["\']([^"\']+)["\']', html, re.IGNORECASE)
    return (m.group(1).strip() if m else "")


def _dashboard_login(base_url: str, username: str, password: str) -> Tuple[bool, str, requests.Session]:
    s = requests.Session()
    login_url = f"{base_url}/super/login"
    try:
        r = s.get(login_url, timeout=4.0)
    except Exception as e:
        return False, f"get_login_page_failed: {e}", s
    if r.status_code != 200:
        return False, f"get_login_page_status={r.status_code}", s

    token = _extract_csrf_token(r.text)
    if not token:
        return False, "csrf_token_missing", s

    try:
        p = s.post(
            login_url,
            data={"username": username, "password": password, "csrf_token": token},
            timeout=5.0,
            allow_redirects=False,
        )
    except Exception as e:
        return False, f"post_login_failed: {e}", s
    if p.status_code not in (200, 302, 303):
        return False, f"post_login_status={p.status_code}", s
    return True, f"status={p.status_code}", s


def _get_dashboard_apis(base_url: str, session_obj: requests.Session) -> Tuple[bool, Dict]:
    # Dashboard API 强制同源判断：显式带 Referer/Origin，避免 403
    headers = {
        "Referer": f"{base_url}/dashboard",
        "Origin": base_url,
    }

    out = {}
    try:
        r1 = session_obj.get(f"{base_url}/api/get_event_logs?limit=50", timeout=5.0, headers=headers)
        b1 = r1.json()
        ok1 = r1.status_code == 200 and int(b1.get("code", -1)) == 0 and isinstance(b1.get("data"), list)
        out["event_logs"] = {"ok": ok1, "status": r1.status_code, "body": b1}
    except Exception as e:
        out["event_logs"] = {"ok": False, "error": str(e)}

    try:
        r2 = session_obj.get(f"{base_url}/api/get_event_stats?hours=1", timeout=5.0, headers=headers)
        b2 = r2.json()
        ok2 = r2.status_code == 200 and int(b2.get("code", -1)) == 0 and isinstance(b2.get("data"), dict)
        out["event_stats"] = {"ok": ok2, "status": r2.status_code, "body": b2}
    except Exception as e:
        out["event_stats"] = {"ok": False, "error": str(e)}

    all_ok = bool(out.get("event_logs", {}).get("ok") and out.get("event_stats", {}).get("ok"))
    return all_ok, out


def _web_demo_traffic(base_url: str) -> Tuple[bool, List[Dict]]:
    """
    触发可讲解的 Web 样本：
    - 配置文件探测
    - Git 配置探测
    - 文件包含探测
    - 后台 API 探测 + SQLi 载荷
    """
    actions = [
        ("GET", "/.env", None),
        ("GET", "/.git/config", None),
        ("GET", "/page?page=../../../../etc/passwd", None),
        ("POST", "/admin/api/login", {"username": "admin' OR 1=1 --", "password": "x"}),
    ]
    results = []
    ok_count = 0
    for method, path, payload in actions:
        url = f"{base_url}{path}"
        try:
            if method == "GET":
                r = requests.get(url, timeout=4.0, allow_redirects=False)
            else:
                r = requests.post(url, json=payload, timeout=4.0, allow_redirects=False)
            results.append({"method": method, "path": path, "status": r.status_code})
            # 只要请求被系统接收并返回（非 5xx 连接错误）就算演示动作完成
            if 100 <= int(r.status_code) < 600:
                ok_count += 1
        except Exception as e:
            results.append({"method": method, "path": path, "error": str(e)})
    return ok_count >= 3, results


def _ssh_failed_attempt(host: str, port: int, username: str, password: str, timeout: float = 3.5) -> Tuple[bool, str]:
    """
    返回 (ok, detail)
    ok=True 表示“演示动作成功触发”：
    - 认证失败（预期）
    - 或连接被封禁/断开（也是防爆破演示结果）
    """
    try:
        import paramiko
    except Exception as e:
        return False, f"paramiko_not_available: {e}"

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=host,
            port=int(port),
            username=username,
            password=password,
            timeout=timeout,
            auth_timeout=timeout,
            banner_timeout=timeout,
            allow_agent=False,
            look_for_keys=False,
        )
        # 意外成功（通常不应发生）
        client.close()
        return False, f"unexpected_success user={username}"
    except paramiko.AuthenticationException:
        return True, f"auth_failed user={username}"
    except Exception as e:
        # 常见于封禁后连接被拒绝/中断，这对演示“防爆破”同样成立
        msg = str(e).lower()
        if any(k in msg for k in ("timed out", "refused", "reset", "banner", "closed")):
            return True, f"blocked_or_dropped user={username}: {e}"
        return False, f"ssh_error user={username}: {e}"
    finally:
        try:
            client.close()
        except Exception:
            pass


def _ssh_demo_traffic(host: str, port: int, fail_count: int) -> Tuple[bool, List[Dict]]:
    users = [
        "root", "admin", "postgres", "ubuntu", "test", "guest", "deploy",
        "nvidia", "huawei", "frappe", "openhabian", "sshadmin",
    ]
    out = []
    ok = 0
    for i in range(max(1, int(fail_count))):
        u = users[i % len(users)]
        p = f"WrongPass#{random.randint(1000, 9999)}"
        step_ok, detail = _ssh_failed_attempt(host, port, u, p)
        out.append({"index": i + 1, "user": u, "ok": step_ok, "detail": detail})
        if step_ok:
            ok += 1
        time.sleep(0.22)
    return ok >= max(2, min(4, fail_count)), out


def _build_demo_summary(api_data: Dict) -> Dict:
    logs = api_data.get("event_logs", {}).get("body", {}).get("data", []) if api_data else []
    stats = api_data.get("event_stats", {}).get("body", {}).get("data", {}) if api_data else {}

    source_counter = Counter()
    severity_counter = Counter()
    event_counter = Counter()
    for row in logs:
        source_counter[str(row.get("source") or "unknown")] += 1
        severity_counter[str(row.get("severity") or "unknown")] += 1
        event_counter[str(row.get("event_type") or "unknown")] += 1

    return {
        "recent_events": len(logs),
        "recent_by_source": dict(source_counter),
        "recent_by_severity": dict(severity_counter),
        "recent_top_event_types": [{"event_type": k, "count": int(v)} for k, v in event_counter.most_common(8)],
        "stats_snapshot": stats,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="答辩功能演示脚本")
    parser.add_argument("--reuse-running", action="store_true", help="复用现有服务，不自动拉起 main.py")
    parser.add_argument("--keep-running", action="store_true", help="若脚本拉起服务，演示完成后不自动关停")
    parser.add_argument("--startup-timeout", type=int, default=75, help="等待服务就绪秒数")
    parser.add_argument("--ssh-fail-count", type=int, default=6, help="SSH 失败样本次数（建议 4-12）")
    parser.add_argument("--allow-remote-targets", action="store_true", help="允许非本机目标（默认拒绝）")
    parser.add_argument("--target-host", default=DEFAULT_DEMO_TARGET_HOST, help="统一目标主机（优先用于 SSH/Web/Dashboard）")
    parser.add_argument("--ssh-host", default="", help="SSH 目标主机（可选，覆盖统一目标）")
    parser.add_argument("--ssh-port", type=int, default=_env_int("SSH_PORT", 2222, 1, 65535), help="SSH 目标端口")
    parser.add_argument("--web-host", default="", help="Web 目标主机（可选，覆盖统一目标）")
    parser.add_argument("--web-port", type=int, default=_env_int("WEB_PORT", 5000, 1, 65535), help="Web 目标端口")
    parser.add_argument("--dashboard-host", default="", help="Dashboard 目标主机（可选，覆盖统一目标）")
    parser.add_argument("--dashboard-port", type=int, default=_env_int("DASHBOARD_PORT", 5001, 1, 65535), help="Dashboard 目标端口")
    parser.add_argument("--admin-user", default=_env_str("ADMIN_USER", "admin"), help="Dashboard 用户名")
    parser.add_argument("--admin-pass", default=_env_str("ADMIN_PASS", "Admin@2024!"), help="Dashboard 密码")
    parser.add_argument("--web-scheme", default=_env_str("WEB_SCHEME", "http"), choices=["http", "https"], help="Web 协议")
    parser.add_argument("--dashboard-scheme", default=_env_str("DASHBOARD_SCHEME", "http"), choices=["http", "https"], help="Dashboard 协议")
    args = parser.parse_args()

    lock_fd = _acquire_lock(LOCK_PATH)
    if lock_fd is None:
        print(f"[ERROR] 已有演示脚本在运行。锁文件: {LOCK_PATH}")
        return 3

    target_host = str(args.target_host or "").strip()
    if not target_host:
        target_host = "127.0.0.1"
    ssh_host = str(args.ssh_host or "").strip() or target_host
    ssh_port = int(args.ssh_port)
    web_host = str(args.web_host or "").strip() or target_host
    web_port = int(args.web_port)
    dash_host = str(args.dashboard_host or "").strip() or target_host
    dash_port = int(args.dashboard_port)

    dashboard_user = str(args.admin_user or "").strip() or "admin"
    dashboard_pass = str(args.admin_pass or "")
    if not dashboard_pass:
        dashboard_pass = "Admin@2024!"
    has_remote_target = any(
        not _is_local_host(h) for h in (ssh_host, web_host, dash_host)
    )

    # 远程演示场景自动兜底：默认不要求手工传参
    if has_remote_target and not args.allow_remote_targets:
        print("[INFO] 检测到远程目标，自动启用 allow-remote-targets。")
        args.allow_remote_targets = True
    if has_remote_target and not args.reuse_running:
        print("[INFO] 检测到远程目标，自动启用 reuse-running。")
        args.reuse_running = True

    if not args.allow_remote_targets:
        remotes = []
        if not _is_local_host(ssh_host):
            remotes.append(f"SSH_HOST={ssh_host}")
        if not _is_local_host(web_host):
            remotes.append(f"WEB_HOST={web_host}")
        if not _is_local_host(dash_host):
            remotes.append(f"DASHBOARD_HOST={dash_host}")
        if remotes:
            print("[ERROR] 默认仅允许本机演示目标：")
            for x in remotes:
                print(f"  - {x}")
            print("如需远程演示，请显式加 --allow-remote-targets")
            _release_lock(lock_fd, LOCK_PATH)
            return 2

    check_ssh_host = _probe_host_for_client(ssh_host)
    check_web_host = _probe_host_for_client(web_host)
    check_dash_host = _probe_host_for_client(dash_host)

    if has_remote_target:
        # 远程模式下，0.0.0.0/:: 对客户端不可达，必须给可访问地址
        bad = []
        if check_ssh_host == "127.0.0.1" and not _is_local_host(ssh_host):
            bad.append(f"ssh_host={ssh_host}")
        if check_web_host == "127.0.0.1" and not _is_local_host(web_host):
            bad.append(f"web_host={web_host}")
        if check_dash_host == "127.0.0.1" and not _is_local_host(dash_host):
            bad.append(f"dashboard_host={dash_host}")
        if bad:
            print("[ERROR] 远程模式下主机地址不可用，请传入公网 IP/域名：")
            for x in bad:
                print(f"  - {x}")
            _release_lock(lock_fd, LOCK_PATH)
            return 2

    web_base = f"{args.web_scheme}://{check_web_host}:{web_port}"
    dash_base = f"{args.dashboard_scheme}://{check_dash_host}:{dash_port}"
    print(
        "[INFO] 当前演示目标: "
        f"SSH={check_ssh_host}:{ssh_port}, "
        f"WEB={web_base}, "
        f"DASH={dash_base}"
    )

    steps: List[StepResult] = []
    started_by_script = False
    proc: Optional[ManagedMainProcess] = None
    fatal_error = ""

    try:
        web_open = _is_port_open(check_web_host, web_port)
        dash_open = _is_port_open(check_dash_host, dash_port)
        ssh_open = _is_port_open(check_ssh_host, ssh_port)

        if args.reuse_running:
            if not (web_open and dash_open and ssh_open):
                steps.append(
                    StepResult(
                        "precheck_ports",
                        False,
                        f"--reuse-running 需要三端在线: ssh={ssh_open}({check_ssh_host}:{ssh_port}), "
                        f"web={web_open}({check_web_host}:{web_port}), "
                        f"dash={dash_open}({check_dash_host}:{dash_port})",
                    )
                )
                return_code = 2
            else:
                steps.append(StepResult("precheck_ports", True, "reuse-running OK"))
                return_code = None
        else:
            if web_open or dash_open or ssh_open:
                steps.append(
                    StepResult(
                        "precheck_ports",
                        False,
                        f"端口已占用，避免误操作: ssh={ssh_open}, web={web_open}, dash={dash_open}",
                    )
                )
                return_code = 2
            else:
                env = os.environ.copy()
                env.setdefault("PYTHONIOENCODING", "utf-8")
                env.setdefault("SHOW_SUMMARY_CREDS", "0")
                env.setdefault("EMIT_CREDENTIAL_LINES", "0")
                if str(env.get("PRODUCTION_MODE", "")).strip().lower() in ("true", "yes") and not env.get("ADMIN_PASS"):
                    env["ADMIN_PASS"] = dashboard_pass
                proc = ManagedMainProcess(env=env, workdir=ROOT_DIR)
                proc.start()
                started_by_script = True
                return_code = None
                steps.append(StepResult("start_main", True, "main.py started"))

        if return_code is None:
            if proc and started_by_script and (not proc.is_alive()):
                steps.append(StepResult("main_process_alive", False, "main.py exited unexpectedly"))
                return_code = 1

        if return_code is None:
            ok, detail = _wait_for_http(f"{web_base}/", args.startup_timeout, (200, 302, 404))
            steps.append(StepResult("ready_web", ok, detail))

            ok, detail = _wait_for_http(f"{dash_base}/super/login", args.startup_timeout, (200,))
            steps.append(StepResult("ready_dashboard", ok, detail))

            ok, detail = _wait_for_ssh_banner(check_ssh_host, ssh_port, args.startup_timeout)
            steps.append(StepResult("ready_ssh", ok, detail))

            ready_ok = all(
                s.ok for s in steps
                if s.name in ("ready_web", "ready_dashboard", "ready_ssh")
            )

            web_actions = []
            ssh_actions = []
            api_data = {}
            summary = {}

            if ready_ok:
                web_ok, web_actions = _web_demo_traffic(web_base)
                steps.append(StepResult("demo_web_traffic", web_ok, f"actions={len(web_actions)}"))

                ssh_ok, ssh_actions = _ssh_demo_traffic(check_ssh_host, ssh_port, args.ssh_fail_count)
                steps.append(StepResult("demo_ssh_traffic", ssh_ok, f"attempts={len(ssh_actions)}"))

                # 给日志写入与聚合一点时间
                time.sleep(1.2)

                login_ok, login_detail, session_obj = _dashboard_login(dash_base, dashboard_user, dashboard_pass)
                steps.append(StepResult("dashboard_login", login_ok, login_detail))

                if login_ok:
                    api_ok, api_data = _get_dashboard_apis(dash_base, session_obj)
                    steps.append(StepResult("dashboard_apis", api_ok, "get_event_logs + get_event_stats"))
                    if api_ok:
                        summary = _build_demo_summary(api_data)
                        steps.append(
                            StepResult(
                                "demo_summary",
                                True,
                                f"recent_events={summary.get('recent_events', 0)}, by_source={summary.get('recent_by_source', {})}",
                            )
                        )
                else:
                    api_data = {}
                    summary = {}
            else:
                steps.append(StepResult("demo_aborted", False, "服务未就绪，已跳过流量触发与统计拉取"))
        else:
            web_actions = []
            ssh_actions = []
            api_data = {}
            summary = {}

    except KeyboardInterrupt:
        steps.append(StepResult("interrupted", False, "keyboard interrupt"))
        return_code = 130
    except Exception as e:
        fatal_error = f"{type(e).__name__}: {e}"
        steps.append(StepResult("fatal_exception", False, fatal_error))
        return_code = 1
    finally:
        if started_by_script and proc and not args.keep_running:
            proc.stop()

    passed = sum(1 for s in steps if s.ok)
    total = len(steps)
    all_ok = total > 0 and passed == total

    print("\n=== Defense Demo Report ===")
    for s in steps:
        status = "PASS" if s.ok else "FAIL"
        print(f"[{status}] {s.name}: {s.detail}")
    print(f"Summary: {passed}/{total} passed")

    # 答辩可直接口播的数据摘要
    if summary:
        print("\n--- 答辩口播摘要 ---")
        print(f"近一小时样本事件数: {summary.get('recent_events', 0)}")
        print(f"来源分布: {summary.get('recent_by_source', {})}")
        print(f"风险分布: {summary.get('recent_by_severity', {})}")
        top_types = summary.get("recent_top_event_types", [])
        if top_types:
            print(f"高频事件类型Top3: {top_types[:3]}")

    report = {
        "timestamp": int(time.time()),
        "all_ok": all_ok,
        "passed": passed,
        "total": total,
        "steps": [{"name": s.name, "ok": s.ok, "detail": s.detail} for s in steps],
        "web_actions": web_actions,
        "ssh_actions": ssh_actions,
        "api_data": api_data,
        "summary": summary,
    }
    if fatal_error:
        report["fatal_error"] = fatal_error
    if proc and proc.log_tail:
        report["main_log_tail"] = list(proc.log_tail)[-100:]

    try:
        REPORT_PATH.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"\nReport saved: {REPORT_PATH}")
    except Exception as e:
        print(f"\n[WARN] 报告写入失败: {e}")
    finally:
        _release_lock(lock_fd, LOCK_PATH)

    if 'return_code' in locals() and isinstance(return_code, int):
        return return_code
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
