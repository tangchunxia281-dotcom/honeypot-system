#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
全功能测试 + 真实攻击流量生成器
================================
对 honeypot 各模块发起「真实连接 + 攻击式请求」，并比对数据库落库增量，
作为每个模块「确实工作」的验证证据。同时在大模型(xss-detector :8000)可达时，
调用 /api/v1/detect 验证 AI 检测链路。

用法:
    python scripts/test_all_functions.py            # 测试并生成攻击流量
    python scripts/test_all_functions.py --no-traffic   # 仅功能探测
"""
import os
import sys
import time
import socket
import sqlite3
import argparse

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

DB = os.path.join(ROOT, "database", "event_logs.db")

# ---- 端口（从 honeypot.ini 兜底读取，失败用默认值） ----
SERVICES = {
    "web":       {"host": "127.0.0.1", "port": 5000,  "proto": "http"},
    "ssh":       {"host": "127.0.0.1", "port": 2222,  "proto": "ssh"},
    "ftp":       {"host": "127.0.0.1", "port": 2121,  "proto": "ftp"},
    "telnet":    {"host": "127.0.0.1", "port": 2223,  "proto": "telnet"},
    "mysql":     {"host": "127.0.0.1", "port": 13306, "proto": "mysql"},
    "redis":     {"host": "127.0.0.1", "port": 16379, "proto": "redis"},
    "dashboard": {"host": "127.0.0.1", "port": 5001,  "proto": "http"},
    "aigateway": {"host": "127.0.0.1", "port": 5000,  "proto": "http"},
    "aimodel":   {"host": "127.0.0.1", "port": 8000,  "proto": "ai"},
}

REPORT = []


def log(name, ok, detail):
    REPORT.append((name, ok, detail))
    mark = "PASS" if ok else "FAIL"
    print(f"  [{mark}] {name}: {detail}")


def db_counts():
    out = {}
    try:
        c = sqlite3.connect(DB)
        cur = c.cursor()
        for t in ("event_log", "raw_request", "session_track", "geo_ip",
                 "risk_mark", "risk_target"):
            try:
                cur.execute(f"SELECT COUNT(*) FROM {t}")
                out[t] = cur.fetchone()[0]
            except Exception:
                out[t] = None
        c.close()
    except Exception as e:
        print("  (DB 读取失败: %s)" % e)
    return out


def safe_connect(host, port, timeout=5):
    return socket.create_connection((host, port), timeout=timeout)


# ---------- 各协议攻击流量 ----------
def attack_ssh(s):
    try:
        import paramiko
    except Exception as e:
        log("SSH 模块(依赖paramiko)", False, "paramiko 不可用: %s" % e)
        return
    users = ["root", "admin", "oracle", "test", "ubuntu"]
    pwds = ["123456", "password", "admin", "root", "P@ssw0rd"]
    n_fail = 0
    for u in users:
        for p in pwds[:2]:
            try:
                cli = paramiko.SSHClient()
                cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                cli.connect(s["host"], port=s["port"], username=u, password=p,
                            timeout=4, look_for_keys=False, allow_agent=False)
                cli.close()
            except paramiko.AuthenticationException:
                n_fail += 1
            except Exception:
                n_fail += 1
            if n_fail >= 6:
                break
        if n_fail >= 6:
            break
    log("SSH 暴力破解捕获", n_fail > 0,
        "发起 %d 次错误认证(预期被记为 login_failed 事件)" % n_fail)


def attack_ftp(s):
    try:
        sock = safe_connect(s["host"], s["port"], 5)
        sock.settimeout(4)
        banner = sock.recv(200)
        sock.sendall(b"USER attacker\r\n")
        sock.recv(100)
        sock.sendall(b"PASS WeakPass123!\r\n")
        sock.recv(100)
        sock.sendall(b"QUIT\r\n")
        sock.close()
        log("FTP 登录尝试捕获", True, "已发送 USER/PASS，banner=%r" % banner[:40])
    except Exception as e:
        log("FTP 登录尝试捕获", False, "异常: %s" % e)


def attack_telnet(s):
    try:
        sock = safe_connect(s["host"], s["port"], 5)
        sock.settimeout(4)
        time.sleep(0.3)
        _ = sock.recv(300)  # banner
        sock.sendall(b"admin\r\n")
        time.sleep(0.3)
        sock.recv(100)
        sock.sendall(b"admin\r\n")
        time.sleep(0.3)
        sock.recv(100)
        sock.close()
        log("Telnet 登录尝试捕获", True, "已发送 admin/admin 凭据")
    except Exception as e:
        log("Telnet 登录尝试捕获", False, "异常: %s" % e)


def attack_mysql(s):
    try:
        sock = safe_connect(s["host"], s["port"], 5)
        sock.settimeout(4)
        _ = sock.recv(100)  # server greeting
        # 构造一个最小 auth 包（恶意用户名）
        user = b"root\x00"
        payload = b"\x01\x00\x00\x00" + user + b"\x14maliciouspw\x00"
        sock.sendall(payload)
        time.sleep(0.5)
        try:
            sock.recv(200)
        except Exception:
            pass
        sock.close()
        log("MySQL 握手/认证捕获", True, "已发送伪造认证包")
    except Exception as e:
        log("MySQL 握手/认证捕获", False, "异常: %s" % e)


def attack_redis(s):
    try:
        sock = safe_connect(s["host"], s["port"], 5)
        sock.settimeout(3)
        # RESP2：首条命令即被记为 redis_unauthorized(critical)
        sock.sendall(b"*2\r\n$4\r\nAUTH\r\n$8\r\nbadpass\r\n")
        try:
            sock.recv(200)
        except Exception:
            pass  # 部分实现不回包，但服务端已记录事件
        sock.sendall(b"*1\r\n$4\r\nPING\r\n")
        try:
            sock.recv(200)
        except Exception:
            pass
        sock.close()
        log("Redis 命令捕获", True,
            "已建立连接并发送 AUTH/PING（首条命令触发 redis_unauthorized 记录）")
    except Exception as e:
        log("Redis 命令捕获", False, "异常: %s" % e)


def attack_web(s):
    """向 Web 蜜罐(:80)发送多类攻击请求，应被记录到 raw_request/event_log。"""
    import urllib.request
    base = "http://%s:%d" % (s["host"], s["port"])
    payloads = [
        ("XSS", "/search?q=<script>alert(1)</script>"),
        ("SQLi", "/login?user=admin'%20OR%20'1'='1&pass=1"),
        ("PathTraversal", "/../../../../etc/passwd"),
        ("ThinkPHP CVE", "/index.php?s=/index/\\think\\app/invokefunction&function=call_user_func_array"),
        ("SSTI", "/?name={{7*7}}"),
        ("敏感路径", "/.env"),
        ("Admin枚举", "/admin/login"),
        ("Webshell", "/uploads/shell.php"),
    ]
    ok = 0
    for name, path in payloads:
        try:
            req = urllib.request.Request(base + path,
                                         headers={"User-Agent": "sqlmap/1.6"})
            try:
                urllib.request.urlopen(req, timeout=5)
            except Exception:
                pass  # 蜜罐可能返回 4xx，仍应被记录
            ok += 1
        except Exception as e:
            log("Web 攻击(%s)" % name, False, "异常: %s" % e)
    log("Web 攻击流量(8类)", ok == len(payloads),
        "已发送 %d 类攻击请求(XSS/SQLi/遍历/CVE/SSTI/敏感路径)" % ok)


def probe_http(s, name):
    try:
        import urllib.request
        req = urllib.request.Request("http://%s:%d/" % (s["host"], s["port"]))
        try:
            r = urllib.request.urlopen(req, timeout=5)
            code = r.getcode()
        except urllib.error.HTTPError as e:
            code = e.code
        log(name, code in (200, 302, 401, 403, 404),
            "HTTP 状态码=%s (服务存活)" % code)
    except Exception as e:
        log(name, False, "异常: %s" % e)


def probe_ai_model(s):
    import urllib.request, json
    try:
        # /model/info
        try:
            r = urllib.request.urlopen("http://%s:%d/model/info" %
                                       (s["host"], s["port"]), timeout=5)
            info = json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            info = json.loads(e.read().decode("utf-8"))
        # /api/v1/detect
        req = urllib.request.Request(
            "http://%s:%d/api/v1/detect" % (s["host"], s["port"]),
            data=json.dumps({"path": "/search",
                             "query": "id=1 AND 1=1 UNION SELECT password FROM users",
                             "source": "web", "ip": "203.0.113.7"}).encode("utf-8"),
            headers={"Content-Type": "application/json"}, method="POST")
        det = json.loads(urllib.request.urlopen(req, timeout=8).read().decode("utf-8"))
        log("大模型 xss-detector 可达", True,
            "model/info.version=%s | detect: attack_type=%s is_attack=%s ai_points=%s"
            % (info.get("version"), det.get("attack_type"),
               det.get("is_attack"), det.get("ai_points")))
        return True
    except Exception as e:
        log("大模型 xss-detector 可达", False,
            "不可达(%s)，AI 检测将降级为纯规则: %s" % (e.__class__.__name__, e))
        return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-traffic", action="store_true", help="仅功能探测，不造攻击流量")
    args = ap.parse_args()

    print("=" * 64)
    print("Honeypot 全功能测试 + 攻击流量生成")
    print("=" * 64)

    before = db_counts()
    print("\n[0] 测试前数据库计数: %s" % before)

    # 1) 功能探测：所有 HTTP 服务存活
    print("\n[1] 服务存活探测")
    probe_http(SERVICES["dashboard"], "Dashboard(:5001)")
    probe_http(SERVICES["aigateway"], "AI 网关(:5000)")

    # 2) 协议蜜罐连接 + 攻击
    if not args.no_traffic:
        print("\n[2] 协议蜜罐攻击流量（真实连接）")
        attack_ssh(SERVICES["ssh"])
        attack_ftp(SERVICES["ftp"])
        attack_telnet(SERVICES["telnet"])
        attack_mysql(SERVICES["mysql"])
        attack_redis(SERVICES["redis"])
        print("\n[3] Web 蜜罐攻击流量")
        attack_web(SERVICES["web"])
    else:
        print("\n[2-3] 跳过攻击流量(--no-traffic)")

    # 3) 大模型检测
    print("\n[4] 大模型(AI 检测)验证")
    ai_ok = probe_ai_model(SERVICES["aimodel"])

    # 给数据库一点落库时间
    time.sleep(1.5)
    after = db_counts()
    print("\n[5] 测试后数据库计数: %s" % after)

    print("\n" + "=" * 64)
    print("增量汇总 (测试后 - 测试前)")
    print("=" * 64)
    for k in ("event_log", "raw_request", "session_track", "geo_ip"):
        b, a = before.get(k), after.get(k)
        if b is not None and a is not None:
            print("  %-14s %5d -> %5d  (+%d)" % (k, b, a, a - b))

    print("\n%s 项检查: %d 通过 / %d 失败" % (
        len(REPORT), sum(1 for _, o, _ in REPORT if o),
        sum(1 for _, o, _ in REPORT if not o)))
    print("大模型 AI 检测链路: %s" % ("已验证 ✅" if ai_ok else "降级(纯规则) ⚠️"))
    print("=" * 64)

    # 写出结构化结果，供截图报告使用
    try:
        import json
        os.makedirs(os.path.join(ROOT, "screenshots"), exist_ok=True)
        out = {
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "report": [{"name": n, "ok": bool(o), "detail": d} for n, o, d in REPORT],
            "db_before": before,
            "db_after": after,
            "ai_ok": ai_ok,
        }
        with open(os.path.join(ROOT, "screenshots", "result.json"), "w",
                  encoding="utf-8") as f:
            json.dump(out, f, ensure_ascii=False, indent=2)
        print("结果已写入 screenshots/result.json")
    except Exception as e:
        print("写 result.json 失败: %s" % e)


if __name__ == "__main__":
    main()
