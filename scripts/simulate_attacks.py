#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
模拟攻击流量，向本机 honeypot 各端口注入攻击事件，用于填充看板/测试。
仅打本机回环地址，无外部影响；每次攻击失败都是预期行为（蜜罐会记录）。
"""
import socket
import time
import sys

HOST = "127.0.0.1"
PORTS = {
    "ssh": 2222,
    "web": 80,
    "ftp": 2121,
    "telnet": 2223,
    "mysql": 13306,
    "redis": 16379,
}

USER_LIST = ["root", "admin", "administrator", "test", "oracle", "postgres", "user", "guest", "ftpuser"]
PASS_LIST = ["123456", "password", "admin", "root", "toor", "letmein", "P@ssw0rd", "qwerty", "secret", "1234"]

stats = {"ok": 0, "fail": 0}


def _done(ok: bool):
    stats["ok" if ok else "fail"] += 1


# ---------- Web :80 ----------
def web_attacks(n=20):
    import requests
    base = f"http://{HOST}:{PORTS['web']}"
    xss = ["<script>alert(1)</script>", "<img src=x onerror=alert(document.cookie)>",
           "';alert(1);//", "%3Cscript%3Ealert(1)%3C/script%3E"]
    sqli = ["' OR '1'='1", "admin'--", "1; DROP TABLE users--", "1' UNION SELECT 1,2,3--",
            "1 AND 1=CONVERT(int,@@version)--"]
    traversal = ["../../../../etc/passwd", "..\\..\\..\\windows\\win.ini",
                 "/%2e%2e/%2e%2e/etc/passwd", "....//....//etc/passwd"]
    cmdinj = [";cat /etc/passwd", "|id", "$(whoami)", "`id`", "&& net user"]
    scan_paths = ["/admin", "/wp-admin/", "/phpmyadmin/", "/.env", "/config.php",
                  "/.git/config", "/actuator/health", "/api/v1/users", "/boaform/admin/formLogin"]
    scanners = ["sqlmap/1.6", "Nikto/2.1.6", "Mozilla/5.0 (Nmap Scripting Engine)",
                "masscan/1.0", "Go-http-client/1.1"]
    payloads = []
    for p in xss + sqli + traversal + cmdinj:
        payloads.append(("/", {"q": p, "search": p, "input": p}))
    for sp in scan_paths:
        payloads.append((sp, {}))
    random.shuffle(payloads)
    payloads = payloads[:n]
    for path, params in payloads:
        ua = random.choice(scanners)
        try:
            requests.get(base + path, params=params, headers={"User-Agent": ua}, timeout=4)
            _done(True)
        except Exception:
            _done(False)
        time.sleep(0.05)


# ---------- SSH :2222 ----------
def ssh_attacks(n=12):
    import paramiko
    for i in range(n):
        u = random.choice(USER_LIST)
        p = random.choice(PASS_LIST)
        try:
            c = paramiko.SSHClient()
            c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            c.connect(HOST, port=PORTS["ssh"], username=u, password=p,
                      timeout=6, look_for_keys=False, allow_agent=False)
            _done(True)
            c.close()
        except Exception:
            _done(False)  # 认证失败即预期（蜜罐记录失败登录）
        time.sleep(0.1)


# ---------- FTP :2121 ----------
def ftp_attacks(n=10):
    for i in range(n):
        u = random.choice(USER_LIST)
        p = random.choice(PASS_LIST)
        try:
            s = socket.create_connection((HOST, PORTS["ftp"]), timeout=6)
            s.recv(1024)
            s.sendall(f"USER {u}\r\n".encode())
            s.recv(1024)
            s.sendall(f"PASS {p}\r\n".encode())
            s.recv(1024)
            s.sendall(b"QUIT\r\n")
            s.close()
            _done(True)
        except Exception:
            _done(False)
        time.sleep(0.1)


# ---------- Telnet :2223 ----------
def telnet_attacks(n=10):
    for i in range(n):
        u = random.choice(USER_LIST)
        p = random.choice(PASS_LIST)
        try:
            s = socket.create_connection((HOST, PORTS["telnet"]), timeout=6)
            s.settimeout(2)
            buf = b""
            try:
                while b"login" not in buf.lower() and b"user" not in buf.lower():
                    chunk = s.recv(256)
                    if not chunk:
                        break
                    buf += chunk
            except Exception:
                pass
            s.sendall((u + "\r\n").encode())
            time.sleep(0.3)
            try:
                s.recv(256)
            except Exception:
                pass
            s.sendall((p + "\r\n").encode())
            time.sleep(0.3)
            s.close()
            _done(True)
        except Exception:
            _done(False)
        time.sleep(0.1)


# ---------- MySQL :13306 ----------
def mysql_attacks(n=10):
    import pymysql
    for i in range(n):
        u = random.choice(USER_LIST)
        p = random.choice(PASS_LIST)
        try:
            pymysql.connect(host=HOST, port=PORTS["mysql"], user=u, password=p,
                            connect_timeout=6, read_timeout=6)
            _done(True)
        except Exception:
            _done(False)  # Access denied 即预期
        time.sleep(0.1)


# ---------- Redis :16379 ----------
def redis_attacks(n=8):
    for i in range(n):
        try:
            s = socket.create_connection((HOST, PORTS["redis"]), timeout=6)
            s.sendall(b"*2\r\n$4\r\nAUTH\r\n$8\r\nwrongpwd\r\n")
            s.recv(1024)
            s.sendall(b"*1\r\n$7\r\nFLUSHALL\r\n")
            s.recv(1024)
            s.sendall(b"*1\r\n$4\r\nKEYS\r\n$1\r\n*\r\n")
            s.recv(1024)
            s.sendall(b"*1\r\n$7\r\nCONFIG\r\n$3\r\nGET\r\n$4\r\nDIR\r\n")
            s.recv(1024)
            s.close()
            _done(True)
        except Exception:
            _done(False)
        time.sleep(0.1)


import random

if __name__ == "__main__":
    print("=== 开始向本机 honeypot 注入模拟攻击流量 ===")
    print(f"目标: {HOST}  Web:{PORTS['web']} SSH:{PORTS['ssh']} FTP:{PORTS['ftp']} "
          f"Telnet:{PORTS['telnet']} MySQL:{PORTS['mysql']} Redis:{PORTS['redis']}\n")

    web_attacks(24)
    print(f"[Web]  完成  (ok={stats['ok']} fail={stats['fail']})")
    ssh_attacks(14)
    print(f"[SSH]   完成  (ok={stats['ok']} fail={stats['fail']})")
    ftp_attacks(12)
    print(f"[FTP]   完成  (ok={stats['ok']} fail={stats['fail']})")
    telnet_attacks(12)
    print(f"[Telnet]完成  (ok={stats['ok']} fail={stats['fail']})")
    mysql_attacks(12)
    print(f"[MySQL] 完成  (ok={stats['ok']} fail={stats['fail']})")
    redis_attacks(10)
    print(f"[Redis] 完成  (ok={stats['ok']} fail={stats['fail']})")

    print(f"\n=== 注入完成：共发起 {sum(stats.values())} 次攻击尝试 "
          f"(连接成功 {stats['ok']} / 被拒或异常 {stats['fail']}) ===")
    print("（失败多为蜜罐拒绝/认证失败，属正常——事件已被记录）")
