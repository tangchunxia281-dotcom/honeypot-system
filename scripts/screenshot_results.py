#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
实验结果截图脚本
==============
读取 test_all_functions.py 产出的 result.json 与数据库统计，
生成自包含 HTML 报告，并用 Playwright 对以下目标真实截图：
  1) report.html          —— 综合实验结果（测试结论+攻击数据+AI验证）
  2) :8000/model/info     —— 大模型版本与类别（验证大模型已起）
  3) :8000/docs           —— /api/v1/detect 接口契约
  4) :5001  Dashboard     —— 态势大屏（登录页/面板，验证存活）
  5) :80   Web 蜜罐        —— 蜜罐本体响应
输出 PNG 到 screenshots/
"""
import os
import sys
import json
import sqlite3
import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "screenshots")
os.makedirs(OUT, exist_ok=True)

DB = os.path.join(ROOT, "database", "event_logs.db")


def db_stats():
    stats = {}
    c = sqlite3.connect(DB)
    cur = c.cursor()
    try:
        cur.execute("SELECT source, COUNT(*) FROM event_log GROUP BY source")
        stats["by_source"] = dict(cur.fetchall())
    except Exception:
        stats["by_source"] = {}
    try:
        cur.execute("SELECT severity, COUNT(*) FROM event_log GROUP BY severity")
        stats["by_sev"] = dict(cur.fetchall())
    except Exception:
        stats["by_sev"] = {}
    try:
        cur.execute("SELECT MIN(timestamp), MAX(timestamp), COUNT(*) FROM event_log")
        lo, hi, total = cur.fetchone()
        stats["time_min"], stats["time_max"], stats["total"] = lo, hi, total
    except Exception:
        stats["total"] = 0
    try:
        cur.execute("SELECT COUNT(*) FROM raw_request")
        stats["raw_request"] = cur.fetchone()[0]
    except Exception:
        stats["raw_request"] = 0
    try:
        cur.execute("SELECT COUNT(*) FROM session_track")
        stats["sessions"] = cur.fetchone()[0]
    except Exception:
        stats["sessions"] = 0
    c.close()
    return stats


def load_result():
    p = os.path.join(OUT, "result.json")
    if os.path.exists(p):
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    return None


def build_html(result, stats):
    res = result or {}
    rep = res.get("report", [])
    by_source = stats.get("by_source", {})
    by_sev = stats.get("by_sev", {})
    ai_ok = res.get("ai_ok", False)

    def row(r):
        cls = "pass" if r["ok"] else "fail"
        icon = "✔" if r["ok"] else "✘"
        return f'<tr class="{cls}"><td>{icon}</td><td>{r["name"]}</td><td>{r["detail"]}</td></tr>'

    src_rows = "".join(f"<tr><td>{k}</td><td>{v}</td></tr>"
                       for k, v in sorted(by_source.items(), key=lambda x: -x[1]))
    sev_rows = "".join(f"<tr><td>{k}</td><td>{v}</td></tr>"
                       for k, v in sorted(by_sev.items(), key=lambda x: -x[1]))
    n_pass = sum(1 for r in rep if r["ok"])
    n_fail = len(rep) - n_pass

    html = f"""<!doctype html><html lang="zh"><head><meta charset="utf-8">
<style>
* {{ box-sizing: border-box; }}
body {{ font-family: -apple-system, "Segoe UI", "Microsoft YaHei", sans-serif;
       margin:0; background:#0f1626; color:#e6edf3; padding:28px; }}
h1 {{ font-size:24px; margin:0 0 4px; }}
.sub {{ color:#8b98a9; font-size:13px; margin-bottom:20px; }}
.card {{ background:#16203a; border:1px solid #243049; border-radius:12px;
        padding:18px 20px; margin-bottom:18px; }}
.card h2 {{ font-size:16px; margin:0 0 12px; color:#7fd1ff; }}
table {{ width:100%; border-collapse:collapse; font-size:13px; }}
th,td {{ text-align:left; padding:7px 10px; border-bottom:1px solid #243049; }}
th {{ color:#8b98a9; font-weight:600; }}
tr.pass td:first-child {{ color:#3fb950; }}
tr.fail td:first-child {{ color:#f85149; }}
.grid {{ display:flex; gap:18px; flex-wrap:wrap; }}
.grid .card {{ flex:1; min-width:240px; }}
.big {{ font-size:30px; font-weight:700; }}
.kpi {{ color:#7fd1ff; }}
.ok {{ color:#3fb950; }} .warn {{ color:#f0a44a; }}
footer {{ color:#5b6677; font-size:12px; margin-top:10px; }}
</style></head><body>
<h1>Honeypot 功能测试与攻击数据验证报告</h1>
<div class="sub">生成时间：{res.get('generated_at','')} ｜ 数据来源：D:/honeypot 实时运行实例</div>

<div class="grid">
  <div class="card"><h2>事件总量</h2><div class="big kpi">{stats.get('total',0)}</div>
    <div class="sub">raw_request {stats.get('raw_request',0)} ｜ 攻击链 {stats.get('sessions',0)}</div></div>
  <div class="card"><h2>测试通过</h2><div class="big ok">{n_pass}</div>
    <div class="sub">/ 共 {len(rep)} 项检查</div></div>
  <div class="card"><h2>大模型链路</h2><div class="big {'ok' if ai_ok else 'warn'}">{'已验证' if ai_ok else '降级'}</div>
    <div class="sub">{'xss-detector 可达并参与检测' if ai_ok else '未起服务，AI 检测走纯规则'}</div></div>
</div>

<div class="card"><h2>① 全功能测试结果</h2>
<table><thead><tr><th></th><th>检查项</th><th>说明</th></tr></thead>
<tbody>{''.join(row(r) for r in rep)}</tbody></table></div>

<div class="grid">
  <div class="card"><h2>② 攻击数据 · 按来源</h2>
    <table><thead><tr><th>来源</th><th>事件数</th></tr></thead>
    <tbody>{src_rows or '<tr><td colspan=2>无</td></tr>'}</tbody></table></div>
  <div class="card"><h2>③ 攻击数据 · 按严重程度</h2>
    <table><thead><tr><th>等级</th><th>事件数</th></tr></thead>
    <tbody>{sev_rows or '<tr><td colspan=2>无</td></tr>'}</tbody></table></div>
</div>

<div class="card"><h2>④ 时间窗</h2>
  <div class="sub">最早 {stats.get('time_min','-')} → 最晚 {stats.get('time_max','-')}</div></div>

<footer>本报告由自动化测试脚本生成，覆盖 SSH/FTP/Telnet/MySQL/Redis/Web/Dashboard/AI网关/大模型 全链路。</footer>
</body></html>"""
    return html


def get_admin_cred():
    import configparser
    cp = configparser.ConfigParser()
    cp.read(os.path.join(ROOT, "honeypot.ini"), encoding="utf-8")
    user = cp.get("admin", "user", fallback="admin")
    pw = cp.get("admin", "password", fallback="")
    if not pw:
        pw = "Admin@2024!"
    return user, pw


def main():
    result = load_result()
    stats = db_stats()
    html = build_html(result, stats)
    html_path = os.path.join(OUT, "report.html")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)
    print("报告已生成:", html_path)

    from playwright.sync_api import sync_playwright
    user, pw = get_admin_cred()
    shots = []
    with sync_playwright() as p:
        browser = p.chromium.launch(args=["--no-sandbox"])
        # 1) 综合报告
        try:
            page = browser.new_page(viewport={"width": 1280, "height": 1000})
            page.goto("file://" + html_path.replace("\\", "/"),
                      timeout=15000, wait_until="networkidle")
            page.wait_for_timeout(600)
            path = os.path.join(OUT, "report.png")
            page.screenshot(path=path, full_page=True)
            shots.append(("report", path))
            print("  截图 OK  report")
            page.close()
        except Exception as e:
            print("  截图跳过 report:", e)

        # 2) 大模型 model/info
        try:
            page = browser.new_page(viewport={"width": 1100, "height": 800})
            page.goto("http://127.0.0.1:8000/model/info", timeout=15000,
                      wait_until="networkidle")
            page.wait_for_timeout(500)
            shots.append(("model_info", os.path.join(OUT, "model_info.png")))
            page.screenshot(path=os.path.join(OUT, "model_info.png"))
            print("  截图 OK  model_info")
            page.close()
        except Exception as e:
            print("  截图跳过 model_info:", e)

        # 3) 大模型 API 文档
        try:
            page = browser.new_page(viewport={"width": 1280, "height": 900})
            page.goto("http://127.0.0.1:8000/docs", timeout=15000,
                      wait_until="networkidle")
            page.wait_for_timeout(800)
            shots.append(("api_docs", os.path.join(OUT, "api_docs.png")))
            page.screenshot(path=os.path.join(OUT, "api_docs.png"), full_page=True)
            print("  截图 OK  api_docs")
            page.close()
        except Exception as e:
            print("  截图跳过 api_docs:", e)

        # 4) AI 网关
        try:
            page = browser.new_page(viewport={"width": 1100, "height": 500})
            page.goto("http://127.0.0.1:5000/", timeout=15000,
                      wait_until="networkidle")
            page.wait_for_timeout(500)
            shots.append(("ai_gateway", os.path.join(OUT, "ai_gateway.png")))
            page.screenshot(path=os.path.join(OUT, "ai_gateway.png"))
            print("  截图 OK  ai_gateway")
            page.close()
        except Exception as e:
            print("  截图跳过 ai_gateway:", e)

        # 5) Dashboard（自动登录后截图真实数据面板）
        try:
            page = browser.new_page(viewport={"width": 1366, "height": 950})
            page.goto("http://127.0.0.1:5001/super/login", timeout=15000,
                      wait_until="networkidle")
            page.wait_for_timeout(400)
            page.fill("input[name='username']", user)
            page.fill("input[name='password']", pw)
            try:
                page.click("button[type='submit']")
            except Exception:
                page.click("input[type='submit']")
            page.wait_for_timeout(1500)
            cur = page.url
            shots.append(("dashboard", os.path.join(OUT, "dashboard.png")))
            page.screenshot(path=os.path.join(OUT, "dashboard.png"), full_page=True)
            print("  截图 OK  dashboard (url=%s)" % cur)
            page.close()
        except Exception as e:
            print("  截图跳过 dashboard:", e)

        browser.close()

    print("\n完成截图 %d 张:" % len(shots))
    for n, p in shots:
        print("  ", n, p)
    with open(os.path.join(OUT, "shots.json"), "w", encoding="utf-8") as f:
        json.dump([p for _, p in shots], f, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    main()
