#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""用 Edge + Playwright 截取蜜罐测试结果页面。

输出到 screenshots/：
  Web 蜜罐首页/诱饵后台、Dashboard 登录/大屏、AI 工作区各页面、
  模型信息/接口文档、测试汇总报告。
"""
from __future__ import annotations

import json
import time
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "screenshots"
OUT.mkdir(exist_ok=True)

DASH = "http://127.0.0.1:5001"
WEB = "http://127.0.0.1:5000"
MODEL = "http://127.0.0.1:8000"

SHOTS = []


def shot(page, name, full=False, wait=0):
    if wait:
        page.wait_for_timeout(wait)
    path = OUT / f"{name}.png"
    page.screenshot(path=str(path), full_page=full)
    SHOTS.append({"name": name, "path": str(path), "full_page": full})
    print(f"  [ok] {name}.png")


def login_dashboard(page):
    page.goto(DASH + "/super/login", wait_until="domcontentloaded", timeout=25000)
    page.fill("input[name=username]", "admin")
    page.fill("input[name=password]", "Admin@2024!")
    page.click("button[type=submit]")
    page.wait_for_url("**/dashboard", timeout=25000)
    page.wait_for_timeout(5000)


def main():
    with sync_playwright() as p:
        browser = p.chromium.launch(channel="msedge", headless=True,
                                    args=["--no-sandbox", "--disable-gpu"])
        ctx = browser.new_context(viewport={"width": 1600, "height": 1000},
                                  locale="zh-CN", timezone_id="Asia/Shanghai")
        page = ctx.new_page()

        # ---------- 无登录页面 ----------
        print("[1] Web 蜜罐")
        page.goto(WEB + "/", wait_until="domcontentloaded", timeout=25000)
        shot(page, "01_web_home", wait=1200)
        page.goto(WEB + "/admin", wait_until="domcontentloaded", timeout=25000)
        shot(page, "02_web_admin_login", wait=800)

        page.fill("input[name=username]", "admin")
        page.fill("input[name=password]", "System123")
        page.click("button[type=submit]")
        page.wait_for_timeout(3500)
        shot(page, "03_web_admin_dashboard", full=True, wait=1500)

        print("[2] Dashboard 登录页")
        page.goto(DASH + "/super/login", wait_until="domcontentloaded", timeout=25000)
        shot(page, "04_dashboard_login", wait=800)

        print("[3] AI 模型服务")
        card = ROOT / "reports" / "model_validation.html"
        page.goto(card.as_uri(), wait_until="domcontentloaded", timeout=25000)
        page.wait_for_timeout(1000)
        shot(page, "14_model_validation", full=True)
        page.goto(MODEL + "/docs", wait_until="domcontentloaded", timeout=25000)
        page.wait_for_timeout(2500)
        shot(page, "15_model_docs")

        # ---------- 登录 Dashboard ----------
        print("[4] 态势大屏")
        login_dashboard(page)
        page.wait_for_timeout(3000)
        shot(page, "05_dashboard")
        shot(page, "06_dashboard_full", full=True)

        print("[5] AI 工作区")
        page.goto(DASH + "/ai", wait_until="domcontentloaded", timeout=25000)
        page.wait_for_timeout(2500)
        try:
            page.click("#probe")
            page.wait_for_timeout(7000)
        except Exception:
            pass
        shot(page, "07_ai_monitor", full=True)

        page.goto(DASH + "/ai/analysis", wait_until="domcontentloaded", timeout=25000)
        page.wait_for_timeout(3500)
        shot(page, "08_ai_analysis_list")
        page.select_option("#stateFilter", "completed")
        page.wait_for_timeout(2000)
        page.select_option("#riskFilter", "high")
        page.wait_for_timeout(2000)
        cards = page.locator(".report-card")
        if cards.count():
            cards.first.click()
            page.wait_for_timeout(2500)
            page.locator("#reportDetail").scroll_into_view_if_needed()
            page.wait_for_timeout(600)
            shot(page, "09_ai_analysis_detail")
            shot(page, "09b_ai_analysis_detail_full", full=True)
        page.select_option("#riskFilter", "")
        page.wait_for_timeout(1200)

        page.goto(DASH + "/ai/detection", wait_until="domcontentloaded", timeout=25000)
        page.wait_for_timeout(2500)
        try:
            page.fill("#sourceIp", "203.0.113.45")
            page.click("#refresh")
            page.wait_for_timeout(2500)
            rows = page.locator("#rows tr").filter(has_text="完成")
            if rows.count():
                rows.first.locator("button").click()
                page.wait_for_timeout(1800)
        except Exception:
            pass
        shot(page, "10_ai_detection")
        shot(page, "10b_ai_detection_full", full=True)

        page.goto(DASH + "/ai/interactions", wait_until="domcontentloaded", timeout=25000)
        page.wait_for_timeout(3500)
        shot(page, "11_ai_interactions")
        shot(page, "11b_ai_interactions_full", full=True)

        page.goto(DASH + "/ai/investigations", wait_until="domcontentloaded", timeout=25000)
        page.wait_for_timeout(3000)
        try:
            case = page.locator(".case-card").first
            if case.count():
                case.click()
                page.wait_for_timeout(2000)
        except Exception:
            pass
        shot(page, "12_ai_investigations", full=True)

        page.goto(DASH + "/ai/team", wait_until="domcontentloaded", timeout=25000)
        page.wait_for_timeout(3000)
        try:
            page.click("#sharedProbe")
            page.wait_for_timeout(8000)
        except Exception:
            pass
        shot(page, "13_ai_team", full=True)

        # ---------- 自动生成的测试汇总 ----------
        print("[6] 测试汇总报告")
        report = ROOT / "reports" / "test_summary.html"
        page.goto(report.as_uri(), wait_until="domcontentloaded", timeout=25000)
        page.wait_for_timeout(1500)
        shot(page, "16_test_summary", full=True)

        browser.close()

    manifest = OUT / "manifest.json"
    manifest.write_text(json.dumps({
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "count": len(SHOTS), "shots": SHOTS,
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n完成 {len(SHOTS)} 张截图 -> {OUT}")
    print(f"清单: {manifest}")


if __name__ == "__main__":
    main()
