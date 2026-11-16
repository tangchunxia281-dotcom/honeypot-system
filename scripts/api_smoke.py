#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Dashboard 全量只读接口冒烟测试（登录 + 同源 + CSRF）。

输出每个接口的 HTTP 状态与业务 code，并抽取关键计数，
用于证明事件、统计、地理、会话、AI、团队、密标等接口均可用。
"""
from __future__ import annotations

import json
import re
import sys
import time
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]
BASE = "http://127.0.0.1:5001"


def login():
    session = requests.Session()
    session.trust_env = False
    page = session.get(BASE + "/super/login", timeout=10)
    token = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
    resp = session.post(
        BASE + "/super/login",
        data={"username": "admin", "password": "Admin@2024!", "csrf_token": token},
        timeout=10,
        allow_redirects=False,
    )
    dashboard = session.get(BASE + "/dashboard", timeout=10)
    csrf = re.search(r'name="csrf-token" content="([^"]+)"', dashboard.text).group(1)
    return session, {"Origin": BASE, "Referer": BASE + "/dashboard", "X-CSRF-Token": csrf}


ENDPOINTS = [
    ("events", "/api/get_event_logs?limit=5&hours=24"),
    ("stats", "/api/get_event_stats?hours=24"),
    ("geo", "/api/get_geo_data?hours=24"),
    ("realtime", "/api/realtime"),
    ("server_info", "/api/server_info"),
    ("system_status", "/api/system_status"),
    ("suspicious", "/api/suspicious_requests?hours=24&limit=10"),
    ("sessions", "/api/session_analysis?hours=24"),
    ("login_audit", "/api/login_audit"),
    ("risk_targets", "/api/risk_targets"),
    ("ai_status", "/api/ai/status"),
    ("ai_analysis", "/api/ai/analysis?limit=5"),
    ("ai_detections", "/api/ai/detections?limit=5"),
    ("ai_interactions", "/api/ai/interactions?limit=5"),
    ("ai_investigations", "/api/ai/investigations"),
    ("ai_archives", "/api/ai/archives"),
    ("ai_chat_history", "/api/ai/chat/history?conversation=0123456789abcdef0123456789abcdef"),
    ("team_graph", "/api/team/graph"),
    ("team_periods", "/api/team/periods"),
    ("team_noise", "/api/team/noise"),
    ("team_evaluations", "/api/team/evaluations"),
    ("team_decoys", "/api/team/decoys"),
    ("team_disagreements", "/api/team/disagreements"),
    ("team_review_samples", "/api/team/review-samples"),
    ("risk_mark_meta", "/api/risk_mark/meta"),
    ("risk_mark_summary", "/api/risk_mark/summary"),
    ("risk_mark_list", "/api/risk_mark/list?limit=5"),
    ("risk_mark_detectors", "/api/risk_mark/detectors"),
]


def digest(name, data):
    if not isinstance(data, dict):
        return f"{type(data).__name__}"
    keys = ("total", "unique_ips", "count", "assigned", "indexed")
    bits = [f"{k}={data[k]}" for k in keys if k in data]
    if "reports" in data:
        bits.append(f"reports={len(data['reports'])}")
    if "records" in data:
        bits.append(f"records={len(data['records'])}")
    if "items" in data:
        bits.append(f"items={len(data['items'])}")
    if "counts" in data:
        bits.append(f"counts={data['counts']}")
    if name == "realtime" and isinstance(data, list):
        bits.append(f"rows={len(data)}")
    return ", ".join(bits) or "ok"


def main():
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    session, headers = login()
    results = []
    print(f"{'接口':22s} {'HTTP':4s} {'code':4s} 摘要")
    print("-" * 78)
    for name, path in ENDPOINTS:
        started = time.perf_counter()
        try:
            resp = session.get(BASE + path, headers=headers, timeout=20)
            elapsed = (time.perf_counter() - started) * 1000
            if "ndjson" in str(resp.headers.get("Content-Type", "")):
                code = 0
                ok = resp.status_code == 200
                summary = f"ndjson {len(resp.text)} bytes"
            else:
                body = resp.json()
                code = body.get("code")
                ok = resp.status_code == 200 and code == 0
                summary = digest(name, body.get("data"))
        except Exception as exc:  # noqa: BLE001
            resp = None
            elapsed = (time.perf_counter() - started) * 1000
            code = None
            ok = False
            summary = f"ERROR {type(exc).__name__}: {exc}"
        results.append({
            "name": name, "path": path, "http": resp.status_code if resp else None,
            "code": code, "ok": ok, "latency_ms": round(elapsed, 1), "summary": summary,
        })
        print(f"{name:22s} {str(resp.status_code if resp else '-'):4s} {str(code):4s} "
              f"{summary} ({elapsed:.0f} ms)")

    # 一条受 CSRF + 同源保护的写接口：AI 探活
    try:
        resp = session.post(BASE + "/api/ai/probe", headers=headers, timeout=60)
        body = resp.json()
        probe = body.get("data") or {}
        print(f"{'ai_probe(POST)':22s} {resp.status_code:4d} {str(body.get('code')):4s} "
              f"status={probe.get('status')} latency={probe.get('latency_ms')}ms")
        results.append({"name": "ai_probe", "path": "/api/ai/probe",
                        "http": resp.status_code, "code": body.get("code"),
                        "ok": bool(body.get("code") == 0 and probe.get("status") == "success"),
                        "summary": f"status={probe.get('status')}"})
    except Exception as exc:  # noqa: BLE001
        print(f"{'ai_probe(POST)':22s} ERROR {exc}")
        results.append({"name": "ai_probe", "ok": False, "summary": str(exc)})

    passed = sum(1 for item in results if item.get("ok"))
    print("-" * 78)
    print(f"通过 {passed}/{len(results)} 个接口")

    output = ROOT / "reports" / "api_smoke.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps({
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "passed": passed, "total": len(results), "results": results,
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"结果已写入: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
