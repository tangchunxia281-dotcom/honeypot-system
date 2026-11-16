#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""生成请求级 AI 模型运行验证卡片（HTML），供截图与交付。"""
from __future__ import annotations

import html as html_lib
import json
import time
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "reports"
URL = "http://127.0.0.1:8000"


def detect(path, query="", body="", ua="Mozilla/5.0"):
    return requests.post(URL + "/api/v1/detect", json={
        "path": path, "query": query, "body": body, "user_agent": ua,
        "source": "web", "ip": "203.0.113.200",
    }, timeout=10).json()


def main():
    health = requests.get(URL + "/health", timeout=10).json()
    info = requests.get(URL + "/model/info", timeout=10).json()
    meta_path = ROOT / "ai_model" / "app" / "models" / "model_meta.json"
    meta = json.loads(meta_path.read_text(encoding="utf-8")) if meta_path.exists() else {}
    metrics = json.loads((REPORTS / "ai_model_live.json").read_text(encoding="utf-8"))["metrics"]

    samples = [
        ("XSS", "/search", "q=<script>alert(document.cookie)</script>", ""),
        ("SQL 注入", "/products", "id=1 UNION SELECT username,password FROM users", ""),
        ("目录穿越", "/page", "file=../../../../etc/passwd", ""),
        ("敏感路径", "/.env", "", ""),
        ("正常搜索", "/search", "q=python+tutorial", ""),
    ]
    rows = ""
    for label, path, query, body in samples:
        r = detect(path, query, body)
        color = "#3fb950" if r["is_attack"] else "#8b98a9"
        request_text = html_lib.escape(path + (("?" + query) if query else ""))
        reason_text = html_lib.escape((r["reasons"] or ["未命中"])[0][:96])
        rows += (
            f"<tr><td>{html_lib.escape(label)}</td><td><code>{request_text}</code></td>"
            f"<td style='color:{color};font-weight:700'>{html_lib.escape(str(r['attack_type']))}</td>"
            f"<td>{r['is_attack']}</td><td>{r['attack_prob']:.2f}</td><td>+{r['ai_points']}</td>"
            f"<td class='reason'>{reason_text}</td></tr>"
        )

    health_ok = health.get("status") == "ok" and health.get("model_loaded")
    html = f"""<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<title>请求级 AI 模型验证</title>
<style>
*{{box-sizing:border-box}} body{{margin:0;padding:34px 42px;background:#0b1220;color:#e6edf3;
font-family:"Microsoft YaHei","Segoe UI",sans-serif}}
h1{{font-size:28px;margin:0 0 6px}} .sub{{color:#8b98a9;font-size:13px;margin-bottom:22px}}
.kpis{{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:20px}}
.kpi{{background:#111a2e;border:1px solid #243049;border-radius:12px;padding:14px 16px}}
.kpi span{{display:block;color:#8b98a9;font-size:12px;margin-bottom:6px}}
.kpi strong{{font-size:24px;color:#7fd1ff}} .kpi strong.g{{color:#3fb950}} .kpi strong.o{{color:#f0a44a}}
section{{background:#101a2e;border:1px solid #243049;border-radius:14px;padding:18px 20px;margin-bottom:18px}}
h2{{font-size:16px;color:#7fd1ff;margin:0 0 12px}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
th{{color:#8b98a9;text-align:left;padding:8px 10px;border-bottom:1px solid #243049}}
td{{padding:8px 10px;border-bottom:1px solid #1b2740;vertical-align:top}}
code{{background:#0b1220;color:#a5d6ff;padding:2px 6px;border-radius:5px;font-size:12px}}
.reason{{color:#8b98a9;font-size:12px}} .ok{{color:#3fb950}} .warn{{color:#f0a44a}}
.grid2{{display:grid;grid-template-columns:1fr 1fr;gap:18px}}
.note{{color:#8b98a9;font-size:12px;line-height:1.8;margin-top:10px}}
</style></head><body>
<h1>请求级 AI 攻击检测模型 · 运行验证</h1>
<div class="sub">服务地址 {URL} ｜ 生成时间 {time.strftime('%Y-%m-%d %H:%M:%S')} ｜
模型镜像 xss-detector:2.0.0 ｜ 测试流量仅来自本机</div>

<div class="kpis">
  <div class="kpi"><span>健康检查</span><strong class="{'g' if health_ok else 'o'}">{'在线' if health_ok else '异常'}</strong></div>
  <div class="kpi"><span>模型版本</span><strong>{info.get('version', '-')}</strong></div>
  <div class="kpi"><span>真实载荷召回</span><strong class="g">{metrics['attack_detected']}/{metrics['attack_total']}</strong></div>
  <div class="kpi"><span>正常误报</span><strong class="g">{metrics['benign_false_positive']}/{metrics['benign_total']}</strong></div>
  <div class="kpi"><span>平均延迟</span><strong>{metrics['avg_latency_ms']:.0f} ms</strong></div>
</div>

<div class="grid2">
<section><h2>模型元数据</h2>
<table><tbody>
<tr><th>健康状态</th><td>{health.get('status')} / loaded={health.get('model_loaded')}</td></tr>
<tr><th>版本</th><td>{info.get('version')}</td></tr>
<tr><th>训练时间</th><td>{info.get('trained_at')}</td></tr>
<tr><th>支持类别</th><td>{' / '.join(info.get('labels') or [])}</td></tr>
<tr><th>模型文件</th><td><code>{info.get('model_path')}</code></td></tr>
<tr><th>训练集/测试集</th><td>{meta.get('train_samples', '-')} / {meta.get('test_samples', '-')}</td></tr>
<tr><th>自报测试指标</th><td>accuracy {meta.get('test_accuracy', 0):.4f} · macro-F1 {meta.get('test_macro_f1', 0):.4f}</td></tr>
</tbody></table>
<div class="note">自报指标来自训练侧留出集；下方为本次用真实攻击载荷独立实测的结果。</div>
</section>
<section><h2>本次实测范围</h2>
<table><tbody>
<tr><th>攻击载荷</th><td>{metrics['attack_total']} 条（XSS/SQLi/穿越/敏感路径/扫描器/命令注入/SSTI/SSRF/XXE）</td></tr>
<tr><th>正常对照</th><td>{metrics['benign_total']} 条</td></tr>
<tr><th>攻击检出率</th><td class="ok">{metrics['recall'] * 100:.1f}%</td></tr>
<tr><th>正常误报率</th><td class="ok">{metrics['false_positive_rate'] * 100:.1f}%</td></tr>
<tr><th>P95 延迟</th><td>{metrics['p95_latency_ms']:.0f} ms</td></tr>
<tr><th>项目 fixtures 压测</th><td class="warn">二分类准确率 61.5%，编码混淆是短板</td></tr>
</tbody></table>
<div class="note">模型五分类之外的 SSTI / 命令注入由蜜罐规则层兜底；端到端 34 条攻击中 31 条形成事件。</div>
</section>
</div>

<section><h2>实时调用样例（POST /api/v1/detect）</h2>
<table><thead><tr><th>类型</th><th>请求</th><th>判定</th><th>is_attack</th><th>attack_prob</th>
<th>ai_points</th><th>模型理由</th></tr></thead><tbody>{rows}</tbody></table>
<div class="note">normal 行的 ai_points 是概率映射的原始建议值；蜜罐融合时对 normal 按 0 计分，不会把正常请求推过可疑阈值。</div>
</section>

<footer style="color:#5b6677;font-size:12px;text-align:center">
模型只做分类与加分，不执行命令、不生成自由文本；服务不可达时蜜罐自动回退纯规则。
</footer>
</body></html>"""
    target = REPORTS / "model_validation.html"
    target.write_text(html, encoding="utf-8")
    print("model card:", target)


if __name__ == "__main__":
    main()
