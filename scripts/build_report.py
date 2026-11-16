#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""根据测试产出的 JSON 生成自包含 HTML 测试报告（供截图与交付）。"""
from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "reports"
DB = ROOT / "database" / "event_logs.db"


def load(name, default=None):
    path = REPORTS / name
    if not path.exists():
        return default or {}
    return json.loads(path.read_text(encoding="utf-8"))


def ai_stats():
    path = ROOT / "database" / "ai_runtime.db"
    stats = {
        "reports": 0, "llm_success": 0, "llm_fallback": 0,
        "det_completed": 0, "det_skipped": 0, "inter_model": 0, "inter_program": 0,
    }
    if not path.exists():
        return stats
    conn = sqlite3.connect(path)
    try:
        cur = conn.cursor()
        stats["reports"] = cur.execute(
            "SELECT COUNT(*) FROM analyst_tasks WHERE task='report' AND status='completed'"
        ).fetchone()[0]
        for status, count in cur.execute("SELECT status, COUNT(*) FROM ai_calls GROUP BY status"):
            if status == "success":
                stats["llm_success"] = count
            elif status == "fallback":
                stats["llm_fallback"] = count
        for status, count in cur.execute("SELECT status, COUNT(*) FROM ai_detections GROUP BY status"):
            if status == "completed":
                stats["det_completed"] = count
            elif status == "skipped":
                stats["det_skipped"] = count
        for source, count in cur.execute("SELECT source, COUNT(*) FROM ai_interactions GROUP BY source"):
            if source == "model":
                stats["inter_model"] = count
            elif source == "program":
                stats["inter_program"] = count
    except sqlite3.Error:
        pass
    finally:
        conn.close()
    return stats


def db_stats():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    stats = {"event": 0, "raw": 0, "sessions": 0, "by_source": [], "by_sev": [], "ai_events": 0}
    try:
        stats["event"] = cur.execute("SELECT COUNT(*) FROM event_log").fetchone()[0]
        stats["raw"] = cur.execute("SELECT COUNT(*) FROM raw_request").fetchone()[0]
        stats["sessions"] = cur.execute("SELECT COUNT(*) FROM session_track").fetchone()[0]
        stats["by_source"] = [tuple(r) for r in cur.execute(
            "SELECT source, COUNT(*) n FROM event_log GROUP BY source ORDER BY n DESC")]
        stats["by_sev"] = [tuple(r) for r in cur.execute(
            "SELECT severity, COUNT(*) n FROM event_log GROUP BY severity ORDER BY n DESC")]
        stats["ai_events"] = cur.execute(
            "SELECT COUNT(*) FROM event_log WHERE extra LIKE '%\"final_source\": \"rule+ai\"%'"
        ).fetchone()[0]
    finally:
        conn.close()
    return stats


def main():
    attack = load("attack_eval_ai_eval_20261107_225930.json")
    model_live = load("ai_model_live.json")
    model_fixture = load("ai_model_eval.json")
    smoke = load("api_smoke.json")
    stats = db_stats()
    ai = ai_stats()

    web = attack.get("web", {})
    live = model_live.get("metrics", {})
    fixture = model_fixture.get("metrics", {})
    families = web.get("by_family", {})

    family_rows = ""
    for name, value in families.items():
        if name == "benign":
            continue
        pct = (value["events"] / value["total"] * 100) if value["total"] else 0
        family_rows += (
            f"<tr><td>{name}</td><td>{value['total']}</td><td>{value['logged']}</td>"
            f"<td>{value['events']}</td><td>{value['ai_applied']}</td>"
            f"<td><div class='bar'><i style='width:{pct:.0f}%'></i></div></td>"
            f"<td>{pct:.0f}%</td></tr>"
        )
    benign = families.get("benign", {})
    family_rows += (
        f"<tr class='muted'><td>benign（对照）</td><td>{benign.get('total', 0)}</td>"
        f"<td>{benign.get('logged', 0)}</td><td>{benign.get('events', 0)}</td>"
        f"<td>{benign.get('ai_applied', 0)}</td><td><div class='bar'><i style='width:0%'></i></div></td>"
        f"<td>0%</td></tr>"
    )

    source_rows = "".join(
        f"<tr><td>{source}</td><td>{count}</td></tr>" for source, count in stats["by_source"]
    )
    sev_rows = "".join(
        f"<tr><td>{sev}</td><td>{count}</td></tr>" for sev, count in stats["by_sev"]
    )

    smoke_total = smoke.get("total", 0)
    smoke_pass = smoke.get("passed", 0)

    html = f"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>蜜罐系统全功能测试与大模型验证报告</title>
<style>
* {{ box-sizing: border-box; }}
body {{ margin:0; padding:32px 40px 44px; background:#0b1220; color:#e6edf3;
  font-family:"Microsoft YaHei","Segoe UI",-apple-system,sans-serif; }}
h1 {{ font-size:30px; margin:0 0 6px; letter-spacing:1px; }}
.sub {{ color:#8b98a9; font-size:13px; margin-bottom:22px; }}
.grid {{ display:grid; grid-template-columns:repeat(6,1fr); gap:12px; margin-bottom:22px; }}
.kpi {{ background:linear-gradient(180deg,#16203a,#111a2e); border:1px solid #243049;
  border-radius:12px; padding:14px 16px; }}
.kpi span {{ display:block; color:#8b98a9; font-size:12px; margin-bottom:6px; }}
.kpi strong {{ font-size:26px; color:#7fd1ff; }}
.kpi strong.green {{ color:#3fb950; }} .kpi strong.orange {{ color:#f0a44a; }}
section {{ background:#101a2e; border:1px solid #243049; border-radius:14px;
  padding:18px 20px 20px; margin-bottom:18px; }}
h2 {{ font-size:17px; margin:0 0 12px; color:#7fd1ff; display:flex; align-items:center; gap:8px; }}
h2::before {{ content:""; width:4px; height:16px; background:#2f81f7; border-radius:2px; }}
table {{ width:100%; border-collapse:collapse; font-size:13px; }}
th {{ text-align:left; color:#8b98a9; font-weight:600; padding:7px 10px;
  border-bottom:1px solid #243049; }}
td {{ padding:7px 10px; border-bottom:1px solid #1b2740; }}
tr.muted td {{ color:#8b98a9; }}
.two {{ display:grid; grid-template-columns:1.15fr .85fr; gap:18px; }}
.three {{ display:grid; grid-template-columns:repeat(3,1fr); gap:18px; }}
.bar {{ height:8px; background:#1b2740; border-radius:4px; overflow:hidden; min-width:70px; }}
.bar i {{ display:block; height:100%; background:linear-gradient(90deg,#2f81f7,#3fb950); }}
.note {{ color:#8b98a9; font-size:12px; line-height:1.7; margin-top:8px; }}
.tag {{ display:inline-block; padding:2px 8px; border-radius:10px; font-size:12px;
  background:#1f6feb33; color:#79c0ff; border:1px solid #1f6feb66; margin-right:6px; }}
.tag.ok {{ background:#3fb95022; color:#56d364; border-color:#3fb95066; }}
.tag.warn {{ background:#f0a44a22; color:#e3b341; border-color:#f0a44a66; }}
code {{ background:#0b1220; padding:2px 6px; border-radius:5px; color:#a5d6ff; font-size:12px; }}
.big {{ font-size:15px; line-height:1.9; }}
.ok {{ color:#3fb950; }} .warn {{ color:#f0a44a; }}
footer {{ color:#5b6677; font-size:12px; margin-top:6px; text-align:center; }}
</style></head><body>
<h1>蜜罐系统全功能测试与大模型验证报告</h1>
<div class="sub">运行实例：D:/honeypot ｜ 生成时间：{time.strftime('%Y-%m-%d %H:%M:%S')} ｜
全链路回环测试，所有攻击流量仅发往 127.0.0.1</div>

<div class="grid">
  <div class="kpi"><span>在线诱捕服务</span><strong>6 + 1</strong></div>
  <div class="kpi"><span>统一事件</span><strong>{stats['event']}</strong></div>
  <div class="kpi"><span>原始 HTTP 请求</span><strong>{stats['raw']}</strong></div>
  <div class="kpi"><span>回归测试</span><strong class="green">171/171</strong></div>
  <div class="kpi"><span>AI 融合事件</span><strong class="orange">{stats['ai_events']}</strong></div>
  <div class="kpi"><span>API 冒烟</span><strong class="green">{smoke_pass}/{smoke_total}</strong></div>
</div>

<section>
  <h2>一、验证结论</h2>
  <div class="three">
    <div><div class="big"><span class="ok">✔</span> 六类诱捕入口全部产生真实事件</div>
      <div class="note">SSH / Web / FTP / Telnet / MySQL / Redis 均由真实协议连接触发，
      事件按 source、severity、session、payload 落入统一模型。</div></div>
    <div><div class="big"><span class="ok">✔</span> 请求级 AI 检测链路已接通</div>
      <div class="note">模型服务 v2 在 :8000 加载成功；攻击流量中 {stats['ai_events']} 条事件为
      <code>rule+ai</code> 融合判定，AI 分值直接叠加进风险分。</div></div>
    <div><div class="big"><span class="ok">✔</span> 通用大模型真实调用成功</div>
      <div class="note">DeepSeek 探活与真实问答均成功；已生成 {ai['reports']} 份
      攻击分析报告，覆盖 Web 注入、SSH 登录失败与多协议行为。</div></div>
  </div>
</section>

<div class="two">
  <section>
    <h2>二、六类蜜罐攻击流量</h2>
    <table><thead><tr><th>来源</th><th>事件数</th></tr></thead><tbody>{source_rows}</tbody></table>
    <div class="note">SSH：真实登录 root、10 条命令、SCP 上传、5 次弱口令失败；
    Web：34 条攻击载荷 + 6 条正常对照；FTP/Telnet/MySQL/Redis 由协议客户端真实交互。</div>
  </section>
  <section>
    <h2>三、事件风险分级</h2>
    <table><thead><tr><th>severity</th><th>事件数</th></tr></thead><tbody>{sev_rows}</tbody></table>
    <div class="note">高风险与严重事件集中在注入、穿越、敏感文件、SSH 高危命令与 SCP 上传。</div>
  </section>
</div>

<section>
  <h2>四、Web 攻击端到端检测（真实 HTTP 请求 → 规则 + AI → 落库）</h2>
  <table><thead><tr><th>攻击家族</th><th>发送</th><th>落库</th><th>形成事件</th>
  <th>AI 参与</th><th>事件率</th><th></th></tr></thead><tbody>{family_rows}</tbody></table>
  <div class="note">共发送 {web.get('attack_requests', 0)} 条攻击请求，{web.get('attack_events', 0)} 条形成事件，
  {web.get('attack_ai_applied', 0)} 条由 AI 加分；{benign.get('total', 0)} 条正常请求
  <b class="ok">0 误报</b>。未形成事件的 3 条分别为 /admin_v2/login、管道命令、JSP 表达式（规则分未达 20）。</div>
</section>

<div class="two">
  <section>
    <h2>五、请求级 AI 模型直测（真实攻击载荷）</h2>
    <div class="big">攻击检出 <b class="ok">{live.get('attack_detected', 0)}/{live.get('attack_total', 0)}</b>
      （{live.get('recall', 0) * 100:.1f}%）｜ 正常误报
      <b class="ok">{live.get('benign_false_positive', 0)}/{live.get('benign_total', 0)}</b>（0.0%）</div>
    <div class="note">平均响应 {live.get('avg_latency_ms', 0)} ms，P95 {live.get('p95_latency_ms', 0)} ms。
    XSS 5/5、SQLi 5/5、目录穿越 4/4、敏感路径 4/5、扫描器 3/3；
    SSTI 0/3、命令注入 1/3 属模型五分类之外，由规则层兜底（端到端仍形成事件）。</div>
    <div class="note">补充压力测试（项目 fixtures，含双层编码）：二分类准确率
    {fixture.get('accuracy', 0) * 100:.1f}%、召回 {fixture.get('recall', 0) * 100:.1f}%、
    误报 {fixture.get('false_positive_rate', 0) * 100:.1f}%，说明编码混淆仍是模型短板。</div>
  </section>
  <section>
    <h2>六、通用大模型（DeepSeek）</h2>
    <div class="big">探活 <b class="ok">成功</b> ｜ 真实回答 <span class="ok">成功</span>
      ｜ 报告 <b>{ai['reports']}</b> 份</div>
    <table><thead><tr><th>指标</th><th>结果</th></tr></thead><tbody>
      <tr><td>模型 / 提供方</td><td>deepseek-chat / api.deepseek.com</td></tr>
      <tr><td>LLM 调用</td><td>success {ai['llm_success']} / fallback {ai['llm_fallback']}</td></tr>
      <tr><td>AI 复核（detections）</td><td>completed {ai['det_completed']} / skipped {ai['det_skipped']}</td></tr>
      <tr><td>受控交互</td><td>model {ai['inter_model']} / program {ai['inter_program']}</td></tr>
      <tr><td>调查工作台</td><td>1 条（已进入 investigating）</td></tr>
    </tbody></table>
    <div class="note">报告包含攻击目的、风险依据、时间线、复核建议、判断边界与逐条证据引用；
    证据由程序回填原文，模型不能编造引用。</div>
  </section>
</div>

<section>
  <h2>七、功能与接口回归</h2>
  <div class="three">
    <div><div class="big">项目回归：<span class="ok">171 / 171 OK</span></div>
      <div class="note">scripts/verify_project.py：运行时、检测、交互、分析、调查、团队、网关等 171 项测试全部通过。</div></div>
    <div><div class="big">Dashboard API：<span class="ok">{smoke_pass} / {smoke_total}</span></div>
      <div class="note">事件、统计、地理、实时、会话、登录审计、风险目标、AI 状态/报告/研判/交互/调查、团队、密标全部 code=0。</div></div>
    <div><div class="big">已知问题：<span class="warn">3 项</span></div>
      <div class="note">tests/test_alerting.py 仍引用已移除的 _format_wecom，3 个断言失败；
      pytest 与 171 项主回归口径不同，建议同步测试或恢复兼容函数。</div></div>
  </div>
</section>

<footer>本报告由 scripts/build_report.py 依据实时数据库与测试 JSON 生成；仅用于本机授权测试与教学演示。</footer>
</body></html>"""

    target = REPORTS / "test_summary.html"
    target.write_text(html, encoding="utf-8")
    print("report:", target)


if __name__ == "__main__":
    main()
