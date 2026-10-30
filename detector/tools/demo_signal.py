# tools/demo_signal.py
"""演示：AI 信号如何作为一维加权特征参与蜜罐风险评分。

用途：比赛演示 / 验收。展示"规则分 + AI 分 = 累加分 -> 双阈值分层"的完整链路。

用法:
    python -m tools.demo_signal
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.config import (AI_POINTS_MAX, HIGH_RISK_THRESHOLD,
                        SUSPICIOUS_THRESHOLD)
from src.predict import predict_signal

# 演示用例：(请求描述, 待检测文本, 期望类型)
CASES = [
    ("经典 XSS",        "<script>alert(document.cookie)</script>",      "xss"),
    ("img onerror",     "<img src=x onerror=alert(1)>",                 "xss"),
    ("布尔注入",        "' or 1=1 --",                                  "sqli"),
    ("联合查询注入",    "union select 1,version() from users",          "sqli"),
    ("having 盲注",     "?id=1 group by userid having 1=1--",           "sqli"),
    ("报错注入",        "?id=1 and extractvalue(1,concat(0x7e,user()))", "sqli"),
    ("目录穿越",        "../../../../etc/passwd",                       "path_traversal"),
    ("编码穿越",        "..%2f..%2f..%2fetc%2fpasswd",                  "path_traversal"),
    ("敏感文件 .env",   "/.env.production",                             "sensitive_path"),
    ("敏感文件 wp",     "/wp-config.php",                               "sensitive_path"),
    ("phpMyAdmin 探测", "/phpmyadmin/index.php",                        "sensitive_path"),
    ("正常文本",        "hello world",                                  "normal"),
    ("正常英文句子",    "The onclick event fires when the user clicks.", "normal"),
    ("正常页面 script", '<script src="_static/doctools.js"></script>',  "normal"),
    ("正常 JS 写法",    "<a href=javascript:void(0)>click</a>",         "normal"),
]


def main():
    print("=" * 108)
    print("AI 作为一维加权特征接入蜜罐 —— 演示")
    print(f"蜜罐量纲: 可疑阈值 {SUSPICIOUS_THRESHOLD} 分 / 高危阈值 "
          f"{HIGH_RISK_THRESHOLD} 分；AI 分值上限 {AI_POINTS_MAX} 分")
    print("=" * 108)
    header = (f"{'场景':<16}{'判定类型':<17}{'AI概率':>7}{'AI分':>6}"
              f"{'规则分':>7}{'生效分':>7}{'累加分':>7}  {'分层':<12}{'结果'}")
    print(header)
    print("-" * 108)

    ok = 0
    for desc, text, expect in CASES:
        r = predict_signal(text)
        tier = ("高危告警" if r["high_risk"]
                else ("可疑事件" if r["suspicious"] else "常规记录"))
        good = "✓" if r["attack_type"] == expect else "✗"
        if r["attack_type"] == expect:
            ok += 1
        print(f"{desc:<16}{r['attack_type']:<17}{r['attack_prob']:>7.3f}"
              f"{r['ai_points']:>6}{r['rule_points']:>7}"
              f"{r['effective_rule_points']:>7}{r['fusion_score']:>7}  "
              f"{tier:<12}{good}")

    print("-" * 108)
    print(f"结果: {ok}/{len(CASES)} 与期望一致\n")

    # 详细展示两个代表性样本
    for text in ["?id=1 group by userid having 1=1--",
                 '<script src="_static/doctools.js"></script>']:
        r = predict_signal(text)
        print("=" * 108)
        print(f"样本: {text}")
        print(f"  reason: {r['reason']}")
        print(f"  规则命中: " + (", ".join(
            f"{h['label']}(+{h['points']})" for h in
            {h["label"]: h for h in reversed(r["rule_hits"])}.values()
        ) or "无"))
        print(f"  模型判定: {r['model_label']}  攻击概率: {r['attack_prob']}")
        print(f"  分值计算: 规则 {r['rule_points']} -> 生效 "
              f"{r['effective_rule_points']}  +  AI {r['ai_points']}  "
              f"= 累加 {r['fusion_score']}")
        print(f"  分层结论: " + (
            "高危告警(>=40)" if r["high_risk"] else
            ("可疑事件(>=20)" if r["suspicious"] else "常规记录(<20)")))


if __name__ == "__main__":
    main()
