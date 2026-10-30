# tools/client_example.py
"""蜜罐侧调用示例：把 AI 作为一维加权特征接入风险评分。

两种调用方式都给出：
  A. HTTP 方式（推荐跨进程/跨机部署，只需标准库，无额外依赖）
  B. 同进程 import 方式（检测器与蜜罐在同一 Python 环境时）

用法:
    python -m tools.client_example                 # 用内置样例演示
    python -m tools.client_example --url http://127.0.0.1:8100
"""
import argparse
import json
import sys
import urllib.error
import urllib.request

DEFAULT_URL = "http://127.0.0.1:8100"

# 蜜罐双阈值（与论文 5.3 节一致）
SUSPICIOUS_THRESHOLD = 20
HIGH_RISK_THRESHOLD = 40


# ============================================================
# A. HTTP 方式：只用标准库 urllib，不引入新依赖
# ============================================================
def ai_signal_http(text, url=DEFAULT_URL, timeout=3.0):
    """
    调用检测服务获取 AI 信号。

    参数:
        text:     待检测文本（蜜罐的 query_string / body / path）
        url:      检测服务根地址，如 http://127.0.0.1:8100
        timeout:  超时秒数；建议设短，避免拖慢蜜罐响应

    返回: dict，失败时返回 None（调用方应做好降级）
    """
    payload = json.dumps({"text": text, "source": "web"}).encode("utf-8")
    req = urllib.request.Request(
        f"{url.rstrip('/')}/predict/signal",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as e:
        print(f"[WARN] AI 服务不可用({e})，本次跳过 AI 特征", file=sys.stderr)
        return None


def integrate_into_honeypot(text, risk_score, signals, url=DEFAULT_URL):
    """
    把 AI 信号并入蜜罐的风险评分链路。

    对应 db/http_requests.py::calculate_threat_score 的改造点：
        risk_score += ai_points
        signals.append(...)

    返回: (risk_score, signals, tier)
    """
    sig = ai_signal_http(text, url=url)

    # --- 降级：AI 服务不可用时，蜜罐必须仍能正常工作 ---
    if sig is None:
        tier = ("高危告警" if risk_score >= HIGH_RISK_THRESHOLD
                else ("可疑事件" if risk_score >= SUSPICIOUS_THRESHOLD else "常规记录"))
        return risk_score, signals, tier

    # --- 累加 AI 分值 ---
    risk_score += sig["ai_points"]
    if sig["ai_points"] > 0:
        signals.append(
            f"AI类型判定: {sig['attack_type']}({sig['attack_prob']:.2f}, "
            f"+{sig['ai_points']})"
        )
    for h in sig["rule_hits"]:
        if h["desc"] not in signals:
            signals.append(f"AI规则: {h['desc']}")

    tier = ("高危告警" if risk_score >= HIGH_RISK_THRESHOLD
            else ("可疑事件" if risk_score >= SUSPICIOUS_THRESHOLD else "常规记录"))
    return risk_score, signals, tier


# ============================================================
# B. 同进程 import 方式
# ============================================================
def demo_inprocess():
    from src.predict import predict_signal

    for text in ["../../../../etc/passwd", "/wp-config.php", "hello world"]:
        r = predict_signal(text)
        print(f"  {text[:34]:<36} {r['attack_type']:<16} "
              f"ai_points={r['ai_points']:<3} fusion={r['fusion_score']:<3} "
              f"high_risk={r['high_risk']}")


# ============================================================
# 演示
# ============================================================
CASES = [
    # (模拟的蜜罐已有评分, 请求文本)
    (0,  "hello world"),
    (0,  "../../../../etc/passwd"),
    (15, "/wp-config.php"),            # 敏感路径 +15（蜜罐已给）
    (0,  "' or 1=1 --"),
    (22, "../../../../etc/passwd"),    # 目录穿越 +22（蜜罐已给）
    (0,  "?id=1 group by userid having 1=1--"),
    (0,  '<script src="_static/doctools.js"></script>'),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default=DEFAULT_URL)
    ap.add_argument("--inprocess", action="store_true", help="只演示同进程方式")
    args = ap.parse_args()

    if args.inprocess:
        demo_inprocess()
        return

    print("=" * 104)
    print("蜜罐侧接入演示：AI 作为一维加权特征")
    print(f"检测服务: {args.url}    可疑阈值 {SUSPICIOUS_THRESHOLD} / 高危阈值 {HIGH_RISK_THRESHOLD}")
    print("=" * 104)

    # 先探活
    try:
        with urllib.request.urlopen(f"{args.url}/health", timeout=5) as r:
            health = json.loads(r.read().decode("utf-8"))
        print(f"服务状态: {health['status']}  模型已加载: {health['model_loaded']}\n")
    except Exception as e:
        print(f"[错误] 检测服务不可用: {e}")
        print(f"请先启动: python -m uvicorn src.api:app --host 127.0.0.1 --port 8100")
        sys.exit(1)

    header = (f"{'蜜罐原分':>10} | {'请求':<38} | {'AI类型':<16} | "
              f"{'AI分':>5} | {'累加后':>7} | {'分层':<10} | 理由摘要")
    print(header)
    print("-" * 120)
    for base_score, text in CASES:
        score, signals, tier = integrate_into_honeypot(
            text, base_score, [], url=args.url)
        sig = ai_signal_http(text, url=args.url)
        atype = sig["attack_type"] if sig else "-"
        ai_pts = sig["ai_points"] if sig else 0
        brief = (sig["reason"][:30] + "…") if sig and len(sig["reason"]) > 30 \
            else (sig["reason"] if sig else "-")
        print(f"{base_score:>10} | {text[:36]:<38} | {atype:<16} | "
              f"{ai_pts:>5} | {score:>7} | {tier:<10} | {brief}")

    print("-" * 120)
    print("\n--- B. 同进程 import 方式 ---")
    demo_inprocess()
    print("\n提示: 蜜罐集成时务必保留 AI 服务不可用的降级分支"
          "（见 integrate_into_honeypot）。")


if __name__ == "__main__":
    main()
