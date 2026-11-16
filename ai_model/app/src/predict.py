# src/predict.py
"""
统一攻击检测入口。

提供两个接口：
  1. predict_xss(text)      —— 旧的级联接口（规则优先，命中即返回），
                               保留以兼容现有调用与测试。
  2. predict_signal(text)   —— 新增的信号接口，适配蜜罐
                               "多特征加权 + 双阈值分层" 机制。
                               规则和模型**同时**输出，各自带分值，
                               由蜜罐累加决策，不做短路。
"""

import os
import sys

import joblib
import pandas as pd

from src.config import (
    MODEL_PATH,
    PREDICT_DATA_PATH,
    PREDICT_OUTPUT_PATH,
    AI_POINTS_MAX,
    SUSPICIOUS_THRESHOLD,
    HIGH_RISK_THRESHOLD,
)
from src.preprocess import normalize_text
from src.rules import (match_rules, match_rules_with_score,
                       get_rule_description, is_benign_path, BENIGN_PENALTY)

ATTACK_LABELS = ("xss", "sqli", "path_traversal", "sensitive_path", "scanner")

# AI 否决：模型判定的攻击概率低于此值时，视为"高置信非攻击"，
# 对弱规则信号做抑制，避免单条规则把正常请求抬过可疑线。
AI_VETO_PROB = 0.15        # 攻击概率低于此值 → 否决
AI_VETO_NORMAL_PROB = 0.50  # 模型判 normal 的概率达到此值 → 否决（明确不同意规则）
AI_VETO_OTHER_PROB = 0.75   # 模型判成其它攻击类的概率达到此值 → 否决（类型可能判错）
AI_VETO_MAX_RULE_POINTS = 22  # 仅当规则证据"弱"（<=此分值）时才允许被否决
AI_VETO_FACTOR = 0.1


_model = None


def get_model():
    global _model
    if _model is None:
        if not os.path.exists(MODEL_PATH):
            raise FileNotFoundError(f"模型文件不存在: {MODEL_PATH}")
        if os.path.getsize(MODEL_PATH) == 0:
            raise ValueError(f"模型文件为空: {MODEL_PATH}")
        _model = joblib.load(MODEL_PATH)
    return _model


def predict_xss(text: str) -> dict:
    """
    旧的级联检测入口（规则优先，命中即返回）。

    注意：此接口会在规则命中时短路，且 confidence 为固定值 0.99，
    **不适合**作为蜜罐的加权特征使用。加权特征请用 predict_signal()。

    返回：
    {
        "label": "xss" / "normal" / ...,
        "is_attack": bool,
        "confidence": float,
        "reason": str
    }
    """
    if text is None:
        text = ""

    normalized = normalize_text(text)

    # 1. 规则优先
    rule_hits = match_rules(normalized)
    if rule_hits:
        label = rule_hits[0][0]
        pattern = rule_hits[0][1]
        return {
            "label": label,
            "is_attack": label != "normal",
            "confidence": 0.99,  # 规则命中固定值，不代表模型概率
            "reason": f"规则命中: {get_rule_description(pattern)}",
        }

    # 2. 模型判断
    model = get_model()
    proba = model.predict_proba([normalized])[0]
    classes = [str(c) for c in model.classes_]
    idx = int(proba.argmax())
    label = str(classes[idx])
    conf = float(proba[idx])

    return {
        "label": label,
        "is_attack": label != "normal",
        "confidence": round(conf, 4),
        "reason": "模型判断",
    }


predict_attack = predict_xss


def _attack_probability(classes, proba):
    """把多分类概率折算为"属于任一攻击类"的总概率。"""
    p = 0.0
    for c, v in zip(classes, proba):
        if str(c) in ATTACK_LABELS:
            p += float(v)
    return min(1.0, max(0.0, p))


def fuse_signals(rule_hits, model_label, attack_prob, conf=0.0,
                 model_note="模型判断", prob_by_label=None, matched_path=""):
    """
    加权融合 + 双阈值分层（纯函数，不依赖模型文件，便于评估与复用）。

    参数:
        rule_hits:    [(label, pattern, points), ...] 规则命中，已按优先级排序
        model_label:  模型独立判定的类别
        attack_prob:  模型给出的"属于任一攻击类"的校准概率
        conf:         模型对其判定类别的置信度
        prob_by_label: {类别: 概率} 完整分类概率表（用于按类别取 AI 分值）
        matched_path: 本次检测的路径（用于已知安全路径白名单）
    返回: 与 predict_signal 相同结构的 dict
    """
    rule_points = max((h[2] for h in rule_hits), default=0)
    hit_dicts = [
        {"label": lab, "pattern": pat, "points": pts,
         "desc": get_rule_description(pat)}
        for lab, pat, pts in rule_hits
    ]
    ai_points = int(round(attack_prob * AI_POINTS_MAX))

    # 规则命中时，AI 分值改用"模型对规则所判类别的概率"。
    # 这样 AI 是一个独立的加权特征：
    #   - 规则与模型一致  -> 分值高（互相印证）
    #   - 模型强烈认为是别的类 / 不是攻击 -> 分值低（明显矛盾）
    #   - 模型没有该类别（如 scanner） -> 取中性值，由规则分主导
    if rule_hits:
        top_label = rule_hits[0][0]
        prob_map = prob_by_label or {}
        if top_label in prob_map:
            ai_points = int(round(prob_map[top_label] * AI_POINTS_MAX))
        elif model_label == top_label:
            ai_points = max(ai_points, int(round(conf * AI_POINTS_MAX)))

    # 已知安全路径白名单：抵消模型对普通短路径的过判
    benign = is_benign_path(matched_path)
    benign_offset = -BENIGN_PENALTY if benign else 0

    # AI 否决：模型与规则结论冲突时抑制规则信号。
    # 触发条件（满足任一）：
    #   a) 模型判定的攻击概率很低（< AI_VETO_PROB）；
    #   b) 模型以较高置信度判 normal（>= AI_VETO_NORMAL_PROB）——明确不同意规则；
    #   c) 模型以较高置信度判成"另一个攻击类"（>= AI_VETO_OTHER_PROB），
    #      说明规则可能抓错了类型。
    # 例外（不否决）：
    #   1. 规则判定的类别模型根本没学过（如 scanner）——模型概率无意义；
    #   2. sensitive_path 类——命中 /.env、/var/log/ 这类确定性证据，
    #      模型对罕见系统路径天然给低概率，否决会把真攻击压成 normal。
    VETO_EXEMPT = {"scanner", "sensitive_path", "path_traversal"}
    top_rule_label = rule_hits[0][0] if rule_hits else None
    prob_map = prob_by_label or {}
    model_knows_label = (not rule_hits) or (top_rule_label in prob_map)
    can_veto = model_knows_label and top_rule_label not in VETO_EXEMPT

    p_normal = float(prob_map.get("normal", 0.0))
    p_other_attack = max(
        (float(v) for c, v in prob_map.items()
         if c != "normal" and c != top_rule_label),
        default=0.0,
    )
    veto_reason = None
    if rule_points and can_veto:
        if attack_prob < AI_VETO_PROB:
            veto_reason = "attack_prob too low"
        elif p_normal >= AI_VETO_NORMAL_PROB:
            veto_reason = "model says normal"
        elif p_other_attack >= AI_VETO_OTHER_PROB:
            veto_reason = "model says another class"

    effective_rule_points = rule_points
    if veto_reason and rule_points <= AI_VETO_MAX_RULE_POINTS:
        effective_rule_points = int(round(rule_points * AI_VETO_FACTOR))

    fusion_score = effective_rule_points + ai_points + benign_offset

    if rule_hits:
        attack_type = rule_hits[0][0]
        # 模型只有在"比该类规则的自身分值明显更强"时才覆盖规则类别。
        # 用严格大于 + 余量，避免弱模型判断翻转明确的规则结论
        # （例如 .DS_Store 命中 sensitive_path(+15)，模型 18 分不应把它改判成 sqli）。
        if (model_label in ATTACK_LABELS and model_label != attack_type
                and ai_points > rule_points + 5):
            attack_type = model_label
        # 同类多条命中只展示一次，并标明该类的建议分值
        seen, parts = set(), []
        for lab, pat, pts in rule_hits:
            if lab in seen:
                continue
            seen.add(lab)
            parts.append(f"{lab}(+{pts}): {get_rule_description(pat)}")
        reason = "规则命中 " + "；".join(parts)
        if model_label not in ("normal", "unknown"):
            reason += f"；模型判定: {model_label}({conf:.2f})"
        if effective_rule_points != rule_points:
            reason += (f"；模型以 {attack_prob:.2f} 判定非攻击，"
                       f"规则分 {rule_points} 抑制为 {effective_rule_points}")
        confidence = 0.99
    else:
        attack_type = model_label
        reason = model_note
        confidence = round(conf, 4)

    if fusion_score < SUSPICIOUS_THRESHOLD:
        is_attack = False
        if attack_type in ATTACK_LABELS:
            attack_type = "normal"
            reason += (f"（累加分 {fusion_score} < 可疑阈值 "
                       f"{SUSPICIOUS_THRESHOLD}，降级为 normal）")
    else:
        is_attack = attack_type in ATTACK_LABELS

    return {
        "attack_type": attack_type,
        "is_attack": is_attack,
        "attack_prob": round(attack_prob, 4),
        "ai_points": ai_points,
        "rule_points": rule_points,
        "effective_rule_points": effective_rule_points,
        "fusion_score": fusion_score,
        "suspicious": fusion_score >= SUSPICIOUS_THRESHOLD,
        "high_risk": fusion_score >= HIGH_RISK_THRESHOLD,
        "confidence": confidence,
        "reason": reason,
        "rule_hits": hit_dicts,
        "model_label": model_label,
    }


def predict_signal(text: str) -> dict:
    """
    信号接口：为蜜罐"多特征加权 + 双阈值分层"提供一维 AI 加权特征。

    与 predict_xss 的区别：
      - 规则与模型**都**执行，不做短路；
      - 输出经校准的攻击概率，并映射为对齐蜜罐量纲的 ai_points (0~AI_POINTS_MAX)；
      - 同时给出规则信号及其建议分值，便于蜜罐统一累加。

    返回：
    {
        "attack_type": str,        # 融合后的攻击类型（未过阈值则为 normal）
        "is_attack": bool,         # 是否判定为攻击（fusion_score 过可疑线）
        "attack_prob": float,      # 校准后的攻击概率 (0~1)
        "ai_points": int,          # AI 建议累加分值 (0~AI_POINTS_MAX)
        "rule_points": int,        # 规则建议累加分值
        "fusion_score": int,       # 累加总分 = rule_points + ai_points
        "suspicious": bool,        # >= SUSPICIOUS_THRESHOLD
        "high_risk": bool,         # >= HIGH_RISK_THRESHOLD
        "confidence": float,       # 判定类型的置信度
        "reason": str,
        "rule_hits": [             # 命中的规则及建议分值
            {"label": str, "pattern": str, "points": int, "desc": str}
        ],
        "model_label": str,        # 模型独立判定结果（便于对比）
    }
    """
    if text is None:
        text = ""
    normalized = normalize_text(text)

    # ---- 规则信号（不短路，全部保留）----
    scored_hits = match_rules_with_score(normalized)

    # ---- 模型信号 ----
    model_label, conf, attack_prob = "normal", 0.0, 0.0
    prob_by_label = {}
    model_note = "模型判断"
    try:
        model = get_model()
        proba = model.predict_proba([normalized])[0]
        classes = [str(c) for c in model.classes_]
        idx = int(proba.argmax())
        model_label = classes[idx]
        conf = float(proba[idx])
        attack_prob = _attack_probability(classes, proba)
        prob_by_label = {c: float(p) for c, p in zip(classes, proba)}
    except Exception as e:
        model_label = "unknown"
        model_note = f"模型不可用: {e}"

    return fuse_signals(scored_hits, model_label, attack_prob, conf, model_note,
                        prob_by_label, matched_path=normalized)


def _split_query(query: str) -> list:
    """把查询串拆成 [(参数名, 参数值), ...]，保留原始顺序。"""
    out = []
    q = str(query or "").lstrip("?")
    if not q:
        return out
    for kv in q.split("&"):
        if not kv:
            continue
        k, _, v = kv.partition("=")
        out.append((k.strip(), v.strip()))
    return out


def _split_path_query(url: str):
    """从完整 URL 中分离 path 与查询串。"""
    s = str(url or "")
    path, _, qs = s.partition("?")
    return path, qs


def detect_request(path="", query="", body="", headers=None, user_agent=""):
    """
    请求级检测入口：按 HTTP 请求的各个部分分别检测，再汇总。

    为什么必须这样做：
        真实攻击载荷常常嵌在完整 URL 里，例如
            /search?id=1 and 1=1&Submit=Submit
        如果把整条 URL 当成一团文本送去检测，后面的 "&Submit=Submit"
        会稀释/破坏规则匹配的上下文，导致漏报。
        分段检测（path 单独、每个参数值单独、body 单独）可以避免这个问题。

    参数:
        path:       请求路径，如 /download
        query:      查询串（可带 ? 前缀，也可为空）
        body:       请求体原文
        headers:    请求头字典（可选）
        user_agent: User-Agent（可选；若 headers 里已有则不重复）

    返回:
        {
          "attack_type": str,       # 综合判定类型，无攻击为 "normal"
          "is_attack": bool,
          "attack_prob": float,
          "ai_points": int,         # 0~AI_POINTS_MAX，可直接并入蜜罐加权
          "confidence": float,
          "high_risk": bool,
          "reasons": [str],         # 每个命中部分的理由
          "signals": [              # 命中明细，便于蜜罐记录证据
             {"field": str, "value": str, "attack_type": str,
              "attack_prob": float, "ai_points": int, "reason": str}
          ],
          "model_label": str,
        }
    """
    headers = headers or {}
    ua = user_agent or headers.get("User-Agent", "") or headers.get("user-agent", "")

    # 若只给了 path 而它其实是完整 URL，自动拆出查询串
    if not query and "?" in str(path):
        path, query = _split_path_query(path)

    # 组装待检测字段
    fields = []
    if str(path or "").strip():
        fields.append(("path", str(path).strip()))
    for k, v in _split_query(query):
        if v:
            fields.append((f"query.{k}" if k else "query", v))
    if str(body or "").strip():
        fields.append(("body", str(body).strip()))
    if str(ua or "").strip():
        fields.append(("user_agent", str(ua).strip()))

    signals = []
    for fname, fval in fields:
        r = predict_signal(fval)
        if r["is_attack"]:
            signals.append({
                "field": fname,
                "value": fval,
                "attack_type": r["attack_type"],
                "attack_prob": r["attack_prob"],
                "ai_points": r["ai_points"],
                "confidence": r["confidence"],
                "fusion_score": r["fusion_score"],
                "high_risk": r["high_risk"],
                "reason": r["reason"],
            })

    # 兜底：所有分段都干净时，把整体拼起来再看一次
    # （用于捕获跨字段的混淆载荷；仅在分段无命中时启用，避免引入误报）
    if not signals and len(fields) > 1:
        joined = " ".join(v for _, v in fields)
        r = predict_signal(joined)
        if r["is_attack"]:
            signals.append({
                "field": "joined",
                "value": joined,
                "attack_type": r["attack_type"],
                "attack_prob": r["attack_prob"],
                "ai_points": r["ai_points"],
                "confidence": r["confidence"],
                "fusion_score": r["fusion_score"],
                "high_risk": r["high_risk"],
                "reason": r["reason"],
            })

    if not signals:
        # 全部字段均无命中：用最高攻击概率作为 AI 分值（可能非零但未过阈值）
        prob = 0.0
        for _, fval in fields:
            prob = max(prob, predict_signal(fval)["attack_prob"])
        return {
            "attack_type": "normal",
            "is_attack": False,
            "attack_prob": round(prob, 4),
            "ai_points": int(round(prob * AI_POINTS_MAX)),
            "confidence": round(1.0 - prob, 4),
            "high_risk": False,
            "reasons": [],
            "signals": [],
            "model_label": "normal",
        }

    # 汇总：取累加分最高的那条作为主判定
    top = max(signals, key=lambda s: s["fusion_score"])
    return {
        "attack_type": top["attack_type"],
        "is_attack": True,
        "attack_prob": max(s["attack_prob"] for s in signals),
        "ai_points": top["ai_points"],
        "confidence": 0.99,
        "high_risk": any(s["high_risk"] for s in signals),
        "reasons": [f"[{s['field']}] {s['reason']}" for s in signals],
        "signals": signals,
        "model_label": top["attack_type"],
    }


def _find_text_column(df: pd.DataFrame) -> str:
    for col in ("text", "content", "payload", "url", "input"):
        if col in df.columns:
            return col
    raise ValueError(
        f"预测数据中找不到文本列，当前列: {list(df.columns)}。"
    )


def _read_predict_csv(input_path: str) -> pd.DataFrame:
    df = pd.read_csv(input_path)
    known_cols = {"text", "content", "payload", "url", "input", "label"}
    if known_cols & set(df.columns):
        return df
    if df.shape[1] == 1:
        df2 = pd.read_csv(input_path, header=None, names=["text"])
        return df2
    return df


def predict_csv(input_path: str = None, output_path: str = None) -> pd.DataFrame:
    input_path = input_path or PREDICT_DATA_PATH
    output_path = output_path or PREDICT_OUTPUT_PATH

    if not os.path.exists(input_path):
        raise FileNotFoundError(f"预测数据不存在: {input_path}")
    if os.path.getsize(input_path) == 0:
        raise ValueError(f"预测数据为空: {input_path}")

    df = _read_predict_csv(input_path)
    if len(df) == 0:
        raise ValueError(f"预测数据没有行: {input_path}")

    text_col = _find_text_column(df)
    print(f"读取预测数据: {input_path}")
    print(f"文本列: {text_col}，样本数: {len(df)}")

    records = []
    for text in df[text_col].fillna("").astype(str).tolist():
        records.append(predict_xss(text))

    result_df = pd.DataFrame(records)
    out_df = pd.concat([df.reset_index(drop=True), result_df], axis=1)

    os.makedirs(os.path.dirname(str(output_path)) or ".", exist_ok=True)
    out_df.to_csv(output_path, index=False, encoding="utf-8-sig")
    print(f"批量预测完成，结果保存到: {output_path}")
    return out_df


if __name__ == "__main__":
    # 交互模式、批量模式、单条模式、默认测试用例（保持原样）
    if len(sys.argv) == 2 and sys.argv[1] == "-i":
        print("输入要检测的文本，输入 q 退出。")
        while True:
            try:
                text = input(">>> ")
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if text.strip().lower() == "q":
                break
            print(predict_xss(text))
    elif len(sys.argv) >= 2 and sys.argv[1] in ("--batch", "-b", "--file", "-f"):
        input_path = sys.argv[2] if len(sys.argv) >= 3 else None
        output_path = sys.argv[3] if len(sys.argv) >= 4 else None
        predict_csv(input_path, output_path)
    elif len(sys.argv) > 1:
        text = " ".join(sys.argv[1:])
        print(predict_xss(text))
    else:
        test_cases = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "%3Cscript%3Ealert(1)%3C/script%3E",
            "hello world",
            "<div>正常内容</div>",
        ]
        for t in test_cases:
            print(t, "->", predict_xss(t))