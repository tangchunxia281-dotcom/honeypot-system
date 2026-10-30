# tools/eval_report.py
"""独立评估脚本：把"规则"和"模型"两条链路分开统计，暴露真实短板。

用法:
    python -m tools.eval_report                # 评估独立测试集 test_raw.csv
    python -m tools.eval_report path/to.csv    # 评估指定带 label 的 CSV
"""
import os
import sys
from collections import Counter

import joblib
import pandas as pd

from src.config import MODEL_PATH, TEST_DATA_PATH
from src.preprocess import normalize_text
from src.rules import match_rules

LABELS = ["xss", "sqli", "path_traversal", "sensitive_path", "normal"]


def load_eval(path):
    df = pd.read_csv(path, encoding="utf-8-sig")
    df = df.dropna(subset=["text", "label"]).copy()
    df["text"] = df["text"].astype(str)
    df["label"] = df["label"].astype(str).str.strip().str.lower()
    return df[df["label"].isin(LABELS)].reset_index(drop=True)


def evaluate(df, path="?", model_path=None):
    model = joblib.load(model_path or MODEL_PATH)
    classes = [str(c) for c in model.classes_]
    texts = df["text"].tolist()
    y_true = df["label"].tolist()
    total = len(y_true)
    norm = [normalize_text(t) for t in texts]

    rule_pred, final_pred, route = [None] * total, [None] * total, ["model"] * total
    for i, n in enumerate(norm):
        hits = match_rules(n)
        if hits:
            rule_pred[i] = hits[0][0]
            final_pred[i] = hits[0][0]
            route[i] = "rule"

    model_idx = [i for i in range(total) if route[i] == "model"]
    model_pred = {}
    if model_idx:
        proba = model.predict_proba([norm[i] for i in model_idx])
        for k, i in enumerate(model_idx):
            j = int(proba[k].argmax())
            model_pred[i] = classes[j]
            final_pred[i] = classes[j]

    out = []
    out.append(f"评估文件: {path}")
    out.append(f"总样本数: {total}")
    rc = Counter(route)
    out.append("")
    out.append("== 路由分布 ==")
    out.append(f"规则命中(直接定label): {rc.get('rule',0)} ({rc.get('rule',0)/total:.1%})")
    out.append(f"交给模型判断:          {rc.get('model',0)} ({rc.get('model',0)/total:.1%})")

    rule_idx = [i for i in range(total) if route[i] == "rule"]
    if rule_idx:
        right = sum(1 for i in rule_idx if rule_pred[i] == y_true[i])
        out.append(f"规则命中样本中判对: {right}/{len(rule_idx)} = {right/len(rule_idx):.1%}")

    fp_rule = [i for i in rule_idx if y_true[i] == "normal"]
    out.append(f"规则把 normal 误判成攻击(规则误报): {len(fp_rule)} 条")
    for i in fp_rule[:10]:
        out.append(f"    [规则FP] {texts[i][:90]!r} -> {rule_pred[i]}")

    fn_idx = [i for i in range(total) if y_true[i] != "normal" and final_pred[i] == "normal"]
    out.append("")
    out.append(f"攻击样本被漏报成 normal: {len(fn_idx)} 条")
    for i in fn_idx[:20]:
        out.append(f"    [FN] 真实={y_true[i]} 路由={route[i]} 文本={texts[i][:90]!r}")

    fp_idx = [i for i in range(total) if y_true[i] == "normal" and final_pred[i] != "normal"]
    out.append("")
    out.append(f"normal 被误报为攻击: {len(fp_idx)} 条")
    for i in fp_idx[:20]:
        out.append(f"    [FP] 判为={final_pred[i]} 路由={route[i]} 文本={texts[i][:90]!r}")

    def cm(title, preds, idxs):
        idxs = list(idxs)
        if not idxs:
            out.append(f"\n== {title} ==\n(无样本)")
            return
        out.append(f"\n== {title} ==  样本数: {len(idxs)}")
        counts = Counter(y_true[i] for i in idxs)
        out.append("真实分布: " + ", ".join(f"{l}={counts.get(l,0)}" for l in LABELS))
        out.append(f"{'真实\\预测':<16}" + "".join(f"{l:>17}" for l in LABELS) + f"{'召回率':>10}")
        for tl in LABELS:
            rows = [i for i in idxs if y_true[i] == tl]
            if not rows:
                continue
            preds_c = Counter(preds[i] for i in rows)
            cells = "".join(f"{preds_c.get(pl,0):>17}" for pl in LABELS)
            out.append(f"{tl:<16}{cells}{preds_c.get(tl,0)/len(rows):>9.1%}")
        acc = sum(1 for i in idxs if preds[i] == y_true[i]) / len(idxs)
        out.append(f"总体准确率: {acc:.2%}")

    cm("最终链路（规则优先 + 模型兜底）", final_pred, range(total))
    cm("只看规则（未命中记 normal）",
       [rule_pred[i] or "normal" for i in range(total)], range(total))
    if model_idx:
        cm("只看模型（仅未命中规则的样本）", model_pred, model_idx)
    return "\n".join(out)


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    opts = {}
    for a in sys.argv[1:]:
        if a.startswith("--") and "=" in a:
            k, v = a[2:].split("=", 1)
            opts[k] = v

    path = args[0] if args else str(TEST_DATA_PATH)
    model_path = opts.get("model")
    out_path = opts.get("out", "eval_report.txt")

    df = load_eval(path)
    report = evaluate(df, path, model_path)
    try:
        print(report)
    except UnicodeEncodeError:
        sys.stdout.reconfigure(encoding="utf-8")
        print(report)
    out_dir = os.path.dirname(os.path.abspath(out_path))
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(report)
    print(f"\n[已保存] {out_path}")


if __name__ == "__main__":
    main()
