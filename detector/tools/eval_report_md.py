# tools/eval_report_md.py
"""生成正式评估报告：独立测试集上的分类别识别率 + 完整评估指标。

输出两份文件：
    eval_report.md    人类可读的评估报告（含每类攻击识别率、混淆矩阵、误报漏报分析）
    eval_report.json  机器可读的指标数据（便于归档与对比）

用法:
    python -m tools.eval_report_md
    python -m tools.eval_report_md --test data/processed/test_raw.csv --outdir .
"""
import argparse
import json
import os
import sys
from collections import Counter
from datetime import datetime

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (accuracy_score, classification_report,
                             confusion_matrix, f1_score, precision_recall_fscore_support)

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.config import (AI_POINTS_MAX, HIGH_RISK_THRESHOLD, MODEL_PATH,
                        MODEL_META_PATH, SUSPICIOUS_THRESHOLD)
from src.predict import fuse_signals, _attack_probability, ATTACK_LABELS
from src.preprocess import normalize_text
from src.rules import match_rules_with_score

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--test", default=os.path.join(BASE, "data", "processed", "test_raw.csv"))
    ap.add_argument("--model", default=str(MODEL_PATH))
    ap.add_argument("--outdir", default=BASE)
    args = ap.parse_args()

    df = pd.read_csv(args.test, encoding="utf-8-sig")
    df = df.dropna(subset=["text", "label"]).copy()
    df["text"] = df["text"].astype(str)
    df["label"] = df["label"].astype(str).str.strip().str.lower()
    model = joblib.load(args.model)
    classes = [str(c) for c in model.classes_]
    labels = [l for l in ["xss", "sqli", "path_traversal", "sensitive_path", "normal"]
              if l in set(df["label"]) | set(classes)]

    y_true = df["label"].tolist()
    texts = df["text"].tolist()
    norm = [normalize_text(t) for t in texts]

    # ---- 逐条过完整链路（与线上 predict_signal 一致）----
    proba = model.predict_proba(norm)
    pred_model, pred_rule, pred_fused = [], [], []
    rows = []
    for k in range(len(texts)):
        p = proba[k]
        idx = int(p.argmax())
        mlabel = classes[idx]
        conf = float(p[idx])
        amap = {c: float(v) for c, v in zip(classes, p)}
        ap = _attack_probability(classes, p)

        scored = match_rules_with_score(norm[k])
        pred_model.append(mlabel)
        pred_rule.append(scored[0][0] if scored else "normal")

        r = fuse_signals(scored, mlabel, ap, conf, prob_by_label=amap,
                         matched_path=norm[k])
        pred_fused.append(r["attack_type"] if r["is_attack"] else "normal")
        rows.append({"text": texts[k], "true": y_true[k], "pred": pred_fused[-1],
                     "model": mlabel, "rule": pred_rule[-1],
                     "prob": ap, "ai_points": r["ai_points"],
                     "rule_points": r["rule_points"],
                     "fusion": r["fusion_score"],
                     "high_risk": r["high_risk"], "reason": r["reason"]})

    res = pd.DataFrame(rows)

    # ---- 指标 ----
    def metrics(pred):
        acc = accuracy_score(y_true, pred)
        macro = f1_score(y_true, pred, average="macro", zero_division=0)
        pr, rc, f1, sup = precision_recall_fscore_support(
            y_true, pred, labels=labels, zero_division=0)
        return acc, macro, pr, rc, f1, sup

    acc_f, macro_f, pr_f, rc_f, f1_f, sup_f = metrics(pred_fused)
    acc_m, macro_m, pr_m, rc_m, f1_m, _ = metrics(pred_model)
    acc_r, macro_r, pr_r, rc_r, f1_r, _ = metrics(pred_rule)

    # 二分类视角
    def binary(pred):
        tp = sum(1 for a, b in zip(y_true, pred) if a in ATTACK_LABELS and b in ATTACK_LABELS)
        fn = sum(1 for a, b in zip(y_true, pred) if a in ATTACK_LABELS and b not in ATTACK_LABELS)
        fp = sum(1 for a, b in zip(y_true, pred) if a not in ATTACK_LABELS and b in ATTACK_LABELS)
        tn = sum(1 for a, b in zip(y_true, pred) if a not in ATTACK_LABELS and b not in ATTACK_LABELS)
        rec = tp / (tp + fn) if (tp + fn) else 0
        prec = tp / (tp + fp) if (tp + fp) else 0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0
        return dict(tp=tp, fn=fn, fp=fp, tn=tn, recall=rec, precision=prec, f1=f1)
    bin_f = binary(pred_fused)

    meta = {}
    if os.path.exists(MODEL_META_PATH):
        meta = json.load(open(MODEL_META_PATH, encoding="utf-8"))

    # ---- 生成 Markdown ----
    L = []
    L.append("# 攻击检测模型评估报告\n")
    L.append(f"- **生成时间**：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    L.append(f"- **模型版本**：{meta.get('version','?')}（训练于 {meta.get('trained_at','?')}）")
    L.append(f"- **模型文件**：`{os.path.relpath(args.model, BASE)}`")
    L.append(f"- **评估数据**：`{os.path.relpath(args.test, BASE)}`（{len(df)} 条）")
    L.append(f"- **评估方式**：独立测试集（未参与训练）\n")
    L.append("---\n")

    L.append("## 一、分类别识别率（本次评估的核心结论）\n")
    L.append("| 攻击类型 | 中文 | 精确率 | **识别率(召回)** | F1 | 测试样本数 |")
    L.append("|---|---|---|---|---|---|")
    CN = {"xss": "跨站脚本", "sqli": "SQL 注入", "path_traversal": "目录穿越",
          "sensitive_path": "敏感路径探测", "normal": "正常流量"}
    for i, lab in enumerate(labels):
        L.append(f"| `{lab}` | {CN.get(lab,'')} | {pr_f[i]:.2%} | "
                 f"**{rc_f[i]:.2%}** | {f1_f[i]:.4f} | {int(sup_f[i])} |")
    L.append("")
    L.append(f"**总体准确率**：{acc_f:.4f}　**宏平均 F1**：{macro_f:.4f}\n")
    L.append(f"**攻击识别率（二分类召回）**：{bin_f['recall']:.2%}　"
             f"**攻击精确率**：{bin_f['precision']:.2%}\n")

    L.append("---\n")
    L.append("## 二、混淆矩阵（规则 + 模型 加权融合链路）\n")
    cm = confusion_matrix(y_true, pred_fused, labels=labels)
    L.append("| 真实\\预测 | " + " | ".join(f"`{l}`" for l in labels) + " |")
    L.append("|---" * (len(labels) + 1) + "|")
    for i, lab in enumerate(labels):
        L.append(f"| **`{lab}`** | " + " | ".join(str(v) for v in cm[i]) + " |")
    L.append("")

    L.append("---\n")
    L.append("## 三、三条链路对比\n")
    L.append("| 链路 | 准确率 | 宏 F1 | 攻击召回 | 攻击精确 |")
    L.append("|---|---|---|---|---|")
    for name, acc, mac, pred in [("只看规则", acc_r, macro_r, pred_rule),
                                 ("只看模型", acc_m, macro_m, pred_model),
                                 ("加权融合+双阈值", acc_f, macro_f, pred_fused)]:
        b = binary(pred)
        L.append(f"| {name} | {acc:.4f} | {mac:.4f} | "
                 f"{b['recall']:.2%} | {b['precision']:.2%} |")
    L.append("")

    L.append("---\n")
    L.append(f"## 四、双阈值分层效果\n")
    L.append(f"蜜罐机制：累计 ≥{SUSPICIOUS_THRESHOLD} 分记为可疑事件，"
             f"≥{HIGH_RISK_THRESHOLD} 分触发高危告警。\n")
    L.append("| 层级 | 样本数 | 其中真实攻击 | 攻击占比 |")
    L.append("|---|---|---|---|")
    hi = res[res["high_risk"]]
    su = res[(~res["high_risk"]) & (res["fusion"] >= SUSPICIOUS_THRESHOLD)]
    no = res[res["fusion"] < SUSPICIOUS_THRESHOLD]
    for name, sub in [("高危（≥40）", hi), ("可疑（20~39）", su), ("常规（<20）", no)]:
        n = len(sub)
        atk = int(sub["true"].isin(ATTACK_LABELS).sum())
        L.append(f"| {name} | {n} | {atk} | {atk/n:.1%} |" if n else f"| {name} | 0 | 0 | — |")
    L.append("")

    L.append("---\n")
    L.append("## 五、误报与漏报明细\n")
    fn = res[(res["true"].isin(ATTACK_LABELS)) & (~res["pred"].isin(ATTACK_LABELS))]
    fp = res[(~res["true"].isin(ATTACK_LABELS)) & (res["pred"].isin(ATTACK_LABELS))]
    L.append(f"**漏报（真实为攻击但被判 normal）：{len(fn)} 条**\n")
    if len(fn):
        by = Counter(fn["true"])
        L.append("按类别：" + "、".join(f"`{k}` {v} 条" for k, v in by.most_common()) + "\n")
        L.append("| 真实类型 | 累加分 | 攻击概率 | 样本 |")
        L.append("|---|---|---|---|")
        for _, r in fn.head(20).iterrows():
            L.append(f"| `{r['true']}` | {r['fusion']} | {r['prob']:.3f} | "
                     f"`{r['text'][:52]}` |")
        L.append("")
    else:
        L.append("（无）\n")

    L.append(f"**误报（正常流量被判为攻击）：{len(fp)} 条**\n")
    if len(fp):
        L.append("| 判为 | 累加分 | 攻击概率 | 样本 |")
        L.append("|---|---|---|---|")
        for _, r in fp.head(20).iterrows():
            L.append(f"| `{r['pred']}` | {r['fusion']} | {r['prob']:.3f} | "
                     f"`{r['text'][:52]}` |")
        L.append("")
    else:
        L.append("（无）\n")

    L.append("---\n")
    L.append("## 六、概率校准质量\n")
    cal = meta.get("calibration") or {}
    if cal.get("brier_mean") is not None:
        L.append(f"平均 Brier 分数：**{cal['brier_mean']:.4f}**（越小越好）\n")
        L.append("| 置信度区间 | 样本数 | 实际正确率 |")
        L.append("|---|---|---|")
        for lo, hi_, n, real, avg in cal.get("bins", []):
            L.append(f"| [{lo:.2f}, {hi_:.2f}) | {n} | {real:.2%} |")
        L.append("")
    else:
        L.append("（模型元数据中无校准信息）\n")

    L.append("---\n")
    L.append("## 七、指标说明\n")
    L.append("| 指标 | 含义 |")
    L.append("|---|---|")
    L.append("| **识别率（召回率）** | 该类真实攻击中被成功识别出来的比例，**漏报的补数** |")
    L.append("| 精确率 | 判为该类的样本中确实是该类的比例，**误报的补数** |")
    L.append("| F1 | 精确率与召回率的调和平均 |")
    L.append("| 攻击识别率 | 所有攻击类样本中被判为任一攻击类的比例 |")
    L.append("")
    L.append("> 注：`path_traversal` 类清洗后真实样本极少，其指标**不具统计置信度**，")
    L.append("> 仅供参考。建议补充该类样本后重新评估。\n")

    outdir = args.outdir
    os.makedirs(outdir, exist_ok=True)
    md_path = os.path.join(outdir, "eval_report.md")
    json_path = os.path.join(outdir, "eval_report.json")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write("\n".join(L))

    payload = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "model_version": meta.get("version"),
        "model_trained_at": meta.get("trained_at"),
        "model_file": os.path.relpath(args.model, BASE),
        "test_file": os.path.relpath(args.test, BASE),
        "n_samples": len(df),
        "accuracy": float(acc_f), "macro_f1": float(macro_f),
        "attack_recall": float(bin_f["recall"]),
        "attack_precision": float(bin_f["precision"]),
        "per_class": {
            lab: {"precision": float(pr_f[i]), "recall": float(rc_f[i]),
                  "f1": float(f1_f[i]), "support": int(sup_f[i])}
            for i, lab in enumerate(labels)
        },
        "confusion_matrix": {"labels": labels, "matrix": cm.tolist()},
        "pipelines": {
            "rule_only": {"accuracy": float(acc_r), "macro_f1": float(macro_r)},
            "model_only": {"accuracy": float(acc_m), "macro_f1": float(macro_m)},
            "fused": {"accuracy": float(acc_f), "macro_f1": float(macro_f)},
        },
        "tiers": {
            "high_risk": {"n": len(hi), "attacks": int(hi["true"].isin(ATTACK_LABELS).sum())},
            "suspicious": {"n": len(su), "attacks": int(su["true"].isin(ATTACK_LABELS).sum())},
            "normal": {"n": len(no), "attacks": int(no["true"].isin(ATTACK_LABELS).sum())},
        },
        "errors": {"false_negatives": len(fn), "false_positives": len(fp)},
    }
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)

    print(f"评估样本数: {len(df)}")
    print(f"总体准确率: {acc_f:.4f}   宏平均F1: {macro_f:.4f}")
    print(f"攻击识别率: {bin_f['recall']:.2%}   攻击精确率: {bin_f['precision']:.2%}")
    print("\n分类别识别率:")
    for i, lab in enumerate(labels):
        print(f"  {lab:<16} 精确率 {pr_f[i]:.2%}  识别率 {rc_f[i]:.2%}  "
              f"F1 {f1_f[i]:.4f}  (n={int(sup_f[i])})")
    print(f"\n[已保存] {md_path}")
    print(f"[已保存] {json_path}")


if __name__ == "__main__":
    main()
