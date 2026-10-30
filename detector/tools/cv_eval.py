# tools/cv_eval.py
"""用分层交叉验证给出可信的逐类指标（解决小样本类别指标不可信的问题）。

背景：独立测试集里 path_traversal 只有 3 条，单次划分的逐类指标没有统计意义。
本脚本改用 K 折交叉验证，每折都让所有类别都出现在验证集里，
从而对每个类别给出基于多折平均的召回率与 F1。

同时对比三条链路：
  1. 只看规则（未命中记 normal）
  2. 只看模型
  3. 规则优先 + 模型兜底（线上 predict_xss 的行为）

用法:
    python -m tools.cv_eval --data <train_clean.csv> [--folds 5]
"""
import argparse
import os
import sys
from collections import Counter, defaultdict

import numpy as np
import pandas as pd
from sklearn.base import clone
from sklearn.metrics import classification_report, confusion_matrix, f1_score
from sklearn.model_selection import StratifiedKFold

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.config import CURRENT_LABELS
from src.preprocess import normalize_for_model, normalize_text
from src.predict import fuse_signals, _attack_probability, ATTACK_LABELS
from src.rules import match_rules, match_rules_with_score
from src.train import build_model
from src.utils import read_csv_safe

ATTACK = ATTACK_LABELS


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True)
    ap.add_argument("--folds", type=int, default=5)
    args = ap.parse_args()

    df = read_csv_safe(args.data)
    df = df.dropna(subset=["text", "label"]).copy()
    df["label"] = df["label"].astype(str).str.strip().str.lower()
    df = df[df["label"].isin(CURRENT_LABELS)]
    df["text"] = df["text"].astype(str)
    df = df.drop_duplicates(subset=["text"]).reset_index(drop=True)

    print(f"数据: {args.data}")
    print(f"样本数: {len(df)}")
    print(f"标签分布:\n{df['label'].value_counts().to_string()}\n")

    labels = [l for l in CURRENT_LABELS if l in set(df["label"])]
    # 每类至少要有 folds 条才能分层
    min_count = df["label"].value_counts().min()
    folds = max(2, min(args.folds, int(min_count)))
    if folds < args.folds:
        print(f"[提示] 最小类别只有 {min_count} 条，折数由 {args.folds} 降为 {folds}")

    texts = [normalize_for_model(t) for t in df["text"].tolist()]
    raw_norm = [normalize_text(t) for t in df["text"].tolist()]
    y = df["label"].tolist()

    skf = StratifiedKFold(n_splits=folds, shuffle=True, random_state=42)

    # 逐折收集预测
    pred_rule = [None] * len(y)
    pred_model = [None] * len(y)
    pred_final = [None] * len(y)
    pred_fused = [None] * len(y)
    fused_tier = [None] * len(y)

    for fold, (tr, va) in enumerate(skf.split(texts, y), 1):
        Xtr = [texts[i] for i in tr]
        ytr = [y[i] for i in tr]
        model = build_model(class_weight="balanced")
        model.fit(Xtr, ytr)
        classes = [str(c) for c in model.classes_]

        # 模型预测
        proba = model.predict_proba([texts[i] for i in va])
        for k, i in enumerate(va):
            pred_model[i] = classes[int(proba[k].argmax())]
            ap = _attack_probability(classes, proba[k])
            conf = float(proba[k].max())
            amap = {c: float(v) for c, v in zip(classes, proba[k])}
            # 规则预测
            hits = match_rules(raw_norm[i])
            pred_rule[i] = hits[0][0] if hits else None
            pred_final[i] = pred_rule[i] if pred_rule[i] else pred_model[i]
            # 加权融合（与线上 predict_signal 同一套逻辑，含白名单与按类别概率）
            scored = match_rules_with_score(raw_norm[i])
            fused = fuse_signals(scored, pred_model[i], ap, conf,
                                 prob_by_label=amap, matched_path=raw_norm[i])
            pred_fused[i] = fused["attack_type"] if fused["is_attack"] else "normal"
            fused_tier[i] = ("high" if fused["high_risk"]
                             else ("susp" if fused["suspicious"] else "normal"))

        print(f"  折 {fold}/{folds}: 训练 {len(tr)} / 验证 {len(va)}  完成")

    def show(title, preds, idxs=None):
        idxs = list(range(len(y))) if idxs is None else list(idxs)
        if not idxs:
            print(f"\n== {title} ==\n(无样本)")
            return
        yt = [y[i] for i in idxs]
        yp = [preds[i] for i in idxs]
        print(f"\n{'='*66}")
        print(f"== {title} ==  验证样本数 {len(idxs)}")
        print("=" * 66)
        print(classification_report(yt, yp, labels=labels, zero_division=0, digits=4))
        cm = confusion_matrix(yt, yp, labels=labels)
        print(f"{'真实\\预测':<16}" + "".join(f"{l:>16}" for l in labels))
        for i, l in enumerate(labels):
            print(f"{l:<16}" + "".join(f"{v:>16}" for v in cm[i]))
        print(f"宏平均F1: {f1_score(yt, yp, average='macro', zero_division=0):.4f}")
        acc = float(np.mean([a == b for a, b in zip(yt, yp)]))
        print(f"准确率:   {acc:.4f}")

        # 攻击/正常二分类视角（蜜罐真正关心的）
        tp = sum(1 for a, b in zip(yt, yp) if a in ATTACK and b in ATTACK)
        fn = sum(1 for a, b in zip(yt, yp) if a in ATTACK and b not in ATTACK)
        fp = sum(1 for a, b in zip(yt, yp) if a not in ATTACK and b in ATTACK)
        tn = sum(1 for a, b in zip(yt, yp) if a not in ATTACK and b not in ATTACK)
        rec = tp / (tp + fn) if (tp + fn) else 0.0
        prec = tp / (tp + fp) if (tp + fp) else 0.0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
        print(f"\n  二分类视角(攻击 vs 正常): 漏报={fn} 误报={fp}")
        print(f"    攻击召回率={rec:.2%}  攻击精确率={prec:.2%}  F1={f1:.4f}")

    show(f"{folds}折交叉验证 - 只看规则（未命中记 normal）",
         [pred_rule[i] or "normal" for i in range(len(y))])
    show(f"{folds}折交叉验证 - 只看模型", pred_model)
    show(f"{folds}折交叉验证 - 规则优先 + 模型兜底（旧 predict_xss）", pred_final)
    show(f"{folds}折交叉验证 - 加权融合 + 双阈值（新 predict_signal）", pred_fused)

    # 分层统计：融合后的可疑/高危分层是否合理
    print(f"\n{'='*66}")
    print("加权融合的分层分布（双阈值机制实际效果）")
    print("=" * 66)
    tc = Counter(t for t in fused_tier if t)
    for tier in ("high", "susp", "normal"):
        n = tc.get(tier, 0)
        # 该层里真实攻击的比例
        atk = sum(1 for i in range(len(y))
                  if fused_tier[i] == tier and y[i] in ATTACK)
        print(f"  {tier:<8} 共 {n:>5} 条, 其中真实攻击 {atk:>5} 条 "
              f"({atk/n:.1%})" if n else f"  {tier:<8} 共 0 条")
    high = tc.get("high", 0) + tc.get("susp", 0)
    atk_above = sum(1 for i in range(len(y))
                    if fused_tier[i] in ("high", "susp") and y[i] in ATTACK)
    fp_above = sum(1 for i in range(len(y))
                   if fused_tier[i] in ("high", "susp") and y[i] not in ATTACK)
    print(f"\n  过可疑线的样本 {high} 条: 真实攻击 {atk_above} / 误报 {fp_above}")

    # 规则的实际覆盖能力
    covered = [i for i in range(len(y)) if pred_rule[i]]
    print(f"\n{'='*66}")
    print("规则覆盖情况")
    print("=" * 66)
    print(f"规则命中(直接定类)的样本: {len(covered)}/{len(y)} = {len(covered)/len(y):.1%}")
    for lab in ATTACK:
        tot = sum(1 for v in y if v == lab)
        cov = sum(1 for i in covered if y[i] == lab)
        print(f"  {lab:<16} 真实 {tot:>5} 条, 规则命中 {cov:>5} 条 ({cov/tot:.1%})")


if __name__ == "__main__":
    main()
