# tools/cross_dataset_eval.py
"""跨数据集泛化测试：一个数据集训练、另一个数据集测试。

回答的问题：
    "模型换一批数据还能不能认对？"——即泛化能力，而非同分布拟合。

两组实验：
    A. 用外部 payload 数据集训练  ->  在原始基准数据上测
    B. 用原始基准数据训练        ->  在外部 payload 数据集上测
    （对照组：同分布 80/20 留出测试，作为上限参考）

为公平比较，只使用两个数据集**共有的标签**：
    xss / sqli / path_traversal / normal
（sensitive_path 只在原始数据里出现，不参与本测试）

用法:
    python -m tools.cross_dataset_eval
"""
import os
import sys
from collections import Counter

import pandas as pd
from sklearn.metrics import (accuracy_score, f1_score,
                             precision_recall_fscore_support)
from sklearn.model_selection import train_test_split

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

from src.preprocess import normalize_for_model  # noqa: E402
from src.train import build_model  # noqa: E402

SHARED_LABELS = ["xss", "sqli", "path_traversal", "normal"]


def load_original():
    """原始基准数据集，只保留共有标签。"""
    p = os.path.join(BASE, "data", "raw", "train_raw_backup_v3.csv")
    df = pd.read_csv(p, encoding="utf-8-sig")
    df = df.dropna(subset=["text", "label"]).copy()
    df["text"] = df["text"].astype(str)
    df["label"] = df["label"].astype(str).str.strip().str.lower()
    # 原始数据的 path_traversal 混杂了敏感路径，这里只保留真穿越
    import re
    trav = re.compile(r"(\.\./|\.\.\\|%2e%2e|\.\.%2f|\.\.%5c|%252e|\.\.;|\.\.//)", re.I)
    is_pt = df["label"] == "path_traversal"
    df.loc[is_pt & ~df["text"].str.contains(trav), "label"] = "sensitive_path"
    df = df[df["label"].isin(SHARED_LABELS)].copy()
    df = df[df["text"].str.strip() != ""]
    df = df.drop_duplicates(subset=["text"]).reset_index(drop=True)
    return df


def load_payload():
    """外部 payload 数据集（已转换好的 extra_samples.csv）。"""
    p = os.path.join(BASE, "data", "raw", "extra_samples.csv")
    df = pd.read_csv(p, encoding="utf-8-sig")
    df = df.dropna(subset=["text", "label"]).copy()
    df["text"] = df["text"].astype(str)
    df["label"] = df["label"].astype(str).str.strip().str.lower()
    df = df[df["label"].isin(SHARED_LABELS)].copy()
    df = df[df["text"].str.strip() != ""]
    df = df.drop_duplicates(subset=["text"]).reset_index(drop=True)
    return df


def prep(df):
    df = df.copy()
    df["text"] = df["text"].map(normalize_for_model)
    df = df[df["text"].str.strip() != ""]
    return df


def evaluate(train_df, test_df, name):
    model = build_model(class_weight="balanced")
    model.fit(train_df["text"].tolist(), train_df["label"].tolist())
    y_true = test_df["label"].tolist()
    y_pred = model.predict(test_df["text"].tolist())

    acc = accuracy_score(y_true, y_pred)
    macro = f1_score(y_true, y_pred, average="macro", zero_division=0)
    pr, rc, f1, sup = precision_recall_fscore_support(
        y_true, y_pred, labels=SHARED_LABELS, zero_division=0)

    print(f"\n{'=' * 88}")
    print(f"  {name}")
    print(f"  训练 {len(train_df)} 条  →  测试 {len(test_df)} 条")
    print(f"{'=' * 88}")
    print(f"  准确率: {acc:.4f}    宏平均F1: {macro:.4f}")
    print()
    print(f"  {'类别':<18}{'精确率':>9}{'识别率':>9}{'F1':>9}{'测试样本':>10}")
    print(f"  {'-' * 55}")
    for i, lab in enumerate(SHARED_LABELS):
        if sup[i] == 0:
            print(f"  {lab:<18}{'—':>9}{'—':>9}{'—':>9}{0:>10}")
            continue
        print(f"  {lab:<18}{pr[i]:>8.2%}{rc[i]:>9.2%}{f1[i]:>9.4f}{int(sup[i]):>10}")

    # 攻击 vs 正常（二分类视角）
    ATT = {"xss", "sqli", "path_traversal"}
    tp = sum(1 for a, b in zip(y_true, y_pred) if a in ATT and b in ATT)
    fn = sum(1 for a, b in zip(y_true, y_pred) if a in ATT and b not in ATT)
    fp = sum(1 for a, b in zip(y_true, y_pred) if a not in ATT and b in ATT)
    rec = tp / (tp + fn) if tp + fn else 0
    prec = tp / (tp + fp) if tp + fp else 0
    print(f"\n  攻击识别率: {rec:.2%}   攻击精确率: {prec:.2%}   "
          f"(漏报 {fn} / 误报 {fp})")
    return {"acc": acc, "macro_f1": macro, "recall": rec, "precision": prec}


def main():
    print("加载数据...")
    orig = prep(load_original())
    pay = prep(load_payload())
    print(f"  原始基准数据: {len(orig)} 条  {dict(orig['label'].value_counts())}")
    print(f"  外部payload : {len(pay)} 条  {dict(pay['label'].value_counts())}")

    results = {}

    # 对照组：同分布 80/20
    tr, te = train_test_split(orig, test_size=0.2, random_state=42,
                              stratify=orig["label"])
    results["同分布（上限参考）"] = evaluate(tr, te, "对照组：原始数据 80/20 留出")

    # A: payload 训练 -> 原始数据测
    results["payload→原始"] = evaluate(pay, orig, "A. 跨集：payload 训练 → 原始数据测")

    # B: 原始训练 -> payload 测
    results["原始→payload"] = evaluate(orig, pay, "B. 跨集：原始数据训练 → payload 测")

    # 汇总
    print(f"\n{'=' * 88}")
    print("  汇总结论")
    print(f"{'=' * 88}")
    print(f"  {'实验':<24}{'准确率':>9}{'宏F1':>9}{'攻击识别率':>12}{'攻击精确率':>12}")
    print(f"  {'-' * 68}")
    for k, v in results.items():
        print(f"  {k:<24}{v['acc']:>8.2%}{v['macro_f1']:>9.4f}"
              f"{v['recall']:>11.2%}{v['precision']:>11.2%}")
    print()
    base = results["同分布（上限参考）"]
    for k in ("payload→原始", "原始→payload"):
        d = base["acc"] - results[k]["acc"]
        print(f"  {k} 相比同分布下降: {d:+.2%}")


if __name__ == "__main__":
    main()
