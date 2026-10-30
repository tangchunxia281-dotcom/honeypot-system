# tools/test_samples.py
"""测试外部样本文件，并给出"哪些是新样本、该怎么处理"的建议。

针对场景：你手里有一个只有一列、没有表头、没有标签的样本文件
（例如桌面的 ceshi2.csv），想知道：
    1. 检测器对它们判定成什么
    2. 哪些模型已经会了（不需要再训练）
    3. 哪些是没训练过的新样本（需要补进训练集）

用法:
    python -m tools.test_samples "D:/path/to/ceshi2.csv"
    python -m tools.test_samples "D:/path/to/ceshi2.csv" --out result.csv
"""
import argparse
import os
import re
import sys
from collections import Counter

import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.config import SUSPICIOUS_THRESHOLD
from src.predict import predict_signal

# 判断某条文本是否与训练集重复（模型已经见过）
TRAIN_PATHS = ["data/raw/train_clean.csv"]


def load_any_csv(path):
    '''读取"单列无表头"或"带表头"的样本文件，返回文本列表。

    处理三种常见情况：
      - 带表头 text/label（标准格式）
      - 单列无表头（每行一个样本）
      - 载荷前后被多余引号包裹（CSV 转义残留）
    '''
    raw_lines = open(path, encoding="utf-8-sig").read().splitlines()

    # 先按标准 CSV 解析（能解析出多列则说明有表头）
    try:
        df = pd.read_csv(path, encoding="utf-8-sig")
        cols = [str(c) for c in df.columns]
        has_header = any(c.lower() in ("text", "content", "payload", "url", "input")
                         for c in cols)
        if has_header:
            col = next(c for c in cols
                       if c.lower() in ("text", "content", "payload", "url", "input"))
            return df[col].dropna().astype(str).tolist(), "带表头"
        if df.shape[1] > 1:
            return df.iloc[:, 0].dropna().astype(str).tolist(), "多列取第一列"
    except Exception:
        pass

    # 回退：按行读取，剥掉外层多余引号
    texts = []
    for line in raw_lines:
        s = line.strip()
        if not s:
            continue
        # 去掉最外层成对的引号，以及单独出现的多余引号
        if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
            s = s[1:-1]
        s = s.strip('"').strip()
        if s:
            texts.append(s)
    return texts, "单列无表头"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path", help="待测试的样本文件")
    ap.add_argument("--out", default=None, help="结果输出 CSV 路径")
    ap.add_argument("--train", default=None, help="训练集路径（用于判断是否重复）")
    args = ap.parse_args()

    texts, fmt = load_any_csv(args.path)
    print(f"读取样本: {args.path}")
    print(f"解析方式: {fmt}    样本数: {len(texts)}\n")

    # 载入训练集文本，用于判断"模型是否见过"
    train_texts = set()
    for tp in ([args.train] if args.train else TRAIN_PATHS):
        if tp and os.path.exists(tp):
            try:
                td = pd.read_csv(tp, encoding="utf-8-sig")
                if "text" in td.columns:
                    train_texts |= set(td["text"].astype(str))
            except Exception:
                pass
    if train_texts:
        print(f"训练集样本数: {len(train_texts)}（用于判断新样本）\n")

    rows = []
    for t in texts:
        r = predict_signal(t)
        seen = t in train_texts if train_texts else None
        rows.append({
            "文本": t,
            "判定类型": r["attack_type"],
            "是否攻击": r["is_attack"],
            "攻击概率": r["attack_prob"],
            "AI分": r["ai_points"],
            "规则分": r["rule_points"],
            "生效分": r["effective_rule_points"],
            "累加分": r["fusion_score"],
            "分层": ("高危" if r["high_risk"]
                     else ("可疑" if r["suspicious"] else "常规")),
            "训练集已有": ("是" if seen else ("否" if seen is not None else "未知")),
            "理由": r["reason"][:80],
        })
    df = pd.DataFrame(rows)

    # ---------- 汇总 ----------
    print("=" * 78)
    print("一、判定结果分布")
    print("=" * 78)
    for k, v in Counter(df["判定类型"]).most_common():
        sub = df[df["判定类型"] == k]
        print(f"  {k:<18} {v:>4} 条   "
              f"(高危 {int((sub['分层']=='高危').sum())}, "
              f"可疑 {int((sub['分层']=='可疑').sum())}, "
              f"常规 {int((sub['分层']=='常规').sum())})")

    print("\n" + "=" * 78)
    print("二、是否模型已见过")
    print("=" * 78)
    for k, v in Counter(df["训练集已有"]).most_common():
        print(f"  {k:<8} {v:>4} 条")

    # ---------- 未识别（判为 normal 或未过阈值）----------
    missed = df[df["是否攻击"] == False]
    print("\n" + "=" * 78)
    print(f"三、未被判为攻击的样本（{len(missed)} 条）——这些是要重点处理的")
    print("=" * 78)
    if len(missed):
        for _, r in missed.iterrows():
            print(f"  [{r['训练集已有']}] 累加分={r['累加分']:<3} "
                  f"概率={r['攻击概率']:.3f}  {r['文本'][:70]}")
    else:
        print("  （无，全部识别为攻击）")

    # ---------- 低置信 / 判为攻击但没过阈值 ----------
    lowconf = df[(df["是否攻击"]) & (df["累加分"] < 40)].copy()
    print("\n" + "=" * 78)
    print(f"四、判为攻击但只到「可疑」层（{len(lowconf)} 条）")
    print("=" * 78)
    if len(lowconf):
        for _, r in lowconf.head(30).iterrows():
            print(f"  {r['判定类型']:<16} 累加分={r['累加分']:<3} "
                  f"概率={r['攻击概率']:.3f}  {r['文本'][:64]}")
    else:
        print("  （无）")

    # ---------- 新样本建议 ----------
    novel = df[(df["训练集已有"] == "否")].copy() if train_texts else pd.DataFrame()
    print("\n" + "=" * 78)
    print(f"五、模型没见过的新样本（{len(novel)} 条）")
    print("=" * 78)
    if len(novel):
        for _, r in novel.head(40).iterrows():
            tag = "✓已识别" if r["是否攻击"] else "✗漏报"
            print(f"  {tag} {r['判定类型']:<16} 累加分={r['累加分']:<3} {r['文本'][:60]}")
        if len(novel) > 40:
            print(f"  ... 其余 {len(novel) - 40} 条见输出文件")
    else:
        print("  （无，或未能读取训练集用于比对）")

    # ---------- 输出 ----------
    out = args.out or os.path.splitext(os.path.abspath(args.path))[0] + "_result.csv"
    df.to_csv(out, index=False, encoding="utf-8-sig")
    print(f"\n[已保存结果] {out}")

    return df


if __name__ == "__main__":
    main()
