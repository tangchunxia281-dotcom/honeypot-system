# tools/import_payload.py
"""把外部数据集转换为本项目的训练格式。

当前支持 payload_full.csv（列：payload,length,attack_type,label）。

转换规则：
    sqli           -> sqli
    xss            -> xss
    path-traversal -> path_traversal
    norm           -> normal
    cmdi 及其他     -> 丢弃（模型不支持的攻击类型）

用法:
    python -m tools.import_payload --src <csv> --dry-run      # 预检，不写文件
    python -m tools.import_payload --src <csv> --write        # 写入 extra_samples.csv
    python -m tools.import_payload --src <csv> --write --replace  # 覆盖而非追加
"""
import argparse
import os
import sys
from collections import Counter

import pandas as pd

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

from src.rules import match_rules  # noqa: E402
from tools.clean_data import is_fragment_noise  # noqa: E402

# 外部数据集的 attack_type -> 本模型 label
LABEL_MAP = {
    "sqli": "sqli",
    "xss": "xss",
    "path-traversal": "path_traversal",
    "path_traversal": "path_traversal",
    "norm": "normal",
    "normal": "normal",
}
# 明确丢弃（模型不支持的攻击类型）
DROP_TYPES = {"cmdi", "cmd", "ssrf", "xxe", "csrf", "lfi", "rfi"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", required=True, help="外部数据集 CSV")
    ap.add_argument("--write", action="store_true", help="写入文件")
    ap.add_argument("--replace", action="store_true", help="覆盖 extra_samples.csv 而非追加")
    ap.add_argument("--out", default=os.path.join(BASE, "data", "raw", "extra_samples.csv"))
    ap.add_argument("--keep-placeholder", action="store_true",
                    help="保留 path-traversal 样本中的 {file} 占位符（默认替换为 etc/passwd）")
    ap.add_argument("--drop-normal", action="store_true",
                    help="丢弃外部数据集的 normal 样本。"
                         "该数据集的 normal 是表单填写数据（姓名/地址/证件号），"
                         "与蜜罐的 URL 访问流量不同质，保留会拉低 Web 流量上的表现")
    ap.add_argument("--normal-ratio", type=float, default=None,
                    help="保留 normal 抽样比例（如 0.2 表示只留 20%%）。"
                         "与 --drop-normal 二选一，用于降采样")
    args = ap.parse_args()

    df = pd.read_csv(args.src, encoding="utf-8-sig")
    print(f"读取: {args.src}")
    print(f"原始行数: {len(df)}")
    print(f"原始 attack_type 分布:\n{df['attack_type'].value_counts().to_string()}\n")

    # ---- 1. 类型映射与过滤 ----
    df["atk"] = df["attack_type"].astype(str).str.strip().str.lower()
    dropped_type = df[~df["atk"].isin(LABEL_MAP) | df["atk"].isin(DROP_TYPES)]
    df = df[df["atk"].isin(LABEL_MAP) & ~df["atk"].isin(DROP_TYPES)].copy()
    df["label"] = df["atk"].map(LABEL_MAP)
    df["text"] = df["payload"].astype(str).str.strip()

    print(f"[1] 类型过滤: 保留 {len(df)} 条, 丢弃 {len(dropped_type)} 条")
    if len(dropped_type):
        print("    丢弃的类型分布:", dict(dropped_type["atk"].value_counts()))

    # ---- 1b. 处理 normal 样本（表单数据与 Web 流量不同质）----
    if args.drop_normal or args.normal_ratio is not None:
        is_norm = df["label"] == "normal"
        n_norm = int(is_norm.sum())
        if args.drop_normal:
            df = df[~is_norm].copy()
            print(f"[1b] 丢弃 normal 样本: {n_norm} 条（表单数据，与 Web 流量不同质）")
        else:
            keep_n = max(1, int(n_norm * args.normal_ratio))
            norm_part = df[is_norm].sample(n=keep_n, random_state=42)
            df = pd.concat([df[~is_norm], norm_part], ignore_index=True)
            print(f"[1b] normal 降采样: {n_norm} -> {keep_n} 条")

    # ---- 2. 占位符处理 ----
    if not args.keep_placeholder:
        n_ph = int(df["text"].str.contains(r"\{file\}", regex=True).sum())
        df["text"] = df["text"].str.replace(r"\{file\}", "etc/passwd", regex=True)
        if n_ph:
            print(f"[2] 替换 {{file}} 占位符: {n_ph} 条 -> etc/passwd")

    # ---- 3. 去空 / 去重 ----
    df = df[df["text"] != ""].copy()
    before = len(df)
    df = df.drop_duplicates(subset=["text"]).copy()
    print(f"[3] 去重: {before - len(df)} 条")

    # ---- 4. 剔除碎片噪声（复用清洗规则） ----
    reasons = Counter()
    keep = []
    for i, row in df.iterrows():
        r = is_fragment_noise(row["text"])
        if r and row["label"] != "normal":
            reasons[r.split(":")[0]] += 1
            continue
        keep.append(i)
    df = df.loc[keep].copy()
    print(f"[4] 剔除碎片噪声: {len(keep) and (before - len(df))} 条")
    for k, v in reasons.most_common():
        print(f"      - {k}: {v}")

    # ---- 5. 与现有数据去重 ----
    # 注意：不能拿 train_clean.csv 比对——它已包含本文件的旧版本，
    # 那样会把本文件的样本全部当成"重复"删掉。只对比基准和其他增量文件。
    exclude_self = os.path.abspath(args.out) if args.out else None
    other_sources = [
        os.path.join(BASE, "data", "raw", "train_raw_backup_v3.csv"),
        os.path.join(BASE, "data", "raw", "extra_benign_paths.csv"),
        os.path.join(BASE, "data", "raw", "extra_benign_html.csv"),
        os.path.join(BASE, "data", "raw", "extra_samples.csv"),
    ]
    old_texts = set()
    for src in other_sources:
        if not src or not os.path.exists(src):
            continue
        if exclude_self and os.path.abspath(src) == exclude_self:
            continue          # 跳过自己
        try:
            o = pd.read_csv(src, encoding="utf-8-sig")
            if "text" in o.columns:
                old_texts |= set(o["text"].astype(str))
        except Exception:
            pass
    if old_texts:
        n_before = len(df)
        df = df[~df["text"].isin(old_texts)].copy()
        print(f"[5] 与现有训练集去重: 移除 {n_before - len(df)} 条重复")

    # ---- 6. 规则命中率（作为质量参考） ----
    df["rule_hit"] = df["text"].map(lambda t: bool(match_rules(t)))
    print("\n[6] 规则命中情况（仅作参考，模型仍会学到规则未覆盖的形态）:")
    for lab in ["sqli", "xss", "path_traversal", "normal"]:
        sub = df[df["label"] == lab]
        if len(sub) == 0:
            continue
        print(f"      {lab:<16} 共 {len(sub):>5} 条, 规则命中 "
              f"{int(sub['rule_hit'].sum()):>5} 条 ({sub['rule_hit'].mean():.1%})")

    # ---- 7. 结果 ----
    out = df[["text", "label"]].copy()
    out["source"] = "payload_full"
    print(f"\n最终导入: {len(out)} 条")
    print("标签分布:")
    for k, v in out["label"].value_counts().items():
        print(f"    {k:<16} {v:>6}")

    if not args.write:
        print("\n(预检模式，未写文件。加 --write 才会写入)")
        print("\n样例（每类 5 条）：")
        for lab in out["label"].unique():
            print(f"  [{lab}]")
            for t in out[out["label"] == lab]["text"].head(5):
                print(f"     {t[:76]}")
        return

    # 追加或覆盖
    if os.path.exists(args.out) and not args.replace:
        old = pd.read_csv(args.out, encoding="utf-8-sig")
        # 兼容空文件（只有表头）
        if len(old):
            out = pd.concat([old, out], ignore_index=True)
            out = out.drop_duplicates(subset=["text"]).reset_index(drop=True)
            print(f"\n追加到既有 extra_samples.csv（原 {len(old)} 条）")
    out.to_csv(args.out, index=False, encoding="utf-8-sig")
    print(f"\n[已写入] {args.out}")
    print(f"合计 {len(out)} 条")
    print(f"标签分布:\n{out['label'].value_counts().to_string()}")


if __name__ == "__main__":
    main()
