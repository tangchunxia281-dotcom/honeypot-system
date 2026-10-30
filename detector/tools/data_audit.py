# tools/data_audit.py
"""数据质量体检：找出误标样本、标签冲突、分布缺口，输出可执行的清洗清单。

用法:
    python -m tools.data_audit
输出:
    <输出目录>/data_audit_report.md   （人类可读报告）
    <输出目录>/suspect_samples.csv    （可疑样本清单，供人工复核）
"""
import os
import re
import sys
from collections import Counter, defaultdict

import pandas as pd

LABELS = ["xss", "sqli", "path_traversal", "normal"]
ATTACK_LABELS = [l for l in LABELS if l != "normal"]

# 归一化后应当"看起来像攻击"的弱特征（用于发现明显的误标）
SQLI_HINT = re.compile(
    r"(select|union|insert|update|delete|drop|from|where|having|group\s+by|order\s+by"
    r"|--|#|/\*|;|'|\"|exec|sleep|benchmark|waitfor|information_schema|or\s+1\s*=\s*1"
    r"|load_file|outfile|@@|xp_|concat|chr\(|ascii\(|substring|version\(|user\(|database\()",
    re.I,
)
PATH_HINT = re.compile(
    r"(\.\.|/etc/|/proc/|%2e|%2f|\.\.\\|\\windows\\|web\.config|\.git|\.env|\.svn"
    r"|actuator|php://|php:|/root/|/var/|/www/|boot\.ini|\.htaccess|\.ssh|id_rsa|/bin/)",
    re.I,
)
XSS_HINT = re.compile(
    r"(<|>|script|onerror|onload|onclick|javascript:|alert|eval|svg|iframe|img|document\.|"
    r"prompt|confirm|%3c|&#|\\u00|fromcharcode|expression\()",
    re.I,
)

# 明显是数据转换垃圾的特征
B64_FRAGMENT = re.compile(r"^[A-Za-z0-9+/=]{1,12}$")
DIGIT_FRAGMENT = re.compile(r"^[0-9\.\-_ ]{1,20}$")
SINGLE_TOKEN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,14}$")


def hint_of(label, text):
    if not isinstance(text, str):
        text = "" if text is None else str(text)
    if label == "sqli":
        return bool(SQLI_HINT.search(text))
    if label == "path_traversal":
        return bool(PATH_HINT.search(text))
    if label == "xss":
        return bool(XSS_HINT.search(text))
    return True


def audit(df, name, out, suspect_rows):
    out.append(f"\n## {name}")
    out.append(f"- 总行数: **{len(df)}**")
    if len(df) == 0:
        return

    vc = df["label"].value_counts()
    out.append("- 标签分布: " + ", ".join(f"`{l}`={vc.get(l,0)}" for l in LABELS if l in vc))
    if "normal" in vc and len(df):
        out.append(f"- normal 占比: **{vc.get('normal',0)/len(df):.1%}**")

    # 1. 缺列 / 空值
    nulls = {c: int(df[c].isna().sum()) for c in df.columns if df[c].isna().any()}
    out.append(f"- 空值列: {nulls if nulls else '无'}")

    # 2. 重复文本（同文本多标签 = 标签冲突）
    texts = df["text"].astype(str)
    dup_total = int(texts.duplicated().sum())
    out.append(f"- 完全重复的 text 行数: **{dup_total}**")
    grp = df.groupby(texts)["label"].nunique()
    conflict_texts = grp[grp > 1]
    out.append(f"- **标签冲突（同一文本对应多个标签）: {len(conflict_texts)} 组**")
    for t in list(conflict_texts.index)[:15]:
        labels_here = sorted(df[texts == t]["label"].unique())
        out.append(f"    - 标签={labels_here} 文本={t[:90]!r}")
        suspect_rows.append({"dataset": name, "issue": "label_conflict",
                             "label": "|".join(labels_here), "text": t})

    # 3. 攻击标签但文本毫无攻击特征 -> 疑似误标
    out.append("- 疑似误标统计（攻击标签但文本不含该类任何特征）:")
    for lab in ATTACK_LABELS:
        sub = df[df["label"] == lab]
        if len(sub) == 0:
            continue
        bad = sub[~sub["text"].astype(str).map(lambda t: hint_of(lab, t))]
        pct = len(bad) / len(sub)
        out.append(f"    - `{lab}`: **{len(bad)}/{len(sub)} ({pct:.1%})** 不含特征")
        for t in bad["text"].astype(str).tolist()[:12]:
            suspect_rows.append({"dataset": name, "issue": f"no_{lab}_feature",
                                 "label": lab, "text": t})

    # 4. 极短/碎片样本（攻击类）
    out.append("- 攻击类里的碎片样本（长度<=6 或纯 alnum 短串）:")
    for lab in ATTACK_LABELS:
        sub = df[df["label"] == lab]["text"].astype(str)
        frag = [t for t in sub if len(t.strip()) <= 6 or B64_FRAGMENT.match(t.strip())]
        frag = [t for t in frag if not hint_of(lab, t)]
        if frag:
            out.append(f"    - `{lab}`: {len(frag)} 条，样例 {frag[:12]}")
            for t in frag[:20]:
                suspect_rows.append({"dataset": name, "issue": f"fragment_{lab}",
                                     "label": lab, "text": t})

    # 5. 各来源标签纯度
    if "source" in df.columns:
        out.append("- 各来源的标签纯度（来源里出现非预期标签说明转换有误）:")
        for src, g in df.groupby("source"):
            mix = Counter(g["label"])
            out.append(f"    - `{src}` (n={len(g)}): " +
                       ", ".join(f"{k}={v}" for k, v in mix.most_common(6)))


def main():
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    files = [
        ("原始备份 v3", os.path.join(base, "data", "raw", "train_raw_backup_v3.csv")),
        ("训练集 train_raw", os.path.join(base, "data", "processed", "train_raw.csv")),
        ("独立测试集 test_raw", os.path.join(base, "data", "processed", "test_raw.csv")),
        ("增强集 augmented", os.path.join(base, "data", "augmented", "augmented.csv")),
    ]

    out = ["# 数据质量体检报告", ""]
    out.append("自动生成，用于定位标签噪声、标签冲突与样本分布缺口。")
    suspect_rows = []
    loaded = {}

    for name, path in files:
        if not os.path.exists(path):
            out.append(f"\n## {name}\n- **文件不存在**: {path}")
            continue
        df = pd.read_csv(path, encoding="utf-8-sig")
        df = df.loc[:, [c for c in df.columns if not str(c).startswith("Unnamed")]]
        if "text" in df.columns:
            df["text"] = df["text"].fillna("").astype(str)
        if "label" in df.columns:
            df["label"] = df["label"].fillna("").astype(str).str.strip().str.lower()
        loaded[name] = df
        out.append(f"\n---\n")
        out.append(f"文件: `{os.path.relpath(path, base)}`")
        audit(df, name, out, suspect_rows)

    # 跨文件一致性
    out.append("\n---\n\n## 跨文件一致性检查")
    if len(loaded) >= 3:
        tr = loaded.get("训练集 train_raw")
        te = loaded.get("独立测试集 test_raw")
        au = loaded.get("增强集 augmented")
        if tr is not None and te is not None:
            s_tr, s_te = set(tr["text"].astype(str)), set(te["text"].astype(str))
            overlap = s_tr & s_te
            out.append(f"- 训练集与测试集文本重叠: **{len(overlap)}** 条 "
                       f"（>0 说明测试集被污染，指标虚高）")
            for t in list(overlap)[:10]:
                out.append(f"    - {t[:90]!r}")
        if au is not None and te is not None:
            ov2 = set(au["text"].astype(str)) & set(te["text"].astype(str))
            out.append(f"- 增强集与测试集文本重叠: **{len(ov2)}** 条")
        # 增强集里 normal 是否被放大
        if au is not None:
            out.append(f"- 增强集标签分布: " +
                       ", ".join(f"{k}={v}" for k, v in au["label"].value_counts().items()))

    # 模型元数据 vs 实际数据
    meta_path = os.path.join(base, "models", "model_meta.json")
    if os.path.exists(meta_path):
        import json
        with open(meta_path, encoding="utf-8") as f:
            meta = json.load(f)
        out.append(f"\n## 模型元数据 vs 当前数据")
        out.append(f"- meta 记录: 训练样本 {meta.get('train_samples')}, "
                   f"测试样本 {meta.get('test_samples')}, 训练时间 {meta.get('trained_at')}")
        if "增强集 augmented" in loaded:
            actual = len(loaded["增强集 augmented"])
            flag = "**不一致，模型已过期**" if actual != meta.get("train_samples") else "一致"
            out.append(f"- augmented 实际行数: {actual} -> {flag}")

    # 输出
    out_dir = sys.argv[1] if len(sys.argv) > 1 else base
    rep = os.path.join(out_dir, "data_audit_report.md")
    with open(rep, "w", encoding="utf-8") as f:
        f.write("\n".join(out))
    sus = pd.DataFrame(suspect_rows).drop_duplicates(subset=["dataset", "issue", "text"])
    sus_path = os.path.join(out_dir, "suspect_samples.csv")
    sus.to_csv(sus_path, index=False, encoding="utf-8-sig")

    print("\n".join(out))
    print(f"\n[报告] {rep}")
    print(f"[可疑样本清单] {sus_path}  共 {len(sus)} 条")


if __name__ == "__main__":
    main()
