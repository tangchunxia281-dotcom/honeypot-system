# tools/clean_data.py
"""数据清洗：修复标签噪声，重建干净的数据集。

针对 data_audit_report.md 中发现的问题：
  1. sqli 类混入 91 条碎片噪声（base64 分片、被拆开的 SQL 函数名、单字符）
  2. path_traversal 标签把"目录穿越"和"敏感文件访问"混在一起
     - 真·目录穿越只有 20 条
     - 97 条其实是敏感文件/路径探测
  3. normal 类里漏标了 37 条含 ../ 的穿越载荷
  4. 混入 1 行重复表头脏行（source=source, label=label）
  5. normal 被灌入 2999 条"英文新闻残句"（来自 sqli.csv，实为负样本语料）

用法:
    python -m tools.clean_data                 # 试运行，只打印统计不写文件
    python -m tools.clean_data --write         # 真正写出清洗后的数据
输出:
    data/raw/train_clean.csv          清洗后的原始数据集
    data/raw/dropped_samples.csv      被丢弃的样本（含丢弃原因，可复核）
"""
import argparse
import os
import re
import sys

import pandas as pd

LABELS_ALL = ["xss", "sqli", "path_traversal", "sensitive_path", "normal"]

# ============================================================
# 标签分类：目录穿越 vs 敏感文件/路径访问
# ============================================================
TRAVERSAL_RE = re.compile(
    r"(\.\./|\.\.\\|%2e%2e|\.\.%2f|\.\.%5c|%252e|\.\.;|\.\.//|\.\./\.\./)",
    re.I,
)

# 明显的"碎片"噪声：base64 分片、单字符、被拆开的 SQL 关键字/函数名
SQL_FUNC_NAMES = {
    "left", "right", "count", "length", "ord", "ascii", "char", "concat",
    "substring", "substr", "mid", "version", "user", "database", "extractvalue",
    "updatexml", "sleep", "benchmark", "having", "group", "order", "union",
    "select", "from", "where", "and", "or", "not", "null", "cast", "convert",
}
B64_FRAGMENT_RE = re.compile(r"^[A-Za-z0-9+/=]{1,12}$")
SHORT_JUNK_RE = re.compile(r"^[^A-Za-z0-9]{0,6}$")   # 纯符号/极短
DIGIT_JUNK_RE = re.compile(r"^[0-9\.\-_ %]{1,20}$")

# 具备真实注入语义的片段（含这些才算有效载荷，否则视为转换残留）
PAYLOAD_SEMANTICS_RE = re.compile(
    r"(--|#|/\*|=|>|<|\bselect\b|\bunion\b|\bor\b|\band\b|\bfrom\b|\bwhere\b"
    r"|\bsleep\b|\bexec\b|\bnull\b|\bcast\b|\.\./|%)",
    re.I,
)


def is_residual_noise(text: str) -> str:
    """识别 2~4 字符的转换残留（如 '{s'、',s'、'.s'、'?s'）。

    这类片段没有注入语义，是数据转换过程中被错误切分的产物，
    模型无法从中学习有效模式，且会干扰特征权重。
    判定条件：长度 ≤4 且不含任何注入语义符号。
    """
    t = str(text or "").strip()
    if 2 <= len(t) <= 4 and not PAYLOAD_SEMANTICS_RE.search(t):
        return f"超短无语义片段: {t}"
    return ""


def is_fragment_noise(text: str) -> str:
    """判断是否为数据转换产生的碎片噪声。返回原因字符串，正常则返回 ''。"""
    t = str(text or "").strip()
    if not t:
        return "空文本"
    if len(t) == 1:
        return "单字符"
    if t.lower() in SQL_FUNC_NAMES:
        return f"SQL关键字/函数名碎片: {t}"
    if SHORT_JUNK_RE.match(t) and len(t) <= 6:
        return f"纯符号短串: {t}"
    if B64_FRAGMENT_RE.match(t) and len(t) <= 4 and not t.isdigit():
        return f"疑似base64分片: {t}"
    if DIGIT_JUNK_RE.match(t):
        return f"纯数字/符号串: {t}"
    r = is_residual_noise(t)
    if r:
        return r
    return ""


def load_extra(path, out):
    """读取用户手工新增的样本文件。

    这是"以后加样本"的正式入口：每次清洗都会从基准备份 + extra 重新生成，
    因此不会重复累加，也不会污染历史数据。
    """
    if not path or not os.path.exists(path):
        out.append(f"[0] 未发现增量样本文件，本次只用基准备份。")
        out.append(f"    以后要加样本，请创建该文件并写入 text,label,source 三列：")
        out.append(f"      {path}")
        return None

    # 容错读取：载荷里常含逗号，若未用引号包裹会导致列数错乱。
    # 这里遇到坏行则跳过并提示，避免整个流程中断。
    try:
        df = pd.read_csv(path, encoding="utf-8-sig")
    except pd.errors.ParserError as e:
        out.append(f"[0] ⚠ 增量样本文件存在格式错误的行（{e}）")
        out.append(f"    常见原因: 载荷中含逗号但没用双引号包裹。")
        out.append(f"    已跳过坏行继续读取；建议修正后重跑。")
        df = pd.read_csv(path, encoding="utf-8-sig", on_bad_lines="skip")

    if "text" not in df.columns or "label" not in df.columns:
        raise ValueError(
            f"增量样本文件必须包含 text 和 label 两列，当前列: {list(df.columns)}\n"
            f"文件: {path}"
        )

    df = df.dropna(subset=["text", "label"]).copy()
    df["text"] = df["text"].astype(str).str.strip()
    df["label"] = df["label"].astype(str).str.strip().str.lower()
    if "source" not in df.columns:
        df["source"] = "extra"
    df["source"] = df["source"].fillna("extra").astype(str)

    # 剔除空文本
    before = len(df)
    df = df[df["text"] != ""].copy()
    if before != len(df):
        out.append(f"[0] 增量样本中剔除空文本 {before - len(df)} 条")

    # 标签合法性校验（防止拼写错误导致样本被静默丢弃）
    valid = set(LABELS_ALL)
    bad = df[~df["label"].isin(valid)]
    if len(bad):
        out.append(f"[0] ⚠ 增量样本中有 {len(bad)} 条标签不合法，将被忽略。"
                   f"合法标签: {sorted(valid)}")
        for lab in sorted(bad["label"].unique()):
            n = int((bad["label"] == lab).sum())
            out.append(f"      非法标签 {lab!r}: {n} 条")
        df = df[df["label"].isin(valid)].copy()

    out.append(f"[0] 读取增量样本: {path}")
    out.append(f"    有效新增 {len(df)} 条，标签分布: "
               + ", ".join(f"{k}={v}" for k, v in df["label"].value_counts().items()))
    return df


def snapshot_previous(out_path, keep=5, out=None):
    """重建前把上一版清洗结果另存为带时间戳的快照。

    这是对"每次训练前手工备份"的自动化替代：
      - 基准文件 train_raw_backup_v3.csv 本身只读，永远不会缩水；
      - 这里额外保留每次生成的版本，方便对比与回退；
      - 内容与上一版完全相同时跳过，避免生成重复快照。
    """
    import hashlib
    import shutil
    from datetime import datetime

    if not os.path.exists(out_path):
        return None

    def digest(p):
        h = hashlib.md5()
        with open(p, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()

    snap_dir = os.path.join(os.path.dirname(out_path), "backup")
    os.makedirs(snap_dir, exist_ok=True)

    # 找出最近一次快照，内容相同则跳过
    existing = sorted(
        (f for f in os.listdir(snap_dir) if f.startswith("train_clean_")),
        reverse=True,
    )
    cur = digest(out_path)
    if existing:
        last = os.path.join(snap_dir, existing[0])
        if digest(last) == cur:
            if out is not None:
                out.append(f"[快照] 与上一版内容一致，跳过备份")
            return last

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    dest = os.path.join(snap_dir, f"train_clean_{ts}.csv")
    shutil.copy2(out_path, dest)
    if out is not None:
        out.append(f"[快照] 上一版已备份: data/raw/backup/{os.path.basename(dest)}")

    # 只保留最近 keep 份
    snaps = sorted(
        (f for f in os.listdir(snap_dir) if f.startswith("train_clean_")),
        reverse=True,
    )
    for old in snaps[keep:]:
        try:
            os.remove(os.path.join(snap_dir, old))
            if out is not None:
                out.append(f"[快照] 清理旧快照: {old}")
        except OSError:
            pass
    return dest


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true", help="真正写出清洗结果")
    parser.add_argument("--base", default=None,
                        help="基准原始数据；默认 data/raw/train_raw_backup_v3.csv")
    parser.add_argument("--extra", default=None, action="append",
                        help="新增样本文件，可重复指定；"
                             "默认 data/raw/extra_samples.csv（不存在则忽略）")
    args = parser.parse_args()

    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    src = args.base or os.path.join(base, "data", "raw", "train_raw_backup_v3.csv")
    default_extras = [
        os.path.join(base, "data", "raw", "extra_samples.csv"),
        os.path.join(base, "data", "raw", "extra_benign_paths.csv"),
        os.path.join(base, "data", "raw", "extra_benign_html.csv"),
        os.path.join(base, "data", "raw", "extra_benign_numeric.csv"),
    ]
    extra_paths = args.extra if args.extra else default_extras

    df = pd.read_csv(src, encoding="utf-8-sig")
    total0 = len(df)
    print(f"读取基准原始数据: {src}")
    print(f"基准行数: {total0}")

    # ---------- 0. 合并用户新增样本 ----------
    _out = []
    extras = []
    for ep in extra_paths:
        e = load_extra(ep, _out)
        if e is not None and len(e):
            extras.append(e)
    for line in _out:
        print(line)
    if extras:
        df = pd.concat([df] + [e[["text", "label", "source"]] for e in extras],
                       ignore_index=True)
        print(f"合并后行数: {len(df)}")

    print(f"原始标签分布:\n{df['label'].value_counts().to_string()}\n")

    df["text"] = df["text"].fillna("").astype(str)
    df["label"] = df["label"].fillna("").astype(str).str.strip().str.lower()
    orig_label = df["label"].copy()

    dropped = []

    # ---------- 1. 删除重复表头脏行 ----------
    mask_header = (df["text"].str.strip().str.lower() == "text") & \
                  (df["label"] == "label")
    for i in df[mask_header].index:
        dropped.append({"text": df.at[i, "text"], "label": orig_label[i],
                        "source": df.at[i, "source"] if "source" in df else "",
                        "reason": "重复表头脏行"})
    df = df[~mask_header].copy()
    print(f"[1] 删除重复表头脏行: {int(mask_header.sum())} 条")

    # ---------- 2. 修正 normal 里漏标的目录穿越 ----------
    mask_mislabel = (df["label"] == "normal") & \
                    df["text"].str.contains(TRAVERSAL_RE, regex=True)
    n_mis = int(mask_mislabel.sum())
    for i in df[mask_mislabel].index:
        dropped.append({"text": df.at[i, "text"], "label": "normal",
                        "source": df.at[i, "source"] if "source" in df else "",
                        "reason": "normal中漏标的目录穿越载荷(已剔除,建议补入穿越类)"})
    df = df[~mask_mislabel].copy()
    print(f"[2] 剔除 normal 中漏标的目录穿越载荷: {n_mis} 条"
          f"（建议人工确认后补入 path_traversal）")

    # ---------- 3. 删除攻击类碎片噪声 ----------
    reasons = {}
    keep = []
    for i in df.index:
        lab = df.at[i, "label"]
        if lab in ("sqli", "xss", "path_traversal"):
            r = is_fragment_noise(df.at[i, "text"])
            if r:
                reasons[r.split(":")[0]] = reasons.get(r.split(":")[0], 0) + 1
                dropped.append({"text": df.at[i, "text"], "label": lab,
                                "source": df.at[i, "source"] if "source" in df else "",
                                "reason": f"碎片噪声-{r}"})
                continue
        keep.append(i)
    n_frag = len(df) - len(keep)
    df = df.loc[keep].copy()
    print(f"[3] 删除攻击类碎片噪声: {n_frag} 条")
    for k, v in sorted(reasons.items(), key=lambda x: -x[1]):
        print(f"      - {k}: {v}")

    # ---------- 4. 拆分 path_traversal / 敏感路径 ----------
    is_pt = df["label"] == "path_traversal"
    mask_trav = is_pt & df["text"].str.contains(TRAVERSAL_RE, regex=True)
    n_trav = int(mask_trav.sum())
    n_sens = int((is_pt & ~mask_trav).sum())
    df.loc[is_pt & ~mask_trav, "label"] = "sensitive_path"
    print(f"[4] 拆分 path_traversal: 真·目录穿越 {n_trav} 条 / "
          f"敏感文件路径 {n_sens} 条 -> 新标签 sensitive_path")

    # ---------- 5. 去重 ----------
    before = len(df)
    df = df.drop_duplicates(subset=["text"]).reset_index(drop=True)
    print(f"[5] 去重: {before - len(df)} 条")

    # ---------- 6. 剔除仍含攻击特征的 normal（保守：只报不删） ----------
    nm = df[df["label"] == "normal"]
    still = nm[nm["text"].str.contains(TRAVERSAL_RE, regex=True)]
    print(f"[6] normal 中仍含 ../ 的样本: {len(still)} 条（已在上一步处理）")

    # ---------- 输出统计 ----------
    print(f"\n清洗后行数: {len(df)}  (原 {total0}, 减少 {total0 - len(df)})")
    print("清洗后标签分布:")
    vc = df["label"].value_counts()
    tot = len(df)
    for k, v in vc.items():
        print(f"    {k:<16} {v:>6}  ({v/tot:.1%})")
    print(f"\n丢弃样本合计: {len(dropped)} 条")
    ddf = pd.DataFrame(dropped)
    if len(ddf):
        print("丢弃原因分布:")
        print(ddf["reason"].str.split("-").str[0].value_counts().to_string())

    if args.write:
        out = os.path.join(base, "data", "raw", "train_clean.csv")

        # 写出前先为上一版留快照（替代"每次训练前手工备份"）
        snap_lines = []
        snapshot_previous(out, out=snap_lines)
        for line in snap_lines:
            print(line)

        # 源数据集安全校验：确认基准文件行数没有异常缩水
        if len(df) < total0 * 0.5:
            print(f"\n[警告] 清洗后行数({len(df)})不足基准({total0})的 50%，"
                  f"请检查 extra_samples.csv 与清洗规则是否异常！")

        df.to_csv(out, index=False, encoding="utf-8-sig")
        print(f"\n[已写出] {out}")
        dpath = os.path.join(base, "data", "raw", "dropped_samples.csv")
        ddf.to_csv(dpath, index=False, encoding="utf-8-sig")
        print(f"[已写出] {dpath}")
        print(f"[提示] 基准文件 train_raw_backup_v3.csv 始终保持 {total0} 行不变，"
              f"不会被训练覆盖。")
    else:
        print("\n(试运行模式，未写文件。加 --write 才会写出)")


if __name__ == "__main__":
    main()
