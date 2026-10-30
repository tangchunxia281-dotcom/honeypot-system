# tools/convert_datasets.py
import pandas as pd
import os

DATA_DIR = "data"
OUTPUT_PATH = os.path.join(DATA_DIR, "train_extra.csv")

all_dfs = []

# ============================================================
# 1. 处理 sqldata.csv（无表头，只有一列 payload）
# ============================================================
try:
    df_sqldata = pd.read_csv(
        os.path.join(DATA_DIR, "sqldata.csv"),
        header=None,
        names=["text"],
        encoding="utf-8-sig",
    )
    df_sqldata["text"] = df_sqldata["text"].astype(str).str.strip()
    df_sqldata = df_sqldata[df_sqldata["text"] != ""]
    df_sqldata["label"] = "sqli"
    df_sqldata["source"] = "sqldata.csv"
    print(f"[sqldata.csv] 转换完成，样本数: {len(df_sqldata)}")
    all_dfs.append(df_sqldata[["text", "label", "source"]])
except Exception as e:
    print(f"[跳过] sqldata.csv 处理失败: {e}")

# ============================================================
# 2. 处理 sqli.csv（尝试多种编码，有表头 Sentence, Label）
# ============================================================
sqli_path = os.path.join(DATA_DIR, "sqli.csv")
if os.path.exists(sqli_path):
    df_sqli = None
    # 依次尝试 utf-16、gbk、utf-8-sig，先成功的就用
    for enc in ("utf-16", "utf-16-le", "gbk", "utf-8-sig", "utf-8"):
        try:
            df_sqli = pd.read_csv(sqli_path, encoding=enc)
            print(f"[sqli.csv] 使用编码 {enc} 读取成功，列名: {df_sqli.columns.tolist()}")
            break
        except Exception as e:
            continue

    if df_sqli is None:
        print("[跳过] sqli.csv 所有编码都读取失败")
    else:
        # 列名映射（兼容 Sentence/Label 或 text/label）
        if "Sentence" in df_sqli.columns and "Label" in df_sqli.columns:
            df_sqli = df_sqli.rename(columns={"Sentence": "text", "Label": "label"})
        elif "text" not in df_sqli.columns or "label" not in df_sqli.columns:
            print(f"[跳过] sqli.csv 列名不匹配，当前列: {df_sqli.columns.tolist()}")
            df_sqli = None

        if df_sqli is not None:
            df_sqli = df_sqli[["text", "label"]].copy()
            df_sqli["text"] = df_sqli["text"].astype(str).str.strip()
            df_sqli = df_sqli[df_sqli["text"] != ""]
            # 标签映射：1 -> sqli，0 -> normal
            df_sqli["label"] = df_sqli["label"].apply(
                lambda x: "sqli" if str(x).strip() in ("1", "1.0") else "normal"
            )
            df_sqli["source"] = "sqli.csv"
            print(f"[sqli.csv] 转换完成，样本数: {len(df_sqli)}")
            print(f"[sqli.csv] 标签分布:\n{df_sqli['label'].value_counts()}")
            all_dfs.append(df_sqli[["text", "label", "source"]])

# ============================================================
# 3. 处理 敏感文件、敏感路径.csv（无表头：path, label, type）
# ============================================================
path_file = os.path.join(DATA_DIR, "敏感文件、敏感路径.csv")
if os.path.exists(path_file):
    try:
        df_path = pd.read_csv(
            path_file,
            header=None,
            names=["text", "label", "type"],
            encoding="utf-8-sig",
        )
        df_path["text"] = df_path["text"].astype(str).str.strip()
        df_path = df_path[df_path["text"] != ""]
        # 标签映射：1 -> path_traversal，0 -> normal
        df_path["label"] = df_path["label"].apply(
            lambda x: "path_traversal" if str(x).strip() in ("1", "1.0") else "normal"
        )
        df_path["source"] = "敏感文件路径.csv"

        print(f"[敏感文件路径] 转换完成，样本数: {len(df_path)}")
        print(f"[敏感文件路径] 标签分布:\n{df_path['label'].value_counts()}")
        print(f"[敏感文件路径] 类型分布:\n{df_path['type'].value_counts()}")

        all_dfs.append(df_path[["text", "label", "source"]])
    except Exception as e:
        print(f"[跳过] 敏感文件路径 处理失败: {e}")
else:
    print(f"[跳过] 找不到文件: {path_file}")

# ============================================================
# 4. 合并并保存
# ============================================================
if not all_dfs:
    print("没有成功转换任何数据集，请检查 data 目录下的文件。")
else:
    df_all = pd.concat(all_dfs, ignore_index=True)
    df_all = df_all.drop_duplicates(subset=["text"]).reset_index(drop=True)

    df_all.to_csv(OUTPUT_PATH, index=False, encoding="utf-8-sig")
    print(f"\n全部合并完成，总样本数: {len(df_all)}")
    print(f"标签分布:\n{df_all['label'].value_counts()}")
    print(f"来源分布:\n{df_all['source'].value_counts()}")
    print(f"已保存到: {OUTPUT_PATH}")