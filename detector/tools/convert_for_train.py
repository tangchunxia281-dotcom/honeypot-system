# tools/convert_for_train.py
"""
把三个数据集转换成 train_raw.csv 的格式 (text,label,source)
输出 data/new_samples.csv，内容可以直接复制粘贴到 train_raw.csv 末尾
"""
import pandas as pd
import os

DATA_DIR = "data"
OUTPUT = os.path.join(DATA_DIR, "new_samples.csv")

all_rows = []

# ============================================================
# 1. sqldata.csv（无表头，单列 payload，全部是 sqli）
# ============================================================
try:
    df1 = pd.read_csv(
        os.path.join(DATA_DIR, "sqldata.csv"),
        header=None, names=["text"], encoding="utf-8-sig"
    )
    df1["text"] = df1["text"].astype(str).str.strip()
    df1 = df1[df1["text"] != ""]
    df1["label"] = "sqli"
    df1["source"] = "sqldata.csv"
    print(f"[sqldata.csv] {len(df1)} 条")
    all_rows.append(df1[["text", "label", "source"]])
except Exception as e:
    print(f"sqldata.csv 失败: {e}")

# ============================================================
# 2. sqli.csv（有表头 Sentence,Label，UTF-16 编码）
# ============================================================
try:
    df2 = pd.read_csv(
        os.path.join(DATA_DIR, "sqli.csv"), encoding="utf-16"
    )
    df2 = df2.rename(columns={"Sentence": "text", "Label": "label"})
    df2["text"] = df2["text"].astype(str).str.strip()
    df2 = df2[df2["text"] != ""]
    df2["label"] = df2["label"].apply(
        lambda x: "sqli" if str(x).strip() in ("1", "1.0") else "normal"
    )
    df2["source"] = "sqli.csv"
    print(f"[sqli.csv] {len(df2)} 条")
    print(df2["label"].value_counts())
    all_rows.append(df2[["text", "label", "source"]])
except Exception as e:
    print(f"sqli.csv 失败: {e}")

# ============================================================
# 3. 敏感文件、敏感路径.csv（无表头，三列：path/label/type）
# ============================================================
try:
    df3 = pd.read_csv(
        os.path.join(DATA_DIR, "敏感文件、敏感路径.csv"),
        header=None, names=["text", "label", "type"], encoding="utf-8-sig"
    )
    df3["text"] = df3["text"].astype(str).str.strip()
    df3 = df3[df3["text"] != ""]
    df3["label"] = df3["label"].apply(
        lambda x: "path_traversal" if str(x).strip() in ("1", "1.0") else "normal"
    )
    df3["source"] = "敏感文件路径.csv"
    print(f"[敏感文件路径] {len(df3)} 条")
    print(df3["label"].value_counts())
    all_rows.append(df3[["text", "label", "source"]])
except Exception as e:
    print(f"敏感文件路径失败: {e}")

# ============================================================
# 合并 + 去重
# ============================================================
df_all = pd.concat(all_rows, ignore_index=True)
df_all = df_all.drop_duplicates(subset=["text"]).reset_index(drop=True)

df_all.to_csv(OUTPUT, index=False, encoding="utf-8-sig")

print(f"\n=== 转换完成 ===")
print(f"总样本数: {len(df_all)}")
print(f"标签分布:\n{df_all['label'].value_counts()}")
print(f"\n已保存到: {OUTPUT}")
print(f"\n接下来：打开 {OUTPUT}，把表头以下的内容全部复制")
print(f"粘贴到 data/train_raw.csv 的最后一行下面")