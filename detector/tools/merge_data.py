# tools/merge_data.py
import pandas as pd
import os

DATA_DIR = "data"
# 关键：永远从备份读基准，不从已被覆盖的 train_raw.csv 读
BASE_PATH = os.path.join(DATA_DIR, "train_raw_backup2.csv")
EXTRA_PATH = os.path.join(DATA_DIR, "train_extra.csv")
OUTPUT_PATH = os.path.join(DATA_DIR, "train_raw.csv")

if not os.path.exists(BASE_PATH):
    raise FileNotFoundError(f"基准文件不存在: {BASE_PATH}")

df_base = pd.read_csv(BASE_PATH, encoding="utf-8-sig")
df_extra = pd.read_csv(EXTRA_PATH, encoding="utf-8-sig")

required = ["text", "label", "source"]
for df in (df_base, df_extra):
    for col in required:
        if col not in df.columns:
            df[col] = "unknown"

df_merged = pd.concat([df_base[required], df_extra[required]], ignore_index=True)
df_merged = df_merged.dropna(subset=["text", "label"]).reset_index(drop=True)
df_merged["text"] = df_merged["text"].astype(str).str.strip()
df_merged["label"] = df_merged["label"].astype(str).str.strip().str.lower()
df_merged = df_merged.drop_duplicates(subset=["text"]).reset_index(drop=True)

print(f"合并后总样本数: {len(df_merged)}")
print(f"标签分布:\n{df_merged['label'].value_counts()}")

df_merged.to_csv(OUTPUT_PATH, index=False, encoding="utf-8-sig")
print(f"已保存到: {OUTPUT_PATH}")