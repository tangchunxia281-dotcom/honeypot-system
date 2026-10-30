# src/build_dataset.py
"""构建数据集：先按原始样本切分训练/测试，再只对训练集做增强。

防泄漏要点：增强必须在切分**之后**、且只对训练集做，
否则增强出的变体会同时出现在训练集和测试集里，指标虚高。

用法:
    python -m src.build_dataset
    python -m src.build_dataset --input data/raw/train_clean.csv --out-dir D:/out
"""
import argparse
import os
from pathlib import Path

import pandas as pd
from sklearn.model_selection import train_test_split

from src.config import (
    RAW_DATA_PATH,
    TRAIN_DATA_PATH,
    TEST_DATA_PATH,
    AUGMENTED_DATA_PATH,
    TEST_SIZE,
    RANDOM_STATE,
    CURRENT_LABELS,
)
from src.augment import build_augmented_dataset
from src.utils import read_csv_safe, write_csv_safe


def main():
    parser = argparse.ArgumentParser(description="构建训练/测试/增强数据集")
    parser.add_argument("--input", default=None,
                        help="原始数据 CSV；默认用 config.RAW_DATA_PATH")
    parser.add_argument("--out-dir", default=None,
                        help="输出根目录；给出后写入 <out-dir>/processed 与 <out-dir>/augmented")
    args = parser.parse_args()

    raw_path = args.input or str(RAW_DATA_PATH)

    if args.out_dir:
        base = Path(args.out_dir)
        train_out = base / "processed" / "train_raw.csv"
        test_out = base / "processed" / "test_raw.csv"
        aug_out = base / "augmented" / "augmented.csv"
        for p in (train_out, test_out, aug_out):
            p.parent.mkdir(parents=True, exist_ok=True)
    else:
        train_out, test_out, aug_out = TRAIN_DATA_PATH, TEST_DATA_PATH, AUGMENTED_DATA_PATH

    print(f"读取原始数据: {raw_path}")
    df = read_csv_safe(raw_path)
    print(f"原始样本数: {len(df)}")

    if "text" not in df.columns or "label" not in df.columns:
        raise ValueError(f"原始数据必须包含 text 和 label 两列，当前列: {list(df.columns)}")

    # 基础清洗
    df = df.dropna(subset=["text", "label"]).copy()
    df["text"] = df["text"].astype(str)
    df["label"] = df["label"].astype(str).str.strip().str.lower()

    # 只保留当前支持的标签（剔除历史遗留标签与脏行）
    before = len(df)
    df = df[df["label"].isin(CURRENT_LABELS)].copy()
    if before != len(df):
        print(f"过滤掉不在 CURRENT_LABELS 内的标签: {before - len(df)} 条")

    # 空文本剔除
    df = df[df["text"].str.strip() != ""].copy()
    df = df.drop_duplicates(subset=["text"]).reset_index(drop=True)
    print(f"清洗后可用样本数: {len(df)}")
    print(f"标签分布:\n{df['label'].value_counts().to_string()}")

    # 【核心】先按原始样本切分，再增强
    print(f"\n按原始样本切分训练集/测试集 (test_size={TEST_SIZE})...")
    train_df, test_df = train_test_split(
        df,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=df["label"],
    )

    print(f"训练集样本数: {len(train_df)}")
    print(f"独立测试集样本数: {len(test_df)}")
    print(f"测试集标签分布:\n{test_df['label'].value_counts().to_string()}")

    write_csv_safe(train_df, train_out)
    write_csv_safe(test_df, test_out)

    # 只对训练集做增强
    print("\n开始对训练集做数据增强...")
    augmented_train = build_augmented_dataset(train_df)
    print(f"增强后训练集样本数: {len(augmented_train)}")
    print(f"增强集标签分布:\n{augmented_train['label'].value_counts().to_string()}")

    write_csv_safe(augmented_train, aug_out)
    print("\n完成。")


if __name__ == "__main__":
    main()
