# src/train.py
"""训练攻击检测模型（带概率校准）。

设计要点（对齐蜜罐"多特征加权 + 双阈值分层"机制）：
  1. 概率必须校准：AI 输出要当作蜜罐的一维加权特征参与累加，
     未校准的概率会让分值系统性偏移，污染可疑/高危分层。
  2. 训练/测试分布要一致：不再靠"只增强攻击类"制造 27% vs 82% 的分布差。
  3. 用独立测试集评估，并同时输出"未校准 vs 校准"的对比。

用法:
    python -m src.train
    python -m src.train --data-dir D:/out --model-out D:/out/models
"""
import argparse
import json
import os
from datetime import datetime
from pathlib import Path

import joblib
import numpy as np
from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, brier_score_loss,
                             classification_report, confusion_matrix, f1_score)
from sklearn.pipeline import Pipeline

from src.config import (
    MODEL_PATH,
    MODEL_META_PATH,
    CURRENT_LABELS,
    TRAIN_DATA_PATH,
    TEST_DATA_PATH,
    AUGMENTED_DATA_PATH,
)
from src.preprocess import normalize_for_model
from src.utils import read_csv_safe


def load_data(path):
    df = read_csv_safe(path)
    if df is None or len(df) == 0:
        raise ValueError(f"数据为空或无法读取: {path}")

    required = {"text", "label"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"数据缺少列: {missing}，当前列: {list(df.columns)}")

    df = df.dropna(subset=["text", "label"]).copy()
    df["label"] = df["label"].astype(str).str.strip().str.lower()
    df = df[df["label"].isin(CURRENT_LABELS)].copy()

    df["text"] = df["text"].astype(str).map(normalize_for_model)
    df = df[df["text"].str.strip() != ""]
    df = df.drop_duplicates(subset=["text"]).copy()
    return df


def build_model(class_weight=None):
    """字符级 TF-IDF + 逻辑回归。

    class_weight='balanced' 让模型自动按频次反比加权，
    取代原先手工硬编码 path_traversal=8 的做法。
    """
    return Pipeline([
        ("tfidf", TfidfVectorizer(
            analyzer="char",
            ngram_range=(1, 4),
            lowercase=False,
            min_df=1,
            sublinear_tf=True,
        )),
        ("clf", LogisticRegression(
            max_iter=3000,
            class_weight=class_weight,
            C=5.0,
        )),
    ])


def eval_model(model, X, y, name, labels):
    """输出准确率/宏F1/混淆矩阵，并返回概率用于校准评估。"""
    y_pred = model.predict(X)
    acc = accuracy_score(y, y_pred)
    macro_f1 = f1_score(y, y_pred, average="macro", zero_division=0)
    print(f"\n===== {name} =====")
    print(f"准确率: {acc:.4f}   宏平均F1: {macro_f1:.4f}")
    print(classification_report(y, y_pred, zero_division=0, digits=4))
    cm = confusion_matrix(y, y_pred, labels=labels)
    print("混淆矩阵 (行=真实, 列=预测)")
    print(f"{'':<16}" + "".join(f"{l:>16}" for l in labels))
    for i, l in enumerate(labels):
        print(f"{l:<16}" + "".join(f"{v:>16}" for v in cm[i]))
    return acc, macro_f1, y_pred


def calibration_report(model, X, y, labels):
    """报出校准质量：Brier 分数 + 各置信度区间的实际准确率。

    对蜜罐加权特征而言，最重要的是"预测 0.8 时是否真有 80% 把握"。
    """
    try:
        proba = model.predict_proba(X)
    except Exception as e:
        print(f"[跳过校准评估] {e}")
        return None

    classes = [str(c) for c in model.classes_]
    max_p = proba.max(axis=1)
    pred = [classes[i] for i in proba.argmax(axis=1)]
    correct = np.array([p == t for p, t in zip(pred, y)])

    # 多分类 Brier（one-hot 平均）
    briers = []
    for j, c in enumerate(classes):
        yt = np.array([1 if t == c else 0 for t in y])
        try:
            briers.append(brier_score_loss(yt, proba[:, j]))
        except Exception:
            pass
    print(f"\n----- 校准质量 (Brier, 越小越好) -----")
    print(f"平均 Brier: {np.mean(briers):.4f}  (各类: " +
          ", ".join(f"{c}={b:.4f}" for c, b in zip(classes, briers)) + ")")

    print("\n置信度分桶  ->  样本数 / 实际正确率  (越接近对角线越校准)")
    bins = [(0.0, 0.4), (0.4, 0.6), (0.6, 0.8), (0.8, 0.9), (0.9, 0.95), (0.95, 1.01)]
    rows = []
    for lo, hi in bins:
        m = (max_p >= lo) & (max_p < hi)
        n = int(m.sum())
        if n == 0:
            continue
        real = float(correct[m].mean())
        rows.append((lo, hi, n, real, float(max_p[m].mean())))
        print(f"  [{lo:.2f}, {hi:.2f})   {n:>6}   {real:>8.2%}   (平均置信 {max_p[m].mean():.3f})")
    return {"brier_mean": float(np.mean(briers)), "bins": rows}


def main():
    parser = argparse.ArgumentParser(description="训练攻击检测模型（含概率校准）")
    parser.add_argument("--data-dir", default=None,
                        help="数据根目录（含 processed/ 与 augmented/）")
    parser.add_argument("--model-out", default=None,
                        help="模型输出目录")
    parser.add_argument("--raw", action="store_true",
                        help="强制用未增强的 train_raw.csv 训练")
    parser.add_argument("--no-calibrate", action="store_true",
                        help="跳过概率校准（用于对比）")
    args = parser.parse_args()

    if args.data_dir:
        base = Path(args.data_dir)
        train_path = base / "processed" / "train_raw.csv"
        test_path = base / "processed" / "test_raw.csv"
        aug_path = base / "augmented" / "augmented.csv"
    else:
        train_path, test_path, aug_path = TRAIN_DATA_PATH, TEST_DATA_PATH, AUGMENTED_DATA_PATH

    model_out = Path(args.model_out) if args.model_out else Path(MODEL_PATH).parent
    model_out.mkdir(parents=True, exist_ok=True)
    model_file = model_out / "attack_model.pkl"
    meta_file = model_out / "model_meta.json"

    # ---- 选训练数据 ----
    if args.raw:
        use_path = train_path
        print(f"训练数据: 原始训练集 {use_path}")
    elif Path(aug_path).exists() and Path(aug_path).stat().st_size > 0:
        use_path = aug_path
        print(f"训练数据: 增强训练集 {use_path}")
    else:
        use_path = train_path
        print(f"训练数据: 未找到增强数据，使用原始训练集 {use_path}")

    train_df = load_data(use_path)
    print(f"训练样本数: {len(train_df)}")
    print(f"训练集标签分布:\n{train_df['label'].value_counts().to_string()}")

    test_df = load_data(test_path)
    print(f"\n独立测试集: {test_path}")
    print(f"测试样本数: {len(test_df)}")
    print(f"测试集标签分布:\n{test_df['label'].value_counts().to_string()}")

    X_train, y_train = train_df["text"].tolist(), train_df["label"].tolist()
    X_test, y_test = test_df["text"].tolist(), test_df["label"].tolist()
    labels = [l for l in CURRENT_LABELS if l in set(y_test) | set(y_train)]

    # ---- 训练基线（未校准）----
    print("\n训练基线模型（未校准，class_weight=balanced）...")
    base_model = build_model(class_weight="balanced")
    base_model.fit(X_train, y_train)
    eval_model(base_model, X_test, y_test, "基线模型（未校准）", labels)

    final_model = base_model
    calib_info = None

    # ---- 概率校准 ----
    if not args.no_calibrate:
        print("\n进行概率校准 (CalibratedClassifierCV, sigmoid, cv=5)...")
        calib = CalibratedClassifierCV(
            build_model(class_weight="balanced"),
            method="sigmoid",
            cv=5,
        )
        calib.fit(X_train, y_train)
        acc_c, f1_c, _ = eval_model(calib, X_test, y_test, "校准后模型", labels)

        print("\n[校准后] 概率质量:")
        calib_info = calibration_report(calib, X_test, y_test, labels)
        print("\n[基线] 概率质量对比:")
        base_info = calibration_report(base_model, X_test, y_test, labels)

        y_pred_base = base_model.predict(X_test)
        f1_b = f1_score(y_test, y_pred_base, average="macro", zero_division=0)
        acc_b = accuracy_score(y_test, y_pred_base)

        brier_c = (calib_info or {}).get("brier_mean")
        brier_b = (base_info or {}).get("brier_mean")

        print(f"\n{'-'*66}")
        print("模型选择对比")
        print(f"{'-'*66}")
        print(f"  基线   : 准确率 {acc_b:.4f}  宏F1 {f1_b:.4f}  Brier {brier_b}")
        print(f"  校准后 : 准确率 {acc_c:.4f}  宏F1 {f1_c:.4f}  Brier {brier_c}")

        # 选择规则（AI 要当加权特征，概率质量与分类质量都要看）：
        #   1. 校准后宏F1 明显更差(>0.5%) -> 用基线；
        #   2. 校准后宏F1 相当或更好，且 Brier 更小 -> 用校准后；
        #   3. 否则用基线。
        if f1_c < f1_b - 0.005:
            final_model = base_model
            print(f"\n采用: 基线模型（校准后宏F1 明显更低）")
        elif brier_c is not None and brier_b is not None and brier_c < brier_b:
            final_model = calib
            print(f"\n采用: 校准后模型（F1 相当，Brier 更优: "
                  f"{brier_c:.4f} < {brier_b:.4f}）")
        else:
            final_model = base_model
            print(f"\n采用: 基线模型（概率质量未见改善，保留更简单的模型）")
        print(f"{'-'*66}")

    # ---- 保存 ----
    joblib.dump(final_model, model_file)
    print(f"\n模型已保存: {model_file}")

    meta = {
        "version": "v2",
        "trained_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "labels": CURRENT_LABELS,
        "train_samples": len(train_df),
        "test_samples": len(test_df),
        "train_data": str(use_path),
        "calibrated": bool(calib_info is not None and final_model is not base_model),
        "calibration": calib_info,
        "test_accuracy": float(accuracy_score(y_test, final_model.predict(X_test))),
        "test_macro_f1": float(f1_score(y_test, final_model.predict(X_test),
                                        average="macro", zero_division=0)),
    }
    with open(meta_file, "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)
    print(f"元数据已保存: {meta_file}")
    print(f"\n测试集准确率: {meta['test_accuracy']:.4f}   宏平均F1: {meta['test_macro_f1']:.4f}")
    print("完成。")


if __name__ == "__main__":
    main()
