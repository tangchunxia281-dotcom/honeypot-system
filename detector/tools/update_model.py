# tools/update_model.py
"""一条命令完成"加样本 -> 清洗 -> 切分 -> 重训 -> 评估"。

以后要添加新样本，流程是：
    1. 打开 data/raw/extra_samples.csv，把新样本追加到文件末尾
    2. 运行  python -m tools.update_model
    3. 完成（模型已更新，指标已打印）

设计要点：
    - 每次运行都从 data/raw/train_raw_backup_v3.csv（基准）+
      data/raw/extra_samples.csv（你的新增样本）**重新生成**，
      因此不会重复累加、不会污染历史数据、随时可回退。
    - 训练/测试自动按 stratified 切分，你不需要手工维护。
    - 重新切分会引入随机性，故用固定 random_state=42 保证可复现。

用法:
    python -m tools.update_model                 # 完整流程
    python -m tools.update_model --skip-train    # 只更新数据，不训练
    python -m tools.update_model --push          # 训练完把产物写回项目目录
"""
import argparse
import os
import shutil
import subprocess
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def run(desc, args):
    print("\n" + "=" * 70)
    print(f"  {desc}")
    print("=" * 70)
    r = subprocess.run([sys.executable, "-W", "ignore", "-m"] + args, cwd=BASE)
    if r.returncode != 0:
        print(f"\n[失败] 步骤出错: {desc}")
        sys.exit(r.returncode)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-train", action="store_true", help="只更新数据，不重训")
    ap.add_argument("--skip-cv", action="store_true", help="跳过交叉验证")
    ap.add_argument("--push", action="store_true",
                    help="训练完把模型与数据集写回项目目录（默认就地写入）")
    ap.add_argument("--extra", default=None, help="指定新增样本文件")
    args = ap.parse_args()

    extra = args.extra or os.path.join(BASE, "data", "raw", "extra_samples.csv")
    if os.path.exists(extra):
        import pandas as pd
        n = len(pd.read_csv(extra, encoding="utf-8-sig"))
        print(f"新增样本文件: {extra}  ({n} 条)")
    else:
        print(f"[提示] 未找到新增样本文件: {extra}")
        print("      本次只用基准备份重训。要加样本请创建该文件，")
        print("      格式为 text,label,source 三列（可参考 README）。")

    # 1) 清洗：基准 + 新增样本 -> train_clean.csv
    run("步骤 1/4  清洗数据（基准 + 新增样本）",
        ["tools.clean_data", "--write"])

    # 2) 切分 + 增强
    clean = os.path.join(BASE, "data", "raw", "train_clean.csv")
    run("步骤 2/4  切分训练/测试集并增强",
        ["src.build_dataset", "--input", clean])

    if args.skip_train:
        print("\n已跳过训练（--skip-train）。数据已更新。")
        return

    # 3) 训练
    run("步骤 3/4  训练模型（含概率校准与独立评估）", ["src.train"])

    # 4) 交叉验证
    if not args.skip_cv:
        run("步骤 4/4  交叉验证（规则 / 模型 / 加权融合 对比）",
            ["tools.cv_eval", "--data", clean, "--folds", "5"])

    print("\n" + "=" * 70)
    print("  全部完成")
    print("=" * 70)
    print(f"  清洗后数据 : data/raw/train_clean.csv")
    print(f"  训练集     : data/processed/train_raw.csv")
    print(f"  独立测试集 : data/processed/test_raw.csv")
    print(f"  增强训练集 : data/augmented/augmented.csv")
    print(f"  模型       : models/attack_model.pkl")
    print("""
  提示:
    - 上面打印的"测试集准确率/宏平均F1"即为本次训练结果。
    - 若某类指标异常，先查 data/raw/dropped_samples.csv 是否误删了样本。
    - 想回退: 数据用 data/raw/train_raw_backup_v3.csv 重新生成即可，
      模型用 models/attack_model_v1_backup.pkl 恢复旧版。""")


if __name__ == "__main__":
    main()
