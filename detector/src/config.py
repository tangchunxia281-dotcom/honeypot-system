# src/config.py
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# ============================================================
# 核心目录定义（按照你的新目录结构）
# ============================================================
DATA_DIR = BASE_DIR / "data"
RAW_DIR = DATA_DIR / "raw"
PROCESSED_DIR = DATA_DIR / "processed"
AUGMENTED_DIR = DATA_DIR / "augmented"
MODEL_DIR = BASE_DIR / "models"

# ============================================================
# 数据路径（修复文件名错误）
# ============================================================
# 原始数据源（只读，永不修改）：指向 raw 文件夹里的备份文件
RAW_DATA_PATH = RAW_DIR / "train_raw_backup_v3.csv"

# 划分后的原始训练集和独立测试集（在 processed 文件夹）
TRAIN_DATA_PATH = PROCESSED_DIR / "train_raw.csv"
TEST_DATA_PATH = PROCESSED_DIR / "test_raw.csv"

# 增强训练集（在 augmented 文件夹）
AUGMENTED_DATA_PATH = AUGMENTED_DIR / "augmented.csv"

# 待预测数据（在 processed 文件夹）
PREDICT_DATA_PATH = PROCESSED_DIR / "predict_raw.csv"
PREDICT_OUTPUT_PATH = PROCESSED_DIR / "predict_result.csv"

# 蜜罐事件日志（保持在 data 根目录）
HONEYPOT_LOG_PATH = DATA_DIR / "honeypot_events.jsonl"

# 模型元数据（记录训练时间、版本）
MODEL_META_PATH = MODEL_DIR / "model_meta.json"

# ============================================================
# 模型路径
# ============================================================
MODEL_PATH = MODEL_DIR / "attack_model.pkl"

# ============================================================
# 标签定义
# ============================================================
# sensitive_path：敏感文件/目录探测（如 /wp-config.php、/.env、/phpmyadmin）
#                 与"目录穿越"（../）语义不同，故单独成类。
# 注意：scanner（扫描器指纹）是纯规则类别，模型未训练该类，
#       故不列入 CURRENT_LABELS，仅在 rules.py 中由规则识别。
CURRENT_LABELS = ["xss", "sqli", "path_traversal", "sensitive_path", "normal"]
ALL_LABELS = ["xss", "normal", "sqli", "csrf", "path_traversal",
              "sensitive_path", "scanner", "ssrf", "xxe"]

# ============================================================
# AI 作为蜜罐"一维加权特征"的映射配置
# ============================================================
# 蜜罐的权重表量纲：探测类 +15~22，利用类 +18~28。
# AI 分数映射上限取 25（与"SQL 注入语义 +25"同档），
# 避免 AI 单独把请求推过 40 分高危线。
AI_POINTS_MAX = 25

# 蜜罐双阈值（与论文 5.3 节一致）
SUSPICIOUS_THRESHOLD = 20   # >=20 记为可疑事件
HIGH_RISK_THRESHOLD = 40    # >=40 触发高危告警


# ============================================================
# 训练超参数
# ============================================================
TEST_SIZE = 0.2
RANDOM_STATE = 42

# ============================================================
# 确保目录存在（自动创建不存在的文件夹）
# ============================================================
DATA_DIR.mkdir(parents=True, exist_ok=True)
RAW_DIR.mkdir(parents=True, exist_ok=True)
PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
AUGMENTED_DIR.mkdir(parents=True, exist_ok=True)
MODEL_DIR.mkdir(parents=True, exist_ok=True)