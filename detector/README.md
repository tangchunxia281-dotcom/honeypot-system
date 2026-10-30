# XSS Detector —— Web 攻击检测 AI 辅助分析层

一个可扩展的 Web 攻击检测小模型，用于为蜜罐系统"多特征加权 + 双阈值分层"
风险判定机制提供**一维 AI 加权特征**与**攻击类型细分**。

## 能力概览

- 输入任意字符串（URL 参数、请求体、路径、payload）
- 输出五分类：`xss` / `sqli` / `path_traversal` / `sensitive_path` / `normal`
- 规则引擎 + 字符级 TF-IDF + 逻辑回归（含概率校准对比）
- 输出对齐蜜罐量纲的 `ai_points`（0~25），可直接参与风险分累加
- 双阈值分层：≥20 可疑事件，≥40 高危告警

## 目录结构

```text
xss_detector/
├── src/
│   ├── config.py          路径、标签、阈值、AI 分值映射配置
│   ├── rules.py           规则引擎（118 条规则，4 类，带中文描述与建议分值）
│   ├── preprocess.py      归一化：NUL 清理、多重 URL 解码、HTML 实体、\uXXXX
│   ├── predict.py         predict_xss（旧级联）+ predict_signal（加权融合）
│   ├── train.py           训练 + 概率校准 + 独立测试集评估
│   ├── build_dataset.py   先切分再增强，防数据泄漏
│   ├── augment.py         按类别的数据增强
│   └── api.py             FastAPI 服务
├── tools/
│   ├── data_audit.py      数据体检：误标/冲突/缺口/泄漏
│   ├── clean_data.py      数据清洗：合并新增样本、拆分类别、剔除噪声
│   ├── update_model.py    ★ 一条命令完成"加样本→清洗→切分→重训→评估"
│   ├── cv_eval.py         交叉验证对比（规则/模型/加权融合）
│   ├── eval_report.py     单次独立评估
│   ├── demo_signal.py     信号链路演示（答辩展示用）
│   └── client_example.py  蜜罐侧接入示例（HTTP + 同进程）
├── tests/
│   ├── test_predict.py    检测功能测试
│   ├── test_api.py        API 接口测试
│   └── run_all.ps1        一键测试脚本
├── data/
│   ├── raw/               基准备份 + extra_samples.csv（新增样本）+ 清洗结果
│   ├── processed/         训练集 / 测试集 / 待预测数据（自动生成）
│   └── augmented/         增强训练集（自动生成）
├── models/                模型与元数据（含 v1 备份）
├── PROJECT_REPORT.md      ★ 项目总报告（给老师/评审看这一份）
├── API_CONTRACT.md        ★ 蜜罐对接接口契约
├── OPERATIONS.md          ★ 部署与操作指南（蜜罐组部署看这份）
├── TESTING.md             测试指南（四层测试与验收清单）
├── DATA_GUIDE.md          数据与训练说明（加样本、重训流程）
└── suspect_samples.csv    数据体检产出的可疑样本清单
```

## 安装依赖

```bash
pip install -r requirements.txt
```

## 快速使用

### 1. 命令行检测

```bash
# 默认测试用例
python -m src.predict

# 单条检测
python -m src.predict "<script>alert(1)</script>"

# 交互模式
python -m src.predict -i

# 批量 CSV
python -m src.predict --batch data/processed/predict_raw.csv data/processed/predict_result.csv
```

### 2. 信号接口（推荐用于蜜罐集成）

```python
from src.predict import predict_signal

r = predict_signal("../../../../etc/passwd")
# {
#   'attack_type': 'path_traversal',
#   'is_attack': True,
#   'attack_prob': 1.0,
#   'ai_points': 25,              # 累加到蜜罐风险分
#   'rule_points': 22,
#   'fusion_score': 47,           # >=40 高危
#   'high_risk': True,
#   'reason': '规则命中: 检测到路径遍历攻击 ../；模型判定: path_traversal(1.00)',
#   ...
# }
```

详见 [API_CONTRACT.md](API_CONTRACT.md)。

### 3. HTTP 服务

```bash
python -m uvicorn src.api:app --host 127.0.0.1 --port 8000
```

**对外只需一个接口：`POST /api/v1/detect`**（蜜罐对接主接口）

| 方法 | 路径 | 用途 |
|---|---|---|
| POST | `/api/v1/detect` | ★ 蜜罐对接主接口（请求级检测） |
| GET | `/health` | 健康检查 |
| GET | `/model/info` | 模型版本信息 |
| — | `/predict`、`/predict/signal`、`/predict/batch` | 【内部调试】不在对外契约内 |

交互式文档：`http://127.0.0.1:8000/docs`（接口按"蜜罐对接 / 内部调试"分组）

对接说明见 [API_CONTRACT.md](API_CONTRACT.md)。

## 完整流水线

```bash
python -m tools.data_audit                    # 1. 数据体检，产出误标清单
python -m tools.clean_data --write            # 2. 清洗，产出 train_clean.csv
python -m src.build_dataset --input data/raw/train_clean.csv   # 3. 切分+增强
python -m src.train                           # 4. 训练 + 校准 + 评估
python -m tools.cv_eval --data data/raw/train_clean.csv --folds 5   # 5. 交叉验证
```

## 以后添加新样本、重新训练

**新样本统一写到 `data/raw/extra_samples.csv`**（三列：`text,label,source`），
然后运行一条命令即可：

```powershell
python -m tools.update_model
```

它会自动完成：合并新增样本 → 清洗 → 切分训练/测试集 → 数据增强 → 训练 → 交叉验证。

要点：
- **训练集 `data/processed/train_raw.csv` 与测试集 `test_raw.csv` 是自动生成的，不要手工编辑**，
  下次跑脚本会被覆盖。
- 每次都是从 `train_raw_backup_v3.csv`（基准）+ `extra_samples.csv`（你的新增）**重新计算**，
  所以反复运行**不会重复累加**，也随时可以回退。
- `label` 只能取 `xss` / `sqli` / `path_traversal` / `sensitive_path` / `normal`。
  注意 `path_traversal` 是**含 `../` 的目录穿越**，`sensitive_path` 是**不含 `../` 的敏感文件探测**。
- 载荷里含逗号时要用双引号包住整个 text，例如：
  `"1' and extractvalue(1,concat(0x7e,database()))-- -",sqli,manual`

完整说明（数据流向图、切分规则、格式陷阱、扩样建议）见 [DATA_GUIDE.md](DATA_GUIDE.md)。

## 测试

```powershell
# 一键测试：单元测试 + 信号链路演示
powershell -ExecutionPolicy Bypass -File tests\run_all.ps1

# 含 API 端到端验证
powershell -ExecutionPolicy Bypass -File tests\run_all.ps1 -Serve

# 含交叉验证（约 1-2 分钟）
powershell -ExecutionPolicy Bypass -File tests\run_all.ps1 -Serve -Full
```

单独运行：

```powershell
python -m pytest -q                  # 单元测试（14 项）
python -m tools.demo_signal          # 信号链路演示（15 个场景）
python -m tools.client_example       # 蜜罐侧接入示例
```

完整测试方法与验收清单见 [TESTING.md](TESTING.md)。

## 当前模型表现

评估方式：5 折分层交叉验证，8493 条清洗后样本。

| 链路 | 准确率 | 宏 F1 | 攻击精确率 | 误报 |
|---|---|---|---|---|
| 只看规则 | 0.9687 | 0.8909 | 98.80% | 15 |
| 只看模型 | 0.9935 | 0.9558 | 98.84% | 17 |
| 加权融合 + 双阈值 | **0.9941** | **0.9662** | **99.45%** | **8** |

双阈值分层效果：高危层（≥40 分）精确率 **100%**，可疑层（20~39）96.7%。

## 两个接口的区别

| 接口 | 行为 | 用途 |
|---|---|---|
| `predict_xss` | 规则命中即短路，`confidence` 固定 0.99 | 旧调用、单元测试 |
| `predict_signal` | 规则与模型都执行，加权累加后按双阈值分层 | **蜜罐加权特征** |

> ⚠️ `predict_xss` 的短路行为与"多特征加权"机制冲突，接入蜜罐请用 `predict_signal`。

## 已知限制

1. **`path_traversal` 样本极少**：清洗后仅 18 条，该类指标不具统计置信度，建议扩充至 500+。
2. `normal` 中混有约 2999 条英文新闻残句（源自 `sqli.csv` 的负样本语料），与真实 HTTP 流量分布不符。
3. 模型尚未在蜜罐**真实评分区间（0~20 分边界样本）**上验证过正交性。
4. 敏感文件名单独出现时（如 `/id_rsa`，总分 19）刻意**不越过 20 分可疑线**，
   需与其他信号叠加才告警——这与蜜罐权重表设计一致。

> 已修复项：日志文件不可写导致服务启动失败（`api.py` 已加异常兜底）；
> 正常短路径被误判为敏感文件（已补正常路径语料 + 白名单机制）。

完整的项目说明、数据治理过程与量化结果见 [PROJECT_REPORT.md](PROJECT_REPORT.md)。
