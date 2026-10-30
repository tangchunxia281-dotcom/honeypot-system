# AI 检测层接入说明（对接蜜罐"多特征加权 + 双阈值分层"）

本文说明如何把 `xss_detector` 的 AI 能力作为**一维加权特征**接入蜜罐的
风险评分链路（`db/http_requests.py::calculate_threat_score`）。

---

## 1. 为什么需要新接口

`src/predict.py` 提供两个接口，用途不同：

| 接口 | 行为 | 适用场景 |
|---|---|---|
| `predict_xss(text)` | **级联**：规则命中即短路返回，`confidence` 固定 0.99 | 旧的独立检测、单元测试 |
| `predict_signal(text)` | **加权融合**：规则与模型都执行，输出分值，按双阈值分层 | **蜜罐加权特征（推荐）** |

`predict_xss` 的短路行为与蜜罐"多特征加权"机制冲突：
- 它把"命中单条规则"直接等同于"攻击成立"，而论文 5.3 节明确否定这种做法；
- 规则命中时 `confidence=0.99` 不携带信息量，作为加权特征会恒定顶格。

因此接入蜜罐请使用 `predict_signal`。

---

## 2. 接口返回结构

```python
from src.predict import predict_signal

r = predict_signal("../../../../etc/passwd")
```

返回：

| 字段 | 类型 | 含义 |
|---|---|---|
| `attack_type` | str | 融合后的攻击类型；未过可疑线时为 `"normal"` |
| `is_attack` | bool | 是否判定为攻击（`fusion_score >= 20`） |
| `attack_prob` | float | 模型给出的校准后攻击概率 (0~1) |
| `ai_points` | int | **AI 建议累加分值**，`round(attack_prob * 25)`，范围 0~25 |
| `rule_points` | int | 规则建议累加分值（未抑制前） |
| `effective_rule_points` | int | 抑制后实际生效的规则分 |
| `fusion_score` | int | 累加总分 = `effective_rule_points + ai_points` |
| `suspicious` | bool | `fusion_score >= 20`（可疑） |
| `high_risk` | bool | `fusion_score >= 40`（高危） |
| `confidence` | float | 判定类型的置信度 |
| `reason` | str | 中文可读说明，可直接入库展示 |
| `rule_hits` | list | 命中的规则明细 `[{label, pattern, points, desc}]` |
| `model_label` | str | 模型独立判定结果（便于对比排查） |

示例输出：

```
payload: ../../../../etc/passwd
attack_type=path_traversal  prob=1.000  ai_points=25
rule_points=22  effective=22  fusion_score=47  high_risk=True
```

---

## 3. 分值映射依据

`AI_POINTS_MAX = 25`，与论文表 5-1 中"SQL 注入语义 +25"同档。理由：

- 蜜罐权重表量纲为：探测类 +15~22，利用类 +18~28；
- AI 作为**一维**特征，不应单独把请求推过 40 分高危线；
- 上限 25 使"AI 高置信攻击"单独即可越过 20 分可疑线，但需与其他信号叠加才达高危。

映射关系：

| `attack_prob` | `ai_points` | 单独效果 |
|---|---|---|
| 0.0 | 0 | 无贡献 |
| 0.20 | 5 | 弱辅助 |
| 0.50 | 13 | 接近可疑线 |
| 0.80 | 20 | 单独达到可疑线 |
| 0.95+ | 24~25 | 接近高危线 |

---

## 4. AI 否决机制

单条规则不足以定性。典型反例：

```
<script src="_static/doctools.js"></script>    # 正常网页里就有 script 标签
<a href=javascript:void(0)>x</a>              # 常见 JS 写法
```

这两例旧规则都判 xss。新机制下：

```
模型判定 attack_prob = 0.088 / 0.070  (< AI_VETO_PROB = 0.15)
  -> 视为"高置信非攻击"
  -> 规则分 22 抑制为 2
  -> fusion_score = 2 + 2 = 4  < 20  ->  正确归为 normal
```

即：**当模型以很高置信度认为"不是攻击"时，抑制弱规则信号。**
反之，"规则命中 + 模型也认为可疑"会累加放大（例如敏感路径 +15 与 AI +25 叠加 = 40，正好进入高危告警）。

---

## 5. 接入方式（两种）

### 方式 A：直接调用（同机/同进程）

```python
from src.predict import predict_signal

sig = predict_signal(query_string or body)
risk_score += sig["ai_points"]          # 作为一维特征累加
if sig["rule_hits"]:
    signals.extend(f"AI规则: {h['desc']}" for h in sig["rule_hits"])
if sig["attack_type"] in ("xss", "sqli", "path_traversal", "sensitive_path"):
    signals.append(f"AI类型判定: {sig['attack_type']}({sig['attack_prob']:.2f})")
```

### 方式 B：HTTP 服务（跨机部署）

`src/api.py` 已提供 FastAPI 服务。若需要在该服务上暴露信号接口，
可新增端点：

```python
@app.post("/predict/signal")
def predict_signal_api(req: PredictRequest):
    return predict_signal(req.text)
```

> 注意：`src/api.py` 中 `RotatingFileHandler` 在**模块导入时**就打开日志文件，
> 若 `data/honeypot_events.jsonl` 不可写，会导致整个服务启动失败。
> 接入前建议改为延迟初始化并捕获异常（见下文"已知问题"）。

---

## 6. 已知问题与建议

| 问题 | 影响 | 建议 |
|---|---|---|
| `api.py` 日志文件不可写则在 import 阶段抛异常 | 服务无法启动 | 包一层 try/except，降级为 stderr 输出 |
| `path_traversal` 真实样本仅 18 条 | 该类指标不可信 | 扩充样本（公开 payload 库）后再重训 |
| `normal` 中混有 2999 条英文新闻残句 | 与真实 HTTP 流量分布不符 | 视情况剔除，或用蜜罐真实流量替换 |
| 模型未在蜜罐真实评分区间上验证 | 正交性未知 | 后续用"蜜罐评分 0~20 的边界样本"重训 |

---

## 7. 复现训练与评估

```bash
# 1. 数据体检（输出误标清单）
python -m tools.data_audit

# 2. 数据清洗（产出 data/raw/train_clean.csv）
python -m tools.clean_data --write

# 3. 构建数据集（切分 + 仅对训练集增强）
python -m src.build_dataset --input data/raw/train_clean.csv

# 4. 训练（含概率校准与独立测试集评估）
python -m src.train

# 5. 交叉验证对比（规则 / 模型 / 加权融合三条链路）
python -m tools.cv_eval --data data/raw/train_clean.csv --folds 5
```
