# AI 检测模块 —— 简单文档

> 说明这个模块做了什么、模型怎么训的、接口怎么调。
> 更新日期：2026-10-21

---

## 一、这个模块是干什么的

给蜜罐系统提供一个**独立的 AI 检测服务**，通过 HTTP 接口工作：

```
蜜罐采集请求  ──POST──>  AI 检测服务  ──返回──>  攻击类型 + 分值 + 理由
```

**输出的核心内容**：

| 字段 | 含义 |
|---|---|
| `attack_type` | 攻击类型：`xss` / `sqli` / `path_traversal` / `sensitive_path` / `scanner` / `normal` |
| `ai_points` | **建议累加的分值（0~25）**，蜜罐加进自己的风险分 |
| `reasons` | 中文判定理由，可直接展示给运维 |

**定位**：AI 不做最终判决，只提供"一维加权特征 + 攻击类型细分"。
是否告警由蜜罐的双阈值（20 分可疑 / 40 分高危）决定。

---

## 二、整体架构

```
                    ┌─────────────────────────────────────┐
   请求进来的文本 →  │  ① 归一化                            │
                    │     URL 解码 / HTML 实体 / \uXXXX    │
                    │           ↓                          │
                    │  ② 规则引擎（166 条，5 类）           │
                    │     命中 → 出分值（如 SQLi +25）      │
                    │           ↓                          │
                    │  ③ 机器学习模型（5 类分类）            │
                    │     输出各类概率 → 折算 AI 分值        │
                    │           ↓                          │
                    │  ④ 加权融合 + 双阈值                  │
                    │     规则分 + AI 分 → 累加             │
                    │     <20 常规 / 20~39 可疑 / ≥40 高危  │
                    └─────────────────────────────────────┘
```

**为什么要规则 + 模型两套**：

- **规则**：精确、可解释，但只能命中写过的形态（166 条规则是有限的）
- **模型**：能识别没写过的变体，但不知道具体理由

实测：测试集 296 条攻击样本里，**规则完全漏掉 37 条（12.5%），模型救回 36 条**。
两者互补，不是替代关系。

---

## 三、模型是怎么训练的

### 3.1 模型结构

```
字符级 TF-IDF  →  逻辑回归
```

不是深度学习，是传统方案，选它的理由是轻量（9 MB、9 ms 推理）。

| 步骤 | 参数 | 为什么这样选 |
|---|---|---|
| **TF-IDF** | 按**字符**切 1~4 个字符的组合 | 攻击特征就是标点和短序列（`../`、`'--'`），词级分词会把它们切碎 |
| | 保留大小写 | 大小写混淆本身是绕过手法 |
| | 词表 160,808 维 | 字符 n-gram 天然维度高 |
| **逻辑回归** | `class_weight='balanced'` | 自动按类别占比加权，解决不均衡 |
| | `C=5.0` | 正则强度 |

### 3.2 训练数据（当前构成）

**清洗后共 20,411 条**：

| 类别 | 条数 | 占比 |
|---|---|---|
| `sqli` | 11,732 | 57.5% |
| `normal` | 7,278 | 35.7% |
| `xss` | 1,002 | 4.9% |
| `sensitive_path` | 243 | 1.2% |
| `path_traversal` | 156 | 0.8% |

**数据来源**：

| 文件 | 条数 | 说明 |
|---|---|---|
| `train_raw_backup_v3.csv` | 8,570 | 项目原始基准数据（只读） |
| `extra_samples.csv` | 11,668 | **外部 payload 数据集**的**攻击样本**（sqli/xss/path_traversal） |
| `extra_benign_paths.csv` | 128 | 正常 Web 路径（教模型"URL 路径是正常的"） |
| `extra_benign_html.csv` | 54 | 正常 HTML/JS 代码（教模型"网页代码是正常的"） |
| `extra_benign_numeric.csv` | 105 | 数字/ID/编号（教模型"数字是正常的"） |

### 3.3 数据清洗做的三件关键事

**① 拆分错误标签（最重要）**

原 `path_traversal` 里 **59% 其实不是目录穿越**，而是敏感文件探测：

| 类别 | 样例 | 判断依据 |
|---|---|---|
| 目录穿越 | `../../etc/passwd` | 含 `../` |
| 敏感文件探测 | `/.env`、`/wp-config.php` | 不含 `../` |

已拆成 `path_traversal`（156 条）和 `sensitive_path`（243 条）两类。

**② 剔除碎片噪声**

`UEf`、`{s`、`left`、`@` 这类数据转换残留，共剔除 85 条。

**③ 只用 Web 流量的 `normal`，不用表单数据**

外部数据集里的 19,302 条 `normal` 是**姓名、地址、证件号、邮箱**（表单填写场景），
和蜜罐收到的 **URL 路径**不是一回事：

```
外部数据集的 normal：24575080v / palazuelos de eresma / plaza de san isidro 45,
蜜罐真实流量：       /index.php / /api/users / /search?q=hello
```

**实测**：用表单数据当 normal，独立 Web 流量准确率只有 **87.91%**；
换成 Web 风格语料后达到 **100%**（47 条典型请求零误报）。

所以这 19,302 条**已从训练集中剔除**，只保留外部数据集的攻击样本。

### 3.4 训练流程（6 步）

```bash
python -m tools.data_audit          # 1. 数据体检，找误标
python -m tools.clean_data --write  # 2. 清洗，产出 train_clean.csv
python -m src.build_dataset         # 3. 按 8:2 分层切分训练/测试集
python -m src.train                 # 4. 训练（含概率校准对比）
python -m tools.cv_eval             # 5. 5 折交叉验证
python -m tools.eval_report_md      # 6. 生成分类别评估报告
```

**关键点**：**先切分，后增强**。
若先增强再切分，同一 payload 的变体会同时出现在训练集和测试集，
测试分数会虚高。代码已保证这个顺序。

### 3.5 以后加新样本怎么办

**两步**：

1. 把样本写进 `data/raw/extra_samples.csv`（三列：`text,label,source`）
2. 运行：

```bash
python -m tools.update_model
```

自动完成：合并 → 清洗 → 切分 → 增强 → 训练 → 验证。

**注意**：每次都是从"基准文件 + 新增样本"**重新计算**，
反复运行不会重复累加，随时能回退。

`label` 只能取：`xss` / `sqli` / `path_traversal` / `sensitive_path` / `normal`

---

## 四、接口怎么调

### 4.1 启动服务

```bash
# 本机使用
python -m uvicorn src.api:app --host 127.0.0.1 --port 8000

# 蜜罐在另一台机器（必须 0.0.0.0，否则别的机器连不上）
python -m uvicorn src.api:app --host 0.0.0.0 --port 8000
```

先探活：

```bash
curl http://127.0.0.1:8000/health
# {"status":"ok","model_loaded":true,...}
```

### 4.2 调检测接口

**只需对接一个接口：`POST /api/v1/detect`**

请求（最少只需 `path`）：

```json
{
  "path": "/search",
  "query": "id=1 and 1=1",
  "body": "",
  "method": "GET",
  "user_agent": "Mozilla/5.0",
  "ip": "203.0.113.9",
  "session_id": "sess-001"
}
```

响应：

```json
{
  "attack_type": "sqli",
  "is_attack": true,
  "attack_prob": 0.899,
  "ai_points": 22,
  "high_risk": true,
  "reasons": ["[query.id] 规则命中 sqli(+25): 检测到 SQL 恒真条件 and N=N"],
  "signals": [
    {"field": "query.id", "value": "1 and 1=1", "attack_type": "sqli",
     "attack_prob": 0.899, "ai_points": 22, "fusion_score": 47, "high_risk": true}
  ]
}
```

### 4.3 蜜罐侧代码（标准库，零依赖）

```python
import json, urllib.request

def ai_detect(path, query="", body=""):
    req = urllib.request.Request(
        "http://AI服务器IP:8000/api/v1/detect",
        data=json.dumps({"path": path, "query": query, "body": body}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        return json.loads(urllib.request.urlopen(req, timeout=3).read())
    except Exception:
        return None      # AI 挂了必须降级，不能影响蜜罐

sig = ai_detect("/search", "id=1 and 1=1")
if sig:
    risk_score += sig["ai_points"]
```

**三个注意点**：

1. **必须保留降级分支**——AI 服务挂了，蜜罐照常工作
2. **超时设 2~3 秒**，不要阻塞蜜罐响应
3. **不要用 `confidence` 做阈值判断**——它是"判定确定性"，规则命中时恒为 0.99，
   包括判成 normal 的样本。要做门控请用 `attack_prob`

### 4.4 其他接口

| 接口 | 用途 |
|---|---|
| `GET /health` | 探活 |
| `GET /model/info` | 查模型版本 |
| `GET /docs` | 交互式接口文档 |

`/predict`、`/predict/signal`、`/predict/batch` 为**内部调试接口**，蜜罐侧无需使用。

---

## 五、现在的效果

### 5.1 分类别识别率（测试集 4,082 条，未参与训练）

| 类型 | 精确率 | 识别率 | 样本数 |
|---|---|---|---|
| `xss` | 98.51% | 98.51% | 201 |
| `sqli` | 99.70% | 99.23% | 2,346 |
| `path_traversal` | 100.00% | 100.00% | 31 |
| `sensitive_path` | 97.96% | 97.96% | 49 |
| `normal` | 98.57% | **99.31%** | 1,455 |

**总体准确率 99.36%，宏平均 F1 0.9898**

### 5.2 交叉验证（5 折，20,411 条）

| 指标 | 数值 |
|---|---|
| 准确率 | 99.50% |
| 宏平均 F1 | **0.9900** |
| 攻击识别率 | 99.34% |
| 攻击精确率 | 99.89% |

**双阈值分层**：高危层（≥40 分）11,319 条**全部是真实攻击**，零误报。

### 5.3 独立 Web 流量验证

用 47 条**不参与训练**的典型正常请求（`/`、`/index.php`、`/api/users`、
`/search?q=hello` 等）测试：**0 条误报，准确率 100%**。

---

## 六、这个模型做得怎么样

### 做得好的地方

| 项 | 说明 |
|---|---|
| ✅ **指标扎实** | 准确率 99.36%、宏 F1 0.9898、高危层零误报 |
| ✅ **数据治理到位** | 发现并修了 4 个数据问题：标签混类、碎片噪声、缺 Web 正常样本、缺数字正常样本 |
| ✅ **有真实增益** | 规则漏掉的 37 条攻击，模型救回 36 条 |
| ✅ **工程可用** | 9 MB / 9 ms / 零依赖调用 / 有降级 / 14 项测试 / 一条命令重训 |
| ✅ **可复现** | 数据幂等，有快照回退，随时能回滚 |

### 需要注意的地方

| 优先级 | 问题 | 说明 |
|---|---|---|
| 🟠 中 | `xss` 是最弱一类 | 98.51%，其余类都 ≥97.9% |
| 🟠 中 | `scanner` 模型未训练 | 完全靠规则，规则失效时无兜底 |
| 🟠 中 | 诱饵后台 `/admin` 本体漏判 | `/admin/login` 能判，`/admin` 只有 11 分（需要调整） |
| 🟡 低 | 模型文件 9 MB 偏大 | 调 `min_df` 可压到 2~3 MB |
| 🟡 低 | 线性模型学不了特征组合 | 可试 LightGBM，但会失去可解释性 |

### 一句话评估

> **工程完成度高、指标扎实、数据治理做得比较透。**
> 剩下的提升空间主要不在算法，而在**用蜜罐真实流量补充样本**——
> 因为蜜罐流量才是最终要面对的数据分布。

---

## 七、文件索引

| 想做的事 | 看哪个文件 |
|---|---|
| 快速上手 | `README.md` |
| 部署 + 调用 | `OPERATIONS.md` |
| 接口字段详解 | `API_CONTRACT.md` |
| 加样本 / 重训 | `DATA_GUIDE.md` |
| 测试方法 | `TESTING.md` |
| 当前指标报告 | `eval_report.md` |
| 优化清单 | `OPTIMIZATION.md` |
| 完整项目报告 | `PROJECT_REPORT.md` |

**代码结构**：

```
src/
├── config.py         配置（阈值、分值上限、标签）
├── rules.py          规则引擎（166 条规则）
├── preprocess.py     归一化（URL/HTML/Unicode 解码）
├── predict.py        检测入口（规则 + 模型融合）
├── train.py          训练
├── build_dataset.py  切分数据集
└── api.py            HTTP 服务

models/attack_model.pkl   模型文件（9 MB）

data/
├── raw/          基准数据 + 各类语料 + 清洗结果
├── processed/    训练集 / 测试集（自动生成）
└── augmented/    增强训练集（自动生成）
```
