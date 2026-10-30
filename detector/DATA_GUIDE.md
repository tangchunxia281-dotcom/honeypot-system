# 数据与训练说明

本文回答三个问题：
1. 训练集和测试集在哪里
2. 以后添加新样本要放在哪里
3. 怎么重新训练模型

---

## 一、核心原则：训练集/测试集是**自动生成**的，不要手工改

关键点：**`data/processed/train_raw.csv` 和 `test_raw.csv` 是脚本切分出来的产物，
不是给你手工编辑的地方。** 你手工改它们，下次跑脚本就会被覆盖。

你要维护的只有两个文件：

| 你要维护的文件 | 作用 |
|---|---|
| `data/raw/train_raw_backup_v3.csv` | 历史基准数据（**只读**，别改） |
| `data/raw/extra_samples.csv` | **你以后新增的样本都放这里** |

其余文件全部由脚本自动生成。

---

## 二、数据目录全貌

```
data/
├── raw/                              【原始层：你维护】
│   ├── train_raw_backup_v3.csv       历史基准 8570 条（只读，永不改动）
│   ├── extra_samples.csv             ★ 新增样本放这里（你唯一要编辑的文件）
│   ├── train_clean.csv               [自动生成] 基准 + 新增，清洗后 8493 条
│   ├── dropped_samples.csv           [自动生成] 被剔除的样本及原因，可复核
│   └── backup/                       [自动生成] 清洗结果的历次快照（最多 5 份）
│       └── train_clean_YYYYMMDD_HHMMSS.csv
│
├── processed/                        【切分层：自动生成】
│   ├── train_raw.csv                 [自动生成] 训练集 6794 条
│   ├── test_raw.csv                  [自动生成] 独立测试集 1699 条
│   ├── predict_raw.csv              待预测数据（你放待检测文本）
│   └── predict_result.csv           [自动生成] 批量预测结果
│
├── augmented/                        【增强层：自动生成】
│   └── augmented.csv                 [自动生成] 只对训练集增强，20570 条
│
└── honeypot_events.jsonl             API 服务的预测事件日志
```

### 数据流向图

```
train_raw_backup_v3.csv ──┐
                          ├──> clean_data.py ──> train_clean.csv
extra_samples.csv ────────┘         (清洗)
                                          │
                                          ▼
                              build_dataset.py (切分：80% / 20%)
                                    │                │
                          ┌─────────┘                └──────────┐
                          ▼                                     ▼
              train_raw.csv (训练集)                  test_raw.csv (独立测试集)
                          │                                     │
                          ▼                                     │
              augment.py 数据增强                                │
                          │                                     │
                          ▼                                     ▼
              augmented.csv (增强训练集) ────> train.py <────────┘
                                                  │
                                                  ▼
                                        attack_model.pkl (模型)
```

**为什么"先切分再增强"很重要**：增强必须在切分之后、且只对训练集做。
否则同一个 payload 的变体会同时出现在训练集和测试集里，测试分数会虚高。
`build_dataset.py` 已经保证了这个顺序。

---

## 三、以后添加新样本：三步

### 第 1 步：把样本写进 `data/raw/extra_samples.csv`

文件格式（UTF-8，三列，第一行是表头）：

```csv
text,label,source
../../../../etc/passwd,path_traversal,manual
/.env,sensitive_path,manual
' or 1=1 --,sqli,manual
<script>alert(1)</script>,xss,manual
这是一个正常的句子,normal,manual
```

**`label` 只能用这 5 个值**（写错会被忽略并提示）：

| label | 含义 | 例子 |
|---|---|---|
| `xss` | 跨站脚本 | `<script>alert(1)</script>` |
| `sqli` | SQL 注入 | `' or 1=1 --` |
| `path_traversal` | **目录穿越**（含 `../`） | `../../../../etc/passwd` |
| `sensitive_path` | **敏感文件/目录探测**（不含 `../`） | `/wp-config.php`、`/.env`、`/phpmyadmin` |
| `normal` | 正常流量 | `hello world` |

> ⚠️ `path_traversal` 和 `sensitive_path` 的区别就是**有没有 `../`**：
> - `../../etc/passwd` → `path_traversal`
> - `/etc/passwd`（没有 `../`）→ `sensitive_path`

### 第 2 步：注意 CSV 格式陷阱

**载荷里含逗号时，必须用双引号把整个 text 包起来**，否则会被当成多列而解析失败：

```csv
"1' and extractvalue(1,concat(0x7e,database()))-- -",sqli,manual
"' union select null,version()-- -",sqli,manual
```

其他注意事项：
- 载荷里的双引号要写成两个：`""`
- 用 Excel 编辑后请**另存为 CSV UTF-8**，否则中文会乱码
- 不要有空行，不要在数据中间插注释行

### 第 3 步：运行一条命令重新训练

```powershell
cd "D:\HuaweiMoveData\Users\20683\Desktop\xss_detector"
python -m tools.update_model
```

它会自动依次完成：清洗 → 切分 → 增强 → 训练 → 交叉验证，并打印新指标。

只要数据、不要训练（先看看清洗结果对不对）：

```powershell
python -m tools.update_model --skip-train
```

---

## 四、为什么这样设计（不会重复累加）

`clean_data.py` 每次都是 **从基准 `train_raw_backup_v3.csv` + `extra_samples.csv` 重新计算**，
而不是往 `train_clean.csv` 上追加。

这意味着：

- 你反复运行 `update_model` **不会**导致样本重复累加；
- 你把 `extra_samples.csv` 里某一行删掉，下次重训该样本就消失了；
- 随时可以回退——数据只需重新生成，模型有 `models/attack_model_v1_backup.pkl`。

不要把新增样本直接写进 `train_raw_backup_v3.csv`。那个文件是历史基准，
一旦被改动，上面说的可复现性就没了。

### 4.1 源数据集会不会越训练越少？

**不会。** 这正是"基准只读"设计要解决的问题，而且比手工备份更彻底：

```
train_raw_backup_v3.csv (只读，8570 行，永不改动)
        │
        ├── 读取 ──┐
        │          ├──> 清洗 ──> train_clean.csv (8493 行)  ← 可覆盖，无所谓
extra_samples.csv ─┘
```

训练和切分**只写 `processed/` 和 `augmented/`，从不写 `raw/`**。
所以无论跑多少次训练，基准始终是完整的 8570 行，源数据不可能"减少"。

**实测验证**（连续跑两次完整流程，校验文件指纹）：

```
基准文件指纹(前): 12B5DAECD9A45AC31B73005F52E102C7
基准文件指纹(后): 12B5DAECD9A45AC31B73005F52E102C7   ← 完全一致
基准文件时间    : 10-13 22:36:17                      ← 未被触碰
```

你在旧流程里之所以需要"每次训练前备份"，是因为当时的
`tools/merge_data.py` 会**往 `train_raw.csv` 上覆盖写**：

```python
# 旧脚本（已不再使用）——这就是问题根源
BASE_PATH   = data/train_raw_backup2.csv
OUTPUT_PATH = data/train_raw.csv          # 覆盖写！
```

读基准 → 合并 → **覆盖同一个文件**，跑几次就会累积/丢失数据，所以只能靠手工备份兜底。
现在这条路径已废弃，改用"基准 + extra 每次重算"的幂等设计。

### 4.2 自动快照（手工备份的替代）

`clean_data.py` 在覆盖 `train_clean.csv` 前，会自动把上一版另存到
`data/raw/backup/`，最多保留 5 份，内容与上一版相同则跳过：

```
data/raw/backup/
└── train_clean_20261014_162847.csv     ← 上一版清洗结果
```

所以完整的回退手段有三层：

| 层级 | 回退方式 |
|---|---|
| 源数据 | `train_raw_backup_v3.csv` 从未改动，直接重跑即可复原 |
| 清洗结果 | `data/raw/backup/train_clean_*.csv` 任选一版 |
| 模型 | `models/attack_model_v1_backup.pkl` |

另外还加了一道安全校验：若清洗后行数不足基准的 50%，
会打印醒目警告，提示你检查 `extra_samples.csv` 或清洗规则是否异常——
避免"规则写错把数据全过滤掉"这类事故。

---

## 五、切分规则

| 项 | 值 | 说明 |
|---|---|---|
| 训练/测试比例 | 80% / 20% | `config.py` 的 `TEST_SIZE = 0.2` |
| 随机种子 | 42 | `RANDOM_STATE = 42`，保证可复现 |
| 分层 | `stratify=label` | 保证每类在训练/测试里比例一致 |
| 去重 | 按 `text` 去重 | 防止同一文本出现在两个集合 |

当前切分结果：

| 集合 | 文件 | 行数 |
|---|---|---|
| 训练集 | `data/processed/train_raw.csv` | 6794 |
| 独立测试集 | `data/processed/test_raw.csv` | 1699 |
| 增强训练集 | `data/augmented/augmented.csv` | 20570 |

> 因为用了 `stratify`，小类别（如 `path_traversal` 仅 18 条）在测试集里会很少，
> 单次划分的该类指标不可信，**请以 `tools/cv_eval.py` 的交叉验证结果为准**。

---

## 六、常见操作速查

```powershell
# 看当前数据分布
python -m tools.data_audit

# 只清洗，不训练（检查新增样本是否被正确读入）
python -m tools.clean_data

# 清洗并写出
python -m tools.clean_data --write

# 完整更新（加样本后跑这个）
python -m tools.update_model

# 只更新数据不训练
python -m tools.update_model --skip-train

# 只重训（数据没变，想换参数时）
python -m src.train

# 看模型质量（交叉验证）
python -m tools.cv_eval --data data/raw/train_clean.csv --folds 5
```

### 检查新增样本是否被正确读入

跑 `python -m tools.clean_data`（不带 `--write`），看输出：

```
[0] 读取增量样本: ...\data\raw\extra_samples.csv
    有效新增 21 条，标签分布: path_traversal=5, sensitive_path=5, sqli=5, xss=3, normal=3
```

如果这里显示的数量和你写入的不一致，通常是：
- **标签拼写错误** → 会提示"标签不合法"，检查是否写成了 `sqlinjection` 之类的
- **载荷含逗号没加引号** → 会提示"格式错误的行"，用双引号包住 text
- **编码不对** → 用 Excel 另存为 CSV UTF-8

---

## 七、各类样本当前缺口（扩样优先顺序）

| 类别 | 当前样本 | 建议目标 | 优先级 |
|---|---|---|---|
| `path_traversal` | **18** | ≥500 | 🔴 最高 |
| `sensitive_path` | 93 | ≥500 | 🟠 高 |
| `xss` | 470 | ≥1000 | 🟡 中 |
| `sqli` | 899 | 已够用 | 🟢 低 |
| `normal` | 7013 | 已够用 | 🟢 低 |

**最该补的是 `path_traversal`**：只有 18 条，测试集里通常只有 3 条，
该类的任何指标都不具统计意义。样本可以从这些来源收集：

- PayloadsAllTheThings 的 `Directory Traversal` 章节
- SecLists 的 `Fuzzing/LFI/` 目录
- 你蜜罐 `honeypot_events.jsonl` 里记录的真实攻击流量（最有价值）

### 用蜜罐真实流量补充样本（推荐做法）

蜜罐日志 `data/honeypot_events.jsonl` 里记录了你系统实际捕获的请求：

```powershell
python -c "
import json, collections
labels = collections.Counter()
for line in open('data/honeypot_events.jsonl', encoding='utf-8'):
    try:
        r = json.loads(line)
        labels[(r.get('label'), r.get('is_attack'))] += 1
    except Exception: pass
for k, v in labels.most_common():
    print(k, v)
"
```

把其中你人工确认过的样本（尤其 `path_traversal` 和 `sensitive_path`）
复制进 `extra_samples.csv`，再跑 `python -m tools.update_model`。
**这些真实样本比公开数据集更贴合你的场景，价值最高。**
