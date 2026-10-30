# AI 检测服务接口契约（蜜罐对接文档）

> 本文档给蜜罐组对接使用。**当前版本采用"两个独立模块 + HTTP 接口"的架构。**

---

## 一、架构说明

```
┌─────────────────────────┐         HTTP POST          ┌──────────────────────────┐
│   蜜罐模块（你们）        │  ───────────────────────>  │  AI 检测服务（我们）      │
│  Web/SSH 蜜罐 + 存储     │                            │  FastAPI + 规则 + 模型    │
│                         │  <───────────────────────  │                          │
└─────────────────────────┘     判定结果 JSON           └──────────────────────────┘
```

- 两个模块**独立部署、独立运行**，只通过 HTTP 接口通信；
- 你们把采集到的请求数据 POST 给我们；
- 我们返回攻击类型判定 + 置信度 + 可读理由 + 证据明细；
- 你们不需要安装任何 Python 依赖（连 `requests` 都不需要，用标准库 `urllib` 即可）。

### 服务启动方式（我们这边）

```bash
python -m uvicorn src.api:app --host 0.0.0.0 --port 8000
```

- 接口文档（Swagger UI）：`http://<服务地址>:8000/docs`
- 健康检查：`GET /health`

---

## 二、你们需要传什么（请求体）

### 主接口

```
POST /api/v1/detect
Content-Type: application/json
```

### 请求体字段

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `url` | string | 二选一 | 完整 URL（含查询串），如 `/search?id=1 and 1=1` |
| `path` | string | 二选一 | 请求路径，如 `/download`。**推荐**与 `query` 分开传 |
| `query` | string | 否 | 查询串，如 `id=1&name=x`（可带 `?` 前缀） |
| `body` | string | 否 | 请求体原文（POST 表单 / JSON / 原始文本） |
| `method` | string | 否 | HTTP 方法，如 `GET` / `POST` |
| `headers` | object | 否 | 请求头字典（键值均为字符串） |
| `user_agent` | string | 否 | User-Agent（若 `headers` 里已有可省略） |
| `source` | string | 否 | 来源标识，默认 `web`，可选 `ssh` / `http` / `api` |
| `ip` | string | 否 | 来源 IP（我们回显时会脱敏） |
| `session_id` | string | 否 | 会话标识，便于你们关联事件 |
| `timestamp` | string | 否 | 事件时间（ISO8601），仅回显 |
| `extra` | object | 否 | 任意额外元信息，仅回显与记录 |

### 关键要求：**请分开传 path 和 query**（很重要）

我们实测过：如果把整条 URL 当一团文本传，后面的无关参数会破坏规则匹配的上下文，
导致漏报。例如：

| 传法 | 检测结果 |
|---|---|
| `{"url": "/search?id=1 and 1=1&Submit=Submit"}` | 内部会自动拆分，能正确识别 ✓ |
| `{"path": "/search", "query": "id=1 and 1=1"}` | **最准确**，推荐 ✓ |
| `{"text": "/search?id=1 and 1=1&Submit=Submit"}`（旧接口） | 会漏报 ✗ |

只传 `url` 我们也能处理（会自动拆分查询串），但分开传更稳妥。

### 请求示例

**示例 1：SQL 注入（GET，推荐写法）**

```json
{
  "method": "GET",
  "path": "/search",
  "query": "id=1 and 1=1",
  "user_agent": "Mozilla/5.0",
  "ip": "203.0.113.9",
  "session_id": "sess-a1b2c3",
  "timestamp": "2026-10-14T16:30:00+08:00",
  "source": "web",
  "extra": {"route": "/search"}
}
```

**示例 2：XSS（POST 请求体）**

```json
{
  "method": "POST",
  "path": "/comment",
  "body": "<script>alert(document.cookie)</script>",
  "headers": {"Content-Type": "application/x-www-form-urlencoded"},
  "ip": "203.0.113.20",
  "session_id": "sess-d4e5f6"
}
```

**示例 3：目录穿越（参数中带载荷）**

```json
{
  "method": "GET",
  "path": "/download",
  "query": "file=../../../../etc/passwd",
  "ip": "198.51.100.7",
  "session_id": "sess-g7h8i9"
}
```

**示例 4：最简写法（只有完整 URL）**

```json
{"url": "/wp-config.php", "ip": "192.0.2.5"}
```

**示例 5：正常请求（也要传，用于校准误报）**

```json
{
  "method": "GET",
  "path": "/search",
  "query": "q=hello&page=2",
  "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
  "ip": "10.0.0.1"
}
```

---

## 三、我们会返回什么（响应体）

### 响应体字段

| 字段 | 类型 | 说明 |
|---|---|---|
| `attack_type` | string | **判定类型**：`xss` / `sqli` / `path_traversal` / `sensitive_path` / `scanner` / `normal` |
| `is_attack` | bool | 是否判定为攻击 |
| `attack_prob` | float | AI 判定为攻击的概率（0~1），可作为你们的加权特征 |
| `ai_points` | int | **AI 建议累加分值（0~25）**，直接对齐你们权重表量纲 |
| `confidence` | float | 判定类型的置信度 |
| `high_risk` | bool | 是否达到高危阈值（累加分 ≥40） |
| `reasons` | string[] | 可读的中文判定理由，可直接入库展示 |
| `signals` | object[] | **命中明细**，含位置与证据，便于你们记录 |
| `model_label` | string | 模型独立判定结果（便于排查） |
| `source` | string | 回显你们传的来源 |
| `ip` | string | 回显来源 IP（**已脱敏**，如 `203.0.113.*`） |
| `session_id` | string | 回显会话标识 |

### `signals[]` 元素结构

| 字段 | 类型 | 说明 |
|---|---|---|
| `field` | string | **命中位置**：`path` / `query.参数名` / `body` / `user_agent` / `joined` |
| `value` | string | 该位置的实际内容 |
| `attack_type` | string | 该位置被判定的类型 |
| `attack_prob` | float | 该位置的攻击概率 |
| `ai_points` | int | 该位置的 AI 分值 |
| `fusion_score` | int | 该位置的累加分 |
| `high_risk` | bool | 该位置是否高危 |
| `reason` | string | 该位置的中文理由 |

### 判定类型取值表

| `attack_type` | 中文含义 | 典型案例 |
|---|---|---|
| `xss` | 跨站脚本 | `<script>alert(1)</script>`、`<img src=x onerror=...>` |
| `sqli` | SQL 注入 | `' or 1=1 --`、`union select ...`、`1 and sleep(5)` |
| `path_traversal` | 目录穿越 | `../../../../etc/passwd`、`..%2f..%2f` |
| `sensitive_path` | 敏感文件/目录探测 | `/.env`、`/wp-config.php`、`/.git/config`、`/phpmyadmin` |
| `scanner` | 自动化扫描器 | UA 含 `sqlmap`、`nikto`、`nmap`、`nuclei` 等 |
| `normal` | 正常流量 | 无攻击特征 |

> ⚠️ `path_traversal` 与 `sensitive_path` 的区别是**有没有 `../`**：
> `../../etc/passwd` → `path_traversal`；`/etc/passwd` → `sensitive_path`。

### 响应示例

**SQL 注入请求的返回：**

```json
{
  "attack_type": "sqli",
  "is_attack": true,
  "attack_prob": 0.9021,
  "ai_points": 22,
  "confidence": 0.99,
  "high_risk": true,
  "reasons": [
    "[query.id] 规则命中 sqli(+25): 检测到 SQL 恒真条件 and N=N；模型判定: sqli(0.87)"
  ],
  "signals": [
    {
      "field": "query.id",
      "value": "1 and 1=1",
      "attack_type": "sqli",
      "attack_prob": 0.9021,
      "ai_points": 22,
      "fusion_score": 47,
      "high_risk": true,
      "reason": "规则命中 sqli(+25): 检测到 SQL 恒真条件 and N=N；模型判定: sqli(0.87)"
    }
  ],
  "model_label": "sqli",
  "source": "web",
  "ip": "203.0.113.*",
  "session_id": "sess-a1b2c3"
}
```

**正常请求的返回：**

```json
{
  "attack_type": "normal",
  "is_attack": false,
  "attack_prob": 0.537,
  "ai_points": 13,
  "confidence": 0.463,
  "high_risk": false,
  "reasons": [],
  "signals": [],
  "model_label": "normal",
  "source": "web",
  "ip": "10.0.0.*",
  "session_id": ""
}
```

---

## 四、如何并入你们的风险评分

你们已有"多特征加权 + 双阈值分层"机制（可疑 ≥20，高危 ≥40）。
最简接入方式：**把 `ai_points` 直接累加进去**。

```python
# 你们 db/http_requests.py::calculate_threat_score 里的改造点
sig = call_ai_service(path=path, query=query, body=body, headers=headers)

if sig is not None:
    risk_score += sig["ai_points"]          # AI 作为一维特征累加
    if sig["is_attack"]:
        signals.append(f"AI判定: {sig['attack_type']}"
                       f"({sig['attack_prob']:.2f}, +{sig['ai_points']})")
    for r in sig["reasons"]:
        signals.append(f"AI: {r}")

# 原有的双阈值逻辑保持不变
is_suspicious = risk_score >= 20
```

**注意：AI 分值上限是 25**，与你们权重表里"SQL 注入语义 +25"同档。
单独一个 AI 信号不足以推到 40 分高危线，需要与其他信号叠加——
这符合你们"不因单一特征直接下结论"的设计。

**典型叠加效果：**

| 场景 | 你们原有分 | AI 分 | 累加 | 分层 |
|---|---|---|---|---|
| 敏感路径探测 `/wp-config.php` | +15（路径探测） | +25 | **40** | 高危告警 |
| 目录穿越 `../../etc/passwd` | +22（LFI 特征） | +25 | **47** | 高危告警 |
| 正常页面含 `<script src=...>` | +22（旧规则误报） | +2 | 24→**抑制** | 保持可疑/常规 |

---

## 五、调用代码示例（标准库，零依赖）

```python
import json
import urllib.error
import urllib.request

AI_URL = "http://127.0.0.1:8000"      # AI 服务地址
TIMEOUT = 3.0                          # 建议设短，不要拖慢蜜罐响应


def ai_detect(path="", query="", body="", headers=None,
              user_agent="", ip="", session_id=""):
    """调用 AI 检测服务。失败返回 None，调用方必须做降级处理。"""
    payload = {
        "path": path,
        "query": query,
        "body": body,
        "headers": headers or {},
        "user_agent": user_agent,
        "ip": ip,
        "session_id": session_id,
        "source": "web",
    }
    req = urllib.request.Request(
        f"{AI_URL}/api/v1/detect",
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as e:
        # ★ 关键：AI 服务不可用时必须降级，蜜罐要照常工作
        print(f"[WARN] AI 服务不可用({e})，本次跳过 AI 特征")
        return None
```

> **必须保留降级分支**：AI 服务挂了不能影响蜜罐主流程。

---

## 六、接口清单

**你们只需要了解这两个：**

| 方法 | 路径 | 用途 |
|---|---|---|
| POST | `/api/v1/detect` | **★ 唯一需要对接的接口** |
| GET | `/health` | 健康检查（建议启动前探活，判断服务是否就绪） |

辅助接口（可选，不影响对接）：

| 方法 | 路径 | 用途 |
|---|---|---|
| GET | `/model/info` | 查看模型版本与支持的类别 |
| GET | `/` | 返回服务信息与最小请求示例 |

**以下接口为【内部调试】，蜜罐侧无需了解，也不属于对外契约：**

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/predict` | 早期级联接口，`confidence` 固定 0.99，**不适用加权特征** |
| POST | `/predict/signal` | 返回 `fusion_score` 等本模块内部字段，已标记 deprecated |
| POST | `/predict/batch` | 离线批量跑样本用 |

> 之所以保留它们，是为了本模块内部自测与离线评估。
> 这些接口的字段会随内部实现调整，**请不要依赖**。

访问 `GET /` 会直接返回主接口与最小请求示例，可作为对接起点：

```json
{
  "main_endpoint": {
    "path": "/api/v1/detect",
    "method": "POST",
    "note": "蜜罐对接只用这个接口",
    "minimal_request": {"path": "/search", "query": "id=1 and 1=1"}
  },
  "auxiliary": {"/health": "健康检查（建议启动前探活）"},
  "internal_debug_only": {"endpoints": ["/predict", "/predict/signal", "/predict/batch"]}
}
```

---

## 七、错误处理

| HTTP 状态码 | 含义 | 你们的处理建议 |
|---|---|---|
| 200 | 成功 | 正常使用返回结果 |
| 400 | 入参错误（如 `url`/`path`/`body` 全为空） | 检查请求体，不要重试 |
| 422 | 字段类型错误（如 `headers` 传了数组） | 检查字段类型 |
| 500 | 服务内部错误 | 记录日志，降级处理 |
| 503 | 模型未就绪（`/health` 返回） | 降级，稍后重试 |

**建议**：调用超时设为 2~3 秒，失败即降级。
不要因为 AI 服务慢而阻塞蜜罐的响应。

---

## 八、我们这边记录的日志

我们会把每次判定写入 `data/honeypot_events.jsonl`（JSON Lines，按 5MB 轮转，保留 5 份），
字段与响应体一致，**IP 已脱敏**。这份日志可作为你们的对账依据。

---

## 九、能力边界（请知悉）

| 项 | 当前指标（5 折交叉验证，39608 条） |
|---|---|
| 判定类型 | 5 类（xss / sqli / path_traversal / sensitive_path / normal）+ scanner 规则类 |
| 攻击识别召回率 | 99.30% |
| 攻击识别精确率 | 99.71% |
| 宏平均 F1 | 0.9872 |
| 高危层（≥40 分）精确率 | **99.9%**（11321 条高危样本中仅 7 条误报） |
| 误报 | 38 条 / 39608 条（0.096%） |

### 分类别识别率（独立测试集，7922 条）

| 攻击类型 | 精确率 | 识别率 | 测试样本数 |
|---|---|---|---|
| `xss` | 98.49% | 98.00% | 200 |
| `sqli` | 100.00% | 99.36% | 2347 |
| `path_traversal` | 100.00% | 100.00% | 31 |
| `sensitive_path` | 100.00% | 100.00% | 49 |
| `normal` | 99.64% | 99.94% | 5295 |

完整报告见项目根目录 `eval_report.md`。

### 正常路径已加入白名单

早期版本有个严重问题：训练集里 `normal` 样本几乎都是长文本（均值 174 字符），
**没有 WEB 路径样本**，而 `sensitive_path` 几乎全是短路径。
导致模型把任何短路径都判成敏感文件（实测 `/` 和 `/index.php` 攻击概率高达 1.0）。

现已修复：
- 补充了 128 条正常 Web 路径语料到训练集（`data/raw/extra_benign_paths.csv`）；
- 增加"已知安全路径白名单"（`src/rules.py::BENIGN_PATHS`），命中时扣减 20 分。

**实测结果：38 条常见正常路径（`/`、`/index.php`、`/api/users`、`/static/css/style.css` 等）
误报 0 条。**

### 需要注意的边界情况

| 情况 | 行为 | 说明 |
|---|---|---|
| `/phpmyadmin`、`/console` | 判为 `sensitive_path`（总分 24~36） | **刻意不过白名单**：访问数据库管理入口通常是攻击/侦察行为。如果你方认为属正常运维，请告知，我们加入白名单 |
| `/admin`、`/administrator` | 判为 `normal`（总分 <20） | 后台首页访问视为正常；`/admin/login` 也在白名单内 |
| 敏感文件名**单独出现**（如 `/id_rsa`） | 总分 19，**不到 20 分可疑线** | 符合你方权重表设计：敏感路径探测 +15，单独不足以告警，需与其他信号叠加 |
| `../../etc/passwd` | `path_traversal`，总分 47 | 目录穿越特征 + 敏感文件叠加，高危 |
| `/etc/passwd`（无 `../`） | `sensitive_path`，总分 40 | 高危 |

**结论**：敏感路径类的"单独出现"信号刻意设计为弱信号（+15），
需要与请求头异常、频率、会话累积等其他信号叠加才会越过可疑线——这与你方机制一致。

### 其他已知短板

1. **`path_traversal` 真实样本仅 18 条**，该类指标统计上不可信。
   **请把蜜罐抓到的真实目录穿越样本回传给我们用于重训**（这是最有价值的输入）。
2. **误报样本也请回传**：我们已经建立了"正常路径白名单"机制，
   你方真实流量里的误报可以快速转化为白名单条目或训练样本。
3. 我们**不做封禁决策**，只输出判定与分值，最终处置由你方决定。

---

## 十、联调步骤

```bash
# 1. 启动我们的服务
python -m uvicorn src.api:app --host 127.0.0.1 --port 8000

# 2. 探活
curl http://127.0.0.1:8000/health

# 3. 用真实请求试一条
curl -X POST http://127.0.0.1:8000/api/v1/detect \
  -H "Content-Type: application/json" \
  -d '{"method":"GET","path":"/search","query":"id=1 and 1=1","ip":"203.0.113.9"}'

# 4. 浏览器打开交互式文档，逐个字段试
#    http://127.0.0.1:8000/docs
```

**联调建议顺序：**
1. 先用 `/health` 确认服务可达；
2. 用上面 5 个示例请求逐条验证字段与响应；
3. 接入到蜜罐评分链路，**务必先保留降级分支**；
4. 用你们的正常流量跑一轮，观察误报；
5. 把误报样本和真实攻击样本回传给我们，用于迭代模型。
