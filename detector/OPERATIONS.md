# AI 检测服务 —— 部署与操作指南

> 面向蜜罐组的操作说明。
> 接口字段与示例见 [API_CONTRACT.md](API_CONTRACT.md)。

---

## 一、先澄清两个常见误解

### 误解 1：「需要本地有训练文件才能用 AI」

**不需要。** 训练文件（`models/attack_model.pkl`）只存在于**跑服务的那台机器**上，
蜜罐侧不需要任何模型文件。

服务是独立进程，通过 HTTP 通信：

```
┌─────────────────────────┐    HTTP     ┌──────────────────────────┐
│ 蜜罐（你们）             │ ──────────> │ AI 检测服务（我们这边跑） │
│ 只需能发 HTTP 请求       │             │ 模型文件在这一台机器上    │
│ 不需要模型文件           │ <────────── │ 不需要你们关心            │
│ 不需要装 Python 库       │             │                          │
└─────────────────────────┘             └──────────────────────────┘
```

蜜罐侧唯一的要求：**能通过网络访问到服务地址**（用标准库 `urllib` 即可，
连 `requests` 都不用装）。

> 只有一种情况需要你们本地有模型文件：**把模型嵌入你们自己的 Python 进程**
> （即不跑独立服务，直接 `import` 我们的代码）。
> 那样才需要装 `scikit-learn`/`joblib`/`numpy`/`pandas` 并拿到 `attack_model.pkl`。
> **不推荐这种接法**——会引入依赖耦合，且模型更新需要你们同步文件。

### 误解 2：「AI 操作指南文件叫 ai_service.md」

我们没有这个文件名。相关文档是：

| 文件 | 内容 |
|---|---|
| `API_CONTRACT.md` | **接口契约**（你们主要看这份） |
| `README.md` | 项目说明与启动命令 |
| `OPERATIONS.md` | 本文件：部署与操作步骤 |

---

## 二、部署步骤

### 步骤 1：确认服务端环境

服务端（跑 AI 的机器）需要 Python 3.9+ 及以下依赖：

```bash
pip install -r requirements.txt
# 即：pandas numpy scikit-learn joblib fastapi uvicorn pydantic
```

### 步骤 2：启动服务

**本机演示（蜜罐和 AI 在同一台机器）：**

```bash
python -m uvicorn src.api:app --host 127.0.0.1 --port 8000
```

**局域网部署（蜜罐在另一台机器）：**

```bash
python -m uvicorn src.api:app --host 0.0.0.0 --port 8000
```

`--host 0.0.0.0` 表示监听所有网卡，其他机器才能访问。
**这是跨机部署的关键**——如果只写 `127.0.0.1`，别的机器连不上。

> 实测：绑定 `0.0.0.0` 后，通过本机局域网地址（如 `192.168.100.199:8000`）
> 可以正常访问 `/health`。

### 步骤 3：验证服务就绪

```bash
# 本机
curl http://127.0.0.1:8000/health

# 从蜜罐那台机器（换成服务端实际 IP）
curl http://192.168.100.199:8000/health
```

预期返回：

```json
{"status": "ok", "model_loaded": true, "model_path": "..."}
```

`model_loaded: true` 说明模型已加载，可以开始调用。

**若连不上，按顺序排查：**

| 现象 | 原因 | 处理 |
|---|---|---|
| `Connection refused` | 服务没起，或端口不对 | 检查启动命令与端口 |
| 本机能通、其他机器不通 | 用了 `127.0.0.1` 而非 `0.0.0.0` | 改用 `--host 0.0.0.0` 重启 |
| 其他机器也不通 | 防火墙拦截 | 放行该端口，或改用同机部署 |
| `/health` 返回 503 | 模型文件缺失 | 检查 `models/attack_model.pkl` 是否存在 |

---

## 三、蜜罐侧调用方式

### 最少代码（标准库，零依赖）

```python
import json
import urllib.error
import urllib.request

AI_URL = "http://192.168.100.199:8000"   # 换成服务端实际地址
TIMEOUT = 3.0                             # 建议 2~3 秒，别拖慢蜜罐响应


def ai_detect(path="", query="", body="", user_agent="", ip="", session_id=""):
    """调用 AI 检测服务。失败返回 None，调用方必须做降级处理。"""
    payload = {
        "path": path,
        "query": query,
        "body": body,
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
        print(f"[WARN] AI 服务不可用({e})，本次跳过 AI 特征")
        return None      # ★ 必须降级，不能因为 AI 挂了影响蜜罐
```

### 接入到风险评分

```python
sig = ai_detect(path=path, query=query, body=body,
                user_agent=ua, ip=client_ip, session_id=sid)

if sig is not None:
    risk_score += sig["ai_points"]         # AI 作为一维特征累加（0~25）
    if sig["is_attack"]:
        signals.append(f"AI判定: {sig['attack_type']}"
                       f"(+{sig['ai_points']})")
    for r in sig["reasons"]:
        signals.append(f"AI: {r}")

# 原有双阈值逻辑不变
is_suspicious = risk_score >= 20
high_risk = risk_score >= 40
```

---

## 四、注意事项

### 1. 必须保留降级分支

AI 服务不可用时（没启动、网络不通、超时），蜜罐要**照常工作**，
只是少一维特征。不要因为 AI 挂了就报错或阻塞。

### 2. 超时设短

建议 2~3 秒。AI 服务响应通常几十毫秒，但异常时不能拖慢蜜罐。

### 3. 不要用 `confidence` 做攻击阈值门控

| 字段 | 含义 | 用途 |
|---|---|---|
| `attack_prob` | **属于攻击的概率** | ✅ 做阈值门控用这个 |
| `ai_points` | 建议累加分值（= `attack_prob × 25`） | ✅ 直接累加 |
| `confidence` | 判定类别的**确定性** | ❌ **不要**用它做攻击门控 |

原因：`confidence` 在规则命中时恒为 `0.99`，**包括最终判定为 normal 的样本**。
用它做「>90% 就以 AI 为准」会导致真攻击被放行。

### 4. 敏感文件名单独出现时刻意不告警

例如 `/id_rsa` 命中规则 +15，模型只给 4 分，累加 19——**差 1 分不到可疑线**。

这是**刻意的设计**，与你们权重表一致（敏感路径探测 +15，单独不足以定性）。
这类弱信号需与请求头异常、访问频率、会话累积等其他信号叠加才会告警。

### 5. `/phpmyadmin`、`/console` 判定为敏感路径

这两个**未加入白名单**（总分 24~36），因为访问数据库管理入口通常是侦察行为。
如果你们认为属于正常运维路径，告知我们，可加入白名单。

---

## 五、常用命令速查

```bash
# 启动（局域网部署）
python -m uvicorn src.api:app --host 0.0.0.0 --port 8000

# 探活
curl http://<服务端IP>:8000/health

# 交互式接口文档（浏览器打开，可直接试接口）
http://<服务端IP>:8000/docs

# 查看服务信息与最小请求示例
http://<服务端IP>:8000/

# 最小调用示例
curl -X POST http://<服务端IP>:8000/api/v1/detect \
  -H "Content-Type: application/json" \
  -d '{"path":"/search","query":"id=1 and 1=1"}'
```

---

## 六、接口速查

| 方法 | 路径 | 用途 |
|---|---|---|
| POST | `/api/v1/detect` | **★ 唯一需要对接的接口** |
| GET | `/health` | 探活（启动前建议先调这个） |
| GET | `/model/info` | 查看模型版本与支持的类别 |
| GET | `/docs` | 交互式接口文档 |
| GET | `/` | 服务信息与最小请求示例 |

以下为**内部调试接口**，蜜罐侧无需了解，也不属于对外契约：

`/predict`、`/predict/signal`、`/predict/batch`

---

## 七、模型更新对你们的影响

**没有影响。** 模型重训后只需在我们这边替换 `models/attack_model.pkl`
并重启服务，蜜罐侧**代码不用改**，接口字段不变。

你们可以通过 `/model/info` 查看当前生效的模型版本：

```json
{"version": "v2", "trained_at": "2026-10-14 16:54:41", "labels": [...]}
```

**建议**：如果发现误报或漏报，把**原始请求样本**回传给我们。
我们建立了增量样本流程，可快速重训；真实流量样本比任何公开数据集都有价值。
