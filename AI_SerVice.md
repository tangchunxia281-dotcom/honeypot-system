# AI 攻击检测服务接入与联调说明

## 1. 接入结论

蜜罐接入 AI 组最新版请求级攻击检测服务：

```http
POST /api/v1/detect
```

AI 服务由 Docker 部署（镜像 `xss-detector:2.0.0`，默认发布 8000 端口）：

```text
http://127.0.0.1:8000          # 同机调用
http://<Docker宿主机IP>:8000    # 蜜罐在其他设备
```

蜜罐只通过 HTTP 调用，**不需要本地模型目录、虚拟环境或 scikit-learn 依赖**。

AI 不直接覆盖蜜罐最终结论，而是返回 `ai_points`，由蜜罐累加到规则分数。

## 2. 请求契约

```json
{
  "path": "/search",
  "query": "q=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
  "body": "",
  "method": "GET",
  "user_agent": "curl/8.0",
  "source": "web",
  "ip": "1.2.3.4",
  "session_id": "abc123",
  "extra": {
    "request_id": "raw_request:25"
  }
}
```

字段说明：

| 字段 | 必填 | 说明 |
|------|------|------|
| `path` | 条件 | 请求路径，通常建议提供 |
| `query` | 条件 | URL 查询串 |
| `body` | 条件 | 请求体原文或受限摘要 |
| `method` | 否 | GET、POST 等 |
| `user_agent` | 否 | 扫描器识别需要 |
| `source` | 否 | 固定为 `web` |
| `ip` | 否 | 来源 IP |
| `session_id` | 否 | 蜜罐会话 ID |
| `extra.request_id` | 否 | 关联 `raw_request.id` |

`path`、`query`、`body` 至少提供一个。

## 3. 响应契约

```json
{
  "attack_type": "xss",
  "is_attack": true,
  "attack_prob": 0.97,
  "ai_points": 24,
  "confidence": 0.99,
  "high_risk": false,
  "reasons": [
    "[query.q] 规则命中 XSS"
  ],
  "signals": [
    {
      "field": "query.q",
      "value": "<script>alert(1)</script>",
      "attack_type": "xss",
      "attack_prob": 0.97,
      "ai_points": 24,
      "fusion_score": 43,
      "high_risk": true,
      "reason": "规则命中 XSS"
    }
  ],
  "model_label": "xss",
  "source": "web",
  "ip": "1.2.3.*",
  "session_id": "abc123"
}
```

支持的攻击类型：

```text
xss
sqli
path_traversal
sensitive_path
scanner
normal
```

## 4. 最终分数融合

蜜罐原规则给出 `rule_score`，AI 给出 `ai_points`。

```python
final_score = min(100, rule_score + ai_points)
if ai_result.is_attack:
    final_score = max(final_score, 20)
if ai_result.high_risk:
    final_score = max(final_score, 40)
final_suspicious = final_score >= 20
```

双阈值下界的作用：

```text
AI 明确 is_attack=true
-> 最终至少 20 分，避免因两套规则差异漏掉攻击

AI 明确 high_risk=true
-> 最终至少 40 分，保留 AI 高危结论
```

示例：

```text
原规则：15 分
AI 建议：+24 分
最终：39 分
```

20 到 39 分进入可疑事件，40 分以上进入高危。

AI 不再执行：

```text
AI 判定 XSS -> 直接覆盖为 60 分
AI 判定 normal -> 直接覆盖为 0 分
```

## 5. 蜜罐侧代码

### 5.1 `utils/ai_client.py`

主要职责：

- 构造 `/api/v1/detect` 请求。
- 发送 `path`、`query`、`body`、`method`、`user_agent`。
- 传递 `source`、`ip`、`session_id` 和 `request_id`。
- 校验 `attack_type`、`is_attack`、`attack_prob`、`ai_points` 等字段。
- 对敏感键值进行二次遮蔽。
- 处理超时、连接失败、非 JSON 和字段异常。
- 连续失败后进入退避。

核心函数：

```python
detect_request(
    path,
    query,
    body,
    method,
    user_agent,
    source,
    ip,
    session_id,
    request_id
)
```

### 5.2 `db/http_requests.py`

接入位置：

```text
INSERT raw_request
-> 得到 raw_request_id
-> 调用 AI /api/v1/detect
-> final_score = rule_score + ai_points
-> 更新 raw_request
-> 更新 session_track
-> 可疑时写入 event_log
```

AI 结果示例：

```json
{
  "attack_type": "xss",
  "is_attack": true,
  "attack_prob": 0.97,
  "ai_points": 24,
  "confidence": 0.99,
  "high_risk": false,
  "reasons": ["[query.q] 规则命中 XSS"],
  "signals": [],
  "model_label": "xss"
}
```

### 5.3 `event_log.extra`

事件扩展字段：

```json
{
  "rule": {
    "score": 15,
    "is_suspicious": false
  },
  "ai": {
    "attack_type": "xss",
    "is_attack": true,
    "attack_prob": 0.97,
    "ai_points": 24,
    "confidence": 0.99,
    "high_risk": false,
    "reasons": [],
    "signals": [],
    "model_label": "xss"
  },
  "ai_applied": true,
  "ai_points": 24,
  "final_source": "rule+ai",
  "score": 39
}
```

`final_source` 可能值：

```text
rule
rule+ai
```

## 6. Dashboard 展示

实时攻击日志会显示：

```text
AI XSS +24
AI SQLI +22
AI PATH_TRAVERSAL +20
AI SENSITIVE_PATH +15
AI SCANNER +18
AI NORMAL +0
```

悬停详情显示：

- AI 判定类型。
- AI 攻击概率。
- AI 加分。
- AI 置信度。
- AI 原因列表。
- 模型标签。
- 最终判定来源。

蜜罐原规则仍保留在事件 `extra.rule` 中。

## 7. 配置

`honeypot.ini`（Docker 模式下只需要 HTTP 地址，不需要本地模型路径）：

```ini
[ai]
enabled = true
url = http://127.0.0.1:8000/api/v1/detect
info_url = http://127.0.0.1:8000/model/info
timeout = 2.0
text_max = 5000
failure_threshold = 3
backoff_seconds = 30
model_info_ttl = 300
```

跨设备部署时把 `127.0.0.1` 换成 Docker 宿主机 IP，或用环境变量临时覆盖
（环境变量优先级最高）：

```powershell
$env:AI_XSS_URL = 'http://192.168.31.41:8000/api/v1/detect'
$env:AI_XSS_INFO_URL = 'http://192.168.31.41:8000/model/info'
```

旧模式（主控拉起本地模型子进程）仍保留，但默认关闭：

```ini
[services.ai_detect]
enabled = false
# path = C:\path\to\xss_detector
# python =
host = 127.0.0.1
port = 8003
```

## 8. 启动 AI 服务

### 8.1 推荐：Docker 托管

在模型项目（xss_detector）目录执行：

```powershell
docker compose up -d --build
curl.exe http://127.0.0.1:8000/health
```

`/health` 返回 `"model_loaded": true` 即可。Docker Desktop 已配置开机自启、
容器 `restart=unless-stopped`，重启后会自动恢复；构建、日志、跨机分发见
xss_detector 的 `DOCKER.md`。

**设备 B 离线部署（蜜罐与检测服务同机）**：在构建机 `docker save` 导出镜像 tar，
设备 B `docker load` 后 `docker run -p 8000:8000` 即可，蜜罐地址保持
`http://127.0.0.1:8000`，不需要源码和 Python 环境。详细步骤见 `DOCKER.md` §9.1。

启动蜜罐时，主控会自动探活该地址并在启动摘要中显示：

```text
> [AI攻击检测·Docker] 请求级攻击检测模型（规则 + ai_points 融合）
  http://127.0.0.1:8000/api/v1/detect
  状态: 在线｜模型 v2（2026-10-22 18:49:38）
```

### 8.2 跨设备连通性自检

在蜜罐所在设备（或任意一台能访问 Docker 宿主机的机器）上执行：

```powershell
python scripts/check_ai_service.py
python scripts/check_ai_service.py --url http://192.168.31.41:8000
```

脚本会检查 `/health`、`/model/info`，并跑 XSS / SQLi / 目录穿越 / 正常 四类用例。

### 8.3 旧模式：随主控本地启动（已弃用）

仅在没有 Docker 时使用：`[services.ai_detect] enabled = true` 并配置
`path`/`python`，主控会拉起 `uvicorn src.api:app`（默认 8003），同时把
`[ai] url` 指回 8003。需要本地虚拟环境：

```powershell
cd C:\Users\ADMIN\Desktop\xss_detector
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
```

### 8.4 手动启动（调试用，本地模式）

```powershell
cd C:\Users\ADMIN\Desktop\xss_detector
.venv\Scripts\python.exe -m uvicorn src.api:app --host 127.0.0.1 --port 8003
```

## 9. 启动蜜罐

另开终端（路径换成你的蜜罐项目目录）

```powershell
cd C:\Users\ADMIN\Desktop\honeypot-system-main finishi1
uv run python main.py
```

发送 XSS 请求：

```powershell
Invoke-WebRequest `
  -Uri 'http://127.0.0.1:5000/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E' `
  -UseBasicParsing
```

预期：

```text
raw_request 记录原始请求
AI 返回 xss
ai_points > 0
final_score = 原规则分 + ai_points
最终可疑时写入 event_log
event_log.raw_request_id 指向 raw_request.id
Dashboard 显示 AI XSS +N
```

## 10. 失败回退

以下情况保留原规则结果：

```text
AI 服务未启动
连接失败
请求超时
HTTP 非 2xx
响应不是 JSON
attack_type 非法
attack_prob 超范围
ai_points 超范围
字段缺失
attack_type 与 is_attack 矛盾
```

失败不会影响：

```text
raw_request
session_track
原规则 event_log
诱饵响应
```

## 11. 联调顺序

1. 启动 AI 服务。
2. 访问 `/health` 确认模型加载。
3. 访问 `/model/info` 确认模型版本。
4. 直接调用 `/api/v1/detect`。
5. 启动蜜罐。
6. 触发 XSS、SQLi、路径穿越、敏感路径和扫描器请求。
7. 检查 `raw_request`、`event_log` 和 `event_log.extra.ai`。
8. 登录 Dashboard，确认实时日志出现 AI 类型和加分标签。
9. 停止 AI 服务，确认蜜罐回退规则且不中断。
