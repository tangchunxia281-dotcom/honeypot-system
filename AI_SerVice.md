# AI 攻击检测服务接入与联调说明

## 1. 接入结论

蜜罐接入 AI 组最新版请求级攻击检测服务：

```http
POST /api/v1/detect
```

AI 服务目录：

```text
D:\train-ai\xss_detector\xss_detector
```

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

`honeypot.ini`：

```ini
[ai]
enabled = true
url = http://127.0.0.1:8003/api/v1/detect
info_url = http://127.0.0.1:8003/model/info
timeout = 2.0
text_max = 5000
failure_threshold = 3
backoff_seconds = 30
model_info_ttl = 300
```

检测服务进程由主控一起管理：

```ini
[services.ai_detect]
enabled = true
# 模型服务根目录（含 src/api.py 与 models/）
path = C:\Users\ADMIN\Desktop\xss_detector
# 留空时自动使用 <path>\.venv\Scripts\python.exe，再退回到主控解释器
python =
host = 127.0.0.1
port = 8003
```

## 8. 启动 AI 服务

### 8.1 推荐：随主控自动启动

`main.py` 会按 `[services.ai_detect]` 拉起检测服务（与 SSH/Web/Dashboard 同级，
崩溃自动重启），启动摘要中会显示：

```text
> [AI攻击检测] 请求级攻击检测模型（规则 + ai_points 融合）
  http://127.0.0.1:8003/health
  http://127.0.0.1:8003/model/info
```

首次准备（只需一次，为模型目录创建独立虚拟环境）：

```powershell
cd C:\Users\ADMIN\Desktop\xss_detector
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
# 依赖下载慢时可用镜像：
# uv pip install --python .venv\Scripts\python.exe -r requirements.txt `
#   --index-url https://pypi.tuna.tsinghua.edu.cn/simple
```

然后正常启动蜜罐即可：`uv run python main.py`。

### 8.2 手动启动（调试用）

```powershell
cd C:\Users\ADMIN\Desktop\xss_detector
.venv\Scripts\python.exe -m uvicorn src.api:app --host 127.0.0.1 --port 8003
```

关闭主控中的自动启动：`[services.ai_detect] enabled = false`，再把 `[ai] enabled`
改为 `false`（或保留 `[ai] enabled = true` 指向外部已启动的服务）。

## 9. 启动蜜罐

另开终端

```powershell
cd D:\honeypot
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
