# API 文档

本文档面向答辩演示和二次开发，说明本项目主要 HTTP 接口。项目由三类入口组成：

- **Dashboard 管理端**：真实管理与态势展示接口，默认 `http://127.0.0.1:5001`
- **Web 蜜罐**：诱饵站点、诱饵后台和攻击探测接口，默认 `http://127.0.0.1:5000`，实际以 `honeypot.ini` 为准
- **SSH 蜜罐**：SSH 协议服务，默认 `127.0.0.1:2222`，不是 HTTP API

> 说明：Web 蜜罐中的 `/admin` 是诱饵后台；Dashboard 的真实登录入口是 `/super/login`。

## 1. 通用约定

### 1.1 配置来源

运行地址、端口、管理员账号、数据库和告警配置集中在根目录 `honeypot.ini`，模板为 `honeypot.ini.example`。读取顺序为：

1. 环境变量
2. `honeypot.ini`
3. 代码默认值

### 1.2 Dashboard JSON 响应格式

Dashboard API 通常返回：

```json
{
  "code": 0,
  "msg": "success",
  "data": {}
}
```

常见 `code`：

| code | 含义 |
| --- | --- |
| `0` | 成功 |
| `-1` | 服务异常 |
| `403` | 未登录、权限不足或 CSRF 校验失败 |
| `429` | 请求过于频繁 |

### 1.3 Dashboard 鉴权

Dashboard API 需要先登录：

- 登录页：`GET /super/login`
- 登录提交：`POST /super/login`
- 登录账号：`honeypot.ini` 的 `[admin] user/password`

登录成功后通过浏览器 Cookie 维持会话。直接调用 API 时，需要携带同一会话 Cookie。

---

## 2. Dashboard 管理端接口

默认地址：`http://127.0.0.1:5001`

### 2.1 页面接口

| 方法 | 路径 | 说明 | 鉴权 |
| --- | --- | --- | --- |
| `GET` | `/` | 重定向到 `/dashboard` | 需要登录 |
| `GET` | `/super/login` | Dashboard 登录页 | 不需要 |
| `POST` | `/super/login` | 提交 Dashboard 登录 | 不需要，需 CSRF |
| `GET` | `/dashboard` | 态势感知主页面 | 需要登录 |
| `GET` | `/logout` | 跳转到登录页，不执行登出 | 不需要 |
| `POST` | `/logout` | 登出 | 需要登录，需 CSRF |
| `GET` | `/favicon.ico` | 图标 | 不需要 |

### 2.2 事件日志列表

```http
GET /api/get_event_logs
```

查询参数：

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `limit` | `100` | 返回条数 |
| `offset` | `0` | 偏移量 |
| `hours` | 空 | 时间窗口，单位小时 |
| `source` | 空 | 来源筛选，如 `web`、`ssh` |
| `severity` | 空 | 风险级别筛选，如 `low`、`medium`、`high`、`critical` |
| `event_type` | 空 | 事件类型 |
| `q` | 空 | 关键词搜索 |

返回 `data` 为事件数组，常见字段：

| 字段 | 说明 |
| --- | --- |
| `timestamp` | 事件时间 |
| `source` | 来源，如 `web`、`ssh`、`dashboard` |
| `severity` | 风险级别 |
| `event_type` | 事件类型 |
| `src_ip` | 来源 IP |
| `session_id` | 会话标识 |
| `tags` | 标签 |
| `payload` | 事件摘要 |
| `raw_ref` | 原始引用 |
| `raw_request_id` | 关联 HTTP 原始请求 ID |
| `extra` | 扩展字段 |
| `location` | 地理位置展示文本 |

示例：

```bash
curl -b cookies.txt "http://127.0.0.1:5001/api/get_event_logs?limit=20&hours=24&source=web"
```

### 2.3 事件统计

```http
GET /api/get_event_stats
```

查询参数：

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `hours` | `24` | 统计窗口，单位小时 |

返回 `data` 常见字段：

| 字段 | 说明 |
| --- | --- |
| `total` | 事件总量 |
| `unique_ips` | 独立来源 IP 数 |
| `by_source` | 按来源聚合 |
| `by_severity` | 按风险级别聚合 |
| `top_ips` | Top IP 列表 |
| `top_event_types` | Top 事件类型 |
| `top_tags` | Top 标签 |

### 2.4 地理分布

```http
GET /api/get_geo_data
```

查询参数：

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `hours` | `24` | 时间窗口，单位小时 |
| `focus_ip` | 空 | 指定聚焦 IP |
| `limit` | 自动 | 返回数量上限，服务端会限制在合理范围内 |

返回 `data` 为 IP 地理分布数组，常见字段包括 `src_ip`、`location`、`latitude`、`longitude`、`count`。

### 2.5 实时事件

```http
GET /api/realtime
```

返回最近 5 条事件，用于前端实时刷新。

### 2.6 服务器信息

```http
GET /api/server_info
```

查询参数：

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `include_system` | `1` | 是否包含系统信息 |

返回服务器基础信息和可选系统信息。

### 2.7 系统状态

```http
GET /api/system_status
```

返回 CPU、内存、磁盘等运行状态。

### 2.8 可疑请求列表

```http
GET /api/suspicious_requests
```

查询参数：

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `hours` | `24` | 时间窗口，单位小时 |
| `limit` | 自动 | 返回数量上限 |

返回可疑 Web 请求和 SSH 可疑命令聚合后的列表，常见字段包括：

- `session_id`
- `src_ip`
- `method`
- `path`
- `query_string`
- `headers`
- `body`
- `user_agent`
- `referer`
- `content_type`
- `threat_score`
- `risk_level`
- `panel_level`
- `location`

### 2.9 会话行为分析

```http
GET /api/session_analysis
```

查询参数：

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `hours` | `24` | 时间窗口，单位小时 |
| `limit` | 自动 | 返回数量上限 |
| `min_count` | 自动 | 最小行为数量 |

返回按会话聚合的攻击链分析，常见字段包括 `session_id`、`src_ip`、`path_sequence`、`path_steps`、`threat_level`、`chain_type`。

### 2.10 管理端登录审计

```http
GET /api/login_audit
```

返回 Dashboard 登录审计信息：

| 字段 | 说明 |
| --- | --- |
| `recent` | 最近登录/登出/失败记录 |
| `top_failed` | 失败次数较多的来源 IP |

### 2.11 密标接口

密标用于对风险对象（来源 IP / 会话 / 账号）打持久化标记，模块说明见 [risk_mark/README.md](risk_mark/README.md)。

统一前缀 `/api/risk_mark`，均需登录态；`POST` 接口需要携带 `X-CSRF-Token`。响应格式同其他 Dashboard API。

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` | `/api/risk_mark/meta` | 枚举元数据：对象类型、密级、状态、识别器清单、配置 |
| `GET` | `/api/risk_mark/summary` | 密标总数、密级分布、识别器清单 |
| `GET` | `/api/risk_mark/list` | 密标列表 |
| `GET` | `/api/risk_mark/check` | 查询对象是否已标注 |
| `POST` | `/api/risk_mark/create` | 新增或覆盖密标 |
| `POST` | `/api/risk_mark/remove` | 移除密标 |
| `POST` | `/api/risk_mark/scan` | 运行风险识别器，生成建议 / 自动落标 |
| `GET` | `/api/risk_mark/detectors` | 已注册风险识别器列表 |

`/list` 查询参数：

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `target_type` | 空 | 对象类型筛选，如 `ip`、`session`、`account` |
| `level` | 空 | 密级筛选，如 `low`、`medium`、`high`、`critical` |
| `status` | `active` | 状态筛选，`active` / `expired`；留空返回全部 |
| `q` | 空 | 关键词，匹配对象值 / 原因 / 密标编号 / 操作人 |
| `limit` | `200` | 返回条数，上限 500 |
| `offset` | `0` | 偏移量 |

`/check` 支持两种用法：

```bash
# 单个查询
curl -b cookies.txt "http://127.0.0.1:5001/api/risk_mark/check?target_type=ip&target_value=203.0.113.10"
# 批量查询（供事件列表批量打标）
curl -b cookies.txt "http://127.0.0.1:5001/api/risk_mark/check?targets=ip:203.0.113.10,ip:198.51.100.2"
```

`/create` 请求体（JSON 或表单）：

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| `target_type` | 否 | 默认 `ip`，可选 `ip` / `session` / `account` |
| `target_value` | 是 | 标注对象值 |
| `level` | 否 | 密级，默认 `medium` |
| `reason` | 否 | 标注原因 |
| `mark_code` | 否 | 密标编号 |
| `ttl_days` | 否 | 有效期天数，`0` 表示长期有效 |
| `expires_at` | 否 | 直接指定到期时间（优先于 `ttl_days`） |
| `created_by` | 否 | 操作人，默认取当前登录账号 |

`/remove` 请求体：传 `id`，或传 `target_type` + `target_value`。

`/scan` 请求体：`hours`（默认 24）、`limit`、`apply`（是否直接落标，默认取 `[risk_mark] auto_detect_apply`）。

> 密标自动识别默认关闭（`[risk_mark] auto_detect_enabled = false`），`/scan` 为人工触发入口，不受该开关限制。

---

## 3. Web 蜜罐接口

默认地址：`http://127.0.0.1:5000`，实际端口以 `honeypot.ini` 的 `[services.web] port` 为准。

Web 蜜罐接口用于模拟企业站点、后台系统、敏感路径和攻击入口。它们的主要作用是**记录探测和攻击行为**，不是给真实业务系统使用。

### 3.1 公共页面

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` | `/` | 首页 |
| `GET` | `/about` | 关于页面 |
| `GET` | `/products` | 产品列表 |
| `GET` | `/products/<slug>` | 产品详情 |
| `GET` | `/solutions` | 方案列表 |
| `GET` | `/solutions/<slug>` | 方案详情 |
| `GET` / `POST` | `/contact` | 联系我们；POST 会记录咨询行为 |
| `POST` | `/subscribe` | 订阅入口；会记录订阅行为 |
| `GET` | `/news` | 新闻列表或详情；`id` 参数会进入检测流程 |
| `GET` | `/search` | 站内搜索；`q`/`keyword` 参数会进入检测流程 |
| `GET` | `/page` | 内容页入口；`page`/`file` 参数会进入文件包含检测流程 |
| `GET` | `/robots.txt` | 爬虫规则，包含诱饵路径 |
| `GET` | `/sitemap.xml` | 站点地图 |
| `GET` | `/favicon.ico` | 图标 |

常见测试示例：

```bash
curl "http://127.0.0.1:5000/search?q=test"
curl "http://127.0.0.1:5000/news?id=1"
```

### 3.2 诱饵后台页面

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` / `POST` | `/admin` | 诱饵后台登录页；成功登录使用动态诱饵凭证 |
| `GET` | `/admin/dashboard` | 诱饵后台首页 |
| `GET` / `POST` | `/admin/logout` | 诱饵后台退出 |
| `GET` | `/admin/preview?id=<id>` | 内容预览 |
| `POST` | `/admin/backup` | 备份导出陷阱 |
| `GET` / `POST` | `/admin/upload` | 配置包上传陷阱 |
| `GET` / `POST` | `/admin/login` | 常见后台登录探测入口 |
| `GET` / `POST` | `/admin/signin` | 常见后台登录探测入口 |
| `GET` / `POST` | `/admin/index.php` | 常见后台登录探测入口 |
| `GET` | `/admin/<path>` | 后台子路径探测 |

> `/admin` 的账号口令是 Web 蜜罐启动时动态生成的诱饵凭证，不等于 Dashboard 的真实管理员密码。

### 3.3 诱饵后台 JSON 接口

这些接口服务于诱饵后台页面，登录后通过 Cookie 访问。

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` | `/admin/api/me` | 当前诱饵后台用户信息 |
| `GET` | `/admin/api/access_logs` | 诱饵后台访问日志，支持分页和关键词 |
| `GET` | `/admin/api/settings` | 诱饵后台设置 |
| `GET` | `/admin/api/content` | 诱饵内容列表，支持分页和关键词 |
| `GET` | `/admin/api/users` | 诱饵用户列表，支持分页和关键词 |
| `POST` | `/admin/api/submit_change` | 提交后台变更；需要 CSRF |
| `GET` | `/admin/audit/log` | 审计日志诱饵入口 |
| `POST` | `/admin/api/login` | 后台 API 登录探测，始终按诱饵逻辑响应 |
| `POST` | `/admin/api/auth/login` | 后台 API 登录探测，始终按诱饵逻辑响应 |

分页接口常见参数：

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `page` | `1` | 页码 |
| `page_size` | `20` | 每页数量 |
| `q` | 空 | 搜索关键词 |

### 3.4 高危路径与敏感文件陷阱

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` / `POST` | `/backup/`、`/backup/<path>` | 备份目录探测 |
| `GET` / `POST` | `/admin_v2/`、`/admin_v2/<path>` | 旧后台路径探测 |
| `GET` | `/.env` | 环境文件探测 |
| `GET` | `/.git/config` | Git 配置探测 |
| `GET` | `/uploads/`、`/uploads/<path>` | 上传目录探测 |
| `GET` | `/old/`、`/old/<path>` | 历史站点目录探测 |
| `GET` | `/backup.zip` | 备份压缩包探测 |
| `GET` | `/www.zip` | 站点压缩包探测 |
| `GET` | `/dump.sql` | 数据库导出文件探测 |
| `GET` | `/config.php~` | 临时配置文件探测 |
| `GET` | `/config.bak` | 备份配置文件探测 |

这些路径会产生高危探测事件，用于 Dashboard 展示和统计。

---

## 4. SSH 蜜罐接口

SSH 蜜罐不是 HTTP API，而是 SSH 协议服务。

默认连接方式：

```bash
ssh root@127.0.0.1 -p 2222
```

实际地址和端口以 `honeypot.ini` 的 `[services.ssh] host/port` 为准。

SSH 蜜罐会记录：

- 登录成功/失败
- 暴力破解行为
- 命令执行行为
- 可疑命令
- SCP 上传捕获
- 会话轨迹

诱饵 SSH 凭证在启动时动态生成；如需在启动摘要中展示，可配置：

```ini
[app]
show_summary_creds = true
emit_credential_lines = true
```
