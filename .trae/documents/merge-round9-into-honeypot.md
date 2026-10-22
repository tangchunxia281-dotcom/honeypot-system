# 合并 round 9 功能到当前蜜罐项目

## Context

round 9 (`C:\Users\ADMIN\Desktop\round 9\honeypot-investigation-full-20261011\honeypot`) 是蜜罐项目的另一个独立演化分支，提供以下当前项目没有的能力：

- **团队数据中心**（team_center/ + utils/team_collector.py + utils/team_store.py）：多设备证据汇聚、成员/设备令牌管理、独立登录、采集端 outbox 持久队列
- **AI 智能调查**（utils/active_investigation.py + attack_story.py + ai_analyst.py + investigations.py + evidence_selection.py + periodic_analysis.py）：主动补查、攻击故事线、带证据问答、周期分析
- **AI 网关与本地模型**（ai_gateway/ + utils/local_ai.py + ai_settings.py + ai_store.py + gateway_client.py）：Ollama 接入 + 多成员共享推理网关
- **AI 检测与交互增强**（utils/ai_detection.py + ai_interaction.py + ai_effectiveness.py + evaluation.py + decoy_profiles.py）：AI 检测、SSH/Web 诱饵交互、效果面板

当前项目独有：多协议蜜罐（db/file/remote_honeypot）、风险目标标注（db/risk_targets.py）、远程 AI XSS 检测（utils/ai_client.py）、protocol_guard 治理层。需全部保留。

## 用户决策

1. 合并全部 4 组功能
2. 合并全部 scripts
3. **保留当前项目的远程 AI 检测服务**（utils/ai_client.py 不动）；**round 9 合并进来的 AI 功能改为调用 DeepSeek API**（OpenAI 兼容协议），不再依赖本地 Ollama
4. **不动现有 ssh_honeypot / web_honeypot**：AI 交互模块（utils/ai_interaction.py、decoy_profiles.py 等）仅作为代码与 dashboard 展示层引入，处于"备用"状态；现有诱骗响应逻辑完全保留。这意味着 AI 交互能力初期只能通过 dashboard 的 AI 交互记录页面观察历史数据，新会话不会实时触发 AI 响应（后续需要时再做接线）
5. **Python 升级到 >=3.11**：跟随 round 9，pyproject.toml 的 `requires-python` 改为 `">=3.11"`

## 合并策略总览

round 9 与当前项目有 6 个共同文件已分叉（main.py、app_config.py、dashboard/server.py、db/event_logs.py、db/http_requests.py、utils/alerting.py），不能整体覆盖。采用**"新增文件直接拷贝 + 分叉文件选择性合并"**策略。

DeepSeek 适配点集中在 `utils/ai_settings.py` 与 `utils/local_ai.py` 两处，新增 `provider=deepseek` 分支，保持原 Ollama/local/gateway 分支兼容；`ai_gateway/server.py` 同步将转发目标从 Ollama 改为 DeepSeek。

## 实施步骤

### 第 1 步：整目录直接拷贝（无冲突新增）

从 round 9 拷贝以下完整目录/文件到当前项目对应位置，均为新增、不覆盖现有文件：

- `team_center/` 整个目录（server.py、store.py、jobs.py、api.py、auth.py、templates/center.html、static/center.js + center.css）
- `ai_gateway/` 整个目录（server.py）
- `evaluation/fixtures.jsonl`
- `scripts/` 下全部文件（含 demo/、system_test/ 子目录、所有 test_*.py / verify_*.py / accept_*.py / deploy.py / team_center.py / setup_local.py / mixed_attack_demo.py / replay_strategy_comparison.py 等约 40 个）。当前项目 scripts/ 只有少量文件，需要先备份当前 scripts/ 内容再合并
- `ai.local.ini.example`（后续改造为 DeepSeek 配置模板）
- `dashboard/templates/` 下新增模板：`ai.html`、`ai_analysis.html`、`ai_detection.html`、`ai_interactions.html`、`ai_sidebar.html`、`ai_team.html`、`investigations.html`（不覆盖现有 admin_login.html、dashboard.html）
- `dashboard/static/js/` 下新增 JS：`ai.js`、`ai_analysis.js`、`ai_dashboard_summary.js`、`ai_detection.js`、`ai_interactions.js`、`ai_shell.js`、`ai_team.js`、`investigations.js`、`panel_updates.js`、`source_links.js`（不覆盖现有 dashboard.js、world_map.js 等）

### 第 2 步：拷贝 utils 新增模块（20 个，全部为新文件）

从 round 9 的 utils/ 拷贝以下文件到当前 utils/（当前项目没有同名文件，直接新增）：

`active_investigation.py`、`ai_analyst.py`、`ai_analyst_store.py`、`ai_detection.py`、`ai_detection_store.py`、`ai_effectiveness.py`、`ai_interaction.py`、`ai_interaction_store.py`、`ai_settings.py`、`ai_store.py`、`attack_story.py`、`decoy_profiles.py`、`evaluation.py`、`evidence_selection.py`、`gateway_client.py`、`investigations.py`、`local_ai.py`、`periodic_analysis.py`、`team_collector.py`、`team_store.py`、`alert_noise.py`、`markdown_export.py`

**不拷贝** round 9 的 `alerting.py`、`ip_location.py`、`logger.py`、`http_fingerprint.py`、`net.py`（当前项目已有版本，功能一致或更全）。

### 第 3 步：DeepSeek API 适配（核心改造）

**文件：utils/ai_settings.py**
- 新增配置项读取：`api_key`（必填）、`deepseek_base_url`（默认 `https://api.deepseek.com`）、`deepseek_model`（默认 `deepseek-chat`）
- `provider` 允许值扩展为 `local / gateway / deepseek`
- 当 `provider=deepseek` 时：校验 `api_key` 形如 `sk-[A-Za-z0-9]{20,}`，`base_url` 必须为 `https://`；跳过 Ollama 的 loopback 校验
- 保持原有 local/gateway 校验逻辑不变

**文件：utils/local_ai.py**
- `_transport` 新增 `provider=='deepseek'` 分支：POST `{base_url}/v1/chat/completions`，Header `Authorization: Bearer {api_key}`，Body 遵循 OpenAI 协议：`{"model": ..., "messages": ..., "response_format": {"type":"json_object"}, "temperature": 0.2, "max_tokens": ..., "stream": false}`
- 响应解析：从 `choices[0].message.content` 取 JSON 字符串，后续 schema 校验逻辑复用现有代码；`model_timing` 从 `usage` 字段映射（prompt_tokens→prompt_ms 不适用则置 None，仅保留 total_tokens 等可映射字段）
- `health()` 新增 deepseek 分支：GET `{base_url}/v1/models` 校验 api_key 可用性，缓存 5 秒逻辑不变
- DeepSeek 有速率限制，`concurrency` 默认保持 1，`timeout` 默认建议调高到 30（DeepSeek 推理较慢）；在 ai_settings 中对 deepseek 单独默认 timeout=30

**文件：ai_gateway/server.py**
- `Gateway.__init__` 的 `url` 参数校验当前强制 loopback，改为：当 URL scheme 为 `https` 时允许外部主机（DeepSeek），`http` 仍强制 loopback
- `infer` 方法将 Ollama `/api/chat` 调用改为 OpenAI 兼容调用，Header 注入 api_key
- 配置文件读取新增 `provider` 字段；当 `provider=deepseek` 时走 DeepSeek 路径

### 第 4 步：分叉文件选择性合并

**app_config.py**（当前 22KB vs round 9 的 19KB，当前更全）
- 保留当前版本主体
- 在 `_ENV_CONFIG_MAP` 追加 round 9 新增且当前没有的 key，主要集中在：
  - `[team_center]`：host、port、enabled、database、secret、allow_lan_http、ai_config
  - `[ai_gateway]`：enabled、host、port、model、url、capacity、queue_limit、clients_json
  - `[ai_detection]`、`[ai_interaction]`、`[ai_analyst]`、`[ai_investigation]`、`[periodic_analysis]` 的对应开关（参照 round 9 app_config.py 末尾章节）
- 在 `Config` 类补充对应常量

**main.py**（当前 26KB vs round 9 的 25KB）
- 保留当前版本（含 db/file/remote 蜜罐注册）
- 在文件末尾参照 DB_HONEYPOT_ENABLED 模式追加：
  - `_env_bool('TEAM_CENTER_ENABLED', False)` 时注册 team_center serve（script=`team_center/server.py`，独立 host/port，默认 127.0.0.1:5169）
  - `_env_bool('AI_GATEWAY_ENABLED', False)` 时注册 ai_gateway（script=`ai_gateway/server.py`，默认 127.0.0.1:11500）
  - 注意：round 9 的 team_center 实际启动入口在 `scripts/team_center.py`，需要改造为可由 main.py 直接以子进程启动 `team_center/server.py` 的方式（参考 dashboard/server.py 模式）；或者注册为 `python scripts/team_center.py serve` 的子进程

**dashboard/server.py**（当前 40KB vs round 9 的 56KB）
- 保留当前版本（含 risk_targets 全部路由与 protocol_guard 相关状态）
- 从 round 9 追加以下区块（约 16KB 新增）：
  - 文件头 import：`from utils import local_ai, ai_detection, ai_analyst`
  - AI 状态/探针/问答/报告/会话/归档等路由（round 9 行 591-830 附近）
  - AI 页面路由：`/ai/detection`、`/ai/interactions`、`/ai/analysis` 等（round 9 行 906-987 附近）
  - 文件尾部：`from dashboard.team_api import register as register_team_api; register_team_api(app, enhanced_login_required, csrf_protect_api, _ai_safe_endpoint, _chat_owner)` 及 `ai_analyst.start_worker()` 启动逻辑
  - 复用当前项目已有的 `enhanced_login_required`、`csrf_protect_api` 装饰器；`_ai_safe_endpoint`、`_chat_owner` 辅助函数从 round 9 拷贝过来
- 模板上下文：在当前 dashboard.html 顶部导航或侧边栏加入"AI 工作区"分组链接（AI 检测、AI 交互、AI 分析、团队中心），参照 round 9 的 ai_sidebar.html 结构

**dashboard/templates/dashboard.html**
- 保留当前版本（含风险目标标注面板）
- 仅追加 AI 工作区导航入口（一个下拉或链接组），不改动其他结构

**honeypot.ini.example**
- 保留当前版本全部配置节
- 追加 `[team_center]`、`[ai_gateway]`、`[ai_detection]`、`[ai_interaction]`、`[ai_analyst]`、`[periodic_analysis]` 节，key 与 round 9 对齐

**ai.local.ini.example**
- 从 round 9 拷贝后改造：`provider = deepseek`，新增 `api_key = sk-your-key-here`、`deepseek_base_url = https://api.deepseek.com`、`deepseek_model = deepseek-chat`，移除/注释 Ollama 相关的 `base_url = http://127.0.0.1:11434`、`model = maternion/mimo-v2.6:9b`

### 第 5 步：数据库 schema 合并

**database/schema.sql**
- 保留当前已有表（geo_ip、raw_request、event_log、risk_target 等）
- 追加 round 9 的 AI 运行时表（从 round 9 utils/ai_store.py、ai_analyst_store.py、ai_detection_store.py、ai_interaction_store.py、investigations.py 中提取 CREATE TABLE 语句）：`ai_calls`、`ai_detections`、`analyst_evidence`、`analyst_reports`、`analyst_conversations`、`interactions`、`interaction_steps`、`investigations` 等
- 注意：team_center 使用独立的 center.sqlite（在 team_center/store.py 中自建表），不进入主 schema.sql；outbox 在采集端本地 deployment 目录

### 第 6 步：依赖与启动脚本

**pyproject.toml**
- 当前与 round 9 的 dependencies 完全一致（均为 flask/werkzeug/paramiko/pymysql/python-dateutil/psutil/requests/cryptography/bcrypt/pynacl），无需修改
- `requires-python` 从 `>=3.9` 升级为 `>=3.11`（跟随 round 9 语法要求）
- 可选：追加 `waitress>=2.1` 作为生产 WSGI（team_center serve 使用）

**scripts/**
- 当前 scripts/ 目录内容备份后，将 round 9 scripts/ 全部并入
- `scripts/team_center.py`、`scripts/deploy.py`、`scripts/setup_local.py` 等入口脚本的 DeepSeek 配置示例同步更新

### 第 7 步：入口与配置联通验证

- 在 dashboard.html 的"团队数据中心"链接指向 `http://127.0.0.1:5169/`（team_center 独立登录）
- 在 ai.local.ini 中配置真实 DeepSeek api_key 后，访问 dashboard 的 AI 检测/分析页面验证调用
- 启动 main.py 验证所有服务（含新注册的 team_center、ai_gateway）正常拉起

## 关键复用点

- 当前项目 `dashboard/server.py` 的 `enhanced_login_required`、`csrf_protect_api` 装饰器直接复用给新挂载的 team_api 路由
- 当前项目 `db/event_logs.py` 的 `log_event`、`get_event_logs` 接口是 team_center 证据源的读取入口，接口签名与 round 9 完全一致，无需修改
- 当前项目 `db/__init__.py` 已导出 risk_targets 相关函数，保持不变；round 9 没有这块，不会冲突
- round 9 的 `utils/team_collector.py` 读取 `raw_request`、`event_log`、`ai_calls` 三张表作为证据源，与当前 schema 完全兼容

## 不合并的内容

- round 9 的 `.venv/`、`logs/`、`demo-results/`、`验收证据/`、`deployment/`、`__pycache__/`、`*.png`、`*.pdf`、`investigation-original-comparison-20261011.json`、各种 `.cmd` 快捷方式
- round 9 的 `utils/alerting.py`、`utils/ip_location.py`、`utils/logger.py`、`utils/http_fingerprint.py`、`utils/net.py`（当前项目已有等价或更全版本）
- round 9 的 `db/`（当前项目的 db 更全，含 risk_targets）
- round 9 的 `main.py`、`app_config.py`、`dashboard/server.py`、`dashboard/templates/dashboard.html`、`dashboard/templates/admin_login.html`、`dashboard/static/js/dashboard.js`、`dashboard/static/js/world_map.js`（均为分叉共同文件，采用合并而非覆盖）
- round 9 的 `ssh_honeypot/`、`web_honeypot/`（**按用户决策不动**：当前项目这两个目录功能相同且运行稳定；round 9 对其的 AI 交互改造不并入，AI 交互模块仅作为代码与展示层引入，处于备用状态）

## 验证方案

1. **语法与导入**：`python -m compileall .` 通过；`python -c "from utils import local_ai, ai_analyst, ai_detection, active_investigation, team_collector; from team_center import store, server, jobs, api, auth; from ai_gateway import server"` 无 ImportError
2. **现有功能回归**：启动 `python main.py`，确认 SSH/Web/DB/FTP/Telnet 蜜罐及 dashboard 正常启动，dashboard 风险目标标注功能可用
3. **DeepSeek 配置**：拷贝 `ai.local.ini.example` 为 `ai.local.ini`，填入真实 api_key；执行 `python scripts/team_center.py doctor`，health 返回 `service_reachable=true`
4. **team_center 启动**：`python scripts/team_center.py init --name admin` 后 `python scripts/team_center.py serve`，浏览器访问 http://127.0.0.1:5169/ 可登录
5. **dashboard AI 页面**：登录 dashboard 后访问 `/ai/detection`、`/ai/analysis`、`/ai/team` 页面正常渲染
6. **采集端闭环**：参照 round 9 使用指南执行一次 `scripts/mixed_attack_demo.py` 模拟攻击，team_center 能看到证据记录
