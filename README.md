# 蜜迹 · 多协议蜜网诱捕与 AI 威胁研判系统

> 比赛交付版 2.4 · 2026 年 10 月 30 日　|　代码仓库：https://github.com/tangchunxia281-dotcom/honeypot-system

本项目是一个面向教学演示、竞赛评审与受控安全研究的多协议蜜罐系统：对外提供 **SSH / Web / MySQL / Redis / FTP / Telnet 六类诱捕服务**，由 **主控进程 + 态势大屏 + AI 检测与研判工作区**统一编排，用于采集攻击载荷、判定其内容风险并形成可追溯的证据链。

项目目标是把 SSH 登录、Web 探测、后台撞库、SQL 注入、XSS、敏感文件探测等行为引导到可控环境中，并通过统一事件模型记录、聚合和展示攻击轨迹。本项目仅用于合法授权的教学、演示和防御研究，不用于承载真实生产业务。

## 团队信息
| 姓名 | 角色 | 主要负责模块 | 投入 |
| --- | --- | --- | --- |
| 唐春霞 | 队长 · 统筹与测试 | 进度统筹、验收口径、回归与验收脚本、设计与使用说明 | 约 38 人天 |
| 郑旭翔 | AI 与检测 | 请求级检测服务与模型（`detector/`）、推理封装、研判工作区 | 约 42 人天 |
| 陈梓铭 | 架构与后端、前端与可视化 | 主控与配置、数据层、协议接入、大屏模板与静态资源 | 约 48 人天 |

> 指导教师、联系方式与队名按赛事表单要求另行填写。上述投入为本作品开发期内的实际投入折算（人天按 8 小时计）。

## 文档导航
- [技术文档](docs/技术文档.md)：项目方案、需求、架构与实现说明
- [API 文档](API.md)：管理端与蜜罐侧接口说明
- [AI 接入说明](AI_SerVice.md)：检测服务接入与联调
- [前端架构与接口文档](前端架构与接口文档.md)：页面结构与前端调用约定
- [分类模型字段对接](docs/分类模型字段对接.md)：请求级检测服务的输入输出契约
- [AI 部署说明](docs/AI部署说明.md)：本机模型与云端接口的配置方式
- [测试与验证说明](测试与验证说明.md)：软件回归、协议、界面与接口验证口径
- [Git 历史说明](docs/Git历史说明.md)：提交历史与交付说明
- [比赛版使用说明](README_比赛版使用说明.md)：一键安装、启动与演示脚本
- [配置模板](honeypot.ini.example)：根目录统一配置文件模板

## 系统入口

| 入口 | 作用 | 默认本地地址 | 账号口径 |
| --- | --- | --- | --- |
| SSH 蜜罐 | 诱捕 SSH 登录、命令执行、SCP 上传等行为 | `ssh root@127.0.0.1 -p 2222` | 诱饵凭证，启动时动态生成 |
| Web 蜜罐 | 模拟企业网站、诱饵后台、敏感路径与攻击入口 | `http://127.0.0.1:5000/` | 公共页面无需登录；`/admin` 为诱饵后台 |
| Dashboard 管理端 | 查看真实事件、统计图表、会话分析和态势展示 | `http://127.0.0.1:5001/super/login` | 使用 `[admin] user/password` |

注意：

- Web 的 `/admin` 是**诱饵后台**，不是 Dashboard。
- Dashboard 的真实登录入口是 `/super/login`，登录后主页面是 `/dashboard`。
- Web/SSH 的诱饵凭证与 Dashboard 管理员密码相互独立。

## 项目结构
```text
honeypot-system/
├─ main.py                    # 主控：端口预检 / 日志流式汇聚 / 崩溃自动重启
├─ app_config.py              # 统一配置：环境变量 > honeypot.ini > 代码默认值
├─ honeypot.ini.example       # 主配置模板（复制为 honeypot.ini）
├─ ai.local.ini.example       # 大模型配置模板（复制为 ai.local.ini）
├─ classifier.ini.example     # 请求级分类模型配置模板
├─ .env.example               # 环境变量模板（systemd / 容器场景）
├─ requirements.txt           # 依赖声明
├─ requirements-lock.txt      # 锁定版本
├─ 安装环境.cmd / 检查环境.cmd / 启动比赛版.cmd / 验证比赛版.cmd
├─ ssh_honeypot/              # SSH 蜜罐：终端仿真、虚拟文件系统、命令审计
├─ web_honeypot/              # Web 蜜罐：企业站、诱饵后台、陷阱路由
├─ db_honeypot/               # MySQL / Redis 协议处理
├─ file_honeypot/             # FTP 协议处理
├─ remote_honeypot/           # Telnet（IoT）协议处理
├─ scripts/protocol_service.py# 六类协议的统一进程入口
├─ dashboard/                 # 管理端：安全概览、攻击事件、调查、系统与评测
├─ investigation_core/        # 本地证据索引与调查工作流
├─ team_center/               # 可选：团队数据中心（多机证据汇聚、角色权限、传感器上报、审计）
├─ db/                        # 数据层：事件、原始请求、会话、地理、风险标注
├─ utils/                     # 治理层与工具：限流封禁、日志、告警、AI 封装、分类适配
├─ detector/                  # 请求级检测服务与模型（src/、models/、data/）
├─ validation/                # 2.4 验收记录：回归、协议、界面、接口
├─ docs/                      # 设计文档 01–06、测试报告、运行截图、AI 部署与对接说明
├─ scripts/                   # 启动、演示、验收与评测脚本
├─ evaluation/                # 评测样本与脚本
└─ database/                  # schema.sql / mysql_archive.sql（运行库 *.db 不入库）
```

仓库约定：**只提交代码、模板与文档**；`honeypot.ini`、`ai.local.ini`、`.env`、`*.db`、`logs/` 等已在 `.gitignore` 中排除。

## 技术架构
系统采用「主控进程 + 多子服务进程」结构，自上而下分为五层，由 `main.py` 统一编排、统一回收日志：

```mermaid
flowchart TB
    ATK[攻击者 / 扫描器] --> IN
    subgraph IN[接入层：六协议诱捕]
        SSH[SSH :2222] --- WEB[Web :5000]
        DBH[MySQL :13306 / Redis :16379] --- FTP[FTP :2121]
        TEL[Telnet :2223]
    end
    IN --> G[治理层：限流 / 爆破封禁 / 扫描检测 / 事件去重]
    G --> D[数据层：事件 / 原始请求 / 会话 / 地理 / 风险标注]
    D --> A[应用层 Dashboard :5001：安全概览 / 攻击事件 / 调查 / 系统与评测]
    WEB -. 请求级判定 .-> M[智能层：检测适配器 + detector/ 模型 ｜ 本机或云端大模型 ｜ 证据索引]
    D -. 异步取数 .-> M
```

| 层次 | 职责 | 主要模块 |
| --- | --- | --- |
| 接入层 | 协议仿真、诱饵交互、攻击行为捕获 | `ssh_honeypot/`、`web_honeypot/`、`db_honeypot/`、`file_honeypot/`、`remote_honeypot/` |
| 治理层 | 并发限制、爆破封禁、扫描检测、事件去重与评分上报 | `utils/protocol_guard.py` |
| 数据层 | 统一事件、原始请求、会话追踪、地理缓存、风险目标标注 | `db/` |
| 应用层 | 态势可视化、事件研判、调查工作台、系统与评测 | `dashboard/` |
| 智能层 | 请求级判定、大模型研判、本地证据索引与调查闭环 | `utils/classifier.py`、`utils/local_ai.py`、`detector/`、`investigation_core/` |

**两条 AI 链路**（互不阻塞，失败自动降级）：

1. **请求级判定（在线）**：Web 请求落 `raw_request` → 规则特征评分 → 异步调用 `detector/` 的 `/api/v1/detect`
   取得加分 → 融合定分 → 超阈值升级为事件；模型不可用时回退纯规则。
2. **大模型研判（离线）**：按游标取事件与证据 → 结构化报告 → 人工复核；模型只做归纳与建议，不改写规则结论。

> 2.4 相对 2.3 的架构变化：六类协议改由 `scripts/protocol_service.py` 统一拉起；新增 `investigation_core/`
> 本地证据索引；请求级检测由 `utils/classifier.py` 以适配器方式接入 `detector/`；
> 团队数据中心（:5169）与共享推理网关（:11500）已移除。

## 技术栈

| 领域 | 选型 | 说明 |
| --- | --- | --- |
| 语言 / 运行时 | Python 3.11+（环境 3.12） | 全系统统一，依赖由 uv 管理 |
| Web 框架 | Flask + Werkzeug | 管理端与 Web 蜜罐 |
| SSH 协议 | Paramiko | SSH 蜜罐服务端仿真 |
| 存储 | SQLite（默认）/ MySQL（可选） | 统一 `db/connection.py` 双后端 |
| 前端 | 原生 HTML/CSS/JS + ECharts | 无构建链，CSP 严格同源 |
| 请求级 AI 检测 | FastAPI + uvicorn；字符级 TF-IDF + 逻辑回归 | 独立服务（默认 `127.0.0.1:8003`），CPU 推理 |
| 大模型研判 | DeepSeek / 本地 Ollama / 自建推理网关 | 统一 `utils/local_ai.py` 封装，可切换 |
| 依赖与部署 | `pyproject.toml` + `requirements-lock.txt`、systemd | Windows / Linux 均可 |

## 快速启动

### 1. 安装依赖

```bash
uv sync
```

如果没有安装 `uv`，请先参考官方文档安装：<https://github.com/astral-sh/uv>

### 2. 创建本地配置

Windows：

```powershell
copy honeypot.ini.example honeypot.ini
```

Linux/macOS：

```bash
cp honeypot.ini.example honeypot.ini
```

然后编辑根目录 `honeypot.ini`。常用配置项：

```ini
[app]
production_mode = false
show_summary_creds = true

[admin]
user = admin
password =

[services.ssh]
port = 2222

[services.web]
port = 5000

[services.dashboard]
port = 5001

[database]
type = sqlite
path = ./database/event_logs.db
```

说明：

- `honeypot.ini` 是本机真实运行配置，可能包含密码、Webhook、密钥，不要公开。
- 读取优先级为：**环境变量 > honeypot.ini > 代码默认值**。

### 3. 启动项目

```bash
uv run python main.py
```

启动成功后会拉起：

- SSH 蜜罐
- Web 蜜罐
- Dashboard 管理端

默认本地访问：

```text
SSH:       127.0.0.1:2222
Web:       http://127.0.0.1:5000/
Dashboard: http://127.0.0.1:5001/super/login
```

## 环境配置
| 项 | 说明 |
| --- | --- |
| Python | 3.11+（交付验证环境为 3.12） |
| 依赖清单 | `requirements.txt`（声明）+ `requirements-lock.txt`（锁定）；`pyproject.toml` 供 uv 使用 |
| 配置模板 | `honeypot.ini.example`（主配置）、`ai.local.ini.example`（大模型）、`classifier.ini.example`（分类模型） |
| 环境变量模板 | `.env.example`（systemd / 容器场景；环境变量优先级高于 ini） |
| 运行产物 | `logs/`、`database/*.db`（本地生成，不入库） |

```powershell
pip install -r requirements.txt          # 或使用 uv：uv sync
copy honeypot.ini.example honeypot.ini     # 首次运行生成真实配置
copy ai.local.ini.example ai.local.ini     # 需要大模型能力时再填密钥
python main.py                             # 或双击 启动比赛版.cmd
```

> 2.4 未附 `uv.lock`，使用 uv 时由 `pyproject.toml` 解析依赖；需要完全一致的版本请按 `requirements-lock.txt` 安装。

## 启动脚本

### Windows

```powershell
scripts\run.bat
```

### Linux

```bash
bash scripts/run_prod.sh
```

脚本会检查根目录 `honeypot.ini`，不存在时从 `honeypot.ini.example` 生成。脚本不再重复维护端口、数据库、告警等默认值，统一由 `app_config.py` 读取根目录配置。

## systemd 部署

适用于云服务器常驻运行：

```bash
cd /your/project/path
uv sync
bash scripts/install_systemd.sh /your/project/path honeypot
```

安装后 systemd 会通过以下环境变量指定统一配置文件：

```text
HONEYPOT_CONFIG=/your/project/path/honeypot.ini
```

部署前请编辑根目录 `honeypot.ini`，尤其是：

- `[app] production_mode`
- `[admin] password`
- `[database]` 数据库配置
- `[alerting]` 告警配置

## 配置说明

配置集中在 [app_config.py](app_config.py) 中读取，模板见 [honeypot.ini.example](honeypot.ini.example)。

### 配置优先级

1. 环境变量
2. 根目录 `honeypot.ini`
3. 代码默认值

### 关键配置项

| 分组 | 配置 | 说明 |
| --- | --- | --- |
| `[app]` | `production_mode` | 是否生产模式；生产模式必须设置管理端密码 |
| `[app]` | `secret_key` | Flask 会话密钥；留空时可使用 `.secret_key` 或临时生成 |
| `[admin]` | `user/password` | Dashboard 真实管理员账号 |
| `[services.ssh]` | `host/port` | SSH 蜜罐监听地址和端口 |
| `[services.web]` | `host/port` | Web 蜜罐监听地址和端口 |
| `[services.dashboard]` | `host/port` | Dashboard 监听地址和端口 |
| `[database]` | `type/path/host/port/user/password/name` | SQLite/MySQL 配置 |
| `[alerting]` | `enabled/webhook_url/*threshold` | 企业微信告警配置和风险阈值 |
| `[archive]` | `hot_days/read_enabled` | SQLite 热数据归档配置 |
| `[geoip]` | `timeout/server_public_ip` | IP 地理位置查询配置 |
| `[dashboard_data]` | `allow_mock_data` | 无真实数据时是否允许 Dashboard 回退演示样本 |

## AI 能力接入（可选）

通用大模型推理通过根目录 `ai.local.ini` 配置（环境变量 `HONEYPOT_AI_*` 优先），三选一：

| provider | 必填 | 说明 |
| --- | --- | --- |
| `deepseek` | `api_key`（`sk-` 开头） | DeepSeek 官方 API，OpenAI 兼容协议 |
| `local` | `base_url` + `model` | 本机 Ollama，如 `http://127.0.0.1:11434` + `qwen2.5:7b` |

启用步骤：

1. `copy ai.local.ini.example ai.local.ini`（或直接编辑仓库内已有的 `ai.local.ini`）。
2. 填写 `[ai] api_key`；如不想写入文件，可设置环境变量 `HONEYPOT_AI_API_KEY`。
3. 验收：`uv run python scripts/ai_verify.py`（配置自检 → 健康检查 → 一次真实调用）；
   无 Key 时可先跑 `uv run python scripts/ai_selftest.py` 验证接线与协议（本地伪端点，13 项检查）。
4. 启动：`uv run python main.py`。

接入后生效：

- AI 日志分析报告与问答（`/ai/analysis`）
- 规则与 AI 攻击研判对照（`/ai/detection`）
- SSH 未知命令受控策略、Web 预览受控策略（`/ai/interactions`）
- 周期态势报告、调查工作台 AI 追问、团队研判工作台

未配置或模型不可用时全部**安全降级**：请求照常记录、规则分数照常计算，AI 任务不排队、不覆盖原结论。

### 请求级 AI 攻击检测（规则 + ai_points 融合）

AI 组的检测模型是独立进程，可在 `honeypot.ini` 中交给主控一起拉起：

```ini
[services.ai_detect]
enabled = true
path = C:\Users\ADMIN\Desktop\xss_detector   # 含 src/api.py 与 models/
python =                                     # 留空自动用 <path>\.venv\Scripts\python.exe
host = 127.0.0.1
port = 8003

[ai]
enabled = true
url = http://127.0.0.1:8003/api/v1/detect
info_url = http://127.0.0.1:8003/model/info
timeout = 2.0
```

检测服务与模型已随仓库放在 `detector/` 目录；按其 `requirements.txt` 安装依赖后，执行 `detector/` 下的启动命令，或在管理端「分类模型」页配置 `/api/v1/detect` 地址。
接入后每个 Web 请求的 `raw_request`、`event_log.extra.ai`、`final_source=rule+ai`
以及大屏实时日志的 `AI XSS +N` 标签均会生效；服务不可达时自动回退为纯规则。

> 请求级检测与通用大模型是两条独立链路：前者只做分类与加分，后者用于日志分析、问答与受控交互。

## API 文档
2.4 不再单独维护 `API.md`，接口与实现说明并入下列文档：

- [技术文档](docs/技术文档.md)：五入口结构、数据字段与会话/调查口径
- [分类模型字段对接](docs/分类模型字段对接.md)：`/api/v1/detect` 的请求与响应契约
- [测试与验证说明](测试与验证说明.md)：软件、协议、界面与接口的验证项与判定口径
- `validation/`：验收记录原始数据（回归、协议、界面、接口）

## 核心能力

### SSH 蜜罐

- SSH 握手和认证流程模拟
- 登录成功/失败记录
- 命令交互仿真
- 可疑命令检测
- 暴力破解封禁与扫描检测
- SCP 上传捕获
- 会话轨迹记录

### Web 蜜罐

- 企业官网页面模拟
- 诱饵后台 `/admin`
- 常见后台路径探测
- 敏感文件探测，如 `/.env`、`/.git/config`、`/dump.sql`
- SQL 注入、XSS、LFI、命令执行、JNDI 等规则识别
- 原始 HTTP 请求记录
- Web 事件升级为统一事件模型

### Dashboard 管理端

- 登录鉴权与 CSRF 防护
- 事件日志列表
- 风险统计和 Top IP
- 地理分布
- 可疑请求分析
- 会话行为分析
- 登录审计
- 系统状态展示

## 统一事件模型

核心表为 `event_log`，用于把 SSH 和 Web 事件统一到同一展示口径。

| 字段 | 含义 |
| --- | --- |
| `timestamp` | 事件时间 |
| `source` | 来源，如 `web`、`ssh`、`dashboard` |
| `severity` | 风险级别 |
| `event_type` | 事件类型 |
| `src_ip` | 来源 IP |
| `session_id` | 会话标识 |
| `tags` | 标签数组 |
| `payload` | 事件摘要，已做脱敏/截断 |
| `raw_ref` | 原始引用字段 |
| `raw_request_id` | 关联的原始 HTTP 请求 ID |
| `extra` | 扩展 JSON 字段 |

## 安全边界

1. 本项目只用于合法授权的教学演示、防御验证和受控安全研究。
2. 不应将本项目部署到未授权目标或用于攻击真实系统。
3. Web 与 SSH 都是诱捕/记录环境，不承载真实业务数据。
4. Dashboard 建议仅监听本机或内网，通过隧道、VPN 或受控反向代理访问。
5. 真实密码、Webhook、密钥只应写入本机 `honeypot.ini`，不要提交或公开。

## 已知限制

1. SSH 输出是拟真仿真，不保证与真实 Ubuntu 完全一致。
2. Web 检测规则覆盖常见攻击样本，但复杂混淆载荷仍可能漏报。
3. Dashboard 地理位置依赖在线查询和缓存，网络不可用时可能显示未知位置。
4. 部分新 SSH 客户端可能提示算法兼容告警，不影响基本演示。

## 代码规范

- 遵循 **PEP 8**：4 空格缩进、UTF-8 编码、行宽上限 120（见 `.editorconfig`）。
- 每个模块顶部保留 `# -*- coding: utf-8 -*-` 与中文模块级 docstring，说明职责与关键约定。
- 公共函数写清参数、返回值与异常行为；涉及安全边界处（脱敏、限流、降级、鉴权）必须写明原因。
- 分层边界：协议层不直接拼 SQL，数据层不感知协议细节，AI 调用统一走
  `utils/local_ai.py`（大模型）与 `utils/ai_client.py`（请求级检测）。
- 新增协议蜜罐按「配置映射 → 来源白名单 → 主控注册」三步接入，并补齐「捕获入库 + 治理限流」两类用例。
- 提交信息遵循 `feat / fix / docs / refactor / test / chore` 前缀约定。

## 仓库与提交说明
提交前请确认三件事：暂存区不含 `honeypot.ini`、`ai.local.ini`、`.env`、`*.db`、`*.log`；
不含 `detector/data/augmented/` 等大文件；提交信息使用 `feat / fix / docs / refactor / test / chore` 前缀。

```powershell
git status --short
git diff --cached --name-only | Select-String 'honeypot\.ini$|ai\.local\.ini$|\.env$|\.db$|\.log$'
```

仓库根目录应当是包含 `main.py` 的这一层；`detector/` 作为子目录随主仓库发布，模型约 19 MB。

## 免责声明

本项目仅用于合法授权的安全研究、教学演示和防御验证场景。禁止将本项目用于任何未授权目标或非法用途。
