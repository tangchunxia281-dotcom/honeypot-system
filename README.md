# 网络威胁态势感知与蜜罐诱捕系统

本项目是一个面向毕业设计、教学演示和受控安全研究场景的三端协同蜜罐系统，由 **SSH 蜜罐 + Web 蜜罐 + Dashboard 管理端** 组成。

项目目标是把 SSH 登录、Web 探测、后台撞库、SQL 注入、XSS、敏感文件探测等行为引导到可控环境中，并通过统一事件模型记录、聚合和展示攻击轨迹。本项目仅用于合法授权的教学、演示和防御研究，不用于承载真实生产业务。

## 文档导航

- [API 文档](API.md)：Dashboard API、Web 蜜罐接口、诱饵后台接口说明
- [配置模板](honeypot.ini.example)：根目录统一配置文件模板
- [脚本说明](scripts/README.md)：启动、部署与演示脚本说明

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
sheji/
├─ main.py                    # 三端统一启动入口
├─ app_config.py              # 统一配置读取入口：环境变量 > honeypot.ini > 默认值
├─ env_utils.py               # 配置读取工具函数兼容层
├─ honeypot.ini.example       # 根目录配置模板
├─ API.md                     # API 文档
├─ pyproject.toml             # Python 项目依赖声明
├─ uv.lock                    # uv 锁定依赖版本
├─ dashboard/                 # Dashboard 管理端
├─ web_honeypot/              # Web 蜜罐
├─ ssh_honeypot/              # SSH 蜜罐
├─ db/                        # 数据库连接、事件写入、统计聚合、归档逻辑
├─ utils/                     # 日志、告警、IP 地理位置、HTTP 指纹等工具
├─ risk_mark/                 # 密标模块：风险对象标注 + 可扩展风险识别（可整体移除）
├─ scripts/                   # 启动、部署和演示脚本
└─ database/                  # 数据库 schema 文件
```

## 技术栈

- Python 3.9+
- Flask
- Paramiko
- SQLite / MySQL
- ECharts
- requests
- uv

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
| `[risk_mark]` | `auto_detect_enabled/auto_detect_apply/*threshold` | 密标模块自动风险识别与有效期配置（可选） |

## API 文档

接口说明已单独整理到 [API.md](API.md)，包括：

- Dashboard 登录和鉴权方式
- Dashboard 事件日志、统计、地理分布、会话分析等 API
- Web 蜜罐公共页面接口
- Web 诱饵后台接口
- 高危路径和敏感文件陷阱
- SSH 蜜罐连接方式

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

### 密标（风险对象标注）

- 对来源 IP / 会话 / 账号打「密级 + 原因 + 有效期」标记，一个对象只有一条密标
- 密级：低危 / 中危 / 高危 / 严重（与事件风险等级同口径）
- 管理端内置独立抽屉面板：列表、新增、移除、批量同步
- 实时日志与 Top IP 面板自动为已标注对象打徽标
- 可扩展风险识别：继承 `BaseDetector` 并注册即可新增策略，内置「单条高危事件」「重复高危行为」两个识别器
- 模块自包含（`risk_mark/`），删除目录即可整体移除；详见 [risk_mark/README.md](risk_mark/README.md)

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

## 免责声明

本项目仅用于合法授权的安全研究、教学演示和防御验证场景。禁止将本项目用于任何未授权目标或非法用途。
