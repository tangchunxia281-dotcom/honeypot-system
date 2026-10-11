# Visual Studio 2022 运行 honeypot 指南

> 本机环境已配置完成，本文档说明如何在 VS 里打开并运行项目。

---

## 一、快速开始（三步）

### 第 1 步：打开解决方案

双击 `D:\honeypot\honeypot-system.sln`

或者在 VS 里：`文件` → `打开` → `项目/解决方案` → 选择该文件

### 第 2 步：确认 Python 解释器

打开后，在**解决方案资源管理器**里右键 `honeypot-system` 项目 → `Python 环境`（或看顶部的 Python 环境下拉框）

应该已经自动指向：

```
D:\honeypot\.venv\Scripts\python.exe
```

如果没指向，点下拉框 → `添加环境` → `现有环境` → 浏览到上面这个路径。

### 第 3 步：按 F5 运行

直接按 **F5**（或点绿色的启动按钮）。

VS 会自动执行 `main.py`，三端服务一起启动：

| 服务 | 地址 | 说明 |
|---|---|---|
| SSH 蜜罐 | `ssh://127.0.0.1:2222` | 模拟 SSH 服务，诱捕爆破 |
| Web 蜜罐 | `http://127.0.0.1:5000` | 模拟 Web 应用，诱捕注入/XSS |
| Dashboard | `http://127.0.0.1:5001` | 管理端，看威胁态势大屏 |

停止：按 **Shift+F5**，或点停止按钮。

---

## 二、已完成的配置清单

| 文件 | 作用 |
|---|---|
| `honeypot-system.sln` | VS 解决方案文件 |
| `honeypot-system.pyproj` | Python 项目定义（含 35 个源文件） |
| `honeypot-system.pyproj.user` | **启动配置**（指定 venv 解释器、工作目录、配置文件） |
| `.venv\` | 项目虚拟环境（Python 3.13.14 + 10 个依赖） |
| `honeypot.ini` | 主配置（从 example 复制生成） |
| `.secret_key` | Flask 会话密钥（32 字节随机） |
| `requirements.txt` | pip 依赖清单 |
| `.vscode\launch.json` | 备用：VS Code 调试配置（4 个配置项） |

### 关键配置说明

`honeypot-system.pyproj.user` 里设了三项重要内容：

```xml
<InterpreterPath>D:\honeypot\.venv\Scripts\python.exe</InterpreterPath>
<WorkingDirectory>D:\honeypot</WorkingDirectory>
<HONEYPOT_CONFIG>D:\honeypot\honeypot.ini</HONEYPOT_CONFIG>
```

- **InterpreterPath** — 指向项目 venv。这是关键，用全局 Python 会找不到依赖
- **WorkingDirectory** — 保证相对路径（如 `database/`、`logs/`）能正确解析
- **HONEYPOT_CONFIG** — 显式指定配置文件位置

---

## 三、调试技巧

### 断点调试

在代码行号左侧点一下就是断点，F5 启动后会在断点处暂停。可以看变量、调用栈。

**建议的断点位置**（想理解威胁评分逻辑的话）：

- `web_honeypot/routes_traps.py` — 攻击特征识别入口
- `db/event_logs.py` 的 `log_event()` — 事件落库逻辑
- `utils/http_fingerprint.py` — 指纹识别与评分

### 查看日志

运行时日志实时输出在 VS 的**输出窗口**（菜单：`视图` → `输出`）。

同时也会写入文件：

```
D:\honeypot\logs\main.log          主进程日志
D:\honeypot\logs\web_honeypot.log  Web 蜜罐日志（含攻击检测）
D:\honeypot\logs\ssh.log           SSH 蜜罐日志
D:\honeypot\logs\alert.log         告警日志
```

### 只跑单个服务

不想三端一起起，可以单独调试。把要调试的文件设为启动文件：

右键某个 `server.py` → `设为启动项`，然后 F5。

例如只调 Web 蜜罐：右键 `web_honeypot\server.py` → `设为启动项`

---

## 四、验证是否跑通

启动后做这几个检查：

### 1. 看 VS 输出窗口

应该看到类似：

```
[INFO] [main] 运行环境: development
[INFO] [main] SQLite D:\honeypot\database\event_logs.db
[INFO] [main] =============================================
[INFO] [main] 蜜罐系统启动中...
[INFO] [main] 所有服务已启动，系统中运行中
```

### 2. 浏览器访问 Dashboard

打开 `http://127.0.0.1:5001`

用 `honeypot.ini` 里 `[admin]` 段的账号密码登录（默认 `admin` / 见配置文件）。

### 3. 手动制造一次攻击，看是否被捕获

浏览器访问：

```
http://127.0.0.1:5000/product?id=1' OR '1'='1
```

应该被识别为 SQL 注入，评分 47，日志里会出现 `[高危] 分数:47`。

其他测试用 URL：

| URL | 预期检测 |
|---|---|
| `/product?id=1' OR '1'='1` | SQL 注入，47 分 |
| `/search?q=<script>alert(1)</script>` | XSS，44 分 |
| `/page?page=../../../../etc/passwd` | 目录穿越/LFI，44 分 |
| `/.env` | 敏感路径，37 分 |

然后在 Dashboard 里能看到这些记录。

---

## 五、常见问题

### Q1：F5 报「找不到模块 flask」

**原因**：解释器没指向 venv。

**解决**：解决方案资源管理器右键项目 → `Python 环境` → 选择 `D:\honeypot\.venv\Scripts\python.exe`

### Q2：端口被占用（2222 / 5000 / 5001）

**原因**：上次的服务没退干净，或别的程序占了。

**解决**：在 VS 里 `Shift+F5` 停止，或改 `honeypot.ini` 里的端口。

### Q3：中文日志显示乱码

**原因**：控制台编码。

**解决**：项目已设 `PYTHONIOENCODING=utf-8`。如果仍乱码，检查 VS 输出窗口的编码设置。

### Q4：想换成 MySQL

编辑 `honeypot.ini`：

```ini
[database]
type = mysql
host = 127.0.0.1
port = 3306
user = root
password = 你的密码
database = honeypot_db
```

然后先执行 `database/schema.sql` 建表。

---

## 六、环境信息

| 项目 | 版本/路径 |
|---|---|
| Visual Studio | Community 2022，17.14.37710.0 |
| VS 安装路径 | `C:\Program Files\Microsoft Visual Studio\2022\Community` |
| VS 工作负载 | Python 开发（已安装） |
| Python | 3.13.14（项目 venv 内） |
| venv 路径 | `D:\honeypot\.venv` |
| 项目路径 | `D:\honeypot` |

### venv 内已装的依赖

```
flask         3.1.3
werkzeug      （随 flask 安装）
paramiko      5.0.0
pymysql       2.2.8
python-dateutil 2.9.0.post0
psutil        7.2.2
requests      2.34.2
cryptography  50.0.1
bcrypt        5.0.0
pynacl        1.6.2
```

---

## 七、项目架构速览

```
D:\honeypot\
├── main.py                    ← 启动入口（VS 的启动文件）
├── app_config.py              ← 配置中心（环境变量 > honeypot.ini > 默认值）
├── env_utils.py               ← 配置读取工具
│
├── ssh_honeypot\              ← SSH 蜜罐（paramiko，:2222）
│   ├── server.py              ← 服务主体
│   ├── commands.py            ← 模拟命令（ls/cat/wget 等）
│   ├── vfs.py                 ← 虚拟文件系统
│   └── session.py             ← 会话管理
│
├── web_honeypot\              ← Web 蜜罐（Flask，:5000）
│   ├── server.py              ← 服务主体
│   ├── routes_public.py       ← 正常业务页面
│   ├── routes_traps.py        ← 陷阱路由（检测攻击）
│   ├── admin_views.py         ← 诱饵后台
│   └── admin_api.py           ← 诱饵 API
│
├── dashboard\                 ← 管理端（Flask，:5001）
│   ├── server.py              ← 服务主体 + 认证
│   └── system_info.py         ← 系统信息采集
│
├── db\                        ← 数据访问层
│   ├── connection.py          ← 连接管理（SQLite/MySQL 双后端）
│   ├── event_logs.py          ← 核心：统一事件表写入
│   ├── http_requests.py       ← 原始 HTTP 报文
│   ├── event_activity.py      ← 活动轨迹
│   └── geo.py                 ← IP 地理缓存
│
├── utils\                     ← 工具层
│   ├── logger.py              ← 日志
│   ├── http_fingerprint.py    ← 攻击指纹识别
│   ├── ip_location.py         ← IP 定位
│   ├── alerting.py            ← 告警
│   └── net.py                 ← 网络工具
│
├── database\                  ← 数据库文件与建表脚本
│   ├── event_logs.db          ← SQLite 数据库文件
│   └── schema.sql             ← MySQL 建表脚本
│
└── logs\                      ← 运行日志
```

### 核心数据流

```
攻击者请求
    ↓
蜜罐服务（SSH/Web）捕获
    ↓
utils/http_fingerprint.py 识别特征并打分
    ↓
db/event_logs.py 的 log_event() 落库
    ↓
database/event_logs.db 的 event_log 表
    ↓
Dashboard (:5001) 读取并展示
```

---

## 八、一个重要的设计说明

**为什么有些攻击在 Dashboard 上看不到？**

风险评分引擎 `calculate_threat_score()` 返回三元组 `(score, is_suspicious, signals)`。

**低于 30 分的请求只写入 `raw_request` 表，不写 `event_log` 表。**

这是**刻意设计**，不是 bug —— 目的是避免爬虫、健康检查等低风险噪音污染大屏统计。

所以：

- `/product?id=1' OR '1'='1` → 47 分 → **入库，Dashboard 可见**
- 普通的 `/` 或 `/favicon.ico` → 低分 → 只存原始报文，不显示

想验证这一点，可以直接查数据库：

```sql
SELECT * FROM raw_request ORDER BY id DESC LIMIT 20;
SELECT * FROM event_log ORDER BY id DESC LIMIT 20;
```

对比两张表的记录数差异，就能看出过滤逻辑。
