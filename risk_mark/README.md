# 密标（Risk Mark）模块

## 1. 功能定位

**密标** = 给风险对象（来源 IP / 会话 / 账号）打上一条持久的「**密级 + 原因 + 有效期**」标记，
用于在态势大屏和事件列表中快速锁定重点关注目标。

与既有能力的关系：

| | 事件日志（event_log） | 密标（risk_mark） |
| --- | --- | --- |
| 形态 | 流水记录，只增不改 | 结论性标记，一个对象一条 |
| 生命周期 | 按时间窗口滚动、归档 | 长期有效，可设有效期 |
| 来源 | 自动采集 | 人工标注 + 自动识别器建议 |
| 用途 | 统计、溯源 | 重点盯防、运营交接 |

## 2. 目录结构

```text
risk_mark/
├─ __init__.py        # 对外门面：公共 API 统一出口
├─ constants.py       # 对象类型 / 密级 / 状态 等常量
├─ config.py          # [risk_mark] 配置读取（环境变量 > honeypot.ini > 默认值）
├─ log.py             # 模块日志器（仅控制台，不额外落文件）
├─ models.py          # RiskMark / MarkProposal 数据模型与字段规范化
├─ store.py           # 持久化层：独立表 risk_mark（SQLite / MySQL 双适配）
├─ detectors.py       # 风险识别扩展点：BaseDetector + 注册表 + 内置识别器
├─ service.py         # 业务门面（上层只需依赖它）
├─ dashboard_api.py   # Flask 蓝图：/api/risk_mark/*
├─ selftest.py        # 端到端自检脚本
├─ static/            # 独立前端资源（抽屉面板，rm- 前缀避免样式冲突）
└─ README.md
```

## 3. 快速使用（Python 调用）

```python
from risk_mark import service

# 标注一个风险 IP（高危，有效期 7 天）
service.mark('ip', '203.0.113.10', 'high', '持续暴力破解 SSH', created_by='admin', ttl_days=7)

# 查询 / 列表 / 批量
service.get_mark('ip', '203.0.113.10')
service.list_marks(level='high', keyword='暴破')
service.marks_for_ips(['203.0.113.10', '198.51.100.2'])

# 取消标注
service.unmark(target_type='ip', target_value='203.0.113.10')
```

自检（不会残留测试数据）：

```bash
python -m risk_mark.selftest
```

## 4. Dashboard 接入

本模块对既有代码只做 **2 处** 增量改动，均带 `[risk-mark]` 标记，便于检索与回滚：

| 文件 | 改动 |
| --- | --- |
| `dashboard/server.py` | 调用 `register_dashboard_api(app, login_required=..., csrf_protect=...)` 注册蓝图（3 行，ImportError 时自动降级） |
| `dashboard/templates/dashboard.html` | 引入 `risk_mark.css` / `risk_mark.js`（2 个标签） |

设计要点：

- **零反向依赖**：鉴权 / CSRF 装饰器由调用方注入，`risk_mark` 不 import `dashboard`，避免循环依赖；
- **零表结构侵入**：只新建 `risk_mark` 表，不 ALTER 任何既有表；
- **零静态目录侵入**：前端资源走蓝图自带 static，对外路径为 `/api/risk_mark/static/`；
- **优雅降级**：删除 `risk_mark/` 后，`dashboard/server.py` 的 try/except ImportError 会静默跳过。

## 5. HTTP 接口

前缀 `/api/risk_mark`，全部需要 Dashboard 登录态；POST 需带 `X-CSRF-Token`。
响应格式与既有 Dashboard API 一致：`{"code": 0, "msg": "success", "data": ...}`。

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` | `/meta` | 枚举元数据（对象类型 / 密级 / 状态 / 识别器 / 配置） |
| `GET` | `/summary` | 密标总数、密级分布、识别器清单 |
| `GET` | `/list` | 密标列表；参数 `target_type/level/status/q/limit/offset` |
| `GET` | `/check` | 单个查询：`target_type` + `target_value`；批量：`targets=ip:1.1.1.1,ip:2.2.2.2` |
| `POST` | `/create` | 新增 / 覆盖密标：`target_type/target_value/level/reason/ttl_days/mark_code/created_by` |
| `POST` | `/remove` | 移除密标：`id` 或 `target_type` + `target_value` |
| `POST` | `/scan` | 运行识别器：`hours` / `limit` / `apply`（是否落标） |
| `GET` | `/detectors` | 已注册识别器列表 |

前端另暴露 `window.RiskMark`（`open` / `refresh` / `isMarked(ip)` / `fetchMarks([ip])`），
供 `dashboard.js` 或其他模块复用。

## 6. 数据表结构

```sql
CREATE TABLE risk_mark (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,  -- MySQL: BIGINT AUTO_INCREMENT
    target_type  TEXT    NOT NULL,                   -- ip / session / account
    target_value TEXT    NOT NULL,                   -- 标注对象值
    level        TEXT    NOT NULL,                   -- low / medium / high / critical
    mark_code    TEXT,                               -- 密标编号（可选）
    reason       TEXT,                               -- 标注原因
    source       TEXT    NOT NULL DEFAULT 'manual',  -- manual / detector:<name>
    status       TEXT    NOT NULL DEFAULT 'active',  -- active / expired
    created_by   TEXT,
    created_at   DATETIME,
    updated_at   DATETIME,
    expires_at   DATETIME,                           -- 空表示长期有效
    extra        TEXT,                               -- 扩展 JSON
    UNIQUE (target_type, target_value)               -- 一个对象只有一条密标
);
```

表由模块首次使用时自动创建，无需手工执行迁移脚本。

## 7. 扩展新风险识别

只需两步：

```python
from risk_mark.detectors import BaseDetector, DetectionContext, MarkProposal, register_detector

class SqlInjectionDetector(BaseDetector):
    name = 'sql_injection'
    description = '命中 SQL 注入特征即建议密标'
    default_level = 'high'

    def detect(self, context: DetectionContext):
        if 'union select' in str(context.payload or '').lower() and context.src_ip:
            return MarkProposal(
                target_type='ip',
                target_value=context.src_ip,
                level='high',
                reason='命中 SQL 注入特征',
                detector=self.name,
            )
        return None

register_detector(SqlInjectionDetector())   # 注册即生效
```

要点：

- `DetectionContext` 提供 `source / event_type / src_ip / session_id / severity / payload / extra / now`；
- 单个识别器抛异常不会影响其他识别器（`run_detectors` 内部隔离）；
- 同名识别器默认不覆盖，需要覆盖时传 `override=True`。

### 接入实时事件链路（可选）

默认关闭自动识别，因此**默认零开销**。若要让事件写入后即时识别，可在事件落库处加一行：

```python
from risk_mark import service
service.on_event(source='web', event_type='sql_injection', src_ip=ip, severity='critical', payload=payload)
```

`on_event` 为异常安全设计：任何异常都会降级为空结果，不会影响蜜罐主流程。
是否真正落标由 `[risk_mark] auto_detect_apply` 控制（默认 `false`，只返回建议）。

## 8. 配置项

写入根目录 `honeypot.ini`（模板见 `honeypot.ini.example` 的 `[risk_mark]` 段）：

| 配置 | 默认值 | 说明 |
| --- | --- | --- |
| `auto_detect_enabled` | `false` | 是否启用自动识别（`on_event` 钩子总开关） |
| `auto_detect_apply` | `false` | 识别结果是否自动落标 |
| `repeat_window_hours` | `24` | 重复高危行为统计窗口 |
| `repeat_threshold` | `5` | 重复高危行为触发阈值 |
| `default_ttl_days` | `0` | 手工密标默认有效期（天），0 = 长期 |

对应环境变量：`RISK_MARK_AUTO_DETECT_ENABLED`、`RISK_MARK_AUTO_DETECT_APPLY`、
`RISK_MARK_REPEAT_WINDOW_HOURS`、`RISK_MARK_REPEAT_THRESHOLD`、`RISK_MARK_DEFAULT_TTL_DAYS`。

## 9. 卸载（GIT 操作）

模块整体自包含，卸载流程如下：

```bash
# 1. 删除模块目录（含前端资源、配置读取、自检）
git rm -r risk_mark

# 2. 还原 2 处接入点
git revert <接入提交>            # 或手工删除 dashboard/ 中带 [risk-mark] 标记的代码块
grep -rn "\[risk-mark\]" dashboard/   # 确认接入点已清理

# 3. 可选：清理数据表
#    SQLite : DROP TABLE IF EXISTS risk_mark;
#    MySQL  : DROP TABLE IF EXISTS honeypot_db.risk_mark;
```

由于 `dashboard/server.py` 的导入是 try/except 保护的，即使只删目录不还原接入点，
Dashboard 也不会启动失败，只会记录一条 info 日志。

## 10. 设计约束

- 不修改任何既有表结构与既有接口签名；
- 不引入新的第三方依赖（仅使用 Flask / 标准库 / 项目已有依赖）；
- 所有 SQL 使用参数化占位符，兼容 SQLite `?` 与 MySQL `%s`；
- 所有对外入参先经 `models.py` 规范化与校验，非法输入抛 `ValueError` 并转成明确提示；
- 前端所有动态内容经 HTML 转义后渲染，避免 XSS。
