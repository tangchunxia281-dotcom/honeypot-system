# 蜜罐合成攻击数据

数据集编号：`d20261107214447dac95c`
生成时间：2026-11-07T21:44:47+08:00
事件数量：85；攻击场景：8；原始 HTTP 请求：49

> 本数据集为**合成数据**，仅用于本机蜜罐演示、检测规则验证和 Dashboard 可视化。
> 所有来源 IP 均为 RFC 5737 文档保留地址，不对应真实目标；
> 其中的命令、口令和上传内容均为无害演示样本。

## 文件说明

| 文件 | 说明 |
| --- | --- |
| `attack_bundle.json` | 完整数据包：事件、原始请求、会话、GeoIP、场景元数据 |
| `attack_events.jsonl` | 每行一个事件，便于流式读取或接入其他工具 |
| `attack_events.csv` | 扁平化事件表，可直接用 Excel 打开 |
| `geoip.csv` | 演示 IP 的地理位置映射 |
| `README.md` | 本说明 |

## 数据字段

- `event_log`：`timestamp / source / severity / event_type / src_ip / session_id / tags / payload / raw_request_id / extra`
- `raw_request`：HTTP 方法、路径、查询串、请求头、请求体、UA、风险分等
- `session_track`：Web 攻击链的路径序列、请求数和威胁等级
- `geo_ip`：演示用国家/城市/经纬度缓存，确保地图离线可见

## 场景构成

| 场景 | 来源 IP | 事件数 | Web 请求数 |
| --- | --- | ---: | ---: |
| 公网扫描器：目录与敏感文件快速枚举 | `203.0.113.17` | 12 | 12 |
| 后台撞库、SQL注入与WebShell上传链 | `198.51.100.23` | 10 | 10 |
| 多技术Web注入：XSS、LFI、SSTI、SSRF、XXE与JNDI | `198.51.100.77` | 9 | 9 |
| SSH弱口令爆破、登录成功与挖矿脚本下载 | `192.0.2.31` | 12 | 0 |
| SSH账号探测、权限枚举与横向移动准备 | `192.0.2.88` | 9 | 0 |
| MySQL / Redis / FTP / Telnet 多协议机会型攻击 | `192.0.2.200` | 15 | 0 |
| 备份、配置与源码泄露探测 | `203.0.113.45` | 10 | 10 |
| API枚举、GraphQL内省与越权参数探测 | `203.0.113.99` | 8 | 8 |

## 导入本机数据库

```powershell
# 仅生成文件，不写数据库
python scripts/generate_attack_data.py

# 生成并追加导入 database/event_logs.db（导入前自动备份）
python scripts/generate_attack_data.py --load

# 先清理旧的 synth-* 合成会话，再导入本次数据
python scripts/generate_attack_data.py --load --reset-demo
```

`--reset-demo` 只会删除 `session_id LIKE 'synth-%'` 的合成记录，
不会删除真实蜜罐事件。导入后启动 `python main.py`，登录 Dashboard 查看。

## 使用边界

- 这些行是**记录数据**，不是攻击流量；不会向任何主机发包。
- 如需真实产生蜜罐事件，请使用项目已有的本机回环演示脚本：
  `scripts/mixed_attack_demo.py`、`scripts/demo/protocol_traffic.py`。
- 不要把这些合成 IP、账号或命令用于未授权目标。
