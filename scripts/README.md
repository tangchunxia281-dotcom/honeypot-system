# scripts 目录说明

`scripts/` 目录用于存放项目部署、启动、演示和测试相关脚本。该目录不承载业务代码，主要服务于环境初始化、远端部署、答辩演示和系统验证。

## 目录结构

```text
scripts/
├─ run_prod.sh                      # Linux 启动脚本
├─ run.bat                          # Windows 启动脚本
├─ install_systemd.sh               # systemd 安装脚本
├─ honeypot.service.example         # systemd 服务模板
├─ honeypot.env.example             # 旧环境变量兼容模板（主配置在 ../honeypot.ini.example）
├─ demo/
│  └─ defense_demo.py               # 演示联动脚本
└─ system_test/
   ├─ common_utils.py               # 测试公共工具
   └─ full_test.py                  # 综合测试（功能验证 + 注入检测 + 压力测试）
```

## 脚本分类

- 启动与部署：`run.bat`、`run_prod.sh`、`install_systemd.sh`
- 演示验证：`demo/defense_demo.py`
- 系统测试：`system_test/full_test.py`

## 推荐使用顺序

1. 完成环境安装，并编辑根目录 `honeypot.ini`。
2. 使用 `run.bat` 或 `run_prod.sh` 启动服务；如需常驻运行，可使用 `install_systemd.sh` 部署为 systemd 服务。
3. 使用 `demo/defense_demo.py` 完成联动演示检查。
4. 使用 `system_test/full_test.py` 执行系统测试。

## 常用命令示例

### 本地启动

Windows：

```powershell
scripts\run.bat
```

Linux：

```bash
bash scripts/run_prod.sh
```

### 远端混合拓扑演示

当 Web 与 SSH 暴露在远端地址、Dashboard 通过本地隧道访问时，应分别指定各组件地址，不宜仅使用单一 `--target-host`。

```powershell
uv run python scripts/demo/defense_demo.py --reuse-running --allow-remote-targets --ssh-host <SSH_HOST> --ssh-port 2222 --web-host <WEB_HOST> --web-port 5000 --dashboard-host 127.0.0.1 --dashboard-port 5001 --admin-user <ADMIN_USER> --admin-pass <ADMIN_PASS>
```

### 系统测试

```powershell
uv run python scripts/system_test/full_test.py --web-port 5000 --dashboard-port 5001 --admin-user admin --admin-pass <密码> --stress-requests 100
```

## 说明

- 主运行配置集中在项目根目录 `honeypot.ini`，模板为 `honeypot.ini.example`；`app_config.py` 统一读取。
- `scripts/honeypot.env.example` 仅保留给旧部署方式兼容，环境变量会覆盖 `honeypot.ini`，不建议重复维护大量默认值。
