# 方式 B：设备 B 同机部署（蜜罐 + AI 检测服务）

> 适用场景：设备 B 上同时跑「蜜罐系统」和「AI 检测服务」，两者通过 `127.0.0.1:8000` 通信。
> 设备 B **不需要**源码、Python 模型环境、scikit-learn；只需要 Docker。

---

## 0. 交付物

| 文件 | 说明 |
|---|---|
| `xss-detector-2.0.0.tar` | 镜像离线包，`docker load` 即可导入 |
| `docker-compose.yml` | 可选，用 `image:` 直接启动（不构建） |
| 本说明 | 部署与排错 |

镜像信息：

```text
镜像名   xss-detector:2.0.0
平台     linux/amd64（x86_64）
大小     约 714 MB（导入后）；tar 约 161 MB
SHA256   513615C72DA69FA3681BC2EC8352AD896DC5DA8C8D9AB4B1A166D98BD9B55502
```

> 每次重新 `docker save` 后 SHA256 会变，以实际 `Get-FileHash` / `sha256sum` 为准。

---

## 1. 设备 B 前置条件

| 项目 | 要求 |
|---|---|
| Docker | Windows：Docker Desktop + WSL2；Linux：Docker Engine 20.10+ |
| 架构 | **x86_64 / amd64**（镜像为 linux/amd64，ARM 设备不能直接运行） |
| 端口 | 8000 空闲（被占用可改 8001，见第 8 节） |
| 磁盘 | ≥ 2 GB（镜像 + 日志 + tar） |
| 网络 | 同机部署不需要外网；首次导入也不需要联网 |

检查：

```powershell
docker version
docker info --format '{{.Architecture}}'   # 期望 x86_64 / amd64
```

---

## 2. 拷贝并校验

把 `xss-detector-2.0.0.tar` 拷到设备 B，例如 `D:\xss-deploy\`，然后校验：

```powershell
Get-FileHash .\xss-detector-2.0.0.tar -Algorithm SHA256
```

```bash
# Linux
sha256sum xss-detector-2.0.0.tar
```

结果应与第 0 节的 SHA256 一致；不一致说明拷贝损坏，重新拷贝。

---

## 3. 导入镜像

```powershell
docker load -i .\xss-detector-2.0.0.tar
```

预期输出：`Loaded image: xss-detector:2.0.0`

确认：

```powershell
docker images xss-detector
# REPOSITORY      TAG     IMAGE ID       SIZE
# xss-detector    2.0.0   xxxxxxxxxxxx   714MB
```

---

## 4. 启动容器

### 方式 1：一条 `docker run`（推荐）

```powershell
docker run -d --name xss-detector --restart unless-stopped `
  -p 8000:8000 `
  -e LOG_TO_STDOUT=1 `
  -v xss-logs:/app/logs `
  xss-detector:2.0.0
```

### 方式 2：用附带的 compose 文件

```powershell
docker compose -f .\docker-compose.yml up -d
```

等状态变为 `healthy`（首次启动需加载模型，约 5~15 秒）：

```powershell
docker ps --filter "name=xss-detector"
# STATUS 应显示 Up ... (healthy)
```

---

## 5. 验证服务

```powershell
curl.exe http://127.0.0.1:8000/health
curl.exe http://127.0.0.1:8000/model/info
```

预期：

```json
{"status":"ok","model_loaded":true,"model_path":"/app/models/attack_model.pkl"}
{"version":"v2","trained_at":"2026-10-22 18:49:38","labels":["xss","sqli","path_traversal","sensitive_path","normal"],"model_path":"..."}
```

---

## 6. 配置设备 B 上的蜜罐

编辑蜜罐目录下的 `honeypot.ini`：

```ini
[services.ai_detect]
enabled = false          # 不再拉起本地模型

[ai]
enabled = true
url = http://127.0.0.1:8000/api/v1/detect
info_url = http://127.0.0.1:8000/model/info
timeout = 2.0
```

> 当前仓库默认值已经是这个，通常无需修改。若之前设置过环境变量
> `AI_XSS_URL` / `AI_XSS_INFO_URL`，请确认没有把它指到旧地址。

自检（在蜜罐目录执行）：

```powershell
python scripts/check_ai_service.py
```

四类用例全部 PASS 即接线成功。

---

## 7. 启动蜜罐

```powershell
cd <蜜罐项目目录>
uv run python main.py
```

启动摘要中应出现：

```text
> [AI攻击检测·Docker] 请求级攻击检测模型（规则 + ai_points 融合）
  http://127.0.0.1:8000/api/v1/detect
  状态: 在线｜模型 v2（2026-10-22 18:49:38）
```

发一条 XSS 请求验证：

```powershell
Invoke-WebRequest `
  -Uri 'http://127.0.0.1:5000/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E' `
  -UseBasicParsing
```

Dashboard 实时日志应出现 `AI XSS +25` 之类的标签，事件类型为 `xss_ai_detected`。

---

## 8. 日常运维

| 操作 | 命令 |
|---|---|
| 查看状态 | `docker ps --filter "name=xss-detector"` |
| 实时日志 | `docker logs -f xss-detector` |
| 审计日志 | `docker cp xss-detector:/app/logs/honeypot_events.jsonl .` |
| 重启 | `docker restart xss-detector` |
| 停止 | `docker stop xss-detector` |
| 删除容器（保留日志卷） | `docker rm -f xss-detector` |
| 升级镜像 | 拷贝新 tar → `docker load -i 新包.tar` → `docker rm -f xss-detector` → 按第 4 节重新 run（日志卷 `xss-logs` 会保留） |

**开机自启**：

- Windows：Docker Desktop 登录时启动 + 容器 `--restart unless-stopped`；
  若 Docker Desktop 未设自启，在 Settings → General 勾选启动项。
- Linux：`sudo systemctl enable --now docker`，容器 `--restart unless-stopped` 即可。

---

## 9. 常见问题

| 现象 | 处理 |
|---|---|
| `docker load` 报错或 SHA256 不一致 | tar 拷贝损坏，重新拷贝 |
| `docker: command not found` | 设备 B 未装 Docker / 未启动 Docker Desktop |
| 端口被占用 `bind: address already in use` | 改用 `-p 8001:8000`，并把蜜罐 `[ai] url` 改成 `8001` |
| 状态一直 `unhealthy` | `docker logs --tail 100 xss-detector`；多为内存不足或模型文件异常 |
| `/health` 返回 503 | 模型未加载，看容器日志 |
| Apple Silicon / ARM 设备 | 镜像为 linux/amd64，不能直接跑；需在 ARM 设备上用源码构建 arm64 镜像 |
| 跨设备访问（蜜罐不在 B 上） | 把地址换成 `http://<B 的 IP>:8000`，并放行 8000/TCP |
| 想确认模型版本 | `curl.exe http://127.0.0.1:8000/model/info` |

---

## 10. 与方式 A 的区别

| | 方式 A（蜜罐在 B、服务在 A） | 方式 B（同机） |
|---|---|---|
| 检测服务位置 | 设备 A | 设备 B |
| 蜜罐配置地址 | `http://<A 的 IP>:8000` | `http://127.0.0.1:8000` |
| 设备 B 需要 Docker | 不需要 | **需要** |
| 网络依赖 | 依赖 A 在线、局域网放行 8000 | 只依赖本机 Docker |
| 适用 | 多台设备共用一个检测服务 | 单机自包含、离线演示/交付 |
