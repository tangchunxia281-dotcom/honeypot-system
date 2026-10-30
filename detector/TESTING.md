# 测试指南

本文按"从快到慢、从局部到整体"分四层说明如何测试本项目。
先看第 0 节的**一键脚本**，30 秒即可验证大部分功能。

---

## 0. 一键测试（推荐先跑这个）

```powershell
cd "D:\HuaweiMoveData\Users\20683\Desktop\xss_detector"

# 基础：单元测试 + 信号链路演示（约 10 秒）
powershell -ExecutionPolicy Bypass -File tests\run_all.ps1

# 完整：额外启动 API 服务并做端到端验证（约 30 秒）
powershell -ExecutionPolicy Bypass -File tests\run_all.ps1 -Serve

# 全部：再追加 5 折交叉验证（约 1-2 分钟）
powershell -ExecutionPolicy Bypass -File tests\run_all.ps1 -Serve -Full
```

> 用 `powershell` 而不是 `pwsh`：本机只装了 Windows PowerShell 5.1。
> 脚本已保存为 UTF-8 with BOM，中文可正常显示。

预期最终输出：

```
==============================================================
  全部通过
==============================================================
```

---

## 1. 第 1 层：单元测试（秒级）

验证模型能否加载、规则是否正确、API 是否可用。

```powershell
python -m pytest -q
```

预期：

```
........                                                                 [100%]
14 passed in ~6s
```

覆盖内容：

| 测试文件 | 验证点 |
|---|---|
| `tests/test_predict.py` | 10 条 XSS 载荷不漏报、10 条正常文本不误报 |
| `tests/test_api.py` | `/`、`/health`、`/model/info`、`/predict`、`/predict/batch`（内部调试接口也一并回归） |

只想跑某一个：

```powershell
python -m pytest tests/test_predict.py -q
python -m pytest tests/test_api.py -q
```

---

## 2. 第 2 层：信号链路演示（秒级，最适合答辩展示）

```powershell
python -m tools.demo_signal
```

它会打印 15 个场景的完整分值计算，**一眼看到 AI 如何作为一维加权特征参与累加**：

```
场景              判定类型           AI概率   AI分  规则分  生效分  累加分  分层
经典 XSS          xss              0.957    24     22     22     46  高危告警    ✓
目录穿越           path_traversal   1.000    25     22     22     47  高危告警    ✓
敏感文件 wp        sensitive_path   0.992    25     15     15     40  高危告警    ✓
正常页面 script     normal           0.088     2     22      2      4  常规记录    ✓
结果: 15/15 与期望一致
```

**重点看最后两行**：`<script src="_static/doctools.js"></script>` 规则给了 22 分，
但模型以 0.088 判定非攻击，规则分被抑制为 2，累加只有 4 分 → 正确归为 normal。
这正是"多特征加权"相对"命中即判定"的价值。

单独测某个 payload（交互式）：

```powershell
python -m src.predict -i
# 然后输入任意文本，q 退出

python -m src.predict "<img src=x onerror=alert(1)>"
```

---

## 3. 第 3 层：API 端到端（约 30 秒）

这一步验证**蜜罐要调用的 HTTP 接口**是否正常。

### 3.1 启动服务

```powershell
# 前台启动（Ctrl+C 停止）
python -m uvicorn src.api:app --host 127.0.0.1 --port 8100
```

看到 `Uvicorn running on http://127.0.0.1:8100` 即成功。
浏览器打开 `http://127.0.0.1:8100/docs` 可看到交互式接口文档（Swagger UI）。

### 3.2 接口验证

| 方法 | 路径 | 用途 |
|---|---|---|
| POST | `/api/v1/detect` | ★ **蜜罐对接主接口**（请求级检测） |
| GET | `/health` | 探活 + 确认模型已加载 |
| GET | `/model/info` | 查看模型版本与支持的类别 |
| — | `/predict`、`/predict/signal`、`/predict/batch` | 【内部调试】自测用，不在对外契约内 |

访问 `GET /` 可直接看到主接口与最小请求示例。

### 3.3 用客户端示例测试（推荐）

```powershell
# 另开一个终端
python -m tools.client_example --url http://127.0.0.1:8100
```

它会演示**蜜罐侧如何把 AI 分值并入风险评分**：

```
      蜜罐原分 | 请求                          | AI类型           | AI分 | 累加后 | 分层
         0 | hello world                   | normal          |    4 |     4 | 常规记录
        15 | /wp-config.php                | sensitive_path  |   25 |    40 | 高危告警
        22 | ../../../../etc/passwd        | path_traversal  |   25 |    47 | 高危告警
```

注意第 2 行：蜜罐原本给敏感路径 +15（单独不够 20 分，只算探测），
AI 再 +25 → 累加 40，正好达到**高危告警线**。这就是 AI 的增量价值。

也可以手动发请求（用对外主接口）：

```powershell
$body = @{ path = "/download"; query = "file=../../../../etc/passwd" } | ConvertTo-Json -Compress
Invoke-RestMethod -Uri "http://127.0.0.1:8100/api/v1/detect" -Method Post `
    -Body $body -ContentType "application/json" | ConvertTo-Json -Depth 5
```

最小请求（只传 path 也能用）：

```powershell
$body = @{ path = "/search"; query = "id=1 and 1=1" } | ConvertTo-Json -Compress
Invoke-RestMethod -Uri "http://127.0.0.1:8100/api/v1/detect" -Method Post `
    -Body $body -ContentType "application/json"
```

### 3.4 一键完成（含启动与停止）

```powershell
powershell -ExecutionPolicy Bypass -File tests\run_all.ps1 -Serve
```

---

## 4. 第 4 层：模型质量验证（1-2 分钟）

### 4.1 交叉验证（对比三条链路）

```powershell
python -m tools.cv_eval --data data/raw/train_clean.csv --folds 5
```

预期结果：

| 链路 | 准确率 | 宏 F1 | 攻击精确率 | 误报 |
|---|---|---|---|---|
| 只看规则 | 0.9540 | 0.8685 | 99.69% | — |
| 只看模型 | 0.9970 | 0.9789 | 99.69% | — |
| **加权融合 + 双阈值** | 0.9967 | **0.9872** | 99.71% | **38** |

以及分层效果：

```
  high     共 11321 条, 其中真实攻击 11314 条 (99.9%)
  susp     共  1758 条, 其中真实攻击  1727 条 (98.2%)
  normal   共 26529 条, 其中真实攻击    92 条 (0.3%)
```

**高危层精确率 99.9%** —— 会触发企业微信告警的样本几乎无误报。

### 4.2 分类别识别率报告

```powershell
python -m tools.eval_report_md
```

生成 `eval_report.md`（含每类攻击的识别率、混淆矩阵、误报漏报明细）
与 `eval_report.json`（机器可读指标）。预期分类别识别率：

| 攻击类型 | 精确率 | 识别率 | 测试样本数 |
|---|---|---|---|
| `xss` | 98.49% | 98.00% | 200 |
| `sqli` | 100.00% | 99.36% | 2347 |
| `path_traversal` | 100.00% | 100.00% | 31 |
| `sensitive_path` | 100.00% | 100.00% | 49 |
| `normal` | 99.64% | 99.94% | 5295 |

### 4.2 独立测试集评估

```powershell
python -m tools.eval_report data/processed/test_raw.csv --out eval_report.txt
```

---

## 5. 第 5 层：完整流水线复现（改数据后重跑）

改了数据或规则后，按顺序执行：

```powershell
python -m tools.data_audit                                   # 1. 数据体检
python -m tools.clean_data --write                           # 2. 清洗
python -m src.build_dataset --input data/raw/train_clean.csv # 3. 切分+增强
python -m src.train                                          # 4. 训练+评估
python -m tools.cv_eval --data data/raw/train_clean.csv      # 5. 验证
```

`python -m src.train` 会打印未校准/校准两版模型的指标与 Brier 分数，
并自动选择更优的一版保存到 `models/attack_model.pkl`。

---

## 6. 常见问题

### Q: `python -m pytest` 报 `PermissionError: honeypot_events.jsonl`？

已修复。`src/api.py` 现在会在日志文件不可写时降级为控制台输出，
不再导致服务启动失败。若仍遇到，检查 `data/` 目录写权限。

### Q: 演示脚本里中文显示成乱码？

是终端代码页问题，不是程序问题。服务端输出的是正确 UTF-8：

```powershell
$env:PYTHONIOENCODING="utf-8"
[Console]::OutputEncoding=[System.Text.Encoding]::UTF8
```

### Q: 蜜罐项目里直接 `from src.predict import predict_signal` 报缺包？

蜜罐的 `venv` 是空的（`venv\Lib\site-packages` 里没有 sklearn/numpy）。
两种解决办法：

1. **推荐**：检测器独立跑 HTTP 服务，蜜罐用 `urllib`（标准库，零依赖）调用；
   见 `tools/client_example.py` 的 `ai_signal_http()`。
2. 把检测器的依赖装进蜜罐环境：`pip install scikit-learn joblib numpy pandas`。

### Q: 端口被占用？

换端口：`python -m uvicorn src.api:app --port 8200`，
调用时加 `--url http://127.0.0.1:8200`。

### Q: 怎么确认用的是新版五分类模型？

```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8100/model/info" | ConvertTo-Json
```

应返回 `"version": "v2"` 和 5 个标签（含 `sensitive_path`）。
旧模型备份在 `models/attack_model_v1_backup.pkl`。

---

## 7. 测试清单（答辩/验收自查）

| # | 检查项 | 命令 | 通过标准 |
|---|---|---|---|
| 1 | 单元测试 | `python -m pytest -q` | 14 passed |
| 2 | 信号链路演示 | `python -m tools.demo_signal` | 15/15 一致 |
| 3 | 服务健康 | `GET /health` | `status: ok`, `model_loaded: true` |
| 4 | 模型版本 | `GET /model/info` | `version: v2`，5 个标签 |
| 5 | **对接主接口** | `POST /api/v1/detect` | 返回 `attack_type`、`ai_points`、`reasons` |
| 6 | 正常路径不误报 | `POST /api/v1/detect {"path":"/index.php"}` | `is_attack: false` |
| 7 | 蜜罐侧接入 | `python -m tools.client_example` | 分值正确累加、分层正确 |
| 8 | 模型质量 | `python -m tools.cv_eval ...` | 融合链路宏 F1 ≈ 0.9872 |
| 9 | 误报控制 | 同上 | 误报 38 条(0.096%)，高危层 99.9% 精确 |
| 10 | **评估报告** | `python -m tools.eval_report_md` | 生成 `eval_report.md` 含分类别识别率 |
| 11 | 一键全流程 | `run_all.ps1 -Serve -Full` | 全部通过 |
