# tests/run_all.ps1 —— xss_detector 一键测试脚本
#
# 用法（在项目根目录）:
#     pwsh -File tests/run_all.ps1            # 单元测试 + 演示
#     pwsh -File tests/run_all.ps1 -Full      # 额外跑 5 折交叉验证（约 1-2 分钟）
#
# 说明: 使用 PowerShell 而非 .bat，避免 cmd 代码页导致中文乱码。

param(
    [switch]$Full,
    [switch]$Serve          # 额外启动 API 服务并做端到端验证
)

$ErrorActionPreference = "Continue"
$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$env:PYTHONIOENCODING = "utf-8"

# 切到项目根目录（本脚本在 tests/ 下）
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

function Section($n, $title) {
    Write-Host ""
    Write-Host ("=" * 62)
    Write-Host "  [$n] $title"
    Write-Host ("=" * 62)
}

$failed = @()

# ---------- 1. 单元测试 ----------
Section "1/4" "单元测试（模型加载 + 规则 + API）"
python -m pytest -q
if ($LASTEXITCODE -ne 0) { $failed += "单元测试" }

# ---------- 2. 信号链路演示 ----------
Section "2/4" "信号链路演示（AI 加权特征 + 双阈值分层）"
python -m tools.demo_signal
if ($LASTEXITCODE -ne 0) { $failed += "演示脚本" }

# ---------- 3. 交叉验证 ----------
if ($Full) {
    Section "3/4" "5 折交叉验证（规则 / 模型 / 加权融合 对比）"
    python -m tools.cv_eval --data data/raw/train_clean.csv --folds 5
    if ($LASTEXITCODE -ne 0) { $failed += "交叉验证" }
} else {
    Section "3/4" "跳过交叉验证（加 -Full 参数可执行）"
}

# ---------- 4. API 端到端 ----------
if ($Serve) {
    Section "4/4" "启动 API 服务并做端到端验证"
    $port = 8123
    $job = Start-Job -ScriptBlock {
        param($r, $p)
        Set-Location $r
        $env:PYTHONIOENCODING = "utf-8"
        python -m uvicorn src.api:app --host 127.0.0.1 --port $p --log-level warning
    } -ArgumentList $root, $port

    # 等待服务就绪
    $ready = $false
    foreach ($i in 1..20) {
        Start-Sleep -Milliseconds 800
        try {
            $h = Invoke-RestMethod "http://127.0.0.1:$port/health" -TimeoutSec 3
            if ($h.status -eq "ok") { $ready = $true; break }
        } catch { }
    }

    if (-not $ready) {
        Write-Host "[失败] API 服务未能启动"
        $failed += "API 服务"
    } else {
        Write-Host "服务已就绪: http://127.0.0.1:$port  (模型 $($h.model_loaded))"
        Write-Host ""
        Write-Host "接口验证（蜜罐对接相关）:"
        foreach ($ep in @("/", "/health", "/model/info")) {
            try {
                $null = Invoke-RestMethod "http://127.0.0.1:$port$ep" -TimeoutSec 5
                Write-Host ("  GET  {0,-18} OK" -f $ep)
            } catch {
                Write-Host ("  GET  {0,-18} 失败: {1}" -f $ep, $_.Exception.Message)
                $failed += "GET $ep"
            }
        }

        # ★ 对外主接口：验证攻击与正常两类输入
        $cases = @(
            @{ name = "SQLi";   body = @{ path = "/search"; query = "id=1 and 1=1" }; want = $true },
            @{ name = "目录穿越"; body = @{ path = "/download"; query = "file=../../../../etc/passwd" }; want = $true },
            @{ name = "敏感文件"; body = @{ path = "/.env" }; want = $true },
            @{ name = "正常首页"; body = @{ path = "/index.php" }; want = $false },
            @{ name = "正常查询"; body = @{ path = "/search"; query = "q=hello&page=2" }; want = $false }
        )
        foreach ($c in $cases) {
            try {
                $r = Invoke-RestMethod "http://127.0.0.1:$port/api/v1/detect" -Method Post `
                    -Body ($c.body | ConvertTo-Json -Compress) `
                    -ContentType "application/json" -TimeoutSec 10
                $ok = ($r.is_attack -eq $c.want)
                $mark = if ($ok) { "OK" } else { "不符预期" }
                if (-not $ok) { $failed += "detect $($c.name)" }
                Write-Host ("  POST {0,-18} {1,-16} attack={2,-6} ai_points={3,-3} {4}" -f `
                    "/api/v1/detect", $c.name, $r.is_attack, $r.ai_points, $mark)
            } catch {
                Write-Host ("  POST {0,-18} {1,-16} 失败: {2}" -f "/api/v1/detect", $c.name, $_.Exception.Message)
                $failed += "detect $($c.name)"
            }
        }

        Write-Host ""
        python -m tools.client_example --url "http://127.0.0.1:$port"
        if ($LASTEXITCODE -ne 0) { $failed += "客户端调用示例" }

        Stop-Job $job -ErrorAction SilentlyContinue
        Remove-Job $job -Force -ErrorAction SilentlyContinue
        Write-Host "`nAPI 服务已停止"
    }
} else {
    Section "4/4" "跳过 API 端到端（加 -Serve 参数可执行）"
}

# ---------- 汇总 ----------
Write-Host ""
Write-Host ("=" * 62)
if ($failed.Count -eq 0) {
    Write-Host "  全部通过"
} else {
    Write-Host ("  以下步骤失败: " + ($failed -join ", "))
}
Write-Host ("=" * 62)
exit $failed.Count
