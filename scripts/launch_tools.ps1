param([ValidateSet('menu','verify')][string]$Mode='menu',[switch]$CheckOnly)
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new()
$env:PYTHONUTF8='1'
$projectRoot=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location -LiteralPath $projectRoot
$logDirectory=Join-Path $projectRoot 'demo-results'
New-Item -ItemType Directory -Path $logDirectory -Force | Out-Null
$logPath=Join-Path $logDirectory ('launcher-'+(Get-Date -Format 'yyyyMMdd-HHmmss')+'.log')

function Find-ProjectPython {
    $candidates=@()
    foreach($relative in @('.venv-local\Scripts\python.exe','.venv\Scripts\python.exe')) {
        $candidatePath=Join-Path $projectRoot $relative
        if(Test-Path -LiteralPath $candidatePath){$candidates+=@{Exe=$candidatePath;Prefix=@()}}
    }
    foreach($name in @('python','py')) {
        $command=Get-Command $name -CommandType Application -ErrorAction SilentlyContinue
        if($command){$candidates+=@{Exe=$command.Source;Prefix=$(if($name -eq 'py'){@('-3')}else{@()})}}
    }
    foreach($candidate in $candidates) {
        try {
            $prefix=@($candidate.Prefix)
            $version=& $candidate.Exe @prefix -c 'import sys, requests, paramiko; print(sys.version.split()[0])' 2>&1 | Out-String
            if($LASTEXITCODE -eq 0){Write-Host ('解释器：'+$candidate.Exe+' · '+$version.Trim());return $candidate}
        } catch {continue}
    }
    throw '没有找到同时装有 requests 和 paramiko 的 Python。请先在项目目录执行 python scripts/setup_local.py，然后重新双击。'
}

try {
    $python=Find-ProjectPython
    if($CheckOnly){Write-Host '启动检查通过。未发送测试流量。';exit 0}
    if($Mode -eq 'verify'){$choice='4'}else {
        Write-Host '请先启动本机蜜罐 main.py；本工具只访问 127.0.0.1。'
        Write-Host '1 快速 Web 演示    2 完整 Web 演示    3 Web + SSH 混合演示    4 整体验证    0 退出'
        $choice=Read-Host '输入数字'
    }
    $arguments=@()
    switch($choice) {
        '1' {$arguments=@((Join-Path $PSScriptRoot 'mixed_attack_demo.py'),'--quick')}
        '2' {$arguments=@((Join-Path $PSScriptRoot 'mixed_attack_demo.py'),'--business')}
        '3' {$arguments=@((Join-Path $PSScriptRoot 'mixed_attack_demo.py'),'--ssh','--business')}
        '4' {$arguments=@((Join-Path $PSScriptRoot 'verify_project.py'))}
        '0' {exit 0}
        default {throw '选项无效，请输入 0～4。'}
    }
    Write-Host ('输出同时保存到：'+$logPath)
    $prefix=@($python.Prefix)
    $previousPreference=$ErrorActionPreference
    $ErrorActionPreference='Continue'
    try {
        & $python.Exe @prefix @arguments 2>&1 | ForEach-Object { if($_ -is [System.Management.Automation.ErrorRecord]) { $_.Exception.Message } else { $_.ToString() } } | Tee-Object -FilePath $logPath
        $resultCode=$LASTEXITCODE
    } finally {$ErrorActionPreference=$previousPreference}
    Write-Host ('运行结束，退出码：'+$resultCode)
    if($resultCode -ne 0){Write-Host '请打开上述日志查看完整报错；不要只双击验证 Python 文件。'}
    exit $resultCode
} catch {
    $_ | Out-String | Tee-Object -FilePath $logPath
    Write-Host ('启动失败。详细信息已保留：'+$logPath)
    exit 1
}
