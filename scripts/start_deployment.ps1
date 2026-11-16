param([Parameter(Mandatory=$true)][string]$Directory,[switch]$CheckOnly,[switch]$Collect)
$ErrorActionPreference='Stop'
$root=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$directoryPath=(Resolve-Path -LiteralPath $Directory).Path
if(-not $directoryPath.StartsWith((Join-Path $root 'deployment')+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)){throw 'Invalid deployment directory'}
$python=$null
foreach($relative in @('.venv-local\Scripts\python.exe','.venv\Scripts\python.exe')) {
    $candidate=Join-Path $root $relative
    if(Test-Path -LiteralPath $candidate){try {& $candidate -c 'import flask, requests, paramiko' 2>$null;if($LASTEXITCODE -eq 0){$python=$candidate;break}} catch {continue}}
}
if(-not $python){$python=(Get-Command python -CommandType Application).Source}
if($CheckOnly){Write-Host ('Deployment interpreter: '+$python);exit 0}
Set-Location -LiteralPath $root
$env:PYTHONUTF8='1'
if($Collect) {
    & $python scripts/team_center.py collect --config (Join-Path $directoryPath 'collector.json')
} elseif(Test-Path -LiteralPath (Join-Path $directoryPath 'center.json')) {
    & $python scripts/team_center.py serve --config (Join-Path $directoryPath 'center.json')
} elseif(Test-Path -LiteralPath (Join-Path $directoryPath 'gateway.json')) {
    & $python -m ai_gateway.server --config (Join-Path $directoryPath 'gateway.json')
} else {
    $settings=Get-Content -LiteralPath (Join-Path $directoryPath 'runtime.json') -Raw | ConvertFrom-Json
    $env:HONEYPOT_CONFIG=Join-Path $directoryPath 'project.ini'
    $env:HONEYPOT_AI_CONFIG=Join-Path $directoryPath 'ai.ini'
    $env:HONEYPOT_PERSONA_SEED=$settings.sensor
    $env:DB_TYPE='sqlite'
    $env:DB_PATH=Join-Path $directoryPath 'events.sqlite'
    $env:SSH_PORT=[string]$settings.ssh_port
    $env:WEB_PORT=[string]$settings.web_port
    $env:DASHBOARD_PORT=[string]$settings.dashboard_port
    $env:ALERT_ENABLED='false'
    if(Test-Path -LiteralPath (Join-Path $directoryPath 'collector.json')) {
        $centerSettings=Get-Content -LiteralPath (Join-Path $directoryPath 'collector.json') -Raw | ConvertFrom-Json
        $env:HONEYPOT_CENTER_URL=$centerSettings.endpoint
    }
    & $python main.py
}
exit $LASTEXITCODE

