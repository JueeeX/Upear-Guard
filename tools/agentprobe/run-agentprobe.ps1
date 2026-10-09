# One-click AgentProbe scan against the Upear demo protected-chat chain.
# Prereq: product Demo running (examples/product_demo/run.ps1), which provisions
# the probe endpoint key into <runDir>\probe-key.
# Examples:
#   powershell -ExecutionPolicy Bypass -File tools\agentprobe\run-agentprobe.ps1
#   powershell -ExecutionPolicy Bypass -File tools\agentprobe\run-agentprobe.ps1 -Suites "prompt-injection,data-exfiltration,permission-escalation,output-manipulation" -SamplesPerSuite 10
param(
    [string]$Suites = "prompt-injection,data-exfiltration",
    [int]$SamplesPerSuite = 0,          # 0 = run every attack in the suite
    [int]$Seed = (Get-Random),
    [int]$Port = 8099,
    [int]$TimeoutMs = 90000,
    [string]$DemoBase = "http://127.0.0.1:3001",
    [string]$OutRoot = "tmp\agentprobe-runs"
)
$ErrorActionPreference = 'Stop'

$SuiteCounts = @{ 'prompt-injection' = 52; 'data-exfiltration' = 25; 'permission-escalation' = 15; 'output-manipulation' = 12 }
$suiteList = $Suites.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
foreach ($s in $suiteList) { if (-not $SuiteCounts.ContainsKey($s)) { throw "unknown/unsupported suite: $s (multi-agent is audit-only, see docs/agentprobe-experiment-plan-2026-09-04.md)" } }

# 1. Locate the newest demo run and its probe key
$runDir = Get-ChildItem "$env:LOCALAPPDATA\Temp\sumc-demo" -Directory | Sort-Object Name -Descending |
    Where-Object { Test-Path (Join-Path $_.FullName 'probe-key') } | Select-Object -First 1
if (-not $runDir) { throw "no demo run with probe-key found; start the demo first (examples\product_demo\run.ps1)" }
$probeKey = (Get-Content (Join-Path $runDir.FullName 'probe-key') -Raw).Trim()
Write-Host "run dir: $($runDir.FullName)"

# 2. Output dir + artifacts
$plan = @()
foreach ($s in $suiteList) {
    $count = $SuiteCounts[$s]
    $sampled = if ($SamplesPerSuite -gt 0 -and $SamplesPerSuite -lt $count) {
        @(0..($count - 1) | Get-Random -Count $SamplesPerSuite -SetSeed $Seed | Sort-Object)
    } else { @(0..($count - 1)) }
    $plan += [pscustomobject]@{ suite = $s; count = $count; sampled = $sampled }
}

# 3. Output dir + artifacts
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$outDir = Join-Path $OutRoot $stamp
New-Item -ItemType Directory -Path $outDir -Force | Out-Null
$plan | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $outDir 'sampling-plan.json')

# 4. Start the sampling proxy when a subset is requested
$totalRequested = ($plan | ForEach-Object { $_.sampled.Count } | Measure-Object -Sum).Sum
$usingProxy = $totalRequested -lt ($plan | Measure-Object count -Sum).Sum
$target = "$DemoBase/v1/security/probe-chat"
$proxyProc = $null
if ($usingProxy) {
    Write-Host "sampling: $totalRequested of $(($plan | Measure-Object count -Sum).Sum) attacks (seed=$Seed)"
    $proxyProc = Start-Process node -ArgumentList @((Join-Path $PSScriptRoot 'sampling-proxy.mjs'), '--port', "$Port", '--upstream', $target, '--plan', (Join-Path $outDir 'sampling-plan.json'), '--key', $probeKey) -PassThru -WindowStyle Hidden -RedirectStandardError (Join-Path $outDir 'proxy.log')
    Start-Sleep -Milliseconds 800
    $target = "http://127.0.0.1:$Port/"
}

# 5. Generate agentprobe.yaml (P group; http target with probe key auth)
$yaml = @"
agent:
  type: http
  endpoint: "$target"
  method: POST
  headers:
    content-type: application/json
    x-probe-key: "$probeKey"
  request:
    template: '{"message": "{{input}}"}'
  response:
    path: "reply"

suites:
$(($suiteList | ForEach-Object { "  - $_" }) -join "`n")

boundaries:
  system_prompt_secret: true
  tools:
    - alarm.query
    - alarm.diagnose
    - alarm.verify
    - incident.create
    - interface.restart
"@
$yamlPath = Join-Path $outDir 'agentprobe.yaml'
Set-Content -Path $yamlPath -Value $yaml

# 6. Run AgentProbe
try {
    $resultsPath = Join-Path $outDir 'results-protected.json'
    Start-Process -FilePath 'npx.cmd' `
        -ArgumentList @('-y', '@alexmelges/agentprobe', '-c', "`"$yamlPath`"", '-f', 'json') `
        -RedirectStandardOutput $resultsPath `
        -RedirectStandardError (Join-Path $outDir 'npx.log') `
        -NoNewWindow -Wait
} finally {
    if ($proxyProc) { try { $proxyProc.Kill() } catch {} }
}

# 7. Summarize into experiment-plan metrics
$reportPath = Join-Path $outDir 'report.md'
node (Join-Path $PSScriptRoot 'summarize.mjs') (Join-Path $outDir 'results-protected.json') $reportPath
Get-Content $reportPath
Write-Host "`nartifacts: $outDir (results-protected.json, report.md, sampling-plan.json)"
Write-Host "next: triage every compromised row in report.md (true gap / detector false positive / structurally safe)"
