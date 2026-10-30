# Shared by agent.ps1. Windows PowerShell 5.1 syntax only.
$script:DmVersion = '1.3.0'
$script:DmRunning = @()
$script:DmInvLast = [DateTime]::MinValue
$script:DmScriptTimeout = 120
$script:DmInventoryEveryHours = 6

function Get-DmScripts([string]$Dir) {
  $folder = Join-Path $Dir 'scripts'
  if (-not (Test-Path $folder)) { return @() }
  return @(Get-ChildItem $folder -Filter '*.ps1' | ForEach-Object {
    [ordered]@{ name = $_.BaseName; sha = (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower() }
  })
}

function Send-DmResult([string]$Hub, [string]$Id, [string]$Token, [string]$Cmd, [bool]$Ok, [string]$Message, [string]$Output) {
  if ($Output.Length -gt 15000) { $Output = $Output.Substring($Output.Length - 15000) }
  $body = [ordered]@{ id = $Id; token = $Token; cmd = $Cmd; ok = $Ok; message = $Message; output = $Output } | ConvertTo-Json -Compress
  try { Invoke-RestMethod -Uri "$Hub/api/result" -Method Post -Body ([Text.Encoding]::UTF8.GetBytes($body)) -ContentType 'application/json' -TimeoutSec 10 | Out-Null } catch { }
}

function Start-DmScript([string]$Dir, [string]$Hub, [string]$Id, [string]$Token, $Command) {
  $name = "$($Command.script)"
  if ($name -notmatch '^[a-z0-9][a-z0-9-]{0,39}$') { Send-DmResult $Hub $Id $Token $Command.id $false 'Bad script name.' ''; return }
  $file = Join-Path (Join-Path $Dir 'scripts') "$name.ps1"
  if (-not (Test-Path -LiteralPath $file)) { Send-DmResult $Hub $Id $Token $Command.id $false 'Script not installed on this device.' ''; return }
  $out = [IO.Path]::GetTempFileName()
  $err = [IO.Path]::GetTempFileName()
  $exe = if ($PSVersionTable.PSEdition -eq 'Core') { 'pwsh' } else { 'powershell.exe' }
  $params = @{ FilePath = $exe; ArgumentList = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', "`"$file`""); RedirectStandardOutput = $out; RedirectStandardError = $err; PassThru = $true }
  if ($env:OS -eq 'Windows_NT') { $params.WindowStyle = 'Hidden' }
  try { $p = Start-Process @params -ErrorAction Stop } catch { Send-DmResult $Hub $Id $Token $Command.id $false "Could not start: $($_.Exception.Message)" ''; return }
  # Without touching Handle, ExitCode reads as empty once a Start-Process child has exited (Windows PowerShell 5.1).
  $null = $p.Handle
  $script:DmRunning += [pscustomobject]@{ Proc = $p; Cmd = $Command.id; Out = $out; Err = $err; Started = [DateTime]::UtcNow }
}

function Update-DmRunning([string]$Hub, [string]$Id, [string]$Token) {
  $still = @()
  foreach ($r in $script:DmRunning) {
    $timedOut = ([DateTime]::UtcNow - $r.Started).TotalSeconds -gt $script:DmScriptTimeout
    if (-not $r.Proc.HasExited -and -not $timedOut) { $still += $r; continue }
    if ($timedOut -and -not $r.Proc.HasExited) { try { $r.Proc.Kill() } catch { } }
    $text = ((Get-Content -LiteralPath $r.Out -Raw) + (Get-Content -LiteralPath $r.Err -Raw))
    Remove-Item -LiteralPath $r.Out, $r.Err -Force -ErrorAction SilentlyContinue
    if ($timedOut) { Send-DmResult $Hub $Id $Token $r.Cmd $false "Stopped after $($script:DmScriptTimeout) s." "$text" }
    elseif ($r.Proc.ExitCode -eq 0) { Send-DmResult $Hub $Id $Token $r.Cmd $true 'Finished.' "$text" }
    else { Send-DmResult $Hub $Id $Token $r.Cmd $false "Exit code $($r.Proc.ExitCode)." "$text" }
  }
  $script:DmRunning = $still
}

function Invoke-DmCommand([string]$Dir, [string]$Hub, [string]$Id, [string]$Token, [string[]]$Enabled, $Command) {
  if ("$($Command.id)" -notmatch '^[a-f0-9]{12}$') { return }
  if ($Enabled -notcontains "$($Command.action)") { Send-DmResult $Hub $Id $Token $Command.id $false "$($Command.action) is off on this device." ''; return }
  switch ("$($Command.action)") {
    'restart' {
      & shutdown.exe /r /t 60 /c "Restart requested by IT support. Save your work; restarting in 60 seconds." 2>&1 | Out-Null
      if ($LASTEXITCODE -eq 0) { Send-DmResult $Hub $Id $Token $Command.id $true 'Restarting in 60 seconds. Cancel at the PC with: shutdown /a' '' }
      else { Send-DmResult $Hub $Id $Token $Command.id $false "shutdown.exe exit code $LASTEXITCODE." '' }
    }
    'script' { Start-DmScript $Dir $Hub $Id $Token $Command }
    default { Send-DmResult $Hub $Id $Token $Command.id $false 'Unknown action.' '' }
  }
}

function Start-DmInventoryIfDue([string]$Dir) {
  if (([DateTime]::UtcNow - $script:DmInvLast).TotalHours -lt $script:DmInventoryEveryHours) { return }
  $script:DmInvLast = [DateTime]::UtcNow
  $file = Join-Path $Dir 'inventory.ps1'
  if (-not (Test-Path $file)) { return }
  $p = Start-Process powershell.exe -ArgumentList @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-WindowStyle', 'Hidden', '-File', "`"$file`"") -WindowStyle Hidden -PassThru
  try { $p.PriorityClass = 'BelowNormal' } catch { }
}

function ConvertFrom-LhmNode($Node, [string]$Parent) {
  foreach ($c in @($Node.Children)) {
    if ($c.SensorId -and $c.Type) {
      $v = $null
      if ("$($c.Value)" -match '-?[0-9]+([.,][0-9]+)?') { $v = [double]($Matches[0] -replace ',', '.') }
      if ($null -ne $v) {
        $id = "$($c.SensorId)"
        [pscustomobject]@{ SensorType = "$($c.Type)"; Parent = $id.Substring(0, [math]::Max(0, $id.LastIndexOf('/', $id.LastIndexOf('/') - 1))); Name = "$($c.Text)"; Value = $v }
      }
    }
    if ($c.Children) { ConvertFrom-LhmNode $c $Parent }
  }
}

# Current LibreHardwareMonitor releases expose sensors through their local web server, not WMI.
function Get-DmLhmSensors {
  $listening = @([Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetActiveTcpListeners() | Where-Object { $_.Port -eq 8085 })
  if (-not $listening.Count) { return $null }
  try { return @(ConvertFrom-LhmNode (Invoke-RestMethod 'http://127.0.0.1:8085/data.json' -TimeoutSec 1) '') } catch { return $null }
}
