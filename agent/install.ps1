# Device Monitor installer (Windows). Served by the hub with its values filled in.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$hub = '__HUB__'; $enroll = '__ENROLL__'; $actions = '__ACTIONS__'
$scripts = '__SCRIPTS_WINDOWS__'; $lhmSha = '__LHM_SHA__'; $pawnSha = '__PAWNIO_SHA__'
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin -and (Test-Path (Join-Path $env:ProgramFiles 'DeviceMonitor'))) { throw 'Device Monitor is installed for all users on this PC. Re-run with Ctrl+Shift+Enter (admin).' }
$dir = if ($isAdmin) { Join-Path $env:ProgramFiles 'DeviceMonitor' } else { Join-Path $env:LOCALAPPDATA 'DeviceMonitor' }
New-Item -ItemType Directory -Force $dir, (Join-Path $dir 'scripts') | Out-Null

Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" | Where-Object { $_.CommandLine -like '*DeviceMonitor\agent.ps1*' } |
  ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }

$id = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography').MachineGuid
if (-not $id) { $id = $env:COMPUTERNAME }
$reply = Invoke-RestMethod -Uri "$hub/api/enroll" -Method Post -ContentType 'application/json' -Body (@{ enroll = $enroll; id = $id; hostname = $env:COMPUTERNAME } | ConvertTo-Json -Compress) -TimeoutSec 15

foreach ($f in 'agent.ps1', 'agent-support.ps1', 'inventory.ps1') { Invoke-WebRequest "$hub/$f" -UseBasicParsing -OutFile (Join-Path $dir $f) }
Get-ChildItem (Join-Path $dir 'scripts') -Filter '*.ps1' | Remove-Item -Force
if ($actions) {
  foreach ($s in $scripts.Split(' ', [StringSplitOptions]::RemoveEmptyEntries)) { Invoke-WebRequest "$hub/agent/scripts/windows/$s" -UseBasicParsing -OutFile (Join-Path $dir "scripts\$s.ps1") }
}
@{ hub = $hub; token = $reply.key; actions = @($actions.Split(' ', [StringSplitOptions]::RemoveEmptyEntries)) } | ConvertTo-Json | Set-Content (Join-Path $dir 'config.json') -Encoding ASCII

if ($isAdmin) {
  & icacls.exe $dir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
  $startup = [Environment]::GetFolderPath('Startup')
  if ($startup) { Remove-Item (Join-Path $startup 'DeviceMonitorAgent.vbs') -Force -ErrorAction SilentlyContinue }
  $a = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$dir\agent.ps1`""
  $p = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
  $o = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 5 -RestartInterval (New-TimeSpan -Minutes 1)
  Register-ScheduledTask -TaskName 'DeviceMonitorAgent' -Action $a -Trigger (New-ScheduledTaskTrigger -AtStartup) -Principal $p -Settings $o -Force | Out-Null
  Start-ScheduledTask -TaskName 'DeviceMonitorAgent'
} else {
  $vbs = Join-Path $dir 'start-agent.vbs'
  @"
CreateObject("WScript.Shell").Run "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File ""$dir\agent.ps1""", 0, False
"@ | Set-Content $vbs -Encoding Unicode
  Copy-Item $vbs (Join-Path ([Environment]::GetFolderPath('Startup')) 'DeviceMonitorAgent.vbs') -Force
  Start-Process wscript.exe -ArgumentList "`"$vbs`""
}

function Get-VerifiedDownload([string]$Name, [string]$Sha) {
  if (-not $Sha) { return $null }
  $file = Join-Path $env:TEMP $Name
  try { Invoke-WebRequest "$hub/download/$Name" -UseBasicParsing -OutFile $file } catch { return $null }
  if ((Get-FileHash $file -Algorithm SHA256).Hash.ToLower() -ne $Sha) { Remove-Item $file -Force; Write-Warning "$Name failed its hash check; skipped."; return $null }
  return $file
}

if ($isAdmin) {
  $zip = Get-VerifiedDownload 'LibreHardwareMonitor.zip' $lhmSha
  $pawn = Get-VerifiedDownload 'PawnIO_setup.exe' $pawnSha
  if ($zip -and $pawn) {
    $pawnOk = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\PawnIO') -or (Test-Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\PawnIO')
    if (-not $pawnOk) { $proc = Start-Process $pawn -ArgumentList '-install', '-silent' -Wait -PassThru; $pawnOk = $proc.ExitCode -eq 0 }
    if ($pawnOk) {
      Stop-ScheduledTask -TaskName 'DeviceMonitorSensors' -ErrorAction SilentlyContinue
      Get-Process LibreHardwareMonitor -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
      Start-Sleep -Seconds 2
      $lhm = Join-Path $dir 'lhm'
      New-Item -ItemType Directory -Force $lhm | Out-Null
      Expand-Archive $zip -DestinationPath $lhm -Force
@'
<?xml version="1.0" encoding="utf-8"?>
<configuration><appSettings>
  <add key="startMinMenuItem" value="true" />
  <add key="minTrayMenuItem" value="true" />
  <add key="runWebServerMenuItem" value="true" />
  <add key="listenerIp" value="127.0.0.1" />
  <add key="listenerPort" value="8085" />
</appSettings></configuration>
'@ | Set-Content (Join-Path $lhm 'LibreHardwareMonitor.config') -Encoding UTF8
      $a = New-ScheduledTaskAction -Execute (Join-Path $lhm 'LibreHardwareMonitor.exe') -WorkingDirectory $lhm
      $p = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
      $o = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero)
      Register-ScheduledTask -TaskName 'DeviceMonitorSensors' -Action $a -Trigger (New-ScheduledTaskTrigger -AtStartup) -Principal $p -Settings $o -Force | Out-Null
      Start-ScheduledTask -TaskName 'DeviceMonitorSensors'
      Write-Host 'Temperature sensors installed (LibreHardwareMonitor + PawnIO).'
    } else { Write-Warning 'PawnIO setup failed; temperature sensors skipped.' }
    Remove-Item $pawn, $zip -Force -ErrorAction SilentlyContinue
  } else { Write-Warning 'Temperature sensor files are not on the hub; skipped.' }
  Write-Host "Installed for all users, runs at startup. Device: $env:COMPUTERNAME -> $hub" -ForegroundColor Green
} else {
  Write-Host "Installed for this user, runs at sign-in. Device: $env:COMPUTERNAME -> $hub" -ForegroundColor Green
  Write-Host 'For temperatures and monitoring while signed out, re-run this in an admin window (Win+R, paste, Ctrl+Shift+Enter).' -ForegroundColor Yellow
}
Write-Host "Uninstall: irm $hub/uninstall.ps1 | iex"
