# Posts software, Windows Update and hardware details to the hub. Started by agent.ps1 every 6 hours.
param([string]$Hub, [string]$Token)
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$cfgPath = Join-Path $PSScriptRoot 'config.json'
if ((-not $Hub -or -not $Token) -and (Test-Path $cfgPath)) { $cfg = Get-Content $cfgPath -Raw | ConvertFrom-Json; $Hub = $cfg.hub; $Token = $cfg.token }
if (-not $Hub -or -not $Token) { exit 1 }
$id = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography').MachineGuid
if (-not $id) { $id = $env:COMPUTERNAME }

$seen = @{}
$apps = @()
$keys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'Registry::HKEY_USERS\S-1-5-21-*\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
foreach ($k in $keys) {
  foreach ($a in Get-ItemProperty $k) {
    if (-not $a.DisplayName -or $a.SystemComponent -eq 1 -or $seen[$a.DisplayName]) { continue }
    $seen[$a.DisplayName] = 1
    $apps += [ordered]@{ name = "$($a.DisplayName)"; version = "$($a.DisplayVersion)"; publisher = "$($a.Publisher)" }
  }
}
$apps = @($apps | Sort-Object { $_.name })

$updates = [ordered]@{ checked = $false; count = 0; items = @(); error = $null }
try {
  $searcher = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()
  $found = $searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software'").Updates
  $updates.checked = $true
  $updates['count'] = [int]$found.Count
  $items = @()
  foreach ($u in $found) {
    if ($items.Count -ge 100) { break }
    $kb = @($u.KBArticleIDs) | Select-Object -First 1
    $items += [ordered]@{ title = "$($u.Title)"; kb = $(if ($kb) { "KB$kb" } else { $null }); severity = "$($u.MsrcSeverity)" }
  }
  $updates.items = $items
} catch { $updates.error = "$($_.Exception.Message)" }

$reboot = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') -or (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending')
$cs = Get-CimInstance Win32_ComputerSystem
$bios = Get-CimInstance Win32_BIOS
$hotfixes = @(Get-CimInstance Win32_QuickFixEngineering | Sort-Object InstalledOn -Descending | Select-Object -First 20 | ForEach-Object {
  [ordered]@{ id = "$($_.HotFixID)"; date = $(if ($_.InstalledOn) { $_.InstalledOn.ToString('yyyy-MM-dd') } else { $null }) }
})
$body = [ordered]@{
  id = $id; token = $Token
  inventory = [ordered]@{
    user = "$($cs.UserName)"; rebootRequired = [bool]$reboot
    hw = [ordered]@{ vendor = "$($cs.Manufacturer)"; model = "$($cs.Model)"; serial = "$($bios.SerialNumber)" }
    apps = $apps; updates = $updates; hotfixes = $hotfixes
  }
} | ConvertTo-Json -Depth 6 -Compress
foreach ($try in 1..10) {
  try { Invoke-RestMethod -Uri "$Hub/api/inventory" -Method Post -Body ([Text.Encoding]::UTF8.GetBytes($body)) -ContentType 'application/json' -TimeoutSec 30 -ErrorAction Stop | Out-Null; break } catch { Start-Sleep -Seconds 60 }
}
