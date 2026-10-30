# Removes the Device Monitor agent from this Windows PC. Run as admin if it was installed as admin.
Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" | Where-Object { $_.CommandLine -like '*DeviceMonitor\agent.ps1*' } |
  ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Remove-Item (Join-Path ([Environment]::GetFolderPath('Startup')) 'DeviceMonitorAgent.vbs') -Force -ErrorAction SilentlyContinue
Remove-Item (Join-Path $env:LOCALAPPDATA 'DeviceMonitor') -Recurse -Force -ErrorAction SilentlyContinue
foreach ($t in 'DeviceMonitorSensors', 'DeviceMonitorAgent') {
  if (Get-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue) {
    Stop-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $t -Confirm:$false
  }
}
Get-Process LibreHardwareMonitor -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
Remove-Item (Join-Path $env:ProgramFiles 'DeviceMonitor') -Recurse -Force -ErrorAction SilentlyContinue
if (Test-Path (Join-Path $env:ProgramFiles 'DeviceMonitor')) { Write-Warning 'Not fully removed. Re-run in an admin window.' }
else { Write-Host 'Device Monitor agent removed. PawnIO stays installed (remove it in Apps if you want). You can delete the device from the dashboard.' -ForegroundColor Green }
