# desc: Restart print spooler: fixes stuck print queues (needs the admin install)
$ErrorActionPreference = 'Stop'
Restart-Service Spooler -Force
Write-Output "Spooler is $((Get-Service Spooler).Status)."
Get-Printer -ErrorAction SilentlyContinue | ForEach-Object { "$($_.Name): $($_.PrinterStatus)" }
