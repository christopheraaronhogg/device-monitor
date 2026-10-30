# desc: Network check: addresses, DNS, internet and Tailscale status
Write-Output '== Addresses'
Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -ne '127.0.0.1' } | ForEach-Object { "$($_.InterfaceAlias): $($_.IPAddress)" }
Write-Output "`n== Internet"
Test-Connection 1.1.1.1 -Count 2 -ErrorAction SilentlyContinue | ForEach-Object { "reply from $($_.Address) in $($_.ResponseTime) ms" }
Write-Output "`n== DNS"
Resolve-DnsName cloudflare.com -Type A -ErrorAction SilentlyContinue | Select-Object -First 3 | ForEach-Object { $_.IPAddress }
Write-Output "`n== Tailscale"
$ts = Join-Path $env:ProgramFiles 'Tailscale\tailscale.exe'
if (Test-Path $ts) { & $ts status 2>&1 | Select-Object -First 12 } else { 'Tailscale not installed' }
