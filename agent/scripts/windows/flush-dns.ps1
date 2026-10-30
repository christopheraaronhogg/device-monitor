# desc: Flush DNS: clears this PC's DNS cache
Clear-DnsClientCache -ErrorAction Stop
Write-Output 'DNS cache cleared.'
