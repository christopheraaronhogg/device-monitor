# desc: Disk report: free space on each drive and the size of common temp folders
Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object {
  '{0} {1,8:N1} GB free of {2,8:N1} GB' -f $_.DeviceID, ($_.FreeSpace / 1GB), ($_.Size / 1GB)
}
Write-Output "`n== Temp folders"
foreach ($p in @($env:TEMP, "$env:SystemRoot\Temp", "$env:SystemRoot\SoftwareDistribution\Download")) {
  $sum = (Get-ChildItem $p -Recurse -Force -File -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum
  '{0}: {1:N2} GB' -f $p, ($sum / 1GB)
}
