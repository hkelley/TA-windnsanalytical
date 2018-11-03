
$eventlogSettings = Get-WinEvent -ListLog 'Microsoft-Windows-DNSServer/Analytical'

# Disable and re-enable the log to clear it
$eventlogSettings.IsEnabled = $false
$eventlogSettings.SaveChanges()

$eventlogSettings.LogMode = [System.Diagnostics.Eventing.Reader.EventLogMode]::Retain
$eventlogSettings.IsEnabled = $true
$eventlogSettings.SaveChanges()
