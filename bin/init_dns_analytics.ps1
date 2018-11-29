
$eventlogSettings = Get-WinEvent -ListLog 'Microsoft-Windows-DNSServer/Analytical'

# Disable and re-enable the log to clear it
$eventlogSettings.IsEnabled = $false
$eventlogSettings.SaveChanges()


#  Bug - can't change the mode via API  https://github.com/PowerShell/xWinEventLog/issues/18
# $eventlogSettings.LogMode = [System.Diagnostics.Eventing.Reader.EventLogMode]::Retain
$eventlogSettings.IsEnabled = $true
$eventlogSettings.SaveChanges()
