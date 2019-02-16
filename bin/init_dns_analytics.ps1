
param
(
      [Parameter(Mandatory = $false)] [string] $computername = "."
    , [Parameter(Mandatory = $false)] [switch] $bounce
)

$eventlogSettings = Get-WinEvent -ListLog 'Microsoft-Windows-DNSServer/Analytical'  -ComputerName $computername

# Disable and re-enable the log to clear it
$eventlogSettings.IsEnabled = $false
$eventlogSettings.SaveChanges()


#  Bug - can't change the mode via API  https://github.com/PowerShell/xWinEventLog/issues/18
# $eventlogSettings.LogMode = [System.Diagnostics.Eventing.Reader.EventLogMode]::Retain
$eventlogSettings.IsEnabled = $true
$eventlogSettings.SaveChanges()

$eventlogSettings

if($bounce)
{
    Invoke-Command -Computer $computername -ScriptBlock {
        Get-Service -Name "SplunkForwarder" -ErrorAction SilentlyContinue | Stop-Service
		
		# Clean up any stranded scripted input processes
		Get-WmiObject Win32_Process -Filter "name = 'powershell.exe'" | ?{$_.CommandLine -like "*\etc\apps\TA-WinDNSAnalytical\bin\*" } | %{Write-Host ("Terminating {0}" -f $_.ProcessID);  $_.Terminate();}
		
        Get-Service -Name "SplunkForwarder" -ErrorAction SilentlyContinue | Start-Service
        Get-Service -Name "SplunkForwarder" -ErrorAction SilentlyContinue
    }
}

