
$filterXPath = "*[System[EventID!=280] and EventData[Data[@Name='InterfaceIP']!='127.0.0.1']]"
$logName = 'Microsoft-Windows-DNSServer/Analytical'

$eventlogSettings = Get-WinEvent -ListLog $logName
$logFile = [System.Environment]::ExpandEnvironmentVariables($eventlogSettings.LogFilePath)  # expand the variables in the file path
$logBkp =  Join-Path -Path $env:TEMP  -ChildPath (Split-Path -Path $logFile -Leaf)

# Extract the DNS "message types" from the event provider into a sparse array (element number == event ID).   This is used later for our lightweight message generation
$prov = Get-WinEvent -ListProvider $eventlogSettings.OwningProviderName 
$messageTypes= new-object string[] 999  # no four-digit event IDs so we not find more than 999
$prov.Events | %{    
    $description = $_.Description -replace ";\s+PacketData=%\d+", ""  # remove packetdata  (for now,  too complicated to parse)
    $description = $description -replace "%(?<token>\d{1,2})", "{`${token}}"   # convert for PS-based tokens
    $messageTypes[$_.Id]  = $description
}


# Clear the log
$logSize = $eventlogSettings.Filesize  # before clearing
$swLogPaused = [Diagnostics.Stopwatch]::StartNew()
$eventlogSettings.IsEnabled = $false
$eventlogSettings.SaveChanges()
Copy-Item $logFile -Destination $logBkp -Force
try
{
    [System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog($eventlogSettings.LogName)
}
catch  [System.Management.Automation.MethodException]
{ # eat this exception.   It says "The process cannot access the file because it is being used by another process" but it lies, the log is cleared    
}
$eventlogSettings.IsEnabled = $true
$eventlogSettings.SaveChanges()
$swLogPaused.Stop()


# Capture the interesting events and then (optimistically) clear+release the log file to minimize the data blackout.
# This lets the log get back to collecting data while we process the events using our lightweight formatting
$swRetrievalTime = [Diagnostics.Stopwatch]::StartNew()
$query = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery($logBkp,[System.Diagnostics.Eventing.Reader.PathType]::FilePath , $filterXPath);
$reader = New-Object System.Diagnostics.Eventing.Reader.EventLogReader($query)

# Do not use Get-WinEvent to avoid performance overhead of FormatDescription()
$events = @()
while(($record = $reader.ReadEvent()) -ne $null)
{
    # convert the raw data to a the format, without relying on EventLogRecord.FormatDescription () 
    $propVals=@($null)
    foreach($prop in $record.psbase.Properties)
    {
        $propVals += $prop.value
    }

    $record | Add-Member -MemberType NoteProperty -Name Message -Value ($messageTypes[$record.Id] -f $propVals)

    $events += $record
}
$swRetrievalTime.Stop()
$reader.Dispose()
Remove-Item -Path $logBkp

# emit for Splunk UF to parse
#$events | fl 

$events[0] | fl TimeCreated
$events[-1] | fl TimeCreated

# Emit some performance stats
[pscustomobject]@{
    LoggingPausedMs=$swLogPaused.ElapsedMilliseconds;
    DataRetrievalMs=$swRetrievalTime.ElapsedMilliseconds;
    LogFileMaxBytes=$eventlogSettings.MaximumSizeInBytes
    LoggedBytes=$logSize
    LoggedRecs=$events.Count
    LoggedTimespanSecs=(New-TimeSpan -Start $events[0].timecreated -End $events[-1].timecreated).TotalSeconds
    ScriptRunSecs=$elapsedTimeSecs = (New-TimeSpan -Start (Get-Process -Id $pid).StartTime  -End (Get-Date)).TotalSeconds  
}   | fl 

