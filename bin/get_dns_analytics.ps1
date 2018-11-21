
$filterXPath = "*[System[EventID!=280] and EventData[Data[@Name='InterfaceIP']!='127.0.0.1']]"
$logName = 'Microsoft-Windows-DNSServer/Analytical'

$ignoredZonesStatic = @("microsoft.com","microsoft.com.akadns.net","sophosxl.net")
$ignoredZonesList = New-Object System.Collections.ArrayList

function BuildRegExPatternFromDomain ([string] $domainBase)
{
    return "{0}" -f $domainBase.ToLower().Replace(".","\.")
}

# build the whitelist/ignore list for records
foreach($domain in $ignoredZonesStatic)
{
    $ignoredZonesList.Add( (BuildRegexPatternFromDomain($domain)))  | Out-Null
}
Get-DnsServerZone | %{
    $ignoredZonesList.Add( (BuildRegexPatternFromDomain($_.ZoneName))) | Out-Null
}

# compile a regex to test the zones
$ignoredZonesRegex = [regex] ("(?i)({0})\.$" -f ($ignoredZonesList -join "|"))


$eventlogSettings = Get-WinEvent -ListLog $logName
$prov = Get-WinEvent -ListProvider $eventlogSettings.OwningProviderName 
$logFile = [System.Environment]::ExpandEnvironmentVariables($eventlogSettings.LogFilePath)  # expand the variables in the file path
$logBkp =  Join-Path -Path $env:TEMP  -ChildPath (Split-Path -Path $logFile -Leaf)

# create sparse arrays to hold mesagetype info.  There are no four-digit event IDs so won't need more than 999 slots
$messageTypes= new-object pscustomobject[] 999 

# Ingest the templates and discover the QNAME positions for each
$NSPREFIX="evt"
$nsm = $nsMgr = New-Object -TypeName System.Xml.XmlNamespaceManager(New-Object System.Xml.NameTable)
$nsm.AddNamespace($NSPREFIX,'http://schemas.microsoft.com/win/2004/08/events')
$filterQnameNode = "/{0}:template/{0}:data[@name='QNAME']" -f $NSPREFIX

$prov.Events | %{
    
    # Get the message template (human-readable, to-be parsed by Splunk)
    $description = $_.Description -replace ";\s+PacketData=%\d+", ""  # remove packetdata  (for now,  too complicated to parse)
    $description = $description -replace "%(?<token>\d{1,2})", "{`${token}}"   # convert for PS-based tokens

    # Find the "slot" holding QNAME in this format/template
    $doc = [xml] $_.Template

    $qnameNodePos = $null
    # If the QNAME node exists
    if($qname = $doc.SelectSingleNode($filterQnameNode,$nsm) )
    {
        # Record the position for later evaluation
        $qnameNodePos = $doc.CreateNavigator().Evaluate( "count($filterQnameNode/preceding-sibling::*)",$nsm)        
    }

    $messageTypes[$_.Id] = [pscustomobject] @{
        Template = $description
        QNAMEPos = $qnameNodePos
    }
}


# Clone and clear the active log
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


# Now process the cloned data
$ignoredRecs=0
$swRetrievalTime = [Diagnostics.Stopwatch]::StartNew()
$query = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery($logBkp,[System.Diagnostics.Eventing.Reader.PathType]::FilePath , $filterXPath);

$reader = New-Object System.Diagnostics.Eventing.Reader.EventLogReader($query)   
$events = New-Object System.Collections.ArrayList
$logStart = $null

while(($record = $reader.ReadEvent()) -ne $null) # Do not use Get-WinEvent to avoid performance overhead of FormatDescription()
{
    if($logStart -eq $null)
    {
        $logStart = $record.TimeCreated
    }
    $logEnd = $record.TimeCreated   # optimize - continuous updating may be inefficient

    # domain of the current record
    $qname = [string] $record.psbase.Properties[$messageTypes[$record.Id].QNAMEPos].value
    if($ignoredZonesRegex.IsMatch( $qname.ToLower().Trim()))
    {
        $ignoredRecs++
        continue
    }   

    # convert the raw data to a the format, without relying on EventLogRecord.FormatDescription () 
    $propVals=@($null)
    foreach($prop in $record.psbase.Properties)
    {
        $propVals += $prop.value
    }

    $record | Add-Member -MemberType NoteProperty -Name Message -Value ($messageTypes[$record.Id].Template -f $propVals)

    $events.Add($record)
}

$LoggedTimespanSecs = (New-TimeSpan -Start $logStart -End $logEnd).TotalSeconds

$swRetrievalTime.Stop()
$reader.Dispose()
if($LoggedTimespanSecs -eq $null) { $LoggedTimespanSecs = -1 }
Remove-Item -Path $logBkp


# emit for Splunk UF to parse
$events | fl 

# Performance benchmarking only
#$events[0] | fl TimeCreated
#$events[-1] | fl TimeCreated

# Emit some performance stats
[pscustomobject]@{
    LogPausedMs=$swLogPaused.ElapsedMilliseconds;
    DataRetrievalMs=$swRetrievalTime.ElapsedMilliseconds;
    LogFileMaxBytes=$eventlogSettings.MaximumSizeInBytes
    LogFileCurBytes=$logSize
    LoggedRecs=$events.Count
    IgnoredRecs=$ignoredRecs
    LogTimespanSecs=$LoggedTimespanSecs
    ScriptRunSecs=$elapsedTimeSecs = (New-TimeSpan -Start (Get-Process -Id $pid).StartTime  -End (Get-Date)).TotalSeconds  
}   | fl 

