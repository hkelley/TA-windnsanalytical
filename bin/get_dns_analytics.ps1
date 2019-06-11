
param
(
      [Parameter(Mandatory = $false)] [int] $MaxRuntimeSecs = 55
    , [Parameter(Mandatory = $false)] [string] $filterXPath = "*[System[EventID=256 or EventID=257 or EventID=261] and EventData[Data[@Name='InterfaceIP']!='127.0.0.1']]"  # trim noise, log only QUERY_RECEIVED or RECURSE_RESPONSE_IN or RESPONSE_SUCCESS
    , [Parameter(Mandatory = $false)] [switch] $SplunkdLogging
)


function Start-Watchdog {
  param(  
      [Int32]     $WaitSeconds
    , [ScriptBlock] $Action = {
            # to splunkd.log
            [Console]::Error.WriteLine(("INFO [{0}:{1}] Script exceeded maximum runtime of {0}.  Terminating PID {1}" -f $WaitSeconds,$PID))

            # to index
            [Console]::WriteLine(("INFO [{0}:{1}] Script exceeded maximum runtime of {0}.  Terminating PID {1}" -f $WaitSeconds,$PID))
            Stop-Process -Id $PID 
       }
  )
  
  $Wait = "Start-Sleep -seconds $WaitSeconds"
  $script:Watchdog = [PowerShell]::Create().AddScript($Wait).AddScript($Action)
  $handle = $Watchdog.BeginInvoke()
#  Write-Warning "Watchdog will terminate process $PID in $WaitSeconds seconds unless Stop-Watchdog is called."
}

function Stop-Watchdog {
  if ( $script:Watchdog -ne $null) {
    $script:Watchdog.Stop()
    $script:Watchdog.Runspace.Close()
    $script:Watchdog.Dispose()
    Remove-Variable Watchdog -Scope script
  } else {
    Write-Warning 'No Watchdog found.'
  }
}

$scriptname = Split-Path $MyInvocation.MyCommand.Path -Leaf

Start-Watchdog $MaxRuntimeSecs
if($SplunkdLogging)
{  [Console]::Error.WriteLine(("INFO [{0}:{1}] Started a watchdog thread to terminate this script if it does not finish within {2}s." -f $scriptname,$PID,$MaxRuntimeSecs))  }


$logName = 'Microsoft-Windows-DNSServer/Analytical'


$ignoredZonesStatic = @("microsoft.com","microsoft.com.akadns.net","sophosxl.net")
$ignoredZonesList = New-Object System.Collections.ArrayList

if($SplunkdLogging)
{  [Console]::Error.WriteLine(("INFO [{0}:{1}] Starting" -f $scriptname,$PID))  }

function BuildRegExPatternFromDomain ([string] $domainBase)
{
    return "{0}" -f $domainBase.ToLower().Replace(".","\.")
}

if($SplunkdLogging)
{  [Console]::Error.WriteLine(("INFO [{0}:{1}] Collecting local zones" -f $scriptname,$PID))  }

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


if($SplunkdLogging)
{  [Console]::Error.WriteLine(("INFO [{0}:{1}] Get the Event Log Settings" -f $scriptname,$PID))  }

$eventlogSettings = Get-WinEvent -ListLog $logName
$prov = Get-WinEvent -ListProvider $eventlogSettings.OwningProviderName 
$logFilePath = [System.Environment]::ExpandEnvironmentVariables($eventlogSettings.LogFilePath)  # expand the variables in the file path
$logFile =  Get-ChildItem $logFilePath
$logBkpPath =  Join-Path -Path $env:TEMP  -ChildPath  ("{0}-PID{1}{2}" -f $logFile.BaseName,$PID,$logFile.Extension) # Generate a unique file path for this proc using the PID
   #  (Split-Path -Path $logFilePath -Leaf)

# create sparse arrays to hold mesagetype info.  There are no four-digit event IDs so won't need more than 999 slots
$messageTypes= new-object pscustomobject[] 999 

# Ingest the templates and discover the QNAME positions for each
$NSPREFIX="evt"
$nsm = $nsMgr = New-Object -TypeName System.Xml.XmlNamespaceManager(New-Object System.Xml.NameTable)
$nsm.AddNamespace($NSPREFIX,'http://schemas.microsoft.com/win/2004/08/events')
$filterQnameNode = "/{0}:template/{0}:data[@name='QNAME']" -f $NSPREFIX


if($SplunkdLogging)
{  [Console]::Error.WriteLine(("INFO [{0}:{1}] Begin processing event log message templates" -f $scriptname,$PID))  }

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


if($SplunkdLogging)
{  [Console]::Error.WriteLine(("INFO [{0}:{1}] Clone and clear the active log" -f $scriptname,$PID))  }

# Clone and clear the active log
$logSize = $eventlogSettings.Filesize  # before clearing
$swLogPaused = [Diagnostics.Stopwatch]::StartNew()
$eventlogSettings.IsEnabled = $false
$eventlogSettings.SaveChanges()
Copy-Item $logFilePath -Destination $logBkpPath -Force
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


# Now process the backed-up log data
$ignoredRecs=0
$swRetrievalTime = [Diagnostics.Stopwatch]::StartNew()
$query = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery($logBkpPath,[System.Diagnostics.Eventing.Reader.PathType]::FilePath , $filterXPath);

$reader = New-Object System.Diagnostics.Eventing.Reader.EventLogReader($query)   
$events = New-Object System.Collections.ArrayList
$logStart = $null

if($SplunkdLogging)
{  [Console]::Error.WriteLine(("INFO [{0}:{1}] Process the events." -f $scriptname,$PID))  }

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

    $events.Add($record) | Out-Null
}

$LoggedTimespanSecs = (New-TimeSpan -Start $logStart -End $logEnd).TotalSeconds

$swRetrievalTime.Stop()
$reader.Dispose()
if($LoggedTimespanSecs -eq $null) { $LoggedTimespanSecs = -1 }

if($SplunkdLogging)
{  [Console]::Error.WriteLine(("INFO [{0}:{1}] Removing the copy of the log at {2}" -f $scriptname,$PID,$logBkpPath))  }

Remove-Item -Path $logBkpPath


if($SplunkdLogging)
{  [Console]::Error.WriteLine(("INFO [{0}:{1}] Writing the formatted events to STDOUT" -f $scriptname,$PID))  }

# emit for Splunk UF to parse
$events | fl 

# Performance benchmarking only
#$events[0] | fl TimeCreated
#$events[-1] | fl TimeCreated

if($SplunkdLogging)
{  [Console]::Error.WriteLine(("INFO [{0}:{1}] Writing performance data to STDOUT" -f $scriptname,$PID))  }

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

Stop-Watchdog

if($SplunkdLogging)
{  [Console]::Error.WriteLine(("INFO [{0}:{1}] Log processing complete and watchdog stopped. Exiting" -f $scriptname,$PID))  }