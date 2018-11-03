# TA-windnsanalytical
Based on Jake Walter's Windows DNS Analytical Log App (https://splunkbase.splunk.com/app/2937/  - Version 1.0  Oct. 26, 2015  Initial release)


ABOUT

The Technology Addon for Windows DNS Analytical logs is designed to be used with Windows DNS servers running on Windows Server 2012 R2 and later. Microsoft has documented a new and recommended method for logging DNS requests using "audit and analytical event logging" as described in this TechNet article:

https://technet.microsoft.com/en-us/library/dn800669.aspx

Analytical logs are written to an event trace log (ETL) and are not able to be read via Splunk's native Windows log monitor. A Powershell script is included that reads the ETL every minute

Lookup tables provide additional data on Windows Event IDs:

https://technet.microsoft.com/en-us/library/dn800669.aspx#analytic

And DNS Resource Record Types:

http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4

INSTALLATION

Install the TA on the target Windows domain controllers, changing DISABLED = 1 to DISABLED = 0 in inputs.conf.

The TA will modify the log rotation settings and initially clear the existing whenever the Splunk UF starts.

Install the TA on search heads and indexers, as needed.



