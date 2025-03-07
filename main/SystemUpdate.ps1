if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process pwsh.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }
$updateservices = @(
"wuauserv"
"usosvc"
"bits"
)
write-host "Updating Defender Definitions" -ForegroundColor red
#updates microsoft defender
Update-MpSignature -UpdateSource MicrosoftUpdateServer
write-host "done" -ForegroundColor red
start-sleep -seconds 5
write-host "Checking for Windows Updates" -ForegroundColor red
#starts needed windows update services
Get-Service -Name $updateservices -ErrorAction SilentlyContinue | Set-Service -StartupType manual
Start-Service $updateservices
start-sleep -seconds 1
#runs windows update
Install-Module -Name PSWindowsUpdate -Force
Import-Module PSWindowsUpdate
Add-WUServiceManager -MicrosoftUpdate -Confirm:$false
Get-WindowsUpdate
Install-WindowsUpdate -MicrosoftUpdate -AcceptAll
write-host "done" -ForegroundColor red
start-sleep -seconds 5
#stops update services
Stop-Service $updateservices
pause
