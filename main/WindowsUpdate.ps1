if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process pwsh.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }
$updateservices = @(
"wuauserv"
"usosvc"
"bits"
)
#starts needed windows update services
Get-Service -Name $updateservices -ErrorAction SilentlyContinue | Set-Service -StartupType manual
Start-Service $updateservices
#runs windows update
Install-Module -Name PSWindowsUpdate -Force
Import-Module PSWindowsUpdate
Add-WUServiceManager -MicrosoftUpdate -Confirm:$false
Get-WindowsUpdate
Install-WindowsUpdate -MicrosoftUpdate -AcceptAll
#stops update services
Stop-Service $updateservices
Get-Service -Name $updateservices -ErrorAction SilentlyContinue | Set-Service -StartupType disabled
pause
