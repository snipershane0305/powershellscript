#put this in your startup folder
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process pwsh.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }
$systemDrive = (Get-WmiObject -Class Win32_OperatingSystem).SystemDrive
start-process pwsh.exe -WindowStyle Minimized "$systemDrive\PowershellScript.ps1"
