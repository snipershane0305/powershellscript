if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process pwsh.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }
Import-Module ScheduledTasks 2>$null
Import-Module NetAdapter 2>$null
Import-Module NetTCPIP 2>$null 
Import-Module DnsClient 2>$null
$forcestopprocesses = @(
"ApplicationFrameHost*"
"dllhost*"
"SecurityHealthService*"
"WmiPrvSE*"
"taskhostw*"
"DataExchangeHost*"
"smartscreen*"
"SystemSettingsBroker*"
)
$disabledservices = @(
)
$manualservices = @(
)


######################################################
write-host "SYSTEM MAINTENANCE" -ForegroundColor white
######################################################


write-host "Stopping Services" -ForegroundColor red
Stop-Service $forcestopservices -force 2>$null
Get-Service -Name $disabledservices -ErrorAction SilentlyContinue | Set-Service -StartupType disabled -force 2>$null
Get-Service -Name $manualservices -ErrorAction SilentlyContinue | Set-Service -StartupType manual -force 2>$null
Stop-Service $forcestopservices -force 2>$null
Get-Process -Name $forcestopprocesses -ErrorAction SilentlyContinue | Stop-Process -force 2>$null
write-host "Releasing Memory" -ForegroundColor red
Set-Location $env:SystemDrive\
if (Test-Path ".\memreduct.exe") {
    Start-Process -FilePath ".\memreduct.exe" -ArgumentList "-clean:full", "-silent" -WindowStyle Hidden
    Start-Sleep -Seconds 5
    taskkill /IM memreduct.exe /F *>$null
}
write-host "Trimming System Drive" -ForegroundColor red
Optimize-Volume -DriveLetter ($env:SystemDrive).Substring(0,1) -ReTrim
Optimize-Volume -DriveLetter ($env:SystemDrive).Substring(0,1) -SlabConsolidate
write-host "Deleting Temp Files" -ForegroundColor red
Get-ChildItem -Path "$env:TEMP\" *.* -Recurse | Remove-Item -Force -Recurse 2>$null
Get-ChildItem -Path "$env:windir\Temp\" *.* -Recurse | Remove-Item -Force -Recurse 2>$null


########################################################
write-host "SYSTEM CONFIGURATION" -ForegroundColor white
########################################################


write-host "Disabling Powershell Telemetry" -ForegroundColor red
[Environment]::SetEnvironmentVariable('POWERSHELL_TELEMETRY_OPTOUT', '1', 'Machine')
write-host "Disabling Hibernation" -ForegroundColor red
powercfg.exe /hibernate off
write-host "Changing Boot Settings" -ForegroundColor red
bcdedit /deletevalue useplatformtick
bcdedit /deletevalue disabledynamictick
bcdedit /deletevalue useplatformclock
bcdedit /deletevalue tscsyncpolicy
bcdedit /deletevalue x2apicpolicy
bcdedit /deletevalue vsmlaunchtype
bcdedit /set useplatformtick yes #//DANGEROUS!!//
bcdedit /set disabledynamictick yes
bcdedit /set useplatformclock no #//DANGEROUS!!//
bcdedit /set tscsyncpolicy legacy
bcdedit /set x2apicpolicy Enable
bcdedit /set vsmlaunchtype off
write-host "Changing Network Settings" -ForegroundColor red
netsh int tcp set global rss=enabled | Out-Null
Enable-NetAdapterRss -Name *
netsh int tcp set global timestamps=enabled | Out-Null
netsh int teredo set state disabled | Out-Null
netsh int tcp set global ecncapability=enable | Out-Null
Set-NetTCPSetting -SettingName internet -EcnCapability enabled
netsh int tcp set global rsc=enabled | Out-Null
Set-NetOffloadGlobalSetting -ReceiveSegmentCoalescing enabled
Set-NetOffloadGlobalSetting -PacketCoalescingFilter Disabled
Enable-NetAdapterChecksumOffload -Name *
Write-Host "Disabling Nagle Algorithm" -ForegroundColor red
foreach ($adapter in $adapters) {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$($adapter.InterfaceGuid)"
    
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }

    Set-ItemProperty -Path $regPath -Name "TcpNoDelay" -Value 1
}
write-host "Changing Registry Settings" -ForegroundColor red
#registry changes
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchBoxTaskbarMode" -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Value 0
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSpeed" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold1" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold2" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSensitivity" -Type string -Value 10
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "EnthusiastMode" -Type DWord -Value 1
Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "AllowAutoGameMode" -Type DWord -Value 1
Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "AutoGameModeEnabled" -Type DWord -Value 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "EnableTransparency" -Type DWord -Value 0
$SystemMemory = (Get-CimInstance -ClassName Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1KB
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "SvcHostSplitThresholdInKB" -Type DWord -Value $SystemMemory
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" -Name "MouseDataQueueSize" -Type DWord -Value 0x00000010
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" -Name "KeyboardDataQueueSize" -Type DWord -Value 0x00000010
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowHibernateOption" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowSleepOption" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name "EnablePrefetcher" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name "EnableSuperfetch" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "ThreadedDpcEnable" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Control\PriorityControl" -Name "Win32PrioritySeparation" -Type DWord -Value 0x00000016
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "HwSchMode" -Type DWord -Value 2
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "disableClearType" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "EnableAeroPeek" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Type DWord -Value 0
#Windows update
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Type DWord -Value 0
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" -Name "SearchOrderConfig" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" -Name "DontPromptForWindowsUpdate" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" -Name "DontSearchWindowsUpdate" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" -Name "DriverUpdateWizardWuSearchEnabled" -Type DWord -Value 0
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AutoInstallMinorUpdates" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "ExcludeWUDriversInQualityUpdate" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "ExcludeWUDriversInQualityUpdate" -Type DWord -Value 1
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "SearchOrderConfig" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontSearchWindowsUpdate" -Type DWord -Value 1
#network
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "NetworkThrottlingIndex" -Type DWord -Value 0xffffffff
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched" -Name "NonBestEffortLimit" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AFD\Parameters" -Name "FastSendDatagramThreshold" -Type DWord -Value 0x10000
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "EnableConnectionRateLimiting" -Type DWord -Value 0
#
Disable-ScheduledTask -taskpath "\Microsoft\Windows\WindowsUpdate" -TaskName "Scheduled Start" | Out-Null
Disable-ScheduledTask -taskpath "\Microsoft\Windows\Windows Error Reporting" -TaskName "QueueReporting" | Out-Null
Disable-ScheduledTask -taskpath "\Microsoft\Windows\User Profile Service" -TaskName "HiveUploadTask" | Out-Null
Disable-ScheduledTask -taskpath "\Microsoft\Windows\Maps" -TaskName "MapsUpdateTask" | Out-Null
Disable-ScheduledTask -taskpath "\Microsoft\Windows\Application Experience" -TaskName "MareBackup" | Out-Null
Disable-ScheduledTask -taskpath "\Microsoft\Windows\Application Experience" -TaskName "Microsoft Compatibility Appraiser" | Out-Null
Disable-ScheduledTask -taskpath "\Microsoft\Windows\Application Experience" -TaskName "Microsoft Compatibility Appraiser Exp" | Out-Null
Disable-ScheduledTask -taskpath "\Microsoft\Windows\Application Experience" -TaskName "StartupAppTask" | Out-Null
Disable-ScheduledTask -taskpath "\Microsoft\Windows\Autochk" -TaskName "Proxy" | Out-Null
Disable-ScheduledTask -taskpath "\Microsoft\Windows\Customer Experience Improvement Program" -TaskName "Consolidator" | Out-Null
Disable-ScheduledTask -taskpath "\Microsoft\Windows\Customer Experience Improvement Program" -TaskName "UsbCeip" | Out-Null
Disable-ScheduledTask -taskpath "\Microsoft\Windows\DiskDiagnostic" -TaskName "Microsoft-Windows-DiskDiagnosticDataCollector" | Out-Null
Disable-ScheduledTask -taskpath "\Microsoft\Windows\DiskDiagnostic" -TaskName "Microsoft-Windows-DiskDiagnosticResolver" | Out-Null
Disable-ScheduledTask -taskpath "\Microsoft\Windows\Feedback\Siuf" -TaskName "DmClient" | Out-Null
Disable-ScheduledTask -taskpath "\Microsoft\Windows\Feedback\Siuf" -TaskName "DmClientOnScenarioDownload" | Out-Null
Disable-ScheduledTask -taskpath "\Microsoft\Windows\Windows Error Reporting" -TaskName "QueueReporting" | Out-Null


##################################################
write-host "SYSTEM CLEANUP" -ForegroundColor white
##################################################


write-host "Stopping Services and Processes" -ForegroundColor red
Stop-Service $forcestopservices -force 2>$null
Get-Service -Name $disabledservices -ErrorAction SilentlyContinue | Set-Service -StartupType disabled -force 2>$null
Get-Service -Name $manualservices -ErrorAction SilentlyContinue | Set-Service -StartupType manual -force 2>$null
Stop-Service $forcestopservices -force 2>$null
Get-Process -Name $forcestopprocesses -ErrorAction SilentlyContinue | Stop-Process -force 2>$null
sc config BITS start=disabled > $null
sc config UsoSvc start=disabled > $null
sc config wuauserv start=disabled > $null
net stop BITS *>&1 | Out-Null
net stop UsoSvc *>&1 | Out-Null
net stop wuauserv *>&1 | Out-Null
write-host "Releasing Memory" -ForegroundColor red
Set-Location $env:SystemDrive\
if (Test-Path ".\memreduct.exe") {
    Start-Process -FilePath ".\memreduct.exe" -ArgumentList "-clean:full", "-silent" -WindowStyle Hidden
    Start-Sleep -Seconds 5
    taskkill /IM memreduct.exe /F *>$null
}
write-host "Done" -ForegroundColor red
pause
