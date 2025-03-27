#force opens powershell 7 as admin.
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process pwsh.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }
#imports modules so they can be used to configure settings
Import-Module ScheduledTasks 2>$null
Import-Module NetAdapter 2>$null
Import-Module NetTCPIP 2>$null 
Import-Module DnsClient 2>$null
Import-Module ConfigDefender -SkipEditionCheck 2>$null
$forcestopprocesses = @(
"ApplicationFrameHost*"
"dllhost*"
"SecurityHealthService*"
"WmiPrvSE*"
"taskhostw*"
"DataExchangeHost*"
)
$forcestopservices = @(
"sshd"
"ssh-agent"
"AppXSvc"
"smphost"
"LanmanServer"
"TokenBroker"
"DusmSvc"
"DeviceAssociationService"
"DPS"
"WdiSystemHost"
"InstallService"
"PcaSvc"
"TokenBroker"
"DoSvc"
"AssignedAccessManagerSvc"
"tzautoupdate"
"BITS"
"wbengine"
"PeerDistSvc"
"DiagTrack"
"DialogBlockingService"
"MapsBroker"
"lfsvc"
"iphlpsvc"
"AppVClient"
"Spooler"
"RmSvc"
"RasAuto"
"RasMan"
"SessionEnv"
"TermService"
"UmRdpService"
"RemoteRegistry"
"RemoteAccess"
"shpamsvc"
"SSDPSRV"
"SysMain"
"SgrmBroker"
"lmhosts"
"UsoSvc"
"UevAgentService"
"VSS"
"SDRSVC"
"Sense"
"EventLog"
"WSearch"
"wuauserv"
"wmiApSrv"
"XboxGipSvc"
"XblAuthManager"
"XblGameSave"
"XboxNetApiSvc"
)
$disabledservices = @(
"AssignedAccessManagerSvc"
"tzautoupdate"
"BITS"
"wbengine"
"PeerDistSvc"
"DiagTrack"
"DialogBlockingService"
"MapsBroker"
"lfsvc"
"iphlpsvc"
"AppVClient"
"Spooler"
"RmSvc"
"RasAuto"
"RasMan"
"SessionEnv"
"TermService"
"UmRdpService"
"RemoteRegistry"
"RemoteAccess"
"shpamsvc"
"SSDPSRV"
"SysMain"
"lmhosts"
"UsoSvc"
"UevAgentService"
"VSS"
"SDRSVC"
"EventLog"
"WSearch"
"wuauserv"
"wmiApSrv"
"XboxGipSvc"
"XblAuthManager"
"XblGameSave"
"XboxNetApiSvc"
)
$manualservices = @(
"AxInstSV"
"AppReadiness"
"Appinfo"
"ALG"
"AppMgmt"
"BthAvctpSvc"
"BDESVC"
"BTAGService"
"bthserv"
"camsvc"
"autotimesvc"
"CertPropSvc"
"KeyIso"
"COMSysApp"
"CDPSvc"
"VaultSvc"
"DsSvc"
"DusmSvc"
"dcsvc"
"DeviceAssociationService"
"DeviceInstall"
"DmEnrollmentSvc"
"dmwappushservice"
"DsmSvc"
"DevQueryBroker"
"diagsvc"
"DPS"
"WdiServiceHost"
"WdiSystemHost"
"MSDTC"
"EFS"
"EapHost"
"fhsvc"
"fdPHost"
"FDResPub"
"GameInputSvc"
"GraphicsPerfSvc"
"hidserv"
"IKEEXT"
"SharedAccess"
"IpxlatCfgSvc"
"PolicyAgent"
"KtmRm"
"LxpSvc"
"lltdsvc"
"wlpasvc"
"McpManagementService"
"wlidsvc"
"cloudidsvc"
"MSiSCSI"
"MsKeyboardFilter"
"swprv"
"smphost"
"InstallService"
"SmsRouter"
"NaturalAuthentication"
"Netlogon"
"NcdAutoSetup"
"NcbService"
"Netman"
"NcaSvc"
"netprofm"
"NlaSvc"
"NetSetupSvc"
"CscService"
"defragsvc"
"WpcMonSvc"
"SEMgrSvc"
"PerfHost"
"pla"
"PhoneSvc"
"PlugPlay"
"WPDBusEnum"
"PrintDeviceConfigurationService"
"PrintNotify"
"PrintScanBrokerService"
"wercplsupport"
"PcaSvc"
"QWAVE"
"TroubleshootingSvc"
"refsdedupsvc"
"RpcLocator"
"RetailDemo"
"seclogon"
"SstpSvc"
"SensorDataService"
"SensrSvc"
"SensorService"
"LanmanServer"
"SCardSvr"
"ScDeviceEnum"
"SCPolicySvc"
"SNMPTrap"
"svsvc"
"WiaRpc"
"StorSvc"
"TieringEngineService"
"TapiSrv"
"Themes"
"upnphost"
"vds"
"WalletService"
"WarpJITSvc"
"TokenBroker"
"webthreatdefsvc"
"WebClient"
"WFDSConMgrSvc"
"WbioSrvc"
"FrameServer"
"FrameServerMonitor"
"wcncsvc"
"WEPHOSTSVC"
"WerSvc"
"Wecsvc"
"StiSvc"
"wisvc"
"LicenseManager"
"WManSvc"
"icssvc"
"TrustedInstaller"
"perceptionsimulation"
"WpnService"
"PushToInstall"
"WinRM"
"W32Time"
"ApxSvc"
"WwanSvc"
"sshd"
"ssh-agent"
)
$autoservices = @(
"EventSystem"
"CryptSvc"
"Dhcp"
"TrkWks"
"InventorySvc"
"LocalKdc"
"nsi"
"Power"
"ShellHWDetection"
"SENS"
"UserManager"
"ProfSvc"
"Audiosrv"
"AudioEndpointBuilder"
"Wcmsvc"
"FontCache"
"Winmgmt"
"dot3svc"
"WlanSvc"
"LanmanWorkstation"
)
Stop-Service $forcestopservices -force 2>$null
Stop-Service $disabledservices -force 2>$null
Get-Service -Name $autoservices -ErrorAction SilentlyContinue | Set-Service -StartupType automatic -force 2>$null
Get-Service -Name $manualservices -ErrorAction SilentlyContinue | Set-Service -StartupType manual -force 2>$null
Get-Service -Name $disabledservices -ErrorAction SilentlyContinue | Set-Service -StartupType disabled -force 2>$null
Stop-Service $forcestopservices -force 2>$null
Stop-Service $disabledservices -force 2>$null
Get-Process -Name $forcestopprocesses -ErrorAction SilentlyContinue | Stop-Process -force 2>$null


######################################################
write-host "SYSTEM MAINTENANCE" -ForegroundColor white
######################################################


write-host "Releasing Memory" -ForegroundColor red
Set-Location $env:SystemDrive\
.\memreduct.exe -clean:full
start-sleep -seconds 5
taskkill /IM memreduct.exe
write-host "Trimming Windows Drive" -ForegroundColor red
Optimize-Volume -DriveLetter ($env:SystemDrive).Substring(0,1) -ReTrim
Optimize-Volume -DriveLetter ($env:SystemDrive).Substring(0,1) -SlabConsolidate
write-host "Cleaning System" -ForegroundColor red
Dism.exe /online /Cleanup-Image /StartComponentCleanup /ResetBase
Get-ChildItem -Path "$env:TEMP\" *.* -Recurse | Remove-Item -Force -Recurse 2>$null
Get-ChildItem -Path "$env:windir\Temp\" *.* -Recurse | Remove-Item -Force -Recurse 2>$null


########################################################
write-host "SYSTEM CONFIGURATION" -ForegroundColor white
########################################################


write-host "Disabling Powershell Telemetry" -ForegroundColor red
[Environment]::SetEnvironmentVariable('POWERSHELL_TELEMETRY_OPTOUT', '1', 'Machine')
write-host "Disabling Hibernation" -ForegroundColor red
powercfg.exe /hibernate off
write-host "Enabling Memory Compression" -ForegroundColor red
Enable-MMAgent -mc
write-host "Changing bcdedit Settings" -ForegroundColor red
bcdedit /deletevalue useplatformtick
bcdedit /deletevalue disabledynamictick
bcdedit /deletevalue useplatformclock
bcdedit /deletevalue tscsyncpolicy
bcdedit /deletevalue MSI
bcdedit /deletevalue x2apicpolicy
bcdedit /deletevalue vsmlaunchtype
bcdedit /set useplatformtick yes #//DANGEROUS!!//
bcdedit /set disabledynamictick yes
bcdedit /set useplatformclock no #//DANGEROUS!!//
bcdedit /set tscsyncpolicy legacy
bcdedit /set MSI Default
bcdedit /set x2apicpolicy Enable
bcdedit /set nx OptIn
bcdedit /set vsmlaunchtype off
write-host "Changing fsutil Settings" -ForegroundColor red
fsutil behavior set disabledeletenotify 0
fsutil behavior set disableLastAccess 1
fsutil behavior set disable8dot3 1
write-host "Changing Network Settings" -ForegroundColor red
netsh int tcp set global rss=enabled
Enable-NetAdapterRss -Name *
netsh int teredo set state disabled
netsh int tcp set global ecncapability=enable
Set-NetTCPSetting -SettingName internet -EcnCapability enabled
Set-NetTCPSetting -SettingName Internetcustom -EcnCapability enabled
netsh int tcp set global rsc=disable
Set-NetOffloadGlobalSetting -ReceiveSegmentCoalescing Disabled
netsh int tcp set global nonsackrttresiliency=disabled
Set-NetTCPSetting -SettingName internet -NonSackRttResiliency disabled
Set-NetTCPSetting -SettingName Internetcustom -NonSackRttResiliency disabled
netsh int tcp set global maxsynretransmissions=2
Set-NetTCPSetting -SettingName internet -MaxSynRetransmissions 2
Set-NetTCPSetting -SettingName internetcustom -MaxSynRetransmissions 2
netsh int tcp set security mpp=disabled
Set-NetTCPSetting -SettingName internet -MemoryPressureProtection disabled
Set-NetTCPSetting -SettingName Internetcustom -MemoryPressureProtection disabled
netsh int tcp set supplemental template=internet enablecwndrestart=enabled
netsh int tcp set supplemental template=custom enablecwndrestart=enabled
netsh int tcp set supplemental Template=Internet CongestionProvider=ctcp
netsh int tcp set supplemental Template=custom CongestionProvider=ctcp
Set-NetTCPSetting -SettingName Internet -CongestionProvider CTCP
Set-NetTCPSetting -SettingName internet -DelayedAckFrequency 2
Set-NetTCPSetting -SettingName Internetcustom -DelayedAckFrequency 2
Set-NetOffloadGlobalSetting -PacketCoalescingFilter Disabled
Set-NetOffloadGlobalSetting -Chimney Disabled
Enable-NetAdapterChecksumOffload -Name *
Disable-NetAdapterLso -Name *
write-host "Setting DNS server to 9.9.9.11" -ForegroundColor red
#sets dns server to quad9's secure and ENC capatible dns
$adapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }
foreach ($adapter in $adapters) {
    $interfaceIndex = $adapter.ifIndex
    Set-DnsClientServerAddress -InterfaceIndex $interfaceIndex -ServerAddresses "9.9.9.11"
}
write-host "Changing Defender Settings" -ForegroundColor red
set-mppreference -AllowSwitchToAsyncInspection $true 2>$null
set-mppreference -DisableArchiveScanning $true 2>$null
set-mppreference -DisableCatchupFullScan $true 2>$null
set-mppreference -DisableCatchupQuickScan $true 2>$null
set-mppreference -DisableEmailScanning $true 2>$null
set-mppreference -DisableNetworkProtectionPerfTelemetry $true 2>$null
Set-MpPreference -DisableCoreServiceTelemetry $true 2>$null
set-mppreference -DisableRemovableDriveScanning $true 2>$null
set-mppreference -DisableRestorePoint $true 2>$null 
set-mppreference -EnableLowCpuPriority $true 2>$null 
set-mppreference -EnableNetworkProtection disable 2>$null
set-mppreference -MAPSReporting 0 2>$null
set-mppreference -RandomizeScheduleTaskTimes $false 2>$null
set-mppreference -RemediationScheduleDay 8 2>$null
set-mppreference -ScanAvgCPULoadFactor 5 2>$null
set-mppreference -ScanOnlyIfIdleEnabled $true 2>$null
set-mppreference -ScanParameters 1 2>$null
set-mppreference -ScanScheduleDay 8 2>$null
set-mppreference -SubmitSamplesConsent 2 2>$null
set-mppreference -DisableDatagramProcessing $true 2>$null
Set-MpPreference -EnableControlledFolderAccess Disabled 2>$null
write-host "Changing Registry Settings" -ForegroundColor red
#registry changes
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSpeed" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold1" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold2" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSensitivity" -Type string -Value 10
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -Type string -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "EnthusiastMode" -Type DWord -Value 1
Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "AllowAutoGameMode" -Type DWord -Value 1
Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "AutoGameModeEnabled" -Type DWord -Value 1
$SystemMemory = (Get-CimInstance -ClassName Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1KB
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "SvcHostSplitThresholdInKB" -Type DWord -Value $SystemMemory
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe" -Force | Out-Null
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" -Name "CpuPriorityClass" -Type DWord -Value 4
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" -Name "IoPriority" -Type DWord -Value 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" -Name "MouseDataQueueSize" -Type DWord -Value 0x00000010
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" -Name "KeyboardDataQueueSize" -Type DWord -Value 0x00000010
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowHibernateOption" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowSleepOption" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name "EnablePrefetcher" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "GlobalTimerResolutionRequests" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "ThreadedDpcEnable" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "HeapDeCommitFreeBlockThreshold" -Type DWord -Value 0x00040000
Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Control\PriorityControl" -Name "Win32PrioritySeparation" -Type DWord -Value 0x00000016
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "HwSchMode" -Type DWord -Value 2
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "disableClearType" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "EnableAeroPeek" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "EnableTransparency" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Affinity" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Background Only" -Type String -Value False
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Clock Rate" -Type DWord -Value 0x00002710
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "GPU Priority" -Type DWord -Value 8
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Priority" -Type DWord -Value 2
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Scheduling Category" -Type String -Value High
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "SFIO Priority" -Type String -Value High
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "SystemResponsiveness" -Type DWord -Value 0
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
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "AutoDownload" -Type DWord -Value 2
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ExcludeWUDriversInQualityUpdate" -Type DWord -Value 1
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "SearchOrderConfig" -Type DWord -Value 0
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontSearchWindowsUpdate" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "ExcludeWUDriversInQualityUpdate" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "SearchOrderConfig" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontSearchWindowsUpdate" -Type DWord -Value 1
#network
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "NetworkThrottlingIndex" -Type DWord -Value 0xffffffff
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched" -Name "NonBestEffortLimit" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AFD\Parameters" -Name "FastSendDatagramThreshold" -Type DWord -Value 0x10000
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "EnableConnectionRateLimiting" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "TcpTimedWaitDelay" -Type DWord -Value 0x00000030
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "DefaultTTL" -Type DWord -Value 0x00000064
#privacy
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Name "GlobalUserDisabled" -Type DWord -Value 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type string -Value deny
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "EnableMDNS" -Type DWord -Value 0
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet" -Name "EnableActiveProbing" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Wifi\AllowWiFiHotSpotReporting" -Name "Value" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Wifi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Type DWord -Value 0
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Name "01" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 0
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -Type DWord -Value 0
New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\VSCommon\15.0\SQM" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\VSCommon\15.0\SQM" -Name "OptIn" -Type DWord -Value 0
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Messenger\Client" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Messenger\Client" -Name "CEIP" -Type DWord -Value 2
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting" -Name "DoReport" -Type DWord -Value 0
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting\Consent" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting\Consent" -Name "DefaultConsent" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\Windows Error Reporting" -Name "DontSendAdditionalData" -Type DWord -Value 1
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" -Name "MaintenanceDisabled" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "LimitDiagnosticLogCollection" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "LimitDumpCollection" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "LimitEnhancedDiagnosticDataWindowsAnalytics" -Type DWord -Value 0
#disabling scheduled tasks
Disable-ScheduledTask -taskpath "\Microsoft\Windows\WindowsUpdate" -TaskName "Scheduled Start" | Out-Null
Disable-ScheduledTask -taskpath "\Microsoft\Windows\Windows Error Reporting" -TaskName "QueueReporting" | Out-Null
Disable-ScheduledTask -taskpath "\Microsoft\Windows\User Profile Service" -TaskName "HiveUploadTask" | Out-Null
Disable-ScheduledTask -taskpath "\Microsoft\Windows\Maps" -TaskName "MapsUpdateTask" | Out-Null
Disable-ScheduledTask -taskpath "\Microsoft\Windows\Application Experience" -TaskName "MareBackup" | Out-Null
Disable-ScheduledTask -taskpath "\Microsoft\Windows\Application Experience" -TaskName "Microsoft Compatibility Appraiser" | Out-Null
Disable-ScheduledTask -taskpath "\Microsoft\Windows\Application Experience" -TaskName "Microsoft Compatibility Appraiser Exp" | Out-Null
Disable-ScheduledTask -taskpath "\Microsoft\Windows\Application Experience" -TaskName "StartupAppTask" | Out-Null
Disable-ScheduledTask -taskpath "\Microsoft\Windows\Application Experience" -TaskName "PcaPatchDbTask" | Out-Null
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


write-host "Releasing Memory" -ForegroundColor red
Set-Location $env:SystemDrive\
.\memreduct.exe -clean:full
start-sleep -seconds 5
taskkill /IM memreduct.exe
#set services to manual/disabled and stops background processes
write-host "Stopping Services and Processes" -ForegroundColor red
Stop-Service $forcestopservices -force 2>$null
Stop-Service $disabledservices -force 2>$null
Get-Service -Name $autoservices -ErrorAction SilentlyContinue | Set-Service -StartupType automatic -force 2>$null
Get-Service -Name $manualservices -ErrorAction SilentlyContinue | Set-Service -StartupType manual -force 2>$null
Get-Service -Name $disabledservices -ErrorAction SilentlyContinue | Set-Service -StartupType disabled -force 2>$null
Stop-Service $forcestopservices -force 2>$null
Stop-Service $disabledservices -force 2>$null
Get-Process -Name $forcestopprocesses -ErrorAction SilentlyContinue | Stop-Process -force 2>$null
sc config BITS start=disabled
sc config UsoSvc start=disabled
sc config wuauserv start=disabled
net stop AppXSvc
net stop InstallService
net stop TokenBroker
net stop BITS
net stop UsoSvc
net stop wuauserv
write-host "done" -ForegroundColor red
pause
