if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process pwsh.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }
Import-Module ScheduledTasks, NetAdapter, NetTCPIP, DnsClient -ErrorAction SilentlyContinue
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
    #Windows Update
    "wuauserv"                           # Windows Update
    "BITS"                               # Background Intelligent Transfer Service
    "UsoSvc"                             # Update Orchestrator Service
    "wuqisvc"                            # Usage & Quality Insights
    #Remote Access
    "TermService"                        # Remote Desktop Services
    "UmRdpService"                       # RDP UserMode Port Redirector
    "SessionEnv"                         # Remote Desktop Configuration
    "WinRM"                              # Windows Remote Management
    "RemoteRegistry"                     # Remote Registry
    "RemoteAccess"                       # Routing and Remote Access
    "RasAuto"                            # Remote Access Auto Connection Manager
    "RasMan"                             # Remote Access Connection Manager
    "SstpSvc"                            # Secure Socket Tunneling (VPN)
    #Telemetry
    "DiagTrack"                          # Connected User Experiences and Telemetry
    "dmwappushservice"                   # Device Management WAP Push
    "DmEnrollmentSvc"                    # Device Management Enrollment
    "diagsvc"                            # Diagnostic Execution Service
    "TroubleshootingSvc"                 # Recommended Troubleshooting Service
    "wisvc"                              # Windows Insider Service
    #Xbox
    "XblAuthManager"                     # Xbox Live Auth Manager
    "XblGameSave"                        # Xbox Live Game Save
    "XboxGipSvc"                         # Xbox Accessory Management
    "XboxNetApiSvc"                      # Xbox Live Networking Service
    #Bluetooth
    "BTAGService"                        # Bluetooth Audio Gateway
    "BthAvctpSvc"                        # AVCTP Service
    "bthserv"                            # Bluetooth Support Service
    "RtkBtManServ"                       # Realtek Bluetooth Device Manager
    #Mobile/Cellular
    "WwanSvc"                            # WWAN AutoConfig
    "autotimesvc"                        # Cellular Time Sync
    "icssvc"                             # Windows Mobile Hotspot
    "SmsRouter"                          # Windows SMS Router
    "McmSvc"                             # Mobile Connectivity Management
    "PhoneSvc"                           # Phone Service
    "SEMgrSvc"                           # Payments and NFC/SE Manager
    #Hyper-V
    "HvHost"                             # HV Host Service
    "vmicguestinterface"                 # Hyper-V Guest Service Interface
    "vmicheartbeat"                      # Hyper-V Heartbeat Service
    "vmickvpexchange"                    # Hyper-V Data Exchange
    "vmicrdv"                            # Hyper-V Remote Desktop Virtualization
    "vmicshutdown"                       # Hyper-V Guest Shutdown
    "vmictimesync"                       # Hyper-V Time Synchronization
    "vmicvmsession"                      # Hyper-V PowerShell Direct
    "vmicvss"                            # Hyper-V Volume Shadow Copy Requestor
    "AppVClient"                         # Microsoft App-V Client
    #Edge/Google
    "edgeupdate"                         # Microsoft Edge Update
    "edgeupdatem"                        # Microsoft Edge Update
    "MicrosoftEdgeElevationService"      # Microsoft Edge Elevation
    "GoogleChromeElevationService"       # Google Chrome Elevation Service
    #Smart Card
    "SCardSvr"                           # Smart Card
    "ScDeviceEnum"                       # Smart Card Device Enumeration
    "SCPolicySvc"                        # Smart Card Removal Policy
    "CertPropSvc"                        # Certificate Propagation
    #Biometrics
    "WbioSrvc"                           # Windows Biometric Service
    "NaturalAuthentication"              # Natural Authentication
    #Printer
    "Spooler"                            # Print Spooler
    "PrintNotify"                        # Printer Extensions and Notifications
    "PrintScanBrokerService"             # Print Scan Broker
    #Sensors
    "SensorDataService"                  # Sensor Monitoring
    "SensorService"                      # Sensor Monitoring
    "SensrSvc"                           # Sensor Monitoring
    #Backup
    "SDRSVC"                             # Windows Backup
    "wbengine"                           # Block Level Backup Engine
    "fhsvc"                              # File History Service
    "refsdedupsvc"                       # ReFS Dedup Service
    #Storage
    "VSS"                                # Volume Shadow Copy (system restore)
    "swprv"                              # Software Shadow Copy Provider
    "TieringEngineService"               # Storage Tiers Management
    #Camera
    "FrameServer"                        # Windows Camera Frame Server
    "FrameServerMonitor"                 # Windows Camera Frame Server Monitor
    "StiSvc"                             # Windows Image Acquisition
    "WiaRpc"                             # Still Image Acquisition Events
    #Disabled
    "RetailDemo"                         # Retail Demo Service
    "WpcMonSvc"                          # Parental Controls
    "WalletService"                      # Wallet
    "MapsBroker"                         # Downloaded Maps Manager
    "lfsvc"                              # Geolocation Service
    "cloudidsvc"                         # Microsoft Cloud Identity Service
    "shpamsvc"                           # Shared PC Account Manager
    "UevAgentService"                    # User Experience Virtualization
    "wcncsvc"                            # Windows Connect Now
    "SNMPTrap"                           # SNMP Trap
    "PeerDistSvc"                        # BranchCache
    "LocalKdc"                           # Kerberos Local KDC
    "WManSvc"                            # Windows Management Service
    "WSAIFabricSvc"                      # WSAIFabric (AI companion service)
    "ADPSvc"                             # Aggregated Data Platform
    "dcsvc"                              # Declared Configuration Service
    "hpatchmon"                          # Hotpatch Monitoring
    "PushToInstall"                      # Windows PushToInstall
    "smphost"                            # Storage Spaces SMP
    "CscService"                         # Offline Files
    "tzautoupdate"                       # Auto Time Zone Updater
    "wlpasvc"                            # Local Profile Assistant
    "McpManagementService"               # McpManagementService
    "DsSvc"                              # Data Sharing Service
    "NetTcpPortSharing"                  # Net.Tcp Port Sharing
    "KtmRm"                              # KtmRm for DTC
    "SysMain"                            # SysMain/SuperFetch
    "WSearch"                            # Windows Search
    "DisplayEnhancementService"          # Display Enhancement (HDR auto-tune)
    "AssignedAccessManagerSvc"           # Assigned Access (kiosk mode)
    "CDPSvc"                             # Connected Devices Platform Service
    "DPS"                                # Diagnostic Policy Service
    "WdiSystemHost"                      # Diagnostic System Host
    "WdiServiceHost"                     # Diagnostic Service Host
    "iphlpsvc"                           # IP Helper
    "RmSvc"                              # Radio Management Service
    "LanmanServer"                       # Server
    "lmhosts"                            # TCP/IP NetBIOS Helper
    "EventLog"                           # Event Log
    "LanmanWorkstation"                  # Workstation
    "WerSvc"                             # Windows Error Reporting Service
    "SSDPSRV"                            # SSDP Discovery
)
$forcestopservices = @(
    #Windows Update
    "wuauserv"                           # Windows Update
    "BITS"                               # Background Intelligent Transfer Service
    "UsoSvc"                             # Update Orchestrator Service
    "wuqisvc"                            # Usage & Quality Insights
    #Remote Access
    "TermService"                        # Remote Desktop Services
    "UmRdpService"                       # RDP UserMode Port Redirector
    "SessionEnv"                         # Remote Desktop Configuration
    "WinRM"                              # Windows Remote Management
    "RemoteRegistry"                     # Remote Registry
    "RemoteAccess"                       # Routing and Remote Access
    "RasAuto"                            # Remote Access Auto Connection Manager
    "RasMan"                             # Remote Access Connection Manager
    "SstpSvc"                            # Secure Socket Tunneling (VPN)
    #Telemetry
    "DiagTrack"                          # Connected User Experiences and Telemetry
    "dmwappushservice"                   # Device Management WAP Push
    "DmEnrollmentSvc"                    # Device Management Enrollment
    "diagsvc"                            # Diagnostic Execution Service
    "TroubleshootingSvc"                 # Recommended Troubleshooting Service
    "wisvc"                              # Windows Insider Service
    #Xbox
    "XblAuthManager"                     # Xbox Live Auth Manager
    "XblGameSave"                        # Xbox Live Game Save
    "XboxGipSvc"                         # Xbox Accessory Management
    "XboxNetApiSvc"                      # Xbox Live Networking Service
    #Bluetooth
    "BTAGService"                        # Bluetooth Audio Gateway
    "BthAvctpSvc"                        # AVCTP Service
    "bthserv"                            # Bluetooth Support Service
    "RtkBtManServ"                       # Realtek Bluetooth Device Manager
    #Mobile/Cellular
    "WwanSvc"                            # WWAN AutoConfig
    "autotimesvc"                        # Cellular Time Sync
    "icssvc"                             # Windows Mobile Hotspot
    "SmsRouter"                          # Windows SMS Router
    "McmSvc"                             # Mobile Connectivity Management
    "PhoneSvc"                           # Phone Service
    "SEMgrSvc"                           # Payments and NFC/SE Manager
    #Hyper-V
    "HvHost"                             # HV Host Service
    "vmicguestinterface"                 # Hyper-V Guest Service Interface
    "vmicheartbeat"                      # Hyper-V Heartbeat Service
    "vmickvpexchange"                    # Hyper-V Data Exchange
    "vmicrdv"                            # Hyper-V Remote Desktop Virtualization
    "vmicshutdown"                       # Hyper-V Guest Shutdown
    "vmictimesync"                       # Hyper-V Time Synchronization
    "vmicvmsession"                      # Hyper-V PowerShell Direct
    "vmicvss"                            # Hyper-V Volume Shadow Copy Requestor
    "AppVClient"                         # Microsoft App-V Client
    #Edge/Google
    "edgeupdate"                         # Microsoft Edge Update
    "edgeupdatem"                        # Microsoft Edge Update
    "MicrosoftEdgeElevationService"      # Microsoft Edge Elevation
    "GoogleChromeElevationService"       # Google Chrome Elevation Service
    #Smart Card
    "SCardSvr"                           # Smart Card
    "ScDeviceEnum"                       # Smart Card Device Enumeration
    "SCPolicySvc"                        # Smart Card Removal Policy
    "CertPropSvc"                        # Certificate Propagation
    #Biometrics
    "WbioSrvc"                           # Windows Biometric Service
    "NaturalAuthentication"              # Natural Authentication
    #Printer
    "Spooler"                            # Print Spooler
    "PrintNotify"                        # Printer Extensions and Notifications
    "PrintScanBrokerService"             # Print Scan Broker
    #Sensors
    "SensorDataService"                  # Sensor Monitoring
    "SensorService"                      # Sensor Monitoring
    "SensrSvc"                           # Sensor Monitoring
    #Backup
    "SDRSVC"                             # Windows Backup
    "wbengine"                           # Block Level Backup Engine
    "fhsvc"                              # File History Service
    "refsdedupsvc"                       # ReFS Dedup Service
    #Storage
    "VSS"                                # Volume Shadow Copy (system restore)
    "swprv"                              # Software Shadow Copy Provider
    "TieringEngineService"               # Storage Tiers Management
    #Camera
    "FrameServer"                        # Windows Camera Frame Server
    "FrameServerMonitor"                 # Windows Camera Frame Server Monitor
    "StiSvc"                             # Windows Image Acquisition
    "WiaRpc"                             # Still Image Acquisition Events
    #Disabled
    "RetailDemo"                         # Retail Demo Service
    "WpcMonSvc"                          # Parental Controls
    "WalletService"                      # Wallet
    "MapsBroker"                         # Downloaded Maps Manager
    "lfsvc"                              # Geolocation Service
    "cloudidsvc"                         # Microsoft Cloud Identity Service
    "shpamsvc"                           # Shared PC Account Manager
    "UevAgentService"                    # User Experience Virtualization
    "wcncsvc"                            # Windows Connect Now
    "SNMPTrap"                           # SNMP Trap
    "PeerDistSvc"                        # BranchCache
    "LocalKdc"                           # Kerberos Local KDC
    "WManSvc"                            # Windows Management Service
    "WSAIFabricSvc"                      # WSAIFabric (AI companion service)
    "ADPSvc"                             # Aggregated Data Platform
    "dcsvc"                              # Declared Configuration Service
    "hpatchmon"                          # Hotpatch Monitoring
    "PushToInstall"                      # Windows PushToInstall
    "smphost"                            # Storage Spaces SMP
    "CscService"                         # Offline Files
    "tzautoupdate"                       # Auto Time Zone Updater
    "wlpasvc"                            # Local Profile Assistant
    "McpManagementService"               # McpManagementService
    "DsSvc"                              # Data Sharing Service
    "NetTcpPortSharing"                  # Net.Tcp Port Sharing
    "KtmRm"                              # KtmRm for DTC
    "SysMain"                            # SysMain/SuperFetch
    "WSearch"                            # Windows Search
    "DisplayEnhancementService"          # Display Enhancement (HDR auto-tune)
    "AssignedAccessManagerSvc"           # Assigned Access (kiosk mode)
    "CDPSvc"                             # Connected Devices Platform Service
    "DPS"                                # Diagnostic Policy Service
    "WdiSystemHost"                      # Diagnostic System Host
    "WdiServiceHost"                     # Diagnostic Service Host
    "iphlpsvc"                           # IP Helper
    "RmSvc"                              # Radio Management Service
    "LanmanServer"                       # Server
    "lmhosts"                            # TCP/IP NetBIOS Helper
    "EventLog"                           # Event Log
    "LanmanWorkstation"                  # Workstation
    "WerSvc"                             # Windows Error Reporting Service
    "SSDPSRV"                            # SSDP Discovery
    "InstallService"                     # Microsoft Store Install Service
    "TokenBroker"                        # Web Account Manager
    "WFDSConMgrSvc"                      # Wi-Fi Direct Services Connection Manager Service
)

######################################################
write-host "SYSTEM MAINTENANCE" -ForegroundColor white
######################################################


write-host "Stopping Services" -ForegroundColor red
Stop-Service $forcestopservices -force 2>$null
Get-Service -Name $disabledservices -ErrorAction SilentlyContinue | Set-Service -StartupType disabled -force 2>$null
Get-Process -Name $forcestopprocesses -ErrorAction SilentlyContinue | Stop-Process -force 2>$null
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
write-host "Disabling memory compression" -ForegroundColor red
Disable-MMAgent -MemoryCompression -ErrorAction SilentlyContinue | Out-Null
write-host "Changing Boot Settings" -ForegroundColor red
bcdedit /deletevalue useplatformtick *>$null
bcdedit /deletevalue disabledynamictick *>$null
bcdedit /deletevalue useplatformclock *>$null
bcdedit /deletevalue tscsyncpolicy *>$null
bcdedit /deletevalue x2apicpolicy *>$null
bcdedit /deletevalue vsmlaunchtype *>$null
bcdedit /deletevalue hypervisorlaunchtype *>$null
bcdedit /set useplatformtick yes *>$null #//DANGEROUS!!//
bcdedit /set disabledynamictick yes *>$null
bcdedit /set useplatformclock no *>$null #//DANGEROUS!!//
bcdedit /set tscsyncpolicy legacy *>$null
bcdedit /set x2apicpolicy Enable *>$null
bcdedit /set vsmlaunchtype off *>$null
bcdedit /set hypervisorlaunchtype off *>$null
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
Get-NetAdapter -Physical |
    Where-Object Status -eq "Up" |
    ForEach-Object {
        if (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$($_.InterfaceGuid)")) {
            New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$($_.InterfaceGuid)" | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$($_.InterfaceGuid)" -Name "TcpNoDelay" -Value 1
    }
write-host "Changing Registry Settings" -ForegroundColor red
#registry changes
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSpeed" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold1" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold2" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSensitivity" -Type string -Value 10
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "RawMouseThrottleEnabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "EnthusiastMode" -Type DWord -Value 1
Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "AllowAutoGameMode" -Type DWord -Value 1
Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "AutoGameModeEnabled" -Type DWord -Value 1
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "EnableTransparency" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Name "GlobalUserDisabled" -Type DWord -Value 1
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BackgroundAppGlobalToggle" -Type DWord -Value 0
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsRunInBackground" -Type DWord -Value 2
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowHibernateOption" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowSleepOption" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "disableClearType" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "EnableAeroPeek" -Type DWord -Value 0
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Type DWord -Value 0
$SystemMemory = (Get-CimInstance -ClassName Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1KB
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "SvcHostSplitThresholdInKB" -Type DWord -Value $SystemMemory
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name "EnablePrefetcher" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name "EnableSuperfetch" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "ThreadedDpcEnable" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Control\PriorityControl" -Name "Win32PrioritySeparation" -Type DWord -Value 0x00000016
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "HwSchMode" -Type DWord -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "DisablePageCombining" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "DisablePagingExecutive" -Type DWord -Value 1
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


##################################################
write-host "SYSTEM CLEANUP" -ForegroundColor white
##################################################


write-host "Stopping Services and Processes" -ForegroundColor red
Stop-Service $forcestopservices -force 2>$null
Get-Service -Name $disabledservices -ErrorAction SilentlyContinue | Set-Service -StartupType disabled -force 2>$null
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
