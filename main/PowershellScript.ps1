if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process pwsh.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }
Import-Module ScheduledTasks, NetAdapter, NetTCPIP, DnsClient -ErrorAction SilentlyContinue
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
    "RmSvc"                              # Radio Management Service
    "LanmanServer"                       # Server
    "lmhosts"                            # TCP/IP NetBIOS Helper
    "LanmanWorkstation"                  # Workstation
    "WerSvc"                             # Windows Error Reporting Service
    "SSDPSRV"                            # SSDP Discovery
    #WS-Discovery/SSDP services for Windows network discovery
    "fdPHost"
    "FDResPub"
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
    "LanmanWorkstation"                  # Workstation
    "WerSvc"                             # Windows Error Reporting Service
    "SSDPSRV"                            # SSDP Discovery
    "InstallService"                     # Microsoft Store Install Service
    "WFDSConMgrSvc"                      # Wi-Fi Direct Services Connection Manager Service
    #WS-Discovery/SSDP services for Windows network discovery
    "fdPHost"
    "FDResPub"
)
$manualservices = @(
    "AxInstSV"
    "AppReadiness"
    "ALG"
    "AppMgmt"
    "camsvc"
    "COMSysApp"
    "VaultSvc"
    "MSDTC"
    "EapHost"
    "InventorySvc"
    "LxpSvc"
    "lltdsvc"
    "MSiSCSI"
    "InstallService"
    "Netlogon"
    "Netman"
    "netprofm"
    "NlaSvc"
    "defragsvc"
    "PerfHost"
    "pla"
    "PlugPlay"
    "wercplsupport"
    "QWAVE"
    "RpcLocator"
    "seclogon"
    "TapiSrv"
    "upnphost"
    "vds"
    "TokenBroker"
    "Wecsvc"
    "TrustedInstaller"
    "perceptionsimulation"
    "FontCache3.0.0.0"
    "WpnService"
    "wmiApSrv"
    "ZTHELPER"
)
write-host "Setting Services" -ForegroundColor red
Stop-Service $forcestopservices -force 2>$null
Get-Service -Name $disabledservices -ErrorAction SilentlyContinue | Set-Service -StartupType disabled -force 2>$null
Stop-Service $forcestopservices -force 2>$null
Get-Service -Name $manualservices -ErrorAction SilentlyContinue | Set-Service -StartupType manual -force 2>$null

write-host "Deleting Temp Files" -ForegroundColor red
Get-ChildItem -Path "$env:TEMP\" *.* -Recurse | Remove-Item -Force -Recurse 2>$null
Get-ChildItem -Path "$env:windir\Temp\" *.* -Recurse | Remove-Item -Force -Recurse 2>$null

write-host "Disabling Powershell Telemetry" -ForegroundColor red
[Environment]::SetEnvironmentVariable('POWERSHELL_TELEMETRY_OPTOUT', '1', 'Machine')
[System.Environment]::SetEnvironmentVariable('POWERSHELL_UPDATECHECK', 'Off', 'Machine')

write-host "Disabling Hibernation" -ForegroundColor red
powercfg.exe /hibernate off

write-host "Disabling memory compression" -ForegroundColor red
Disable-MMAgent -MemoryCompression -ErrorAction SilentlyContinue | Out-Null

write-host "Changing Boot Settings" -ForegroundColor red
bcdedit /deletevalue useplatformclock *>$null
bcdedit /deletevalue tscsyncpolicy *>$null
bcdedit /deletevalue x2apicpolicy *>$null
bcdedit /deletevalue vsmlaunchtype *>$null
bcdedit /deletevalue hypervisorlaunchtype *>$null
bcdedit /set useplatformclock no *>$null #DANGEROUS
bcdedit /set tscsyncpolicy legacy *>$null
bcdedit /set x2apicpolicy Enable *>$null
bcdedit /set vsmlaunchtype off *>$null
bcdedit /set hypervisorlaunchtype off *>$null

write-host "Changing Network Settings" -ForegroundColor red
netsh int tcp set global rss=enabled | Out-Null
Enable-NetAdapterRss -Name *
netsh int tcp set global timestamps=enabled | Out-Null
netsh int teredo set state disabled | Out-Null
netsh int 6to4 set state disabled | Out-Null
netsh int isatap set state disabled | Out-Null
netsh int tcp set global ecncapability=enable | Out-Null
Set-NetTCPSetting -SettingName internet -EcnCapability enabled
netsh int tcp set global rsc=disabled | Out-Null
Set-NetOffloadGlobalSetting -ReceiveSegmentCoalescing Disabled
Disable-NetAdapterRsc -Name *
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
Write-Host "Disabling NetBIOS" -ForegroundColor red
Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=TRUE" |
Invoke-CimMethod -MethodName SetTcpipNetbios -Arguments @{TcpipNetbiosOptions=2} | Out-Null

Write-Host "Editing host file" -ForegroundColor red    
$hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
$blocklist = "services.gfe.nvidia.com", "settings-win.data.microsoft.com", "inputsuggestions.msdxcdn.microsoft.com"
$changed = $false
foreach ($domain in $blocklist) {
    if ((Get-Content $hostsPath) -notcontains "0.0.0.0 $domain") {
        Add-Content -Path $hostsPath -Value "0.0.0.0 $domain"
        $changed = $true
    }
}
if ($changed) { Clear-DnsClientCache }

write-host "Changing Registry Settings" -ForegroundColor red
if (-not (Test-Path "HKCU:\Control Panel\Mouse")) { New-Item -Path "HKCU:\Control Panel\Mouse" | Out-Null }
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSpeed" -Type String -Value 0
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold1" -Type String -Value 0
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold2" -Type String -Value 0
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "RawMouseThrottleEnabled" -Type DWord -Value 0
if (-not (Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager")) { New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" | Out-Null }
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "EnthusiastMode" -Type DWord -Value 1
if (-not (Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize")) { New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" | Out-Null }
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "EnableTransparency" -Type DWord -Value 0
if (-not (Test-Path "HKCU:\Software\Microsoft\Windows\DWM")) { New-Item -Path "HKCU\Software\Microsoft\Windows\DWM" | Out-Null }
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "EnableAeroPeek" -Type DWord -Value 0
if (-not (Test-Path "HKCU:\Control Panel\Desktop")) { New-Item -Path "HKCU:\Control Panel\Desktop" | Out-Null }
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "FontSmoothing" -Type String -Value 0
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "FontSmoothingType" -Type DWord -Value 1
if (-not (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings")) { New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" | Out-Null }
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowHibernateOption" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowSleepOption" -Type DWord -Value 0
if (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power")) { New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" | Out-Null }
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Type DWord -Value 0

if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR")) { New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" | Out-Null }
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Type DWord -Value 0
if (-not (Test-Path "HKCU:\Software\Microsoft\GameBar")) { New-Item -Path "HKCU:\Software\Microsoft\GameBar" | Out-Null }
Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "AllowAutoGameMode" -Type DWord -Value 1
Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "AutoGameModeEnabled" -Type DWord -Value 1
if (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers")) { New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" | Out-Null }
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "HwSchMode" -Type DWord -Value 2

if (-not (Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications")) { New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" | Out-Null }
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Name "GlobalUserDisabled" -Type DWord -Value 1
if (-not (Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search")) { New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" | Out-Null }
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BackgroundAppGlobalToggle" -Type DWord -Value 0
if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) { New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" | Out-Null }
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsRunInBackground" -Type DWord -Value 2
if (-not (Test-Path "HKLM:\SOFTWARE\Microsoft\Input")) { New-Item -Path "HKLM:\SOFTWARE\Microsoft\Input" | Out-Null }
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Input" -Name "InputServiceEnabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Input" -Name "InputServiceEnabledForCCI" -Type DWord -Value 0
if (-not (Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Connectivity\DisableCrossDeviceResume")) { New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Connectivity\DisableCrossDeviceResume" | Out-Null }
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Connectivity\DisableCrossDeviceResume" -Name "value" -Type DWord -Value 1

if (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard")) { New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" | Out-Null }
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Type DWord -Value 0
if (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity")) { New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" | Out-Null }
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -Type DWord -Value 0

$SystemMemory = (Get-CimInstance -ClassName Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1KB
if (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control")) { New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control" | Out-Null }
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "SvcHostSplitThresholdInKB" -Type DWord -Value $SystemMemory
if (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters")) { New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" | Out-Null }
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name "EnablePrefetcher" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name "EnableSuperfetch" -Type DWord -Value 0
if (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management")) { New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" | Out-Null }
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "DisablePageCombining" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "DisablePagingExecutive" -Type DWord -Value 1
if (-not (Test-Path "HKLM:\SYSTEM\ControlSet001\Control\PriorityControl")) { New-Item -Path "HKLM:\SYSTEM\ControlSet001\Control\PriorityControl" | Out-Null }
Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Control\PriorityControl" -Name "Win32PrioritySeparation" -Type DWord -Value 0x00000016

#Windows update
if (-not (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config")) { New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" | Out-Null }
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Type DWord -Value 0
if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata")) { New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" | Out-Null }
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -Type DWord -Value 1
if (-not (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching")) { New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" | Out-Null }
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" -Name "SearchOrderConfig" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" -Name "DontPromptForWindowsUpdate" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" -Name "DontSearchWindowsUpdate" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" -Name "DriverUpdateWizardWuSearchEnabled" -Type DWord -Value 0
if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU")) { New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" | Out-Null }
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AutoInstallMinorUpdates" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "ExcludeWUDriversInQualityUpdate" -Type DWord -Value 1
if (-not (Test-Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings")) { New-Item -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" | Out-Null }
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "ExcludeWUDriversInQualityUpdate" -Type DWord -Value 1
if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching")) { New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" | Out-Null }
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "SearchOrderConfig" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontSearchWindowsUpdate" -Type DWord -Value 1

#Microsoft Store automatic app updates (2 = off, 4 = on)
if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore")) { New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" | Out-Null }
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "AutoDownload" -Type DWord -Value 2

#Network
if (-not (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile")) { New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" | Out-Null }
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "NetworkThrottlingIndex" -Type DWord -Value 0xffffffff
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "SystemResponsiveness" -Type DWord -Value 0
if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched")) { New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched" | Out-Null }
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched" -Name "NonBestEffortLimit" -Type DWord -Value 0
if (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\AFD\Parameters")) { New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AFD\Parameters" | Out-Null }
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AFD\Parameters" -Name "FastSendDatagramThreshold" -Type DWord -Value 0x10000
if (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters")) { New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" | Out-Null }
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "EnableConnectionRateLimiting" -Type DWord -Value 0
if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient")) { New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" | Out-Null }
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "DisableSmartNameResolution" -Type DWord -Value 1
if (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters")) { New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" | Out-Null }
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "EnableMDNS" -Type DWord -Value 0
if (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet")) { New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet" | Out-Null }
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet" -Name "EnableActiveProbing" -Type DWord -Value 0
if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator")) { New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator" | Out-Null }
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator" -Name "NoActiveProbe" -Type DWord -Value 1
if (-not (Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings")) { New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" | Out-Null }
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "AutoDetect" -Type DWord -Value 0
if (-not (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp")) { New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" | Out-Null }
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" -Name "DisableWpad" -Type DWord -Value 1
if (-not (Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad")) { New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" | Out-Null }
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" -Name "WpadOverride" -Type DWord -Value 1

write-host "Disabling ScheduledTasks" -ForegroundColor red
Disable-ScheduledTask -taskpath "\Microsoft\Windows\WindowsUpdate" -TaskName "Scheduled Start" | Out-Null
Disable-ScheduledTask -taskpath "\Microsoft\Windows\Windows Error Reporting" -TaskName "QueueReporting" | Out-Null
Disable-ScheduledTask -taskpath "\Microsoft\Windows\User Profile Service" -TaskName "HiveUploadTask" | Out-Null
Disable-ScheduledTask -taskpath "\Microsoft\Windows\Maps" -TaskName "MapsUpdateTask" | Out-Null
Disable-ScheduledTask -taskpath "\Microsoft\Windows\Application Experience" -TaskName "MareBackup" | Out-Null
Disable-ScheduledTask -taskpath "\Microsoft\Windows\Application Experience" -TaskName "Microsoft Compatibility Appraiser Exp" | Out-Null
Disable-ScheduledTask -taskpath "\Microsoft\Windows\Customer Experience Improvement Program" -TaskName "Consolidator" | Out-Null
Disable-ScheduledTask -taskpath "\Microsoft\Windows\Customer Experience Improvement Program" -TaskName "UsbCeip" | Out-Null
Disable-ScheduledTask -taskpath "\Microsoft\Windows\Feedback\Siuf" -TaskName "DmClient" | Out-Null
Disable-ScheduledTask -taskpath "\Microsoft\Windows\Feedback\Siuf" -TaskName "DmClientOnScenarioDownload" | Out-Null
Disable-ScheduledTask -TaskPath "\Microsoft\Windows\InstallService\" -TaskName "ScanForUpdates" | Out-Null
Disable-ScheduledTask -TaskPath "\Microsoft\Windows\InstallService\" -TaskName "ScanForUpdatesAsUser" | Out-Null
Disable-ScheduledTask -TaskPath "\Microsoft\Windows\Device Information" -TaskName "Device" | Out-Null
Disable-ScheduledTask -TaskPath "\Microsoft\Windows\Device Information" -TaskName "Device User" | Out-Null
Disable-ScheduledTask -TaskPath "\Microsoft\Windows\Flighting\FeatureConfig" -TaskName "UsageDataFlushing" | Out-Null
Disable-ScheduledTask -TaskPath "\Microsoft\Windows\Flighting\FeatureConfig" -TaskName "UsageDataReceiver" | Out-Null
Disable-ScheduledTask -TaskPath "\Microsoft\Windows\Flighting\FeatureConfig" -TaskName "ReconcileFeatures" | Out-Null
Disable-ScheduledTask -TaskPath "\Microsoft\Windows\WwanSvc\" -TaskName "OobeDiscovery" | Out-Null
Disable-ScheduledTask -TaskPath "\Microsoft\Windows\Sustainability\" -TaskName "PowerGridForecastTask" | Out-Null
Disable-ScheduledTask -TaskPath "\Microsoft\Windows\Hotpatch\" -TaskName "Monitoring" | Out-Null
Disable-ScheduledTask -TaskPath "\Microsoft\Windows\Speech\" -TaskName "SpeechModelDownloadTask" | Out-Null
Disable-ScheduledTask -TaskPath "\Microsoft\Windows\PushToInstall\" -TaskName "Registration" | Out-Null
Disable-ScheduledTask -TaskPath "\Microsoft\Windows\PushToInstall\" -TaskName "LoginCheck" | Out-Null
Disable-ScheduledTask -TaskPath "\Microsoft\Windows\Flighting\OneSettings\" -TaskName "RefreshCache" | Out-Null
Disable-ScheduledTask -TaskPath "\Microsoft\Windows\Windows Defender\" -TaskName "Windows Defender Cache Maintenance" | Out-Null
Disable-ScheduledTask -TaskPath "\Microsoft\Windows\Windows Defender\" -TaskName "Windows Defender Scheduled Scan" | Out-Null
Disable-ScheduledTask -TaskPath "\Microsoft\Windows\Windows Defender\" -TaskName "Windows Defender Cleanup" | Out-Null
Disable-ScheduledTask -TaskPath "\Microsoft\Windows\Windows Defender\" -TaskName "Windows Defender Verification" | Out-Null

write-host "Setting Services" -ForegroundColor red
Stop-Service $forcestopservices -force 2>$null
Get-Service -Name $disabledservices -ErrorAction SilentlyContinue | Set-Service -StartupType disabled -force 2>$null
Stop-Service $forcestopservices -force 2>$null
Get-Service -Name $manualservices -ErrorAction SilentlyContinue | Set-Service -StartupType manual -force 2>$null

write-host "Stopping Update Services" -ForegroundColor red
net stop BITS *>&1 | Out-Null
net stop UsoSvc *>&1 | Out-Null
net stop wuauserv *>&1 | Out-Null
net stop DoSvc *>&1 | Out-Null

write-host "Killing Smartscreen.exe and usoclient.exe" -ForegroundColor red
$files = @(
    "$env:SystemDrive\WINDOWS\system32\usoclient.exe",
    "$env:SystemDrive\WINDOWS\system32\smartscreen.exe"
)
foreach ($file in $files) {
    if (-not (Test-Path $file)) {
        continue
    }
    takeown /f $file /a | Out-Null
    icacls $file /grant "*S-1-5-32-544:F" | Out-Null
    $newName = (Split-Path $file -Leaf) + ".disabled"
    Rename-Item -Path $file -NewName $newName -Force
}
write-host "Running IdleTasks" -ForegroundColor red
Rundll32.exe advapi32.dll,ProcessIdleTasks

write-host "Releasing Memory" -ForegroundColor red
Set-Location $env:SystemDrive\
if (Test-Path ".\memreduct.exe") {
    Start-Process -FilePath ".\memreduct.exe" -ArgumentList "-clean:full", "-silent" -WindowStyle Hidden
    Start-Sleep -Seconds 5
    taskkill /IM memreduct.exe /F *>$null
}
write-host "Done" -ForegroundColor red
pause
