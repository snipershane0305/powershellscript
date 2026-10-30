if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process pwsh.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }
Import-Module ScheduledTasks, NetAdapter, NetTCPIP, DnsClient -ErrorAction SilentlyContinue
write-host "Setting Services" -ForegroundColor red
$manualServices = @"
Name,StartupType,OriginalType,ForceStop,DisplayName
ALG,Manual,Manual,False,Application Layer Gateway Service
AppIDSvc,Manual,Manual,False,Application Identity
AppMgmt,Manual,Manual,False,Application Management
AppReadiness,Manual,Manual,False,App Readiness
Appinfo,Manual,Manual,False,Application Information
AudioEndpointBuilder,Automatic,Automatic,False,Windows Audio Endpoint Builder
Audiosrv,Automatic,Automatic,False,Windows Audio
AxInstSV,Manual,Manual,False,ActiveX Installer Service
BDESVC,Manual,Manual,False,BitLocker Drive Encryption Service
BFE,Automatic,Automatic,False,Base Filtering Engine
BTAGService,Manual,Manual,False,Bluetooth Audio Gateway Service
BcastDVRUserService_*,Manual,Manual,False,GameDVR and Broadcast User Service
BluetoothUserService_*,Manual,Manual,False,Bluetooth User Support Service
BrokerInfrastructure,Automatic,Automatic,False,Background Tasks Infrastructure Service
Browser,Manual,Manual,False,Computer Browser
BthHFSrv,Manual,Automatic,False,Bluetooth Handsfree Service
COMSysApp,Manual,Manual,False,COM+ System Application
CaptureService_*,Manual,Manual,False,CaptureService
CertPropSvc,Manual,Manual,False,Certificate Propagation
ConsentUxUserSvc_*,Manual,Manual,False,ConsentUX User Service
CoreMessagingRegistrar,Automatic,Automatic,False,CoreMessaging
CredentialEnrollmentManagerUserSvc_*,Manual,Manual,False,CredentialEnrollmentManagerUserSvc
CryptSvc,Automatic,Automatic,False,Cryptographic Services
CscService,Manual,Manual,False,Offline Files
DcomLaunch,Automatic,Automatic,False,DCOM Server Process Launcher
DcpSvc,Manual,Manual,False,Data Collection Publishing Service (uncertain)
DevQueryBroker,Manual,Manual,False,DevQuery Background Discovery Broker
DeviceAssociationBrokerSvc_*,Manual,Manual,False,DeviceAssociationBroker
DeviceAssociationService,Manual,Manual,False,Device Association Service
DeviceInstall,Manual,Manual,False,Device Install Service
DevicePickerUserSvc_*,Manual,Manual,False,DevicePickerUserSvc
DevicesFlowUserSvc_*,Manual,Manual,False,DevicesFlowUserSvc
Dhcp,Automatic,Automatic,False,DHCP Client
DispBrokerDesktopSvc,Manual,Automatic,False,Display Policy Service
Dnscache,Automatic,Automatic,False,DNS Client
DsmSvc,Manual,Manual,False,Device Setup Manager
EFS,Manual,Manual,False,Encrypting File System (EFS)
EapHost,Manual,Manual,False,Extensible Authentication Protocol
EntAppSvc,Manual,Manual,False,Microsoft Store Install Service (Enterprise App Management)
EventLog,Automatic,Automatic,False,Windows Event Log
EventSystem,Automatic,Automatic,False,COM+ Event System
Fax,Manual,Manual,False,Fax
FontCache,Automatic,Automatic,False,Windows Font Cache Service
FrameServer,Manual,Manual,False,Windows Camera Frame Server
FrameServerMonitor,Manual,Manual,False,Windows Camera Frame Server Monitor
GraphicsPerfSvc,Manual,Manual,False,GraphicsPerfSvc
HomeGroupListener,Manual,Manual,False,HomeGroup Listener
HomeGroupProvider,Manual,Manual,False,HomeGroup Provider
HvHost,Manual,Manual,False,Hyper-V Host Compute Service
IEEtwCollectorService,Manual,Manual,False,IE ETW Collector Service
IKEEXT,Manual,Manual,False,IKE and AuthIP IPsec Keying Modules
InventorySvc,Manual,Manual,False,Inventory and Compatibility Appraisal service
IpxlatCfgSvc,Manual,Manual,False,IP Translation Configuration Service
KeyIso,Automatic,Automatic,False,CNG Key Isolation
KtmRm,Manual,Manual,False,KtmRm for Distributed Transaction Coordinator
LSM,Automatic,Automatic,False,Local Session Manager
LxpSvc,Manual,Manual,False,Language Experience Service
MSDTC,Manual,Manual,False,Distributed Transaction Coordinator
MSiSCSI,Manual,Manual,False,Microsoft iSCSI Initiator Service
McpManagementService,Manual,Manual,False,MCP Management Service (uncertain)
MessagingService_*,Manual,Manual,False,MessagingService
MixedRealityOpenXRSvc,Manual,Manual,False,Windows Mixed Reality OpenXR Service
MpsSvc,Automatic,Automatic,False,Windows Defender Firewall
MsKeyboardFilter,Manual,Disabled,False,Microsoft Keyboard Filter
NPSMSvc_*,Manual,Manual,False,Now Playing Session Manager
NaturalAuthentication,Manual,Manual,False,Natural Authentication
NcaSvc,Manual,Manual,False,Network Connectivity Assistant
NcbService,Manual,Manual,False,Network Connection Broker
NcdAutoSetup,Manual,Manual,False,Network Connected Devices Auto-Setup
NetSetupSvc,Manual,Manual,False,Network Setup Service
Netman,Manual,Manual,False,Network Connections
NgcCtnrSvc,Manual,Manual,False,Microsoft Passport Container
NgcSvc,Manual,Manual,False,Microsoft Passport (Windows Hello)
NlaSvc,Manual,Manual,False,Network Location Awareness
P9RdrService_*,Manual,Manual,False,P9 Redirector Service (Plan 9 filesystem, for WSL)
PNRPAutoReg,Manual,Manual,False,PNRP Machine Name Publication Service
PNRPsvc,Manual,Manual,False,Peer Name Resolution Protocol
PeerDistSvc,Manual,Manual,False,BranchCache
PenService_*,Manual,Manual,False,Pen Service
PerfHost,Manual,Manual,False,Performance Counter DLL Host
PhoneSvc,Manual,Manual,False,Phone Service
PimIndexMaintenanceSvc_*,Manual,Manual,False,Contact Data (PIM Index Maintenance)
PlugPlay,Manual,Manual,False,Plug and Play
Power,Automatic,Automatic,False,Power
PrintWorkflowUserSvc_*,Manual,Manual,False,PrintWorkflowUserSvc
ProfSvc,Automatic,Automatic,False,User Profile Service
PushToInstall,Manual,Manual,False,Windows PushToInstall Service
QWAVE,Manual,Manual,False,Quality Windows Audio Video Experience
RetailDemo,Manual,Manual,False,Retail Demo Service
RpcEptMapper,Automatic,Automatic,False,RPC Endpoint Mapper
RpcLocator,Manual,Manual,False,Remote Procedure Call (RPC) Locator
RpcSs,Automatic,Automatic,False,Remote Procedure Call (RPC)
SCPolicySvc,Manual,Manual,False,Smart Card Removal Policy
SCardSvr,Manual,Manual,False,Smart Card
SEMgrSvc,Manual,Manual,False,Payments and NFC/SE Manager
SENS,Automatic,Automatic,False,System Event Notification Service
SNMPTRAP,Manual,Manual,False,SNMP Trap
SNMPTrap,Manual,Manual,False,SNMP Trap (alt casing)
SamSs,Manual,Automatic,False,Security Accounts Manager
ScDeviceEnum,Manual,Manual,False,Smart Card Device Enumeration Service
Schedule,Automatic,Automatic,False,Task Scheduler
SecurityHealthService,Manual,Manual,False,Windows Security Service
Sense,Manual,Manual,False,Windows Defender Advanced Threat Protection Service
SgrmBroker,Automatic,Automatic,False,System Guard Runtime Monitor Broker
SharedAccess,Manual,Manual,False,Internet Connection Sharing (ICS)
SharedRealitySvc,Manual,Manual,False,Spatial Data Service (uncertain)
ShellHWDetection,Manual,Automatic,False,Shell Hardware Detection
SmsRouter,Manual,Manual,False,Microsoft Windows SMS Router Service
StateRepository,Manual,Automatic,False,State Repository Service
SystemEventsBroker,Automatic,Automatic,False,System Events Broker
TabletInputService,Manual,Manual,False,Touch Keyboard and Handwriting Panel Service
TapiSrv,Manual,Manual,False,Telephony
Themes,Automatic,Automatic,False,Themes
TimeBroker,Manual,Manual,False,Time Broker
TimeBrokerSvc,Manual,Manual,False,Time Broker (per-session variant)
TokenBroker,Manual,Manual,False,Web Account Manager
TrustedInstaller,Manual,Manual,False,Windows Modules Installer
UI0Detect,Manual,Manual,False,Interactive Services Detection
UdkUserSvc_*,Manual,Manual,False,UdkUserSvc (uncertain - User Data Keys)
UnistoreSvc_*,Manual,Manual,False,User Data Storage
UserDataSvc_*,Manual,Manual,False,User Data Access
UserManager,Automatic,Automatic,False,User Manager
VacSvc,Manual,Manual,False,Volumetric Audio Compositor Service (uncertain)
VaultSvc,Automatic,Automatic,False,Credential Manager
W32Time,Manual,Manual,False,Windows Time
WEPHOSTSVC,Manual,Manual,False,Windows Encryption Provider Host Service
WFDSConMgrSvc,Manual,Manual,False,Wi-Fi Direct Services Connection Manager Service
WMPNetworkSvc,Manual,Manual,False,Windows Media Player Network Sharing Service
WManSvc,Manual,Manual,False,Windows Management Service
WPDBusEnum,Manual,Manual,False,Portable Device Enumerator Service
WSService,Manual,Manual,False,Windows Store Service (uncertain)
WaaSMedicSvc,Manual,Manual,False,Windows Update Medic Service
WalletService,Manual,Manual,False,WalletService
WarpJITSvc,Manual,Manual,False,WarpJITSvc (D3D software rasterizer JIT, uncertain)
WbioSrvc,Manual,Manual,False,Windows Biometric Service
Wcmsvc,Manual,Automatic,False,Windows Connection Manager
WcsPlugInService,Manual,Manual,False,Windows Color System
WdNisSvc,Manual,Manual,False,Microsoft Defender Antivirus Network Inspection Service
WebClient,Manual,Manual,False,WebClient (WebDAV)
Wecsvc,Manual,Manual,False,Windows Event Collector
WiaRpc,Manual,Manual,False,Still Image Acquisition Events
WinHttpAutoProxySvc,Manual,Manual,False,WinHTTP Web Proxy Auto-Discovery Service
Winmgmt,Automatic,Automatic,False,Windows Management Instrumentation
WlanSvc,Automatic,Automatic,False,WLAN AutoConfig
WpcMonSvc,Manual,Manual,False,Parental Controls
WpnService,Manual,Automatic,False,Windows Push Notifications System Service
WpnUserService_*,Automatic,Automatic,False,Windows Push Notifications User Service
WwanSvc,Manual,Manual,False,WWAN AutoConfig
XblAuthManager,Manual,Manual,False,Xbox Live Auth Manager
XblGameSave,Manual,Manual,False,Xbox Live Game Save
XboxGipSvc,Manual,Manual,False,Xbox Accessory Management Service
XboxNetApiSvc,Manual,Manual,False,Xbox Live Networking Service
autotimesvc,Manual,Manual,False,Cellular Time
bthserv,Manual,Manual,False,Bluetooth Support Service
cloudidsvc,Manual,Manual,False,Microsoft Cloud Identity Service
dcsvc,Manual,Manual,False,Declared Configuration(DC) Service
defragsvc,Manual,Manual,False,Optimize Drives
diagnosticshub.standardcollector.service,Manual,Manual,False,Microsoft (R) Diagnostics Hub Standard Collector Service
embeddedmode,Manual,Manual,False,Embedded Mode
gpsvc,Automatic,Automatic,False,Group Policy Client
hidserv,Manual,Manual,False,Human Interface Device Service
icssvc,Manual,Manual,False,Windows Mobile Hotspot Service
lltdsvc,Manual,Manual,False,Link-Layer Topology Discovery Mapper
mpssvc,Automatic,Automatic,False,Windows Defender Firewall
msiserver,Manual,Manual,False,Windows Installer
netprofm,Manual,Manual,False,Network List Service
nsi,Automatic,Automatic,False,Network Store Interface Service
p2pimsvc,Manual,Manual,False,Peer Networking Identity Manager
p2psvc,Manual,Manual,False,Peer Networking Grouping
perceptionsimulation,Manual,Manual,False,Windows Perception Simulation Service
pla,Manual,Manual,False,Performance Logs & Alerts
seclogon,Manual,Manual,False,Secondary Logon
smphost,Manual,Manual,False,Microsoft Storage Spaces SMP
spectrum,Manual,Manual,False,Windows Perception Service (uncertain)
svsvc,Manual,Manual,False,Spot Verifier
tiledatamodelsvc,Automatic,Automatic,False,Tile Data model server
upnphost,Manual,Manual,False,UPnP Device Host
vds,Manual,Manual,False,Virtual Disk
vmicguestinterface,Manual,Manual,False,Hyper-V Guest Service Interface
vmicheartbeat,Manual,Manual,False,Hyper-V Heartbeat Service
vmickvpexchange,Manual,Manual,False,Hyper-V Data Exchange Service
vmicrdv,Manual,Manual,False,Hyper-V Remote Desktop Virtualization Service
vmicshutdown,Manual,Manual,False,Hyper-V Guest Shutdown Service
vmictimesync,Manual,Manual,False,Hyper-V Time Synchronization Service
vmicvmsession,Manual,Manual,False,Hyper-V PowerShell Direct Service
vmicvss,Manual,Manual,False,Hyper-V Volume Shadow Copy Requestor
vmvss,Manual,Manual,False,Hyper-V Volume Shadow Copy Requestor
wcncsvc,Manual,Manual,False,Windows Connect Now - Config Registrar
wercplsupport,Manual,Manual,False,Problem Reports and Solutions Control Panel Support
wlidsvc,Manual,Manual,False,Microsoft Account Sign-in Assistant
wlpasvc,Manual,Manual,False,Local Profile Assistant Service
wmiApSrv,Manual,Manual,False,WMI Performance Adapter
workfolderssvc,Manual,Manual,False,Work Folders
wscsvc,Manual,Automatic,False,Security Center
wudfsvc,Manual,Manual,False,Windows Driver Foundation - User-mode Driver Framework
"@ | ConvertFrom-Csv

$disabledServices = @"
Name,StartupType,OriginalType,ForceStop,DisplayName
AJRouter,Disabled,Manual,True,AllJoyn Router Service
AppVClient,Disabled,Disabled,True,Microsoft App-V Client
AssignedAccessManagerSvc,Disabled,Manual,True,Assigned Access Manager Service
DialogBlockingService,Disabled,Disabled,True,DialogBlockingService
NetTcpPortSharing,Disabled,Disabled,True,Net.Tcp Port Sharing Service
SysMain,Disabled,Automatic,True,SysMain (Superfetch)
UevAgentService,Disabled,Disabled,True,User Experience Virtualization Service
WSearch,Disabled,Automatic,True,Windows Search
lmhosts,Disabled,Manual,True,TCP/IP NetBIOS Helper
shpamsvc,Disabled,Disabled,True,Shared PC Account Manager
ssh-agent,Disabled,Disabled,True,OpenSSH Authentication Agent
tzautoupdate,Disabled,Disabled,True,Auto Time Zone Updater
uhssvc,Disabled,Disabled,True,Microsoft Uev Host Service (uncertain)
webthreatdefsvc,Disabled,Manual,True,Windows Defender Core Service (SmartScreen)
webthreatdefusersvc_*,Disabled,Automatic,True,Windows Defender Core Service (SmartScreen, per-user)
midisrv,Disabled,Automatic,True,Windows MIDI Services
WSAIFabricSvc,Disabled,Automatic,True,WSAIFabricSvc (AI Fabric Service)
RmSvc,Disabled,Disabled,True,Radio Management Service
StorSvc,Disabled,Automatic,True,Storage Service
PcaSvc,Disabled,Automatic,True,Program Compatibility Assistant Service
LicenseManager,Disabled,Manual,True,Windows License Manager Service
Netlogon,Disabled,Automatic,True,Netlogon
LanmanWorkstation,Disabled,Automatic,True,Workstation
DisplayEnhancementService,Disabled,Manual,True,Display Enhancement Service
InstallService,Disabled,Manual,True,Microsoft Store Install Service
LanmanServer,Disabled,Automatic,True,Server
CDPUserSvc_*,Disabled,Automatic,True,Connected Devices Platform User Service
OneSyncSvc_*,Disabled,Automatic,True,Sync Host Service
BthAvctpSvc,Disabled,Automatic,True,AVCTP service
TrkWks,Disabled,Automatic,True,Distributed Link Tracking Client
PolicyAgent,Disabled,Manual,True,IPsec Policy Agent
dot3svc,Disabled,Manual,True,Wired AutoConfig
whesvc,Disabled,Automatic,True,Windows Health and Optimized Experiences
StiSvc,Disabled,Manual,True,Windows Image Acquisition (WIA)

wuauserv,Disabled,Manual,True,Windows Update
BITS,Disabled,Automatic,True,Background Intelligent Transfer Service
UsoSvc,Disabled,Automatic,True,Update Orchestrator Service
DoSvc,Disabled,Automatic,True,Delivery Optimization

DiagTrack,Disabled,Automatic,True,Connected User Experiences and Telemetry
dmwappushservice,Disabled,Manual,True,Device Management Wireless Application Protocol (WAP) Push message Routing Service
DmEnrollmentSvc,Disabled,Manual,True,Device Management Enrollment Service
wisvc,Disabled,Manual,True,Windows Insider Service
CDPSvc,Disabled,Automatic,True,Connected Devices Platform Service
lfsvc,Disabled,Manual,True,Geolocation Service
MapsBroker,Disabled,Automatic,True,Downloaded Maps Manager
WerSvc,Disabled,Manual,True,Windows Error Reporting Service
DsSvc,Disabled,Manual,True,Data Sharing Service

SSDPSRV,Disabled,Manual,True,SSDP Discovery
fdPHost,Disabled,Manual,True,Function Discovery Provider Host
FDResPub,Disabled,Manual,True,Function Discovery Resource Publication

TermService,Disabled,Automatic,True,Remote Desktop Services
UmRdpService,Disabled,Manual,True,Remote Desktop Services UserMode Port Redirector
SessionEnv,Disabled,Manual,True,Remote Desktop Configuration
WinRM,Disabled,Manual,True,Windows Remote Management
RemoteRegistry,Disabled,Disabled,True,Remote Registry
RemoteAccess,Disabled,Disabled,True,Routing and Remote Access
RasAuto,Disabled,Manual,True,Remote Access Auto Connection Manager
RasMan,Disabled,Manual,True,Remote Access Connection Manager
SstpSvc,Disabled,Manual,True,Secure Socket Tunneling Protocol Service

diagsvc,Disabled,Manual,True,Diagnostic Execution Service
TroubleshootingSvc,Disabled,Manual,True,Recommended Troubleshooting Service
DPS,Disabled,Automatic,True,Diagnostic Policy Service
WdiSystemHost,Disabled,Manual,True,Diagnostic System Host
WdiServiceHost,Disabled,Manual,True,Diagnostic Service Host

SDRSVC,Disabled,Manual,True,Windows Backup
wbengine,Disabled,Manual,True,Block Level Backup Engine Service
fhsvc,Disabled,Manual,True,File History Service
refsdedupsvc,Disabled,Manual,True,ReFS Dedup Service
VSS,Disabled,Manual,True,Volume Shadow Copy
swprv,Disabled,Manual,True,Microsoft Software Shadow Copy Provider
TieringEngineService,Disabled,Manual,True,Storage Tiers Management

Spooler,Disabled,Automatic,True,Print Spooler
PrintNotify,Disabled,Manual,True,Printer Extensions and Notifications
PrintScanBrokerService,Disabled,Manual,True,Print Scan Broker Service

SensorDataService,Disabled,Manual,True,Sensor Data Service
SensorService,Disabled,Manual,True,Sensor Service
SensrSvc,Disabled,Manual,True,Sensor Monitoring Service

edgeupdate,Disabled,Automatic,True,Microsoft Edge Update Service
edgeupdatem,Disabled,Manual,True,Microsoft Edge Update Service (medium tier)
MicrosoftEdgeElevationService,Disabled,Manual,True,Microsoft Edge Elevation Service
GoogleChromeElevationService,Disabled,Manual,True,Google Chrome Elevation Service
"@ | ConvertFrom-Csv

$forcestopOnlyServices = @"
Name,StartupType,OriginalType,ForceStop,DisplayName
sppsvc,Manual,Automatic,True,Software Protection
ClipSVC,Manual,Manual,True,Client License Service (ClipSVC)
TextInputManagementService,Manual,Automatic,True,Text Input Management Service
camsvc,Manual,Manual,True,Capability Access Manager Service
cbdhsvc_*,Manual,Automatic,True,Clipboard User Service
DusmSvc,Manual,Automatic,True,Data Usage
iphlpsvc,Manual,Automatic,True,IP Helper
AppXSvc,Manual,Manual,True,AppX Deployment Service
"@ | ConvertFrom-Csv

$allServices = @($manualServices) + @($disabledServices) + @($forcestopOnlyServices)
$existingSvc = Get-CimInstance Win32_Service | Group-Object Name -AsHashTable -AsString
$forcestopList = [System.Collections.Generic.List[string]]::new()
foreach ($entry in $allServices) {
    if ($entry.Name.EndsWith('*')) {
        $prefix = $entry.Name.TrimEnd('*')
        $svcMatches = $existingSvc.Keys | Where-Object { $_ -like "$prefix*" }
        $startValue = switch ($entry.StartupType) { 'Disabled' {4} 'Manual' {3} default {$null} }
        $template = "HKLM:\SYSTEM\CurrentControlSet\Services\$($prefix.TrimEnd('_'))"
        if ($startValue -and (Test-Path $template)) {
            Set-ItemProperty -Path $template -Name Start -Value $startValue -ErrorAction SilentlyContinue
        }
    } else {
        $svcMatches = @($entry.Name)
    }
    foreach ($svcName in $svcMatches) {
        $svc = $existingSvc[$svcName]
        if (-not $svc) { continue }

        if ($entry.ForceStop -eq 'True') { $forcestopList.Add($svcName) }

        $currentType = switch ($svc.StartMode) { 'Auto' {'Automatic'} default {$svc.StartMode} }
        if ($currentType -eq $entry.StartupType) { continue }
        Set-Service -Name $svcName -StartupType $entry.StartupType -ErrorAction SilentlyContinue
    }
}
if ($forcestopList.Count -gt 0) {
    Stop-Service -Name $forcestopList -Force -ErrorAction SilentlyContinue
}
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

write-host "Disabling LastAccess" -ForegroundColor red
fsutil behavior set disablelastaccess 1 *>$null

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
Get-NetAdapter -Physical | ForEach-Object {
    $p = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$($_.InterfaceGuid)"
    if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
    Set-ItemProperty -Path $p -Name "TcpAckFrequency" -Value 1
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
Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Control\PriorityControl" -Name "Win32PrioritySeparation" -Type DWord -Value 0x0000002A

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
if (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\AFD\Parameters")) { New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AFD\Parameters" | Out-Null }
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AFD\Parameters" -Name "FastSendDatagramThreshold" -Type DWord -Value 0x10000
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
Disable-ScheduledTask -TaskPath "\Microsoft\Windows\Sysmain\" -TaskName "ResPriStaticDbSync" | Out-Null
Disable-ScheduledTask -TaskPath "\Microsoft\Windows\Sysmain\" -TaskName "WsSwapAssessmentTask" | Out-Null
Disable-ScheduledTask -TaskPath "\Microsoft\Windows\Maintenance\" -TaskName "WinSAT" | Out-Null

write-host "Stopping Update Services" -ForegroundColor red
sc config BITS start=disabled > $null
sc config UsoSvc start=disabled > $null
sc config wuauserv start=disabled > $null
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
    $newName = (Split-Path $file -Leaf) + ".old"
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
