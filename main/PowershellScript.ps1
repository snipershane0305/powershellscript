if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process pwsh.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }
Import-Module ScheduledTasks, NetAdapter, NetTCPIP, DnsClient -ErrorAction SilentlyContinue
$sw = [Diagnostics.Stopwatch]::StartNew()
function Say($m) { Write-Host ("{0,6:N1}s  {1}" -f $sw.Elapsed.TotalSeconds, $m) }
function Set-Reg($Path, $Name, $Value, $Type = "DWord") {
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    $current = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name
    if ($Type -eq "DWord") { $same = ($null -ne $current) -and ([int64]$current -eq [int64]$Value) }
    else { $same = ($null -ne $current) -and ("$current" -eq "$Value") }
    if (-not $same) {
        Set-ItemProperty -Path $Path -Name $Name -Type $Type -Value $Value
    }
}
$taskName = "powershellscript"
$taskUser = "$env:USERDOMAIN\$env:USERNAME"
if (-not (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue)) {
    Say "Installed Logon Task"
    $action    = New-ScheduledTaskAction -Execute (Get-Process -Id $PID).Path -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Minimized -File `"$PSCommandPath`""
    $trigger   = New-ScheduledTaskTrigger -AtLogOn -User $taskUser
    $trigger.Delay = "PT10S"
    $principal = New-ScheduledTaskPrincipal -UserId $taskUser -LogonType Interactive -RunLevel Highest
    $settings  = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
}
Say "Running Idle Tasks"
Rundll32.exe advapi32.dll,ProcessIdleTasks

Say "Setting Services"
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
SamSs,Automatic,Automatic,False,Security Accounts Manager
ScDeviceEnum,Manual,Manual,False,Smart Card Device Enumeration Service
Schedule,Automatic,Automatic,False,Task Scheduler
SecurityHealthService,Manual,Manual,False,Windows Security Service
Sense,Manual,Manual,False,Windows Defender Advanced Threat Protection Service
SgrmBroker,Automatic,Automatic,False,System Guard Runtime Monitor Broker
SharedAccess,Manual,Manual,False,Internet Connection Sharing (ICS)
SharedRealitySvc,Manual,Manual,False,Spatial Data Service (uncertain)
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
Winmgmt,Automatic,Automatic,False,Windows Management Instrumentation
WlanSvc,Automatic,Automatic,False,WLAN AutoConfig
WpcMonSvc,Manual,Manual,False,Parental Controls
WpnService,Manual,Automatic,False,Windows Push Notifications System Service
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
wudfsvc,Manual,Manual,False,Windows Driver Foundation - User-mode Driver Framework
NetSetupSvc,Manual,Manual,False,Network Setup Service
WinHttpAutoProxySvc,Manual,Manual,False,WinHTTP Web Proxy Auto-Discovery Service
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
TextInputManagementService,Disabled,Automatic,True,Text Input Management Service
ShellHWDetection,Disabled,Automatic,True,Shell Hardware Detection
DeviceAssociationService,Disabled,Manual,True,Device Association Service
hidserv,Disabled,Manual,True,Human Interface Device Service

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
wscsvc,Disabled,Automatic,True,Security Center

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
camsvc,Manual,Manual,True,Capability Access Manager Service
cbdhsvc_*,Manual,Automatic,True,Clipboard User Service
DusmSvc,Manual,Automatic,True,Data Usage
iphlpsvc,Manual,Automatic,True,IP Helper
AppXSvc,Manual,Manual,True,AppX Deployment Service
WpnUserService_*,Manual,Automatic,True,Windows Push Notifications User Service
FrameServer,Manual,Manual,True,Windows Camera Frame Server
FrameServerMonitor,Manual,Manual,True,Windows Camera Frame Server Monitor
"@ | ConvertFrom-Csv

function Set-Services {
    $allServices = @($manualServices) + @($disabledServices) + @($forcestopOnlyServices)
    $existingSvc = Get-CimInstance Win32_Service | Group-Object Name -AsHashTable -AsString
    $forcestopList = [System.Collections.Generic.List[string]]::new()
    foreach ($entry in $allServices) {
        if ($entry.Name.EndsWith('*')) {
            $prefix = $entry.Name.TrimEnd('*')
            $svcMatches = $existingSvc.Keys | Where-Object { $_ -like "$prefix*" }
        } else {
            $svcMatches = @($entry.Name)
        }
        foreach ($svcName in $svcMatches) {
            $svc = $existingSvc[$svcName]
            if (-not $svc) { continue }
            if ($entry.ForceStop -eq 'True' -and $svc.State -ne 'Stopped') { $forcestopList.Add($svcName) }
            $currentType = switch ($svc.StartMode) { 'Auto' {'Automatic'} default {$svc.StartMode} }
            if ($currentType -eq $entry.StartupType) { continue }
            Set-Service -Name $svcName -StartupType $entry.StartupType -ErrorAction SilentlyContinue
        }
    }
    if ($forcestopList.Count -gt 0) { Stop-Service -Name $forcestopList -Force -ErrorAction SilentlyContinue }
}
Set-Services

Say "Deleting Temp Files"
Get-ChildItem -Path "$env:TEMP\" *.* -Recurse | Remove-Item -Force -Recurse 2>$null
Get-ChildItem -Path "$env:windir\Temp\" *.* -Recurse | Remove-Item -Force -Recurse 2>$null

Say "Disabling Powershell Telemetry"
if ([Environment]::GetEnvironmentVariable('POWERSHELL_TELEMETRY_OPTOUT', 'Machine') -ne '1') {
    [Environment]::SetEnvironmentVariable('POWERSHELL_TELEMETRY_OPTOUT', '1', 'Machine')
}
if ([Environment]::GetEnvironmentVariable('POWERSHELL_UPDATECHECK', 'Machine') -ne 'Off') {
    [Environment]::SetEnvironmentVariable('POWERSHELL_UPDATECHECK', 'Off', 'Machine')
}

Say "Disabling Hibernation"
if ((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "HibernateEnabled" -ErrorAction SilentlyContinue).HibernateEnabled -ne 0) {
    powercfg.exe /hibernate off
}

Say "Disabling Memory Compression"
if ((Get-MMAgent).MemoryCompression) {
    Disable-MMAgent -MemoryCompression -ErrorAction SilentlyContinue | Out-Null
}

Say "Changing Boot Settings"
$bcd = @{
    useplatformclock="no"
    tscsyncpolicy="legacy"
    x2apicpolicy="Enable"
    vsmlaunchtype="off"
    hypervisorlaunchtype="off"
}

$bcdNow = bcdedit /enum '{current}' | Out-String
foreach ($key in $bcd.Keys) {
    if ($bcdNow -notmatch "(?im)^\s*$key\s+$($bcd[$key])\s*$") {
        bcdedit /set $key $bcd[$key] *> $null
    }
}
Say "Changing File System Settings"
if ((fsutil behavior query disablelastaccess | Out-String) -notmatch 'registry state is:\s*1') { fsutil behavior set disablelastaccess 1 *>$null }
if ((fsutil behavior query disable8dot3 | Out-String) -notmatch 'registry state is:\s*1') { fsutil behavior set disable8dot3 1 *>$null }

Say "Changing Network Settings"
$offload = Get-NetOffloadGlobalSetting
if ($offload.ReceiveSideScaling -ne 'Enabled') { netsh int tcp set global rss=enabled | Out-Null }
$rssOff = Get-NetAdapterRss -ErrorAction SilentlyContinue | Where-Object { -not $_.Enabled }
if ($rssOff) { $rssOff | Enable-NetAdapterRss -ErrorAction SilentlyContinue }
if ((Get-NetTeredoConfiguration -ErrorAction SilentlyContinue).Type -ne 'Disabled') { netsh int teredo set state disabled | Out-Null }
if ((Get-Net6to4Configuration -ErrorAction SilentlyContinue).State -ne 'Disabled') { netsh int 6to4 set state disabled | Out-Null }
if ((Get-NetIsatapConfiguration -ErrorAction SilentlyContinue).State -ne 'Disabled') { netsh int isatap set state disabled | Out-Null }
if ((Get-NetTCPSetting -SettingName Internet -ErrorAction SilentlyContinue).EcnCapability -ne 'Enabled') {
    netsh int tcp set global ecncapability=enable | Out-Null
    Set-NetTCPSetting -SettingName internet -EcnCapability enabled
}
if ($offload.ReceiveSegmentCoalescing -ne 'Disabled') {
    netsh int tcp set global rsc=disabled | Out-Null
    Set-NetOffloadGlobalSetting -ReceiveSegmentCoalescing Disabled
}
$rscOn = Get-NetAdapterRsc -ErrorAction SilentlyContinue | Where-Object { $_.IPv4Enabled -or $_.IPv6Enabled }
if ($rscOn) { $rscOn | Disable-NetAdapterRsc }
if ($offload.PacketCoalescingFilter -ne 'Disabled') { Set-NetOffloadGlobalSetting -PacketCoalescingFilter Disabled }
$csOff = Get-NetAdapterChecksumOffload -ErrorAction SilentlyContinue | Where-Object {
    $_.PSObject.Properties | Where-Object { $_.Name -match '(IPv4|IPv6)Enabled$' -and "$($_.Value)" -in 'Disabled', 'RxEnabled', 'TxEnabled' }
}
if ($csOff) { $csOff | Enable-NetAdapterChecksumOffload }

Say "Disabling NetBIOS"
$nbOn = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=TRUE" | Where-Object { $_.TcpipNetbiosOptions -ne 2 }
if ($nbOn) {
    $nbOn | Invoke-CimMethod -MethodName SetTcpipNetbios -Arguments @{TcpipNetbiosOptions=2} | Out-Null
}

Say "Editing Host File"
$hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
$blocklist = "services.gfe.nvidia.com", "inputsuggestions.msdxcdn.microsoft.com"
$changed = $false
foreach ($domain in $blocklist) {
    if ((Get-Content $hostsPath) -notcontains "0.0.0.0 $domain") {
        Add-Content -Path $hostsPath -Value "0.0.0.0 $domain"
        $changed = $true
    }
}
if ($changed) { Clear-DnsClientCache }

Say "Changing Registry Settings"
Set-Reg "HKCU:\Control Panel\Mouse" "MouseSpeed" 0 String
Set-Reg "HKCU:\Control Panel\Mouse" "MouseThreshold1" 0 String
Set-Reg "HKCU:\Control Panel\Mouse" "MouseThreshold2" 0 String
Set-Reg "HKCU:\Control Panel\Mouse" "RawMouseThrottleEnabled" 0
Set-Reg "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" "EnthusiastMode" 1
Set-Reg "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" "EnableTransparency" 0
Set-Reg "HKCU:\Software\Microsoft\Windows\DWM" "EnableAeroPeek" 0
Set-Reg "HKCU:\Control Panel\Desktop" "FontSmoothing" 0 String
Set-Reg "HKCU:\Control Panel\Desktop" "FontSmoothingType" 1
Set-Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" "ShowHibernateOption" 0
Set-Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" "ShowSleepOption" 0
Set-Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" "HiberbootEnabled" 0
Set-Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" "PowerThrottlingOff" 1

Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" "AllowGameDVR" 0
Set-Reg "HKCU:\Software\Microsoft\GameBar" "AllowAutoGameMode" 1
Set-Reg "HKCU:\Software\Microsoft\GameBar" "AutoGameModeEnabled" 1
Set-Reg "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" "HwSchMode" 2

Set-Reg "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" "GlobalUserDisabled" 1
Set-Reg "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" "BackgroundAppGlobalToggle" 0
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" "LetAppsRunInBackground" 2
Set-Reg "HKLM:\SOFTWARE\Microsoft\Input" "InputServiceEnabled" 0
Set-Reg "HKLM:\SOFTWARE\Microsoft\Input" "InputServiceEnabledForCCI" 0
Set-Reg "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Connectivity\DisableCrossDeviceResume" "value" 1

Set-Reg "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" "EnableVirtualizationBasedSecurity" 0
Set-Reg "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" "Enabled" 0

$SystemMemory = (Get-CimInstance -ClassName Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1KB
Set-Reg "HKLM:\SYSTEM\CurrentControlSet\Control" "SvcHostSplitThresholdInKB" $SystemMemory
Set-Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" "EnablePrefetcher" 0
Set-Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" "EnableSuperfetch" 0
Set-Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "DisablePageCombining" 1
Set-Reg "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "DisablePagingExecutive" 1
Set-Reg "HKLM:\SYSTEM\ControlSet001\Control\PriorityControl" "Win32PrioritySeparation" 0x0000002A

#Windows update
Set-Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" "DODownloadMode" 0
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" "PreventDeviceMetadataFromNetwork" 1
Set-Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" "SearchOrderConfig" 0
Set-Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" "DontPromptForWindowsUpdate" 1
Set-Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" "DontSearchWindowsUpdate" 1
Set-Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" "DriverUpdateWizardWuSearchEnabled" 0
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" "AutoInstallMinorUpdates" 0
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" "NoAutoUpdate" 1
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" "AUOptions" 1
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" "ExcludeWUDriversInQualityUpdate" 1
Set-Reg "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" "ExcludeWUDriversInQualityUpdate" 1
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" "SearchOrderConfig" 0
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" "DontSearchWindowsUpdate" 1

#Microsoft Store automatic app updates (2 = off, 4 = on)
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" "AutoDownload" 2

#Network
Set-Reg "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" "NetworkThrottlingIndex" 0xffffffff
Set-Reg "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" "SystemResponsiveness" 0
Set-Reg "HKLM:\SYSTEM\CurrentControlSet\Services\AFD\Parameters" "FastSendDatagramThreshold" 0x10000
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" "EnableMulticast" 0
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" "DisableSmartNameResolution" 1
Set-Reg "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" "EnableMDNS" 0
Set-Reg "HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet" "EnableActiveProbing" 0
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator" "NoActiveProbe" 1
Set-Reg "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" "AutoDetect" 0
Set-Reg "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" "DisableWpad" 1
Set-Reg "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" "WpadOverride" 1

#Privacy
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry" 0
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "DoNotShowFeedbackNotifications" 1
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowDeviceNameInTelemetry" 0
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "DisableOneSettingsDownloads" 1
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "LimitDiagnosticLogCollection" 1
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "LimitDumpCollection" 1
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" "Disabled" 1
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" "CEIPEnable" 0
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" "DisableInventory" 1
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" "AITEnable" 0
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" "DisableUAR" 1
Set-Reg "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" "NumberOfSIUFInPeriod" 0

Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnableActivityFeed" 0
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "PublishUserActivities" 0
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "UploadUserActivities" 0
Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" "Enabled" 0
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" "DisabledByGroupPolicy" 1
Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" "TailoredExperiencesWithDiagnosticDataEnabled" 0
Set-Reg "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableTailoredExperiencesWithDiagnosticData" 1
Set-Reg "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableThirdPartySuggestions" 1
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableWindowsConsumerFeatures" 1
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableCloudOptimizedContent" 1

Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "Start_TrackProgs" 0
Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "Start_IrisRecommendations" 0
Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "Start_AccountNotifications" 0
Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "ShowSyncProviderNotifications" 0
Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "ContentDeliveryAllowed" 0
Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "OemPreInstalledAppsEnabled" 0
Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "PreInstalledAppsEnabled" 0
Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SilentInstalledAppsEnabled" 0
Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SoftLandingEnabled" 0
Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SystemPaneSuggestionsEnabled" 0
Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "RotatingLockScreenEnabled" 0
Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "RotatingLockScreenOverlayEnabled" 0
Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SubscribedContent-338387Enabled" 0
Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SubscribedContent-338388Enabled" 0
Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SubscribedContent-338389Enabled" 0
Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SubscribedContent-353694Enabled" 0
Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SubscribedContent-353696Enabled" 0
Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SubscribedContent-338393Enabled" 0

Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" "BingSearchEnabled" 0
Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" "CortanaConsent" 0
Set-Reg "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" "DisableSearchBoxSuggestions" 1
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowCortana" 0
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowCloudSearch" 0
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowSearchToUseLocation" 0
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "ConnectedSearchUseWeb" 0
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "DisableWebSearch" 1
Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" "IsDynamicSearchBoxEnabled" 0
Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" "IsAADCloudSearchEnabled" 0
Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" "IsMSACloudSearchEnabled" 0
Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" "IsDeviceSearchHistoryEnabled" 0

Set-Reg "HKCU:\SOFTWARE\Microsoft\Input\TIPC" "Enabled" 0
Set-Reg "HKCU:\SOFTWARE\Microsoft\Input\Settings" "InsightsEnabled" 0
Set-Reg "HKCU:\SOFTWARE\Microsoft\Input\Settings" "EnableHwkbTextPrediction" 0
Set-Reg "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" "AcceptedPrivacyPolicy" 0
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC" "PreventHandwritingDataSharing" 1
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" "PreventHandwritingErrorReports" 1

Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "AllowCrossDeviceClipboard" 0
Set-Reg "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnableCdp" 0
Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CDP" "CdpSessionUserAuthzPolicy" 0
Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CDP" "NearShareChannelUserAuthzPolicy" 0
Set-Reg "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CDP" "RomeSdkChannelUserAuthzPolicy" 0

Say "Disabling Scheduled Tasks"
$Tasks = @"
TaskPath,TaskName
\Microsoft\Windows\WindowsUpdate\,Scheduled Start
\Microsoft\Windows\Windows Error Reporting\,QueueReporting
\Microsoft\Windows\User Profile Service\,HiveUploadTask
\Microsoft\Windows\Maps\,MapsUpdateTask
\Microsoft\Windows\Application Experience\,MareBackup
\Microsoft\Windows\Application Experience\,Microsoft Compatibility Appraiser Exp
\Microsoft\Windows\Customer Experience Improvement Program\,Consolidator
\Microsoft\Windows\Customer Experience Improvement Program\,UsbCeip
\Microsoft\Windows\Feedback\Siuf\,DmClient
\Microsoft\Windows\Feedback\Siuf\,DmClientOnScenarioDownload
\Microsoft\Windows\InstallService\,ScanForUpdates
\Microsoft\Windows\InstallService\,ScanForUpdatesAsUser
\Microsoft\Windows\Device Information\,Device
\Microsoft\Windows\Device Information\,Device User
\Microsoft\Windows\Flighting\FeatureConfig\,UsageDataFlushing
\Microsoft\Windows\Flighting\FeatureConfig\,UsageDataReceiver
\Microsoft\Windows\Flighting\FeatureConfig\,ReconcileFeatures
\Microsoft\Windows\WwanSvc\,OobeDiscovery
\Microsoft\Windows\Sustainability\,PowerGridForecastTask
\Microsoft\Windows\Hotpatch\,Monitoring
\Microsoft\Windows\Speech\,SpeechModelDownloadTask
\Microsoft\Windows\PushToInstall\,Registration
\Microsoft\Windows\PushToInstall\,LoginCheck
\Microsoft\Windows\Flighting\OneSettings\,RefreshCache
\Microsoft\Windows\Windows Defender\,Windows Defender Cache Maintenance
\Microsoft\Windows\Windows Defender\,Windows Defender Scheduled Scan
\Microsoft\Windows\Windows Defender\,Windows Defender Verification
\Microsoft\Windows\Sysmain\,ResPriStaticDbSync
\Microsoft\Windows\Sysmain\,WsSwapAssessmentTask
\Microsoft\Windows\Maintenance\,WinSAT

\Microsoft\Windows\ExploitGuard\,ExploitGuard MDM policy Refresh
\Microsoft\Windows\Power Efficiency Diagnostics\,AnalyzeSystem
\Microsoft\Windows\Management\Provisioning\,Logon
\Microsoft\Windows\DiskFootprint\,StorageSense
\Microsoft\Windows\DiskCleanup\,SilentCleanup
\Microsoft\Windows\Servicing\,StartComponentCleanup
\Microsoft\Windows\CertificateServicesClient\,KeyPreGenTask
\Microsoft\Windows\WindowsColorSystem\,Calibration Loader

\Microsoft\Windows\Setup\,PITRTask
\Microsoft\Windows\Setup\,SetupRecoveryDataTask
\Microsoft\Windows\DiskFootprint\,Diagnostics
\Microsoft\Windows\Chkdsk\,ProactiveScan
\Microsoft\Windows\Registry\,RegIdleBackup
\Microsoft\Windows\MUI\,LPRemove
\Microsoft\Windows\Containers\,CmCleanup
\Microsoft\Windows\LanguageComponentsInstaller\,ReconcileLanguageResources
\Microsoft\Windows\MemoryDiagnostic\,AutomaticOfflineMemoryDiagnostic
\Microsoft\Windows\MemoryDiagnostic\,ProcessMemoryDiagnosticEvents
\Microsoft\Windows\Diagnosis\,Scheduled
\Microsoft\Windows\Wininet\,CacheTask

\Microsoft\Windows\Flighting\FeatureConfig\,UsageDataReporting
\Microsoft\Windows\PI\,Sqm-Tasks
\Microsoft\Windows\Sustainability\,SustainabilityTelemetry
\Microsoft\Windows\ConsentUX\UnifiedConsent\,UnifiedConsentSyncTask
\Microsoft\Windows\Application Experience\,PcaPatchDbTask
\Microsoft\Windows\TPM\,Tpm-PreAttestationHealthCheck
\Microsoft\Windows\CertificateServicesClient\,AikCertEnrollTask
\Microsoft\Windows\AppxDeploymentClient\,UCPD velocity

\Microsoft\Windows\International\,Synchronize Language Settings
\Microsoft\Windows\Shell\,ThemesSyncedImageDownload
\Microsoft\Windows\WlanSvc\,CDSSync
\Microsoft\Windows\AppListBackup\,Backup
\Microsoft\Windows\Time Zone\,SynchronizeTimeZone
\Microsoft\Windows\ApplicationData\,appuriverifierdaily
\Microsoft\Windows\Network Connectivity Status Indicator\,NcsiIdentifyUserProxies

\Microsoft\XblGameSave\,XblGameSaveTask
\Microsoft\Windows\FileHistory\,File History (maintenance mode)
\Microsoft\Windows\InstallService\,SmartRetry
\Microsoft\Windows\Printing\,PrintJobCleanupTask
\Microsoft\Windows\Shell\,IndexerAutomaticMaintenance
\Microsoft\Windows\ApplicationData\,DsSvcCleanup
\Microsoft\Windows\License Manager\,TempSignedLicenseExchange
"@ | ConvertFrom-Csv
$enabledTasks = @{}
Get-ScheduledTask | Where-Object State -ne 'Disabled' | ForEach-Object { $enabledTasks["$($_.TaskPath)$($_.TaskName)"] = $true }
foreach ($t in $Tasks) {
    if ($enabledTasks["$($t.TaskPath)$($t.TaskName)"]) {
        Disable-ScheduledTask -TaskPath $t.TaskPath -TaskName $t.TaskName | Out-Null
    }
}
Say "Disabling Trace Loggers"
$loggers = "CimFSUnionFS-Filter", "Circular Kernel Context Logger", "DefenderApiLogger", "DefenderAuditLogger", "DiagLog", "Diagtrack-Listener", "FilterMgr-Logger", "LwtNetLog", "Microsoft-Windows-Rdp-Graphics-RdpIdd-Trace", "NtfsLog", "ReFSLog", "UBPM", "WdiContextLog", "WiFiDriverIHVSession", "WiFiDriverIHVSessionRepro", "WiFiSession"
$pendingLoggers = @()
foreach ($l in $loggers) {
    $p = "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\$l"
    if (-not (Test-Path $p)) { continue }
    if ((Get-ItemProperty -Path $p -Name "Start" -ErrorAction SilentlyContinue).Start -eq 0) { continue }
    Set-ItemProperty -Path $p -Name "Start" -Type DWord -Value 0 -ErrorAction SilentlyContinue
    if ((Get-ItemProperty -Path $p -Name "Start" -ErrorAction SilentlyContinue).Start -ne 0) { $pendingLoggers += $l }
}
$psexec = "$env:SystemDrive\PsExec64.exe"
if (Test-Path $psexec) {
    $protectedTasks = @"
TaskPath,TaskName
\Microsoft\Windows\WindowsAI\Recall\,PolicyConfiguration
\Microsoft\Windows\WindowsAI\Settings\,InitialConfiguration
\Microsoft\Windows\DeviceDirectoryClient\,IntegrityCheck
\Microsoft\Windows\DeviceDirectoryClient\,RegisterUserDevice
\Microsoft\Windows\DeviceDirectoryClient\,RegisterDeviceAccountChange
\Microsoft\Windows\Device Setup\,Metadata Refresh
\Microsoft\Windows\WaaSMedic\,PerformRemediation
\Microsoft\Windows\UpdateOrchestrator\,UIEOrchestrator
\Microsoft\Windows\Kernel\,La57Cleanup
"@ | ConvertFrom-Csv

    $pendingTasks = $protectedTasks | Where-Object {
        $t = Get-ScheduledTask -TaskPath $_.TaskPath -TaskName $_.TaskName -ErrorAction SilentlyContinue
        $t -and $t.State -ne 'Disabled'
    }
    $pendingServices = "WaaSMedicSvc", "wscsvc", "DoSvc" | Where-Object {
        $s = Get-Service $_ -ErrorAction SilentlyContinue
        $s -and $s.StartType -ne 'Disabled'
    }

    if ($pendingTasks -or $pendingServices -or $pendingLoggers) {
        Set-Service LanmanWorkstation -StartupType Manual
        Set-Service LanmanServer -StartupType Manual
        Start-Service LanmanWorkstation, LanmanServer

        foreach ($t in $pendingTasks) {
            & $psexec -accepteula -nobanner -s schtasks.exe /Change /TN "$($t.TaskPath)$($t.TaskName)" /DISABLE *>$null
        }
        foreach ($s in $pendingServices) {
            & $psexec -accepteula -nobanner -s reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\$s" /v Start /t REG_DWORD /d 4 /f *>$null
            & $psexec -accepteula -nobanner -s net.exe stop $s *>$null
        }
        foreach ($l in $pendingLoggers) {
            & $psexec -accepteula -nobanner -s reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\$l" /v Start /t REG_DWORD /d 0 /f *>$null
        }
        Set-Service LanmanServer -StartupType Disabled
        Set-Service LanmanWorkstation -StartupType Disabled
        Stop-Service LanmanServer, LanmanWorkstation -Force -ErrorAction SilentlyContinue
    }
}
Say "Setting Power Plan"
$planGuid = "5a4d0a2e-7c3b-4f1e-9d3a-6b1c2e8f4a10"
$powerCsv = @"
SubGroup,Setting,Value
SUB_PROCESSOR,PROCTHROTTLEMIN,5
SUB_PROCESSOR,PROCTHROTTLEMAX,100
SUB_PROCESSOR,PERFBOOSTMODE,2
SUB_PROCESSOR,PERFEPP,25
SUB_PROCESSOR,CPMINCORES,100
SUB_PROCESSOR,CPMAXCORES,100
SUB_PROCESSOR,IDLEDISABLE,0
SUB_PROCESSOR,SYSCOOLPOL,1
SUB_PCIEXPRESS,ASPM,0
2a737441-1930-4402-8d77-b2bebba308a3,48e6b7a6-50f5-4782-a5d4-53bb8f07e226,0
2a737441-1930-4402-8d77-b2bebba308a3,d4e98f31-5ffe-4ce1-be31-1b38b384c009,0
19cbb8fa-5279-450e-9fac-8a3d5fedd0c1,12bbebe6-58d6-4636-95bb-3217ef867c1a,0
SUB_SLEEP,STANDBYIDLE,0
SUB_VIDEO,VIDEOIDLE,0
"@
$regPath = "HKLM:\SOFTWARE\CustomPowerPlan"
$applied = (Get-ItemProperty -Path $regPath -Name "Applied" -ErrorAction SilentlyContinue).Applied
$exists  = [bool](powercfg /list | Select-String $planGuid)
$active  = [bool]((powercfg /getactivescheme) -match $planGuid)
if (-not $exists -or -not $active -or $applied -ne $powerCsv) {
    if (-not $exists) {
        powercfg /duplicatescheme 381b4222-f694-41f0-9685-ff5bb260df2e $planGuid | Out-Null
        powercfg /changename $planGuid "Custom Performance" "Fast ramp-up, normal idle" | Out-Null
    }
    foreach ($s in ($powerCsv | ConvertFrom-Csv)) {
        powercfg /setacvalueindex $planGuid $s.SubGroup $s.Setting $s.Value | Out-Null
    }
    powercfg /setactive $planGuid | Out-Null
    if (-not (Test-Path $regPath)) { New-Item -Path $regPath | Out-Null }
    Set-ItemProperty -Path $regPath -Name "Applied" -Type String -Value $powerCsv
}
Say "Killing Smartscreen.exe, CrossDeviceResume, and UsageAndQualityInsights.MaintenanceTask.exe"
$files = @(
    "$env:SystemDrive\WINDOWS\system32\smartscreen.exe"
    "$env:SystemDrive\WINDOWS\system32\Microsoft.Data.UsageAndQualityInsights.MaintenanceTask.exe"
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
Get-Process -Name *CrossDeviceResume* -ErrorAction SilentlyContinue | Stop-Process -Force

Say "Waiting 3 minutes to stop lingering processes/services"
$total = 180
for ($i = $total; $i -ge 0; $i--) {
    Write-Progress -Activity "Paused" `
        -Status ("{0:mm\:ss} remaining" -f [TimeSpan]::FromSeconds($i)) `
        -PercentComplete ((($total - $i) / $total) * 100)
    Start-Sleep -Seconds 1
}
Write-Progress -Activity "Waiting" -Completed
Say "Releasing Memory"
Set-Location $env:SystemDrive\
if (Test-Path ".\memreduct.exe") {
    Start-Process -FilePath ".\memreduct.exe" -ArgumentList "-clean:full", "-silent" -WindowStyle Hidden
    Start-Sleep -Seconds 5
    taskkill /IM memreduct.exe /F *>$null
}
Say "Setting Services"
Set-Services

Say "Done"
pause
