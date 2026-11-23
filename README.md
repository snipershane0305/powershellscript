<div align="center">

**A PowerShell script that improves the privacy and performance of Windows and keeps those settings persistent, because Windows loves reverting changes randomly.**

[Wiki](https://github.com/snipershane0305/powershellscript/wiki) · [How to Use](#-how-to-use) · [Extra Information](#-extra-information)

</div>

---


## About

This repository is for my PowerShell script made to configure many Windows settings to improve privacy and performance, and to keep those settings in place after Windows tries to change them back.

It may improve system stability, performance, and network performance by using more performant configurations and lowering system resource usage.

You **won't** see a big performance impact in **games** if there were no previous issue with Windows. Game performance depends much more on your specific hardware and clock speeds. Consider overclocking/undervolting and better cooling for better performance in games!

> [!WARNING]
> This script changes many things that can cause problems or break features you may use, so make sure it won't disable anything you need. Check the [wiki](https://github.com/snipershane0305/powershellscript/wiki) for what each configuration does before running it.

## How to Use

**1.** Put these four files in the `C:\` directory (or whichever drive Windows is installed on):

| File | Purpose |
|---|---|
| `PowershellScript.ps1` | The script |
| `memreduct.exe` | Memory cleaner |
| `PsExec64.exe` | Runs commands with higher privileges |
| `SetTimerResolution.exe` | Timer resolution tool |

**2.** You may need to run these:

```powershell
Set-ExecutionPolicy -Scope CurrentUser Unrestricted
```

```powershell
Unblock-File -Path "C:\PowershellScript.ps1"
```

You may also need to add the script to your exclusion list in Windows Defender.

**3.** Run `PowershellScript.ps1` once. It creates a scheduled task, so from then on it runs automatically at logon.

> [!TIP]
> The script is launched with PowerShell 7 (`pwsh.exe`), so make sure it's installed.

## Extra Information

| Resource | Link |
|---|---|
| PC-Tuning | https://github.com/valleyofdoom/PC-Tuning |
| PC-Optimization-Hub | https://github.com/BoringBoredom/PC-Optimization-Hub |
| GamingPCSetup | https://github.com/djdallmann/GamingPCSetup |
| winutil | https://github.com/ChrisTitusTech/winutil |
| Calypto's Latency Guide | https://docs.google.com/document/d/1c2-lUJq74wuYK1WrA_bIvgb89dUN0sj8-hO3vqmrau4 |
| Google Doc | https://docs.google.com/document/d/14ma-_Os3rNzio85yBemD-YSpF_1z75mZJz1UdzmW8GE |
