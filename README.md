This repository is for my powershell script that was made to configure many settings to improve the privacy and performance of windows and to keep these settings persistent because windows loves reverting changes randomly.
This script changes many things that can cause problems so make sure this wont disable anything you need. You may need to set powershell Execution Policy to unrestricted with the `Set-ExecutionPolicy -Scope CurrentUser Unrestricted` or `Unblock-File -Path "C:\PowershellScript.ps1"` command and maybe add it to your exclusion list in windows defender.

This may improve some system stability, performance, and network performance by setting more performant configurations and lowering the system resources at idle but you WONT see big performance impact in GAMES if there are no previous issues with windows. Video game performance is more impacted by your specific hardware and clock speeds. Consider overclocking/undervolting and better cooling solutions for better performance in GAMES!

Also check the wiki section for more information about these configurations. https://github.com/snipershane0305/powershellscript/wiki

# How to Use

To use this script as intended, put PowershellScript.ps1, memreduct.exe, PsExec64.exe, and SetTimerResolution.exe into the "C:\" directory or whatever drive windows is installed on, then run the PowershellScript.ps1 once and it will create a scheduled task so it will run automatically on logon.


# Extra Information

https://github.com/valleyofdoom/PC-Tuning

https://github.com/BoringBoredom/PC-Optimization-Hub

https://docs.google.com/document/d/1c2-lUJq74wuYK1WrA_bIvgb89dUN0sj8-hO3vqmrau4

https://github.com/djdallmann/GamingPCSetup

https://docs.google.com/document/d/14ma-_Os3rNzio85yBemD-YSpF_1z75mZJz1UdzmW8GE

https://github.com/ChrisTitusTech/winutil
