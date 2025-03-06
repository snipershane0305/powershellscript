This repository is for my powershell script that was made to configure a bunch of settings to improve the privacy and performance of windows and to keep these settings persistent because windows loves reverting changes randomly.
This script changes A LOT so make sure this wont disable anything you need.

You will need to set powershells ExecutionPolicy to unrestricted with the `Set-ExecutionPolicy unrestricted` command and maybe add it to your exculsions list in defender.

Also check the wiki section for more information about these configurations. https://github.com/snipershane0305/powershell-script/wiki

To use this script as intended, put the StartUpScript.ps1 file in `C:\Users\YOUR USERNAME HERE\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup` folder, anything in this directory will start when you login to windows.

Then put the PowershellScript.ps1, memreduct.exe, and SetTimerResolution.exe into the "C:" directory or whatever drive windows is installed on.

This may improve some system stability, performance, and network performance by setting more performant configurations and lowering the system resources at idle but you WONT see big performance impact in GAMES. 
video game performance is more impacted by your specific hardware and clock speeds. Consider overclocking/undervolting and better cooling solutions for better performance in GAMES!

# Extra Information

https://github.com/valleyofdoom/PC-Tuning

https://github.com/BoringBoredom/PC-Optimization-Hub

https://docs.google.com/document/d/1c2-lUJq74wuYK1WrA_bIvgb89dUN0sj8-hO3vqmrau4

https://github.com/djdallmann/GamingPCSetup

https://docs.google.com/document/d/14ma-_Os3rNzio85yBemD-YSpF_1z75mZJz1UdzmW8GE

https://github.com/ChrisTitusTech/winutil
