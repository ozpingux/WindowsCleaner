@echo off
cls
::Clean Manually for deleted users on Windows HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList
::This is not a complete script!!!; supplement it with other tools if you wish. 
::This script has already been tested on Windows 10
::I am not responsible for any use that may be made of it. It is for research purposes only. 
netsh wlan delete profile *
ipconfig /flushdns 
powershell -Command "Clear-DnsClientCache"
arp -d *
nbtstat -R
taskkill /F /IM firefox.exe
taskkill /F /IM iexplore.exe
taskkill /F /IM chrome.exe
taskkill /F /IM teams.exe
taskkill /f /t /fi "IMAGENAME eq teams.exe"
taskkill /F /IM explorer.exe 
net stop eventlog /y
net stop eventlog-service /y
net stop eventlog-service-keywords /y
net stop eventlog-service-winevent /y
reg add 'HKLM\SYSTEM\CurrentControlSet\Services\eventlog' /v Start /t REG_DWORD /d 4 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem" /v NtfsDisableLastAccessUpdate /t REG_DWORD /d 1 /f
powershell -Command "Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "NtfsDisableLastAccessUpdate" -Value 1"
fsutil usn deletejournal /d C:
::Disable prefetch and Stand By - Experimental 
::reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v EnablePrefetcher /t REG_DWORD /d 0 /f
::reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v EnableSuperfetch /t REG_DWORD /d 0 /f
::reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v CsEnabled /t REG_DWORD /d 0 /f
fsutil behavior set encryptpagingfile 1
fsutil behavior set disablelastaccess 1
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\Settings" /v "NoLog" /t REG_DWORD /d 1 /f
auditpol /clear /y 
auditpol /remove /allusers
powershell -Command "Disable-ComputerRestore -Drive "C:""
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v "DisableSR" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f
reg delete "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths" /va /f
attrib /d /s -r -h -s "%LocalAppData%\Microsoft\Windows\Explorer\thumbcache*"
attrib /d /s -r -h -s %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
attrib /d /s -r -h -s C:\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces\*
attrib /d /s -r -h -s %userprofile%\AppData\Local\Microsoft\Windows\Explorer\*.db
attrib /d /s -r -h -s %userprofile%\AppData\Local\Microsoft\Windows\Explorer\*.etl
attrib /d /s -r -h -s %userprofile%\AppData\Local\ConnectedDevicesPlatform\*.*
attrib /d /s -r -h -s %AppData%\Microsoft\Windows\Recent\AutomaticDestinations\*.*
attrib /d /s -r -h -s %AppData%\Microsoft\Windows\Recent\CustomDestinations\*.*
attrib /d /s -r -h -s %AppData%\Microsoft\Windows\Recent\AutomaticDestinations\*.*
attrib /d /s -r -h -s %AppData%\Microsoft\Windows\Recent\CustomDestinations\*.*
attrib /d /s -r -h -s %SystemRoot%\AppCompat\Programs\*.*
attrib /d /s -r -h -s C:\Windows\appcompat\Programs\Install\*.*
attrib /d /s -r -h -s C:\Windows\System32\sru\*.*
attrib /d /s -r -h -s %userprofile%\AppData\Local\Temp\*.*
attrib /d /s -r -h -s C:\Windows\Temp\*.*
attrib /d /s -r -h -s C:\Windows\AppCompat\Programs\Amcache\sysmain.sdb
attrib /d /s -r -h -s C:\Windows\AppCompat\Programs\Amcache\*.*
attrib /d /s -r -h -s C:\Windows\appcompat\Programs\*.*
attrib /d /s -r -h -s C:\ProgramData\Microsoft\Diagnosis\EventTranscript\*.*
attrib /d /s -r -h -s %UserProfile%\AppData\Local\Microsoft\Windows\Notifications\*.*
attrib /d /s -r -h -s "%userprofile%\AppData\Local\Microsoft\Terminal Server Client\*.*"
attrib /d /s -r -h -s C:\ProgramData\Microsoft\Windows\WER\*.*
attrib /d /s -r -h -s %userprofile%\Appdata\Local\Microsoft\Windows\WER\*.*
attrib /d /s -r -h -s %windir%\System32\LogFiles\Sum\*.*
attrib /d /s -r -h -s C:\Windows\apppatch\*.sdb
attrib /d /s -r -h -s %windir%\SoftwareDistribution\DataStore\*.*
net stop WSearch
powershell -Command "Stop-Service -Name WSearch -Force"
attrib /d /s -r -h -s C:\ProgramData\Microsoft\Search\Data\Applications\Windows\*.*
erase "%ALLUSERSPROFILE%\TEMP\*.*" /f /s /q
for /D %%i in ("%ALLUSERSPROFILE%\TEMP\*") do RD /S /Q "%%i"
REG DELETE "HKCU\Software\Microsoft\Terminal Server Client" /F
del /f /q "%appdata%\Microsoft\teams\application cache\cache\*.*" > nul 2>&1
del /f /q "%appdata%\Microsoft\teams\blob_storage\*.*" > nul 2>&1
del /f /q "%appdata%\Microsoft\teams\databases\*.*" > nul 2>&1
del /f /q "%appdata%\Microsoft\teams\GPUcache\*.*" > nul 2>&1
del /f /q "%appdata%\Microsoft\teams\IndexdDB\*.db" > nul 2>&1
del /f /q "%appdata%\Microsoft\teams\Local Storage\*.*" > nul 2>&1
del /f /q "%appdata%\Microsoft\teams\tmp\*.*" > nul 2>&1
DEL /F /S /Q /A %UserProfile%\Documents\Default.rdp
del /s /q /f "%LocalAppData%\Microsoft\Windows\Explorer\thumbcache*"
del /f /s /q %AppData%\Microsoft\Windows\Recent\AutomaticDestinations\*.*
del /f /s /q %AppData%\Microsoft\Windows\Recent\CustomDestinations\*.*
del /f /s /q %AppData%\Microsoft\Windows\Recent\AutomaticDestinations\*.*
del /f /s /q %AppData%\Microsoft\Windows\Recent\CustomDestinations\*.*
del /f /s /q C:\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces\*.*
del /f /s /q %userprofile%\AppData\Local\Microsoft\Windows\Explorer\*.db
del /f /s /q %userprofile%\AppData\Local\Microsoft\Windows\Explorer\*.etl
del /f /s /q %userprofile%\AppData\Local\ConnectedDevicesPlatform\*.*
del /f /s /q %SystemRoot%\AppCompat\Programs\*.*
del /f /s /q C:\Windows\appcompat\Programs\Install\*.*
del /f /s /q C:\Windows\System32\sru\*.*
del /f /s /q %userprofile%\AppData\Local\Temp\*.*
del /f /s /q C:\Windows\Temp\*.*
del /f /s /q C:\ProgramData\Microsoft\Search\Data\Applications\Windows\*.*
del /f /s /q C:\Windows\AppCompat\Programs\Amcache\sysmain.sdb
del /f /s /q C:\Windows\AppCompat\Programs\Amcache\*.*
del /f /s /q C:\ProgramData\Microsoft\Diagnosis\EventTranscript\*.*
del /f /s /q C:\Windows\appcompat\Programs\*.*
del /f /s /q "%userprofile%\AppData\Local\Microsoft\Terminal Server Client\*.*"
del /f /s /q C:\ProgramData\Microsoft\Windows\WER\*.*
del /f /s /q %userprofile%\Appdata\Local\Microsoft\Windows\WER\*.*
del /f /s /q C:\Windows\apppatch\*.sdb
del /f /s /q  %windir%\System32\LogFiles\Sum\*.*
del /f /s /q %windir%\SoftwareDistribution\DataStore\*.*
del /f /s /q C:\Windows\Prefetch\*.pf
RunDll32.exe InetCpl.cpl,ClearMyTracksByProcess 8
erase "%LOCALAPPDATA%\Microsoft\Windows\Tempor~1\*.*" /f /s /q
for /D %%i in ("%LOCALAPPDATA%\Microsoft\Windows\Tempor~1\*") do RD /S /Q "%%i"
REG DELETE "HKEY_CURRENT_USER\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache" /va /f
REG DELETE "HKEY_CURRENT_USER\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU" /f
REG DELETE "HKEY_CURRENT_USER\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags" /f
REG DELETE "HKEY_CURRENT_USER\Software\Microsoft\Windows\Shell\BagMRU" /f
REG DELETE "HKEY_CURRENT_USER\Software\Microsoft\Windows\Shell\Bags" /f
REG DELETE "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" /va /f
REG DELETE "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\FirstFolder" /va /f
REG DELETE "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU" /va /f
REG DELETE "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRULegacy" /va /f
REG DELETE "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU" /f
REG DELETE "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\CIDSizeMRU" /f
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU"
REG DELETE "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist" /f
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache" /va /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Session Manager\AppCompatCache" /va /f
REG DELETE "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\RADAR\HeapLeakDetection\DiagnosedApplications" /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\RADAR\HeapLeakDetection\DiagnosedApplications"
::Configure your usersid -- whoami /user /fo table /nh -- set usersid=YOURSID
FOR /F "tokens=2" %%i IN ('whoami /user /fo table /nh') DO SET usersid=%%i
REG DELETE "HKEY_USERS\%usersid%\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps" /f
REG ADD "HKEY_USERS\%usersid%\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps"
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bam\UserSettings\%usersid%" /va /f
REG DELETE "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\bam\UserSettings\%usersid%" /va /f
REG DELETE "HKEY_USERS\%usersid%\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store" /va /f
REG DELETE "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery" /va /f 
REG DELETE  "HKEY_USERS\%usersid%\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers" /va /f
REG DELETE "HKEY_USERS\%usersid%\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2" /f
REG ADD "HKEY_USERS\%usersid%\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2"
DEL /f /q %APPDATA%\Microsoft\Windows\Recent\*.*
DEL /f /q %APPDATA%\Microsoft\Windows\Recent\CustomDestinations\*.*
DEL /f /q %APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\*.*
DEL /f /q %systemroot%\Panther\*.*
DEL /f /q %systemroot%\appcompat\Programs\*.txt
DEL /f /q %systemroot%\appcompat\Programs\*.xml
DEL /f /q %systemroot%\appcompat\Programs\Install\*.txt
DEL /f /q %systemroot%\appcompat\Programs\Install\*.xml
DEL /f /q %systemroot%\Prefetch\*.pf
DEL /f /q %systemroot%\Prefetch\*.ini
DEL /f /q %systemroot%\Prefetch\*.7db
DEL /f /q %systemroot%\Prefetch\*.ebd
DEL /f /q %systemroot%\Prefetch\*.bin
DEL /f /q %systemroot%\Prefetch\*.db
del /s /f /q C:\Windows\Prefetch\Ag*.db
DEL /f /q %systemroot%\Prefetch\ReadyBoot\*.fx
DEL /f /q %systemroot%\Minidump\*.*
del /f /s /q c:\windows\logs\cbs\*.log
del /f /s /q C:\Windows\Logs\MoSetup\*.log
del /f /s /q C:\Windows\Panther\*.log /s /q
del /f /s /q C:\Windows\inf\*.log /s /q
del /f /s /q C:\Windows\logs\*.log /s /q
del /f /s /q C:\Windows\SoftwareDistribution\*.log /s /q
del /f /s /q C:\Windows\Microsoft.NET\*.log /s /q
del /f /s /q C:\Users\%USERNAME%\AppData\Local\Microsoft\Windows\WebCache\*.log /s /q
del /f /s /q C:\Users\%USERNAME%\AppData\Local\Microsoft\Windows\SettingSync\*.log /s /q
del /f /s /q C:\Users\%USERNAME%\AppData\Local\Microsoft\Windows\Explorer\ThumbCacheToDelete\*.tmp /s /q
del /f /s /q C:\Users\%USERNAME%\AppData\Local\Microsoft\"Terminal Server Client"\Cache\*.bin /s /q
del /f /s /q %UserProfile%\AppData\Local\Microsoft\Windows\Notifications\*.*
rmdir /q /s C:\Users\%USERNAME%\AppData\Local\Microsoft\Windows\INetCache\
del /s /f /q %WinDir%\Temp\*.*
del /s /f /q %Temp%\*.*
del /s /f /q %AppData%\Temp\*.*
del /s /f /q %HomePath%\AppData\LocalLow\Temp\*.*
fsutil behavior set encryptpagingfile 1
powershell -Command "vssadmin delete shadows /all"
vssadmin delete shadows /all
vssadmin delete shadows /all /quiet
rd /s /q c:\$Recycle.bin
rd /s /q d:\$Recycle.bin
del /s /f /q %WinDir%\Prefetch\*.*
del /f /s /q %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v ClearPageFileAtShutdown /t REG_DWORD /d 1 /f
fsutil behavior set encryptpagingfile 1
powercfg.exe /hibernate off
powershell -Command "Remove-Item -Path "C:\hiberfil.sys" -Force"
powershell.exe -Command "Clear-History"
powershell.exe -Command "Remove-Item (Get-PSReadlineOption).HistorySavePath"
net stop vss /y
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR" /f /va
for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"
start explorer.exe 
doskey /listsize=0
doskey /reinstall 
pause
