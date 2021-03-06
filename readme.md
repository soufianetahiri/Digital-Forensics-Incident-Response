# Digital-Forensics-Incident-Response
Digital Forensics and Incident Response

This Post is mainly the work of Jai Minton (https://twitter.com/CyberRaiju)

# Introduction
This post is inspired by all the hard working DFIR, and more broadly security professionals, who have put in the hard yards over the years to discuss in depth digital forensics and incident response.

# Disclaimer
This page contains a variety of commands and concepts which are known through experience, higher education, tutorials, online blogs, YouTube Videos, professional training, reading the manual, and more. All references to original posts or material will aim to be documented in the ‘Special Thanks’ section. This is not designed as a manual on how to perform DFIR, and serves only as a quick reference sheet for commands, tools, and common items of interest when performing Incident Response. If you need to undertake Digital Forensics for legal proceedings, seek specialist advice.

# Artifact locations
A number of forensic artifacts are known for a number of operating systems.

A large number of these are covered on the Digital Forensics Artifact Repository, and can be ingested both by humans and systems given the standard YAML format.

- [ForensicArtifacts](https://github.com/ForensicArtifacts/artifacts/tree/master/data "ForensicArtifacts")
# Windows Cheat Sheet
## Order of Volatility
If performing Evidence Collection rather than IR, respect the order of volatility as defined in: rfc3227

- registers, cache
- routing table, arp cache, process table, kernel statistics, memory
- temporary file systems
- disk
- remote logging and monitoring data that is relevant to the system in question
- physical configuration, network topology
- archival media
## Memory Files (Locked by OS during use)
- hiberfil.sys (RAM stored during machine hibernation)

- %SystemRoot%\hiberfil.sys
- pagefile.sys (Virtual memory used by Windows)

- %SystemDrive%\pagefile.sys

swapfile.sys (Virtual memory used by Windows Store Apps)

- %SystemDrive%\swapfile.sys
## [Binalyze IREC Evidence Collector](https://binalyze.com/products/irec "Binalyze IREC Evidence Collector") (GUI or CommandLine)
> IREC.exe --license AAAA-BBBB-CCDD-DDDD --profile memory

Note: Can be used as an all in one collector (License required for full collection, free version available).

[Latest documentation](https://irec.readthedocs.io/en/latest/commandline.html "Latest documentation")

##[ Belkasoft Live RAM Capturer](https://belkasoft.com/get?product=ram " Belkasoft Live RAM Capturer")
> RamCapture64.exe "output.mem"

OR for 32 bit OS

> RamCapture32.exe "output.mem"

## Redline
Excellent resource:
> https://resources.infosecinstitute.com/memory-analysis-using-redline/

## Memoryze

> MemoryDD.bat --output [LOCATION]

## Comae DumpIT
> DumpIt.exe /O [LOCATION]

	- Used for getting a memory crash file (Useful for analysis with both windbg and volatility)
	
DumpIt.exe /O [LOCATION]\mem.raw /T RAW

	- Used for getting a raw memory dump (Considered a legacy format)

These can be bundled with PSEXEC to execute on a remote PC; however, this will copy the file to the remote PC for executing. There’s limitations if the tool requires other drivers or files to execute (such as RamCapture). An example command may be:

> psexec \\remotepcname -c DumpIt.exe

## Magnet Forensics (Mostly GUI)
- [ Magnet Forensics Tools](https://www.magnetforensics.com/resources/?cat=Free%20Tool " Magnet Forensics Tools")
- [Magnet RAM Capture](https://www.magnetforensics.com/free-tool-magnet-ram-capture "Magnet RAM Capture")
- [Magnet Process Capture](https://www.magnetforensics.com/resources/magnet-process-capture/ "Magnet Process Capture")

# Imaging Live Machines
## [ FTK Imager (Cmd version, mostly GUI for new versions)](https://accessdata.com/product-download "## FTK Imager (Cmd version, mostly GUI for new versions)")

> ftkimager --list-drives
ftkimager \\.\PHYSICALDRIVE0 "[Location]\Case" --e01
ftkimager [source] [destination]
ftkimager \\.\PHYSICALDRIVE0 "[Location]\Case" --e01 --outpass securepasswordinsertedhere 

## DD
> dd.exe --list
dd.exe if=/dev/<drive> of=Image.img bs=1M
dd.exe if=\\.\<OSDrive>: of=<drive>:\<name>.img bs=1M --size --progress
(LINUX) sudo dd if=/dev/<OSDrive> of=/mnt/<name>.ddimg bs=1M conv=noerror,sync

# Live Windows IR/Triage
CMD and WMIC (Windows Management Instrumentation Command-Line) Note: less information can be gathered by using ‘list brief’.

## Interact with remote machine
> wmic /node:[IP] process call create "powershell enable-psremoting -force"

Powershell:
> Enter-PSSession -ComputerName [IP]

PSExec:
> PsExec: psexec \\IP -c cmd.exe

https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/enter-pssession?view=powershell-6

## System information

> echo %DATE% %TIME%
date /t
time /t
systeminfo
wmic computersystem list full
wmic /node:localhost product list full /format:csv
wmic softwarefeature get name,version /format:csv
wmic softwareelement get name,version /format:csv
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /s
echo %PATH%
SET
wmic bootconfig get /all /format:List
wmic computersystem get name, domain, manufacturer, model, numberofprocessors,primaryownername,username,roles,totalphysicalmemory /format:list
wmic timezone get Caption, Bias, DaylightBias, DaylightName, StandardName
wmic recoveros get /all /format:List
wmic os get /all /format:list
wmic partition get /all /format:list
wmic logicaldisk get /all /format:list
wmic diskdrive get /all /format:list
fsutil fsinfo drives

(psinfo requires sysinternals psinfo.exe):

> psinfo -accepteula -s -h -d

## Obtain list of all files on a computer
> tree C:\ /F > output.txt
dir C:\ /A:H /-C /Q /R /S /X

## User and admin information
> whoami
net users
net localgroup administrators
net group /domain [groupname]
net user /domain [username]
wmic sysaccount
wmic useraccount get name,SID
wmic useraccount list

## Logon information
> wmic netlogin list /format:List

## NT Domain/Network Client Information
> wmic ntdomain get /all /format:List
wmic netclient get /all /format:List
nltest /trusted_domains

## Firewall Information

> netsh Firewall show state
netsh advfirewall firewall show rule name=all dir=in type=dynamic
netsh advfirewall firewall show rule name=all dir=out type=dynamic
netsh advfirewall firewall show rule name=all dir=in type=static
netsh advfirewall firewall show rule name=all dir=out type=dynamic

## Pagefile information
> wmic pagefile

## Group and access information
(Accesschk requires accesschk64.exe or accesschk.exe from sysinternals):

> net localgroup
accesschk64 -a *

## RecentDocs Information [Special thanks Barnaby Skeggs](https://twitter.com/barnabyskeggs "Special thanks Barnaby Skeggs")

*Note: Run with Powershell, get SID and user information with ‘wmic useraccount get name,SID’

> $SID = "S-1-5-21-1111111111-11111111111-1111111-11111"; $output = @(); Get-Item -Path "Registry::HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" | Select-Object -ExpandProperty property | ForEach-Object {$i = [System.Text.Encoding]::Unicode.GetString((gp "Registry::HKEY_USERS\$SID\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" -Name $_).$_); $i = $i -replace '[^a-zA-Z0-9 \.\-_\\/()~ ]', '\^'; $output += $i.split('\^')[0]}; $output | Sort-Object -Unique

## Startup process information
> wmic startup list full
wmic startup list brief
Get-CimInstance Win32_StartupCommand | Select-Object Name, command, Location, User | FL

## Scheduled task/job information

> at (For older OS)
schtasks
schtasks /query /fo LIST /v
schtasks /query /fo LIST /v | findstr "Task To Run:"
schtasks /query /fo LIST /v | findstr "appdata"
schtasks /query /fo LIST /v | select-string "Enabled" -CaseSensitive -Context 10,0 | findstr "exe"
schtasks /query /fo LIST /v | select-string "Enabled" -CaseSensitive -Context 10,0 | findstr "Task"
schtasks /query /fo LIST /v | Select-String "exe" -Context 2,27 
wmic job get Name, Owner, DaysOfMonth, DaysOfWeek, ElapsedTime, JobStatus, StartTime, Status

Powershell:

> Get-ScheduledTask
gci -path C:\windows\system32\tasks |Select-String Command|FT Line, Filename

## Remediate malicious scheduled tasks

> schtasks /Delete /TN [taskname] /F

Powershell:

> Unregister-ScheduledTask -TaskName [taskname]
Unregister-ScheduledTask -TaskPath [taskname]

## Quick overview of persistent locations ([AutoRuns](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns "AutoRuns"))

> autorunsc.exe -accepteula -a * -c -h -v -m > autoruns.csv
autorunsc.exe -accepteula -a * -c -h -v -m -z 'E:\Windows' > autoruns.csv

## Persistence and Automatic Load/Run Reg Keys
Replace: “*reg query*” with “*Get-ItemProperty -Path HK:*" in Powershell*

e.g.: **Get-Item -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run**

**User Registry (NTUSER.DAT HIVE)** - Commonly located at: C:\Users[username] *Note: These are setup for querying the current users registry only (HKCU), to query others you will need to load them from the relevant NTUSER.DAT file and then query them.


> reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx"
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
reg query "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /f run
reg query "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /f load
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Windows\Scripts"
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\RecentDocs"
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\RunMRU"
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
reg query "HKCU\SOFTWARE\AcroDC"
reg query "HKCU\SOFTWARE\Itime"
reg query "HKCU\SOFTWARE\info"
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\User Shell Folders"
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Applets\RegEdit" /v LastKey
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU" /s
reg query "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell"
reg query "HKCU\SOFTWARE\Microsoft\Windows\currentversion\run"
reg query "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Microsoft\Windows\CurrentVersion\Run"
reg query "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Microsoft\Windows\CurrentVersion\RunOnce"
reg query "HKCU\SOFTWARE\Microsoft\Office\[officeversion]\[word/excel/access etc]\Security\AccessVBOM"
	reg query "HKCU\SOFTWARE\Microsoft\Office\15.0\Excel\Security\AccessVBOM
	reg query "HKCU\SOFTWARE\Microsoft\Office\15.0\Word\Security\AccessVBOM
	reg query "HKCU\SOFTWARE\Microsoft\Office\15.0\Powerpoint\Security\AccessVBOM
	reg query "HKCU\SOFTWARE\Microsoft\Office\15.0\Access\Security\AccessVBOM

**Local Machine (SOFTWARE HIVE)**

> reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices"
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\System\Scripts"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /f AppInit_DLLs
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Win\Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" /s
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit" /s
reg query "HKLM\SOFTWARE\Classes\piffile\shell\open\command"
reg query "HKLM\SOFTWARE\Classes\exefile\shell\open\Command"
reg query "HKLM\SOFTWARE\Classes\htafile\shell\open\Command"
reg query "HKLM\SOFTWARE\wow6432node\Microsoft\Windows\CurrentVersion\policies\explorer\run"
reg query "HKLM\SOFTWARE\wow6432node\Microsoft\Windows\CurrentVersion\run"
reg query "HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows"
reg query "HKLM\SOFTWARE\Microsoft\Office\[officeversion]\[word/excel/access etc]\Security\AccessVBOM"
	reg query "HKLM\SOFTWARE\Microsoft\Office\15.0\Excel\Security\AccessVBOM
	reg query "HKLM\SOFTWARE\Microsoft\Office\15.0\Word\Security\AccessVBOM
	reg query "HKLM\SOFTWARE\Microsoft\Office\15.0\Powerpoint\Security\AccessVBOM
	reg query "HKLM\SOFTWARE\Microsoft\Office\15.0\Access\Security\AccessVBOM


Don't be afraid to use “*findstr*” to find entries of interest, for example file extensions which may also invoke malicious executables when run, or otherwise.

> reg query "HKLM\SOFTWARE\Classes" | findstr "file"
reg query HKCR\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5} /s
reg query HKCR\AppID\ /s | findstr "exe"

**Local Machine (SYSTEM HIVE)**

Note: This not only contains services, but also malicious drivers which may run at startup (these are in the form of “.sys” files and are generally loaded from here: \SystemRoot\System32\drivers)

> reg query "HKLM\SYSTEM\CurrentControlSet\Services\[Random_name]\imagePath"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\ /s /f "*.exe"
reg query "HKLM\SYSTEM\CurrentControlSet\Services" /s | findstr "ImagePath" | findstr ".exe"
reg query "HKLM\SYSTEM\CurrentControlSet\Services" /s | findstr "ImagePath" | findstr ".sys"
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\*" | FL DisplayName,ImagePath,ObjectName
gci -Path C:\Windows\system32\drivers -include *.sys -recurse -ea 0 -force | Get-AuthenticodeSignature
gci -Path C:\Windows\system32\drivers -include *.sys -recurse -ea 0 -force | Get-FileHash

## Locate all user registry keys

> $UserProfiles = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*" | Where {$_.PSChildName -match "S-1-5-21-(\d+-?){4}$" } | Select-Object @{Name="SID"; Expression={$_.PSChildName}}, @{Name="UserHive";Expression={"$($_.ProfileImagePath)\ntuser.dat"}}

## Load all users registry keys from their ntuser.dat file (perform above first)

> Foreach ($UserProfile in $UserProfiles) {If (($ProfileWasLoaded = Test-Path Registry::HKEY_USERS\$($UserProfile.SID)) -eq $false) {reg load HKU\$($UserProfile.SID) $($UserProfile.UserHive) | echo "Successfully loaded: $($UserProfile.UserHive)"}}

## Query all users run key

> Foreach ($UserProfile in $UserProfiles) {reg query HKU\$($UserProfile.SID)\SOFTWARE\Microsoft\Windows\CurrentVersion\Run}




## Unload all users registry keys

> [gc]::Collect()
Foreach ($UserProfile in $UserProfiles) {reg unload HKU\$($UserProfile.SID)}

## Remediate Automatic Load/Run Reg Keys
> reg delete [keyname] /v [ValueName]
reg delete [keyname]
Foreach ($UserProfile in $UserProfiles) {reg delete HKU\$($UserProfile.SID)\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce}

Powershell:

> Remove-ItemProperty -Path "[Path]" -Name "[name]"

## Persistent file locations of interest

> %localappdata%\<random>\<random>.<4-9 file ext>
%localappdata%\<random>\<random>.lnk
%localappdata%\<random>\<random>.bat
%appdata%\<random>\<random>.<4-9 file ext>
%appdata%\<random>\<random>.lnk
%appdata%\<random>\<random>.bat
%appdata%\<random>\<random>.bat
%SystemRoot%\<random 4 chars starting with digit>
%appdata%\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\*.lnk
%SystemRoot%\System32\<randomnumber>\
%SystemRoot%\System32\tasks\<randomname>
%SystemRoot%\\<randomname>
C:\Users\[user]\appdata\roaming\[random]
C:\Users\Public\*

You can scan these directories for items of interest e.g. unusual exe, dll, bat, lnk etc files with:


> dir /s /b %localappdata%\*.exe | findstr /e .exe
dir /s /b %appdata%\*.exe | findstr /e .exe
dir /s /b %localappdata%\*.dll | findstr /e .dll
dir /s /b %appdata%\*.dll | findstr /e .dll
dir /s /b %localappdata%\*.bat | findstr /e .bat
dir /s /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup\" | findstr /e .lnk
dir /s /b "C:\Users\Public\" | findstr /e .exe
dir /s /b "C:\Users\Public\" | findstr /e .lnk
dir /s /b "C:\Users\Public\" | findstr /e .dll
dir /s /b "C:\Users\Public\" | findstr /e .bat
ls "C:\Users\[User]\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup" | findstr /e .lnk

## Locate BITSAdmin Persistence

> bitsadmin /list /allusers /verbose


## Remove BITSAdmin Persistence

> bitsadmin /reset /allusers

> import-module bitstransfer
Get-BitsTransfer -AllUsers | Remove-BitsTransfer

## Find files without extensions
> Get-ChildItem -Path C:\Users\[user]\AppData -Recurse -Exclude *.* -File -Force -ea SilentlyContinue

## Remediate malicious files
> rmdir %localappdata%\maliciousdirectory\ /s
del /F %localappdata%\maliciousdirectory\malware.exe

Powershell:

> Remove-Item [C:\Users\Public\*.exe]
Remove-Item -Path [C:\Users\Public\malware.exe] -Force
Get-ChildItem * -Include *.exe -Recurse | Remove-Item

## Detect Persistent WMI Subscriptions
> Get-WmiObject -Class __FilterToConsumerBinding -Namespace root\subscription
Get-WmiObject -Class __EventFilter -Namespace root\subscription
Get-WmiObject -Class __EventConsumer -Namespace root\subscription


## Remediate Persistent WMI Subscriptions
> Get-WMIObject -Namespace root\subscription -Class __EventFilter -Filter "Name='[Name]'" | Remove-WmiObject
Get-WMIObject -Namespace root\subscription -Class CommandLineEventConsumer -Filter "Name='[Name]'" | Remove-WmiObject
Get-WMIObject -Namespace root\subscription -Class __FilterToConsumerBinding -Filter "__Path like '%[Name]%'" | Remove-WmiObject 

##[ Enumerate WMI Namespaces](https://learn-powershell.net/2014/05/09/quick-hits-list-all-available-wmi-namespaces-using-powershell/ "## Enumerate WMI Namespaces")
> 
Function Get-WmiNamespace ($Path = 'root')
{
	foreach ($Namespace in (Get-WmiObject -Namespace $Path -Class __Namespace))
	{
		$FullPath = $Path + "/" + $Namespace.Name
		Write-Output $FullPath
		Get-WmiNamespace -Path $FullPath
	}
}
Get-WMINamespace -Recurse

## Mimikatz Detection
The below represent registry keys which make it more difficult for Mimikatz to work. Modification of these keys may indicate an attacker trying to execute Mimikatz within an environment if they were set to their more secure state. Always test prior to changing registry keys such as these in a production environment to ensure nothing breaks.

> HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest
	- “UseLogonCredential” should be 0 to prevent the password in LSASS
HKLM\SYSTEM\CurrentControlSet\Control\Lsa
	- “RunAsPPL” should be set to dword:00000001 to enable LSA Protection which prevents non-protected processes from interacting with LSASS. 
	- Mimikatz can remove these flags using a custom driver called mimidriver. This uses the command **!+** and then **!processprotect /remove /process:lsass.exe** by default so tampering of this registry key can be indicative of Mimikatz activity.

The [Mimikatz Yara rule](https://github.com/gentilkiwi/mimikatz/blob/master/kiwi_passwords.yar "Mimikatz Yara rule") may also prove useful.

## Installed Updates
(WMI Quick Fix Engineering)

> wmic qfe

## Installed Software/Packages
> reg query HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\ /s | findstr "DisplayName"
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\ /s | findstr "DisplayName"
wmic product get name,version /format:csv
wmic product get /ALL
dism /online /get-packages

Powershell: Full List for all users using uninstall keys in registry

> $(Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*; Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*;New-PSDrive -Name HKU -PSProvider Registry -Root Registry::HKEY_USERS| Out-Null;$UserInstalls += gci -Path HKU: | where {$_.Name -match 'S-\d-\d+-(\d+-){1,14}\d+$'} | foreach {$_.PSChildName };$(foreach ($User in $UserInstalls){Get-ItemProperty HKU:\$User\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*});$UserInstalls = $null;try{Remove-PSDrive -Name HKU}catch{};)|where {($_.DisplayName -ne $null) -and ($_.Publisher -ne $null)} | Select DisplayName,DisplayVersion,Publisher,InstallDate,UninstallString |FT

## Process information
(pslist requires sysinternals pslist.exe):
> wmic process list full /format:csv
wmic process get name,parentprocessid,processid /format:csv
wmic process get ExecutablePath,processid /format:csv
wmic process get name,ExecutablePath,processid,parentprocessid /format:csv | findstr /I "appdata"
wmic process where processid=[PID] get parentprocessid
wmic process where processid=[PID] get commandline
wmic process where "commandline is not null and commandline!=''" get name,commandline /format:csv
Get-WmiObject win32_process -Filter "name like '%powershell.exe'" | select processId,commandline|FL
pslist

## Scan for malware with Windows Defender
> "%ProgramFiles%\Windows Defender\MpCmdRun.exe" -Scan -ScanType 1
"%ProgramFiles%\Windows Defender\MpCmdRun.exe" -Scan -ScanType 2
"%ProgramFiles%\Windows Defender\MpCmdRun.exe" -Scan -ScanType 3 -File C:\Users\[username]\AppData\Local\Temp

Note: Types are as follows
1. Quick scan
2. Full system scan
3. File and directory custom scan



