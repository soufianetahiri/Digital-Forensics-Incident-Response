# Digital-Forensics-Incident-Response
Digital Forensics and Incident Response

This Post is a copy/past of this post https://www.jaiminton.com/cheatsheet/DFIR/ by Jai Minton (https://twitter.com/CyberRaiju)

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


