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

