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
