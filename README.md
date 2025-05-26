# network-security-assessment
Comprehensive network security assessment toolkit and documentation


                                                                                                  TASK -- 1

Network Security Assessment Methodology
Overview

This document outlines the systematic approach used for conducting network security assessments in controlled lab environments.
Phase 1: Reconnaissance and Discovery
Network Enumeration

    Objective: Identify live hosts and network topology
    Tools: Nmap TCP SYN scan (-sS)
    Command: nmap -sS [target_network]/24

Service Discovery

    Objective: Identify running services and versions
    Tools: Nmap service detection (-sV)
    Command: nmap -sV -sC [target_hosts]

OS Fingerprinting

    Objective: Determine operating systems
    Tools: Nmap OS detection (-O)
    Command: nmap -O [target_hosts]

Phase 2: Vulnerability Assessment
Service-Specific Testing

    SMB Testing: Check for EternalBlue and related vulnerabilities
    RPC Testing: Assess Windows RPC security
    DNS Testing: Evaluate DNS service configuration

Automated Vulnerability Scanning

    Tools: Nmap NSE scripts
    Command: nmap --script vuln [target_hosts]

Phase 3: Analysis and Reporting
Risk Assessment

    Categorize findings by severity (Critical, High, Medium, Low)
    Assess business impact and exploitability
    Prioritize remediation efforts

Documentation

    Technical findings with evidence
    Executive summary for management
    Detailed remediation recommendations

docs/vulnerability-assessment.md
Vulnerability Assessment Guide
SMB (Server Message Block) Testing
Critical Vulnerabilities to Test
MS17-010 (EternalBlue)

bash

nmap --script smb-vuln-ms17-010 -p 445 [target]

    Risk: Critical - Remote Code Execution
    Affected: Windows XP to Windows 10/Server 2016
    Impact: Full system compromise

MS08-067 (Conficker)

bash

nmap --script smb-vuln-ms08-067 -p 445 [target]

    Risk: Critical - Remote Code Execution
    Affected: Windows 2000 to Windows Server 2008
    Impact: Worm propagation vector

SMB Configuration Assessment
Protocol Version Check

bash

nmap --script smb-protocols -p 445 [target]

    SMBv1: Deprecated, should be disabled
    SMBv2/3: Recommended versions

Security Mode Analysis

bash

nmap --script smb-security-mode -p 445 [target]

    Check authentication requirements
    Assess signing configuration

RPC (Remote Procedure Call) Testing
Common RPC Vulnerabilities

bash

nmap --script vuln -p 135 [target]

    MS03-026: Buffer overflow in RPC interface
    MS03-039: Buffer overflow in RPCSS service
    MS05-012: SMB and NetBIOS vulnerabilities

DNS Security Assessment
DNSmasq Specific Tests

bash

# Check version and known CVEs
nmap -sV -p 53 [target]

# Test for DNS amplification
nmap --script dns-recursion [target]

Known DNSmasq Vulnerabilities (v2.78)

    CVE-2017-14491: Heap buffer overflow
    CVE-2017-14492: Heap buffer overflow
    CVE-2017-14493: Stack buffer overflow
    CVE-2017-14494: Information leak
    CVE-2017-14495: Memory corruption
    CVE-2017-14496: Integer underflow

docs/remediation-guide.md
Security Remediation Guide
Immediate Actions (Critical Priority)
SMB Security Hardening
Disable SMBv1

Windows:

powershell

# Disable SMBv1
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol

Linux/Samba:

bash

# Edit smb.conf
[global]
min protocol = SMB2

Apply Security Patches

    Install MS17-010 patch (KB4013389)
    Enable automatic Windows Updates
    Verify patch installation

RPC Service Hardening

    Restrict RPC endpoints
    Configure Windows Firewall rules
    Disable unnecessary RPC services

DNS Service Updates

    Upgrade DNSmasq to latest version (2.89+)
    Configure DNS forwarding restrictions
    Implement query logging

Network Security Controls
Firewall Configuration

bash

# Block SMB from external networks
iptables -A INPUT -p tcp --dport 445 -s ! 10.0.2.0/24 -j DROP
iptables -A INPUT -p tcp --dport 135 -s ! 10.0.2.0/24 -j DROP

Network Segmentation

    Implement VLANs for service isolation
    Create DMZ for public-facing services
    Restrict inter-VLAN communication

Monitoring and Detection
Log Configuration

    Enable Windows Security Auditing
    Configure Sysmon for enhanced logging
    Implement centralized log collection

Network Monitoring

    Deploy network intrusion detection (Suricata/Snort)
    Monitor for lateral movement patterns
    Alert on SMB vulnerability exploitation attempts

tools/nmap-commands.md
Nmap Commands Reference
Basic Scanning
Host Discovery

bash

# Ping scan to find live hosts
nmap -sn 192.168.1.0/24

# TCP SYN scan (stealthy)
nmap -sS 192.168.1.0/24

# TCP Connect scan (full connection)
nmap -sT 192.168.1.0/24

Service Detection

bash

# Service version detection
nmap -sV [target]

# Service and OS detection
nmap -sV -O [target]

# Aggressive scan (service, OS, traceroute, scripts)
nmap -A [target]

Vulnerability Scanning
SMB Vulnerabilities

bash

# All SMB vulnerability scripts
nmap --script smb-vuln* -p 445 [target]

# Specific vulnerability tests
nmap --script smb-vuln-ms17-010 -p 445 [target]
nmap --script smb-vuln-ms08-067 -p 445 [target]
nmap --script smb-vuln-ms10-054 -p 445 [target]

General Vulnerability Assessment

bash

# All vulnerability scripts
nmap --script vuln [target]

# Specific service vulnerabilities
nmap --script vuln -p 80,443 [target]  # Web services
nmap --script vuln -p 22 [target]      # SSH
nmap --script vuln -p 3389 [target]    # RDP

Advanced Techniques
Timing and Evasion

bash

# Timing templates (T0=paranoid, T5=insane)
nmap -T4 [target]  # Aggressive timing

# Fragment packets
nmap -f [target]

# Decoy scanning
nmap -D RND:10 [target]

Output Formats

bash

# Normal output
nmap -oN scan_results.txt [target]

# XML output
nmap -oX scan_results.xml [target]

# Greppable output
nmap -oG scan_results.gnmap [target]

# All formats
nmap -oA scan_results [target]

tools/wireshark-filters.md
Wireshark Analysis Filters
Common Network Protocols
SMB/CIFS Traffic

smb || smb2

RPC Traffic

dcerpc

DNS Queries

dns

Security-Focused Filters
Suspicious SMB Activity

smb.cmd == 0x72  # SMB Negotiate Protocol
smb2.cmd == 0     # SMB2 Negotiate

Failed Authentication

smb.nt_status == 0xc000006d  # Logon failure

Port Scanning Detection

tcp.flags.syn == 1 && tcp.flags.ack == 0

Analysis Techniques
Timeline Analysis

    Sort by timestamp
    Look for rapid connection attempts
    Identify scan patterns

Protocol Analysis

    Examine handshake sequences
    Check for protocol downgrades
    Analyze error responses

LICENSE

MIT License

Copyright (c) 2025 Network Security Assessment Project

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
