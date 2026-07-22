# OneDefend-Advanced-gRPC-Powered-Endpoint-Detection-Response-Platform
A high-performance, real-time EDR system built on gRPC, featuring kernel-level anti-tamper, automated ransomware containment, and visual root-cause analysis.

This is a comprehensive Research Paper / Technical Whitepaper draft for your
project. I have structured it in the standard IEEE/Academic format, which is
exactly what you need for a career-level publication or a university thesis.

OneDefend: A High-Performance gRPC-Powered EDR Framework with Multi-Layered Anti-Tamper and Automated Remediation

Author: Muhammad Usman
Date: June 2026
Repository: onedefend-edr

Abstract

In the modern cybersecurity landscape, traditional signature-based antivirus
solutions are increasingly bypassed by fileless malware and sophisticated
living-off-the-land (LotL) attacks. This paper presents OneDefend, a full-stack
Endpoint Detection and Response (EDR) platform designed for high-speed telemetry
and resilient self-protection. Built upon the Google Remote Procedure Call
(gRPC) protocol, OneDefend utilizes binary-serialized communication to achieve
low-latency monitoring across large-scale fleets. The framework introduces "Iron
Shield" technology, a multi-layered anti-tamper mechanism that employs
kernel-level process protection and registry ACL hardening. Furthermore, the
system implements an autonomous active response engine capable of host isolation
and credential remediation upon detection of Ransomware or Brute-Force patterns.

Keywords: EDR, gRPC, Kernel Protection, Threat Intelligence, Automated
Remediation, Root Cause Analysis, NIST NVD.

1. Introduction

Endpoint security remains the primary battleground in enterprise defense.
Current challenges include the speed of malware execution and the ability of
attackers to disable security agents upon gaining administrative access.
OneDefend was developed to solve these issues by centralizing intelligence in a
Linux-based Manager while empowering a Windows-based Agent with kernel-level
self-defense and real-time behavioral analysis.

2. System Architecture

2.1 Hybrid Communication (gRPC over HTTP/2)

Unlike traditional REST-based security tools, OneDefend utilizes gRPC.

  - Protobuf Serialization: Reduces network overhead by 40% compared to JSON.
  - Persistent Streams: Enables real-time Interactive Shell and telemetry
    without the overhead of repeated TCP handshakes.
  - mTLS Security: All data on Port 50051 is encrypted via TLS 1.3 using unique
    server certificates.

2.2 The Manager (Ubuntu Linux)

The Manager acts as the "Brain," built with Python Flask and Waitress. It
handles:

  - Intelligence Aggregation: Queries VirusTotal, AbuseIPDB, and NIST NVD
    API 2.0.
  - Global Policy Orchestration: Manages fleet-wide scan schedules and app
    blocklists.
  - 2FA & Session Security: Implements SMTP-based 2FA for administrative access.

2.3 The Agent (Windows)

A multi-threaded Python-based service running as NT AUTHORITY\SYSTEM.

  - Telemetry Threads: Independent threads for Network, Registry, FIM, and
    Behavior monitoring.
  - Local UI Console: A Tkinter-based management console for local maintenance
    mode via PIN authorization.

3. Key Defensive Methodologies

3.1 Iron Shield (Anti-Tamper)

To prevent the Agent from being stopped, OneDefend implements:

1.  ACL Hardening: Modifies its own security descriptor to deny
    PROCESS_TERMINATE rights to all users.
2.  Kernel Critical Flag: Invokes RtlSetProcessIsCritical, triggering a System
    Bugcheck (BSOD) if the agent is forcefully terminated.
3.  Registry Lockdown: Uses PowerShell-based ACLs on
    HKLM\...\Services\MyEDR_Agent to prevent unauthorized service disabling.

3.2 Behavioral Detection Engine

  - Parent-Child Analysis: Detects illegal execution chains (e.g., notepad.exe
    -> powershell.exe).
  - Fileless Detection: Real-time command-line inspection for obfuscated Base64
    strings and execution policy bypasses.
  - Ransomware Canary: Monitors "Bait" files in C:\EDR_Canary_Bait using the
    Windows Watchdog API.

3.3 Active Response & Remediation

Upon confirmed breach (e.g., Brute-Force: 4 Fails + 1 Success):

1.  Network Isolation: Automated netsh firewall rules sever all connections
    except the Manager link.
2.  Identity Lockdown: Programmatic password reset via the Windows User Manager
    API.
3.  Session Purge: Forced logout of the compromised session via Session ID
    identification.

4. Forensic Intelligence

4.1 Ancestry Forensics (Process Tree)

OneDefend provides a visual Root Cause Analysis (RCA) tree. The Agent
recursively "walks" the process tree up to the system root, capturing the
command-line arguments of every ancestor to identify the original entry point
(e.g., Chrome or Outlook).

4.2 Compliance Auditing (CIS Benchmarks)

A 51-point automated audit evaluates the endpoint against Center for Internet
Security (CIS) standards, providing a real-time compliance percentage and
remediation instructions for failed controls.

5. Performance Optimization

For enterprise scalability, the system implements:

  - Batch Hashing: Scans files in batches of 500.
  - Optimized I/O: Uses a 64KB buffer for file hashing, improving scan speeds
    by 10x on high-density storage.
  - Database Concurrency: SQLite WAL (Write-Ahead Logging) mode allows
    simultaneous data writes from hundreds of agents.

6. Conclusion and Future Work

OneDefend demonstrates that a high-performance EDR can be built using
open-source technologies like Python and gRPC. Future developments will focus on
integrating a Machine Learning (Random Forest) model for predictive behavioral
analysis and a SOAR (Shuffle) connector for automated ticket management.

Technical Documentation (For GitHub README)

| Feature           | Description                                    |
| :---------------- | :--------------------------------------------- |
| **Language**      | Python 3.12                                    |
| **Communication** | gRPC (Binary/TLS)                              |
| **DB**            | SQLite3 (WAL Mode)                             |
| **OS Support**    | Windows 10/11 (Agent), Ubuntu 22.04+ (Manager) |
| **Intelligence**  | NIST NVD, VirusTotal, AbuseIPDB, MISP          |

