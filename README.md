# 🦈 Wireshark Packet Analysis

## Overview

This project focuses on network traffic analysis using **Wireshark**, a leading packet analyzer tool. The goal is to simulate how cybersecurity professionals examine raw network traffic to uncover threats, misconfigurations, or performance issues. Using both live and pre-recorded PCAP (Packet Capture) files, I demonstrate how to identify:

* Port scans
* Malicious payloads
* Unusual protocol usage
* Potential command-and-control (C2) traffic

These skills are essential for threat hunting, incident response, and security monitoring roles.

## Tools Used

* **Wireshark**: GUI-based packet capture and analysis tool
* **tcpdump**: CLI utility to capture traffic in PCAP format
* **Nmap**: To simulate port scans and create traffic
* **Python HTTP server**: To simulate web traffic
* **Public PCAPs**: From malware traffic analysis repositories

## Lab Setup

* Two VMs on a virtual LAN: one attacker (Kali), one victim (Ubuntu Server)
* Wireshark installed on attacker and/or victim
* Port mirroring enabled to see all traffic (or Wireshark run locally)
* PCAPs also downloaded for advanced malware scenarios

## Analysis Scenarios

### 1. Detecting a Port Scan

* **Technique**: Run Nmap SYN scan from attacker to victim
* **Wireshark Filter**: `tcp.flags.syn == 1 && tcp.flags.ack == 0`
* **Observation**: Sequential SYN packets to multiple ports, few/no replies = scan behavior

### 2. Identifying Exploit Payloads

* **Technique**: Analyze PCAP with HTTP-based command injection
* **Wireshark View**: Follow TCP Stream
* **Observation**: Payload like `cmd.exe /c whoami` embedded in HTTP request

### 3. Finding C2 Beaconing

* **Technique**: Filter for repeated outbound connections to a single IP/domain
* **Wireshark Tool**: Statistics > Endpoints
* **Observation**: Periodic traffic to unknown domain/IP over HTTP or DNS

### 4. ICMP Flood (DoS Simulation)

* **Technique**: View PCAP of ICMP flood
* **Wireshark Filter**: `icmp`
* **Observation**: Repetitive echo requests with large payloads, abnormal volume

### 5. Extracting Files

* **Technique**: Use "Export Objects" in HTTP or SMB sessions
* **Example**: Retrieve EXE or DOC file from transfer
* **Safety**: Hash file and scan with VirusTotal

## Findings

| Scenario      | Key Takeaway                                               |
| ------------- | ---------------------------------------------------------- |
| Port Scan     | Scans show up clearly with SYNs and no ACKs                |
| Exploit       | Payloads can be spotted directly in TCP stream             |
| C2 Traffic    | Beaconing often uses regular intervals or odd ports        |
| DoS           | Floods result in protocol imbalance (e.g., too many ICMPs) |
| File Recovery | Wireshark can recover files for further forensic use       |

## Takeaways

* **Filter Mastery**: Learned to use Wireshark filters like `ip.addr == x.x.x.x`, `tcp.port == 80`, etc.
* **Protocol Understanding**: Recognized TCP/UDP patterns, HTTP request types, DNS behaviors
* **Forensics Mindset**: Practiced thinking like an analyst—"what's normal vs suspicious"
* **Communication**: Documented findings in clear, structured format suitable for SOC reports

---

This project illustrates how packet-level analysis supports cybersecurity operations. From detection to forensics, Wireshark provides visibility into the raw truth of network behavior. Proficiency in this tool is essential for any SOC analyst, threat hunter, or incident responder.
