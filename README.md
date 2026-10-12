# Task-2-Network-Traffic-Packet-Analysis
Network traffic inspection and protocol analysis using Wireshark and Python for a cybersecurity internship project.
# Task 2: Network Traffic Packet Inspection & Analysis with Wireshark

**Internship:** Arrowstack Cyber Security Internship  
**Track:** Technical Track – Intermediate  
**Author:** Abdul Rehman

## Overview

This project documents a network-traffic inspection exercise using Wireshark and a Python-based PCAP analysis workflow. It focuses on examining packet metadata, applying display filters, identifying protocols, and recording observations carefully.

The supplied evidence screenshots show DNS, TCP/TLS 1.3, QUIC, STUN, SSDP, NAT-PMP/PCP-related traffic, and ICMP destination-unreachable messages. These observations do **not**, by themselves, prove that an attack or compromise occurred.

## Objectives

- Inspect packet captures in Wireshark.
- Use display filters such as `udp` and `tcp`.
- Review source/destination addresses, protocols, packet lengths, and packet details.
- Document visible network activity and possible follow-up checks.
- Support repeatable analysis using Python where applicable.
- Apply privacy-aware handling to packet captures and screenshots.

## Tools

- Wireshark
- Python 3
- Scapy, Pandas, and Matplotlib (if used by the analysis script)





### Windows PowerShell

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

If PowerShell blocks activation, you can run the environment's Python directly:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

## Wireshark workflow

1. Open an authorized PCAP/PCAPNG capture in Wireshark.
2. Enter `udp` in the display-filter bar to inspect UDP-related traffic.
3. Enter `tcp` to inspect TCP traffic.
4. Select individual packets and review the packet-details pane.
5. Record findings with the capture filename, date, filter, and relevant context.
6. Treat unusual packets as leads for further investigation—not automatic proof of malicious activity.

## Run the Python analyzer

Check the command-line options implemented by your script first:

```powershell
python analyze_pcap.py --help
```

Then use the supported input option shown by the help output. For example, **only if your script supports this syntax**:

```powershell
python analyze_pcap.py "path\to\your_capture.pcapng"
```

Run the script against the exact capture you intend to analyze and retain the actual terminal output. Document only counts, percentages, and charts that the script genuinely produces.

## Observations from the supplied screenshots

- DNS queries and responses are visible.
- TCP traffic to port 443 and TLS 1.3 application-data records are visible.
- QUIC and STUN packets appear in the capture view.
- SSDP and NAT-PMP/PCP-related messages are visible.
- ICMP destination-unreachable messages include “Port unreachable.”

These are observations, not confirmed vulnerabilities. Interpret them in the context of the device, applications, capture scope, and surrounding packets.

## Privacy and safe use

- Analyze only traffic you own or have explicit permission to inspect.
- PCAP/PCAPNG files can contain private IP addresses, public IPs, DNS queries, MAC addresses, timestamps, and other sensitive metadata.
- Do not publish raw captures from a personal or workplace network unless you have permission and have reviewed the privacy impact.
- Prefer sanitized screenshots and generated summary outputs for a public repository.
- Never commit passwords, API keys, tokens, or other secrets.
- Keep the `.venv/` directory out of GitHub.

## Limitations

The current screenshots alone do not establish that the network is compromised. They also do not support verified protocol percentages or a complete analysis of both capture files. Add numerical results only after running and checking the analyzer against the exact submitted capture.

## Report

The internship report is included as a separate Word document. If a PDF is required, export the reviewed document to PDF before uploading it.

## Authorized-use statement

This project is intended for educational network analysis and defensive security learning on authorized captures only.
