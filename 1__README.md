# CodeAlpha_InternshipTasks

1

# 🛡️ NetworkSniffer – Lightweight Network Packet Sniffer

A simple yet powerful Python-based network packet analyzer using **Scapy** and **socket** libraries. It captures and displays key details of Ethernet, IP, TCP, UDP, and ICMP packets in real-time. Output can be optionally saved to a `.txt` file for analysis.

---

## VIDEO

https://github.com/user-attachments/assets/1aff11bb-498c-4c10-b012-a04c90c4cacf

---

## 🔧 Features

- 🧼 Clean CLI interface for packet capturing
- 🕵️ Displays:
  - Ethernet frame details
  - IP headers and TTL
  - TCP flags, sequence, and acknowledgment
  - UDP and ICMP information
  - Raw packet data using Python's `socket` hex view
- 📊 Summary statistics: protocol breakdown, top IP flows
- 🗂️ Optional saving of results to a timestamped text file

---

## ⚙️ Requirements

- Python 3.x
- [Scapy](https://scapy.net/)


pip install scapy

---

▶️ **How to Run**

python packet_analyzer.py


💾 Example Output (Partial)
Ethernet  00:0c:29:ab:cd:ef -> ff:ff:ff:ff:ff:ff  type 0x0800
IP        192.168.1.10 -> 192.168.1.1  ttl=64 proto=6
TCP       52344->80 seq=12345 ack=67890 flags=SYN,ACK
RAW       45 00 00 3c 1c 46 40 00 40 06 a6 ec c0 a8 01 0a ...
