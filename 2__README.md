# Snort 3 - Intrusion Detection System on Kali Linux

## Overview

This project demonstrates the setup and execution of **Snort 3 (Snort++)** on Kali Linux with custom rules for detecting simple ICMP and HTTP traffic.

---

## VIDEO

https://github.com/user-attachments/assets/45efc90d-8ee0-4e50-8593-161e5745138f

---

## 🔧 Prerequisites

- Kali Linux (tested on latest version)
- Snort 3 (version 3.8.1.0)
- Root or sudo access
- Internet connection (for rule testing like ping and HTTP traffic)

---

## 📁 Directory Structure

/opt/snort3/etc/snort/
├── snort.lua # Main Snort configuration file (Lua format)
├── custom.rules # Custom rule set written by user
└── ... # Other config/rule files

---

## 🔒 Custom Rules

File: `/opt/snort3/etc/snort/custom.rules`

1.  alert icmp any any -> any any (msg:"ICMP test ping detected"; sid:1000001; rev:1;)
2.  alert tcp any any -> any 80 (msg:"HTTP test alert on port 80"; sid:1000002; rev:1;)

---

## ✅ Configuration Check
Before running Snort, check if configuration is valid:

snort -v

Output should end with:
Snort successfully validated the configuration (with 0 warnings).
Snort exiting

---

## 🚀 Running Snort
Run Snort in passive mode with custom rules:

sudo snort \
  -c /opt/snort3/etc/snort/snort.lua \
  -R /opt/snort3/etc/snort/custom.rules \
  -i eth0 -A alert_fast

-c specifies the main configuration file.

-R loads custom rules.

-i is the interface (change eth0 to match your active NIC).

-A alert_fast specifies output format.

---

## 🧪 Testing Detection
ICMP Test:
On another terminal, run:

ping google.com
or ping any site from Kali to generate ICMP traffic.

HTTP Test:
From browser or terminal:

curl http://example.com
Snort will print alerts like:

[**] [1:1000001:1] "ICMP test ping detected" [**] {ICMP} ...
[**] [1:1000002:1] "HTTP test alert on port 80" [**] {TCP} ...

---

📦 Useful Snort Directories

Rules: /opt/snort3/etc/snort/

Binaries: /usr/local/bin/

Logs (if enabled): /var/log/snort/

