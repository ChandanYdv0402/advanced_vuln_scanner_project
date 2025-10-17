# Network Security Vulnerability Scanner

## Overview

This repository contains a **network security vulnerability scanner** built from scratch in Python.  It aims to demonstrate how you can combine **Nmap**, **Scapy**, and basic socket programming to perform port scanning, identify open services, and perform simple checks for common web‑application vulnerabilities on local or remote systems.  It is designed for educational and defensive purposes only; **always obtain explicit permission before scanning any system**.

### Key Features

The scanner provides a unified command‑line interface that orchestrates several scanning techniques:

1. **Port Scanning (Nmap)** — Uses the [python‑nmap](https://pypi.org/project/python‑nmap/) wrapper to run Nmap scans and identify open TCP/UDP ports and service banners.  This gives a high‑level view of the attack surface on a host or network range.
2. **Custom Packet Crafting (Scapy)** — Leverages [Scapy](https://scapy.net/) to build and send raw TCP SYN packets or HTTP requests to specific ports.  This allows you to validate Nmap results, send custom payloads (e.g. unusual flags), and observe low‑level responses.
3. **Vulnerability Checks** — Implements simple, non‑intrusive checks for common web vulnerabilities:
   - **SQL injection**: sends a benign injection string like `' OR '1'='1` to HTTP parameters and looks for database error patterns in the response.
   - **Cross‑Site Scripting (XSS)**: submits a harmless script payload and checks whether it is reflected unescaped.
   - **Buffer Overflow**: sends an overly long string to services that echo input (e.g. HTTP forms) and monitors for connection resets.
4. **Report Generation** — Outputs findings to a human‑readable report (plain text or JSON) summarising open ports, services, and any potential issues identified.  Each vulnerability check logs the target, payload sent, and response analysis.

### Installation

Clone this repository and install the required dependencies in a virtual environment:

```bash
git clone https://github.com/your‑username/advanced_vuln_scanner_project.git
cd advanced_vuln_scanner_project
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

> **Note**: Running Nmap and Scapy may require root or administrator privileges on your system.  Ensure you have the necessary permissions.

### Usage

Run the scanner from the command line with a target hostname or IP address:

```bash
python network_vuln_scanner.py --target 192.168.1.10 --scan-type comprehensive --report json
```

**Options:**

| Flag | Description | Default |
|------|-------------|---------|
| `--target` | Target IP or hostname to scan.  Required. | N/A |
| `--scan-type` | Type of scan to perform: `fast` (top ports), `comprehensive` (all ports), or `custom` (specify ports via `--ports`). | `fast` |
| `--ports` | Comma‑separated list of ports (only used with `custom` scan type). | None |
| `--skip-vuln-checks` | If provided, skip vulnerability checks and only report open ports/services. | False |
| `--report` | Report format: `text` or `json`.  Determines how results are printed and saved. | `text` |

The scanner will:

1. Run an Nmap scan based on the scan type and collect a list of open ports and service banners.
2. Use Scapy to validate the open ports by sending raw packets and capturing responses.
3. (Unless `--skip-vuln-checks` is set) send benign test payloads to HTTP services to probe for SQL injection, XSS, and buffer overflow vulnerabilities.
4. Save the findings to a timestamped report file in the chosen format in the `reports/` directory.

### Example

To scan a web server at `example.com` for open ports and run basic vulnerability checks:

```bash
python network_vuln_scanner.py --target example.com --scan-type fast --report text
```

You will receive output similar to:

```
Starting scan of example.com...
Open ports:
  80/tcp: http, Apache 2.4.54
  443/tcp: https, nginx 1.23
Running vulnerability checks...
  [SQL Injection] Tested URL http://example.com/?test=' OR '1'='1 — no SQL errors detected.
  [XSS] Tested payload reflected? No.
  [Buffer Overflow] Service stable.
Scan complete.  Report saved to reports/example.com_2025-10-17T14-35-00.txt
```

### Ethical Use

This project is provided for **educational** purposes and should be used responsibly.  Scanning networks or systems without permission may violate laws and terms of service.  Always obtain explicit consent from the system owner before running any scans.  The included vulnerability checks are intentionally minimal and benign; they do not exploit vulnerabilities but merely detect potential weaknesses.

### Contributing

Contributions are welcome!  If you have ideas for additional modules (e.g. directory enumeration, SSL/TLS security checks, or expanded vulnerability signatures), feel free to open an issue or submit a pull request.

### License

This project is licensed under the MIT License.  See the [LICENSE](LICENSE) file for details.