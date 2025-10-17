#!/usr/bin/env python3
"""
network_vuln_scanner.py
=======================

This script orchestrates a simple network vulnerability scanner combining:

* **Nmap** for discovering open ports and service banners
* **Scapy** for validating open ports with raw packets
* Basic tests for common web vulnerabilities (SQL injection, XSS, buffer overflow)

The scanner is intended for educational and defensive purposes.  Do **not** scan
networks without the owner’s permission.  Use responsibly.
"""

import argparse
import datetime
import json
import os
import re
import socket
import sys
from typing import Dict, List, Optional

# Attempt to import optional dependencies.  If they are missing, the
# corresponding functionality will be disabled but the rest of the scanner can
# still operate.  This allows users to run the script even if they have not
# installed all packages yet.
try:
    import nmap  # type: ignore
except ImportError:
    nmap = None  # type: ignore

try:
    from scapy.all import IP, TCP, sr1  # type: ignore
except ImportError:
    IP = TCP = sr1 = None  # type: ignore

try:
    import requests  # type: ignore
    from requests.exceptions import RequestException
except ImportError:
    requests = None  # type: ignore
    RequestException = Exception  # type: ignore


# Payloads and patterns for vulnerability checks
SQL_PAYLOAD = "' OR '1'='1"
XSS_PAYLOAD = "<script>alert('XSS')</script>"
BUFFER_PAYLOAD = "A" * 2048  # 2KB payload to test for buffer overflows

SQL_ERROR_PATTERNS = [
    r"SQL syntax",
    r"mysql_fetch",
    r"ORA-",
    r"ODBC SQL",
    r"JDBC driver",
]
SQL_ERROR_REGEX = re.compile("|".join(SQL_ERROR_PATTERNS), re.IGNORECASE)
XSS_REFLECT_REGEX = re.compile(re.escape(XSS_PAYLOAD), re.IGNORECASE)


def run_nmap_scan(target: str, scan_type: str, ports: Optional[str] = None) -> Dict[int, Dict[str, str]]:
    """Run an Nmap scan on the target and return a dictionary of open ports.

    Args:
        target: Hostname or IP to scan.
        scan_type: One of 'fast', 'comprehensive' or 'custom'.  Determines
            which ports are scanned.
        ports: Comma‑separated port string for custom scans.

    Returns:
        Dictionary mapping port numbers to service information (name and
        product/version strings).
    """
    if nmap is None:
        print("[!] python-nmap is not installed; skipping port scan.")
        return {}

    scanner = nmap.PortScanner()
    args = ""
    if scan_type == "fast":
        # Top 100 common ports
        args = "-sS --top-ports 100 -Pn"
    elif scan_type == "comprehensive":
        # Full TCP scan with service version detection
        args = "-sS -sV -sC -O -Pn"
    elif scan_type == "custom" and ports:
        args = f"-sS -p {ports} -sV -Pn"
    else:
        args = "-sS --top-ports 100 -Pn"

    try:
        scanner.scan(hosts=target, arguments=args)
    except Exception as e:
        print(f"[!] Nmap scan failed: {e}")
        return {}

    results: Dict[int, Dict[str, str]] = {}
    for host in scanner.all_hosts():
        for proto in scanner[host].all_protocols():
            ports_list = scanner[host][proto].keys()
            for port in ports_list:
                state = scanner[host][proto][port]["state"]
                if state != "open":
                    continue
                service = scanner[host][proto][port].get("name", "unknown")
                product = scanner[host][proto][port].get("product", "")
                version = scanner[host][proto][port].get("version", "")
                results[port] = {
                    "service": service,
                    "product": f"{product} {version}".strip(),
                }
    return results


def validate_ports_with_scapy(target: str, ports: List[int]) -> Dict[int, bool]:
    """Validate open ports using Scapy by sending a SYN packet and
    confirming a SYN/ACK response.

    Args:
        target: Hostname or IP.
        ports: List of port numbers to validate.

    Returns:
        Dictionary mapping each port to True if a SYN/ACK was received,
        otherwise False.
    """
    responses: Dict[int, bool] = {}
    if IP is None or TCP is None or sr1 is None:
        print("[!] Scapy is not installed; skipping port validation.")
        for p in ports:
            responses[p] = False
        return responses

    for port in ports:
        pkt = IP(dst=target) / TCP(dport=port, flags="S")
        try:
            ans = sr1(pkt, timeout=2, verbose=False)
            if ans and ans.haslayer(TCP) and ans.getlayer(TCP).flags & 0x12:  # SYN/ACK
                responses[port] = True
            else:
                responses[port] = False
        except Exception:
            responses[port] = False
    return responses


def check_sql_injection(url: str) -> bool:
    """Send a simple SQL injection payload and check for database error patterns.

    Returns True if a possible SQL error is detected, otherwise False.
    """
    if requests is None:
        print("[!] requests library is not installed; skipping SQL injection check.")
        return False

    try:
        # Append query parameter with injection payload
        separator = '&' if '?' in url else '?'
        test_url = f"{url}{separator}test={SQL_PAYLOAD}"
        resp = requests.get(test_url, timeout=5)
        body = resp.text
    except RequestException:
        return False
    # Search for common SQL error patterns
    return bool(SQL_ERROR_REGEX.search(body))


def check_xss(url: str) -> bool:
    """Send an XSS payload and determine if it is reflected in the response.

    Returns True if the payload is reflected, otherwise False.
    """
    if requests is None:
        print("[!] requests library is not installed; skipping XSS check.")
        return False

    try:
        separator = '&' if '?' in url else '?'
        test_url = f"{url}{separator}xss={XSS_PAYLOAD}"
        resp = requests.get(test_url, timeout=5)
        body = resp.text
    except RequestException:
        return False
    return bool(XSS_REFLECT_REGEX.search(body))


def check_buffer_overflow(host: str, port: int) -> bool:
    """Send a long payload to test for potential buffer overflows.

    Returns True if the connection resets unexpectedly (possible overflow),
    otherwise False.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, port))
        # Attempt to send buffer payload
        sock.sendall(BUFFER_PAYLOAD.encode())
        # Try receiving a response
        _ = sock.recv(1024)
        sock.close()
        return False
    except (socket.timeout, socket.error):
        # If the connection times out or resets, we treat it as a potential overflow
        return True


def perform_vulnerability_checks(host: str, open_ports: Dict[int, Dict[str, str]]) -> List[Dict[str, str]]:
    """Iterate over services and perform simple vulnerability checks.

    Only HTTP/HTTPS services are tested for SQLi and XSS.  Buffer overflow
    checks are performed on all open ports.

    Returns:
        List of dictionaries describing any findings.
    """
    findings = []
    for port, info in open_ports.items():
        service = info.get("service", "")
        host_url = None
        if service in {"http", "https"}:
            scheme = "https" if port == 443 or service == "https" else "http"
            host_url = f"{scheme}://{host}:{port}"

        # SQL Injection check
        if host_url:
            try:
                if check_sql_injection(host_url):
                    findings.append({
                        "port": port,
                        "type": "sql_injection",
                        "description": "Potential SQL injection vulnerability detected.",
                        "target": host_url,
                    })
            except Exception:
                pass

        # XSS check
        if host_url:
            try:
                if check_xss(host_url):
                    findings.append({
                        "port": port,
                        "type": "xss",
                        "description": "Reflected XSS detected.",
                        "target": host_url,
                    })
            except Exception:
                pass

        # Buffer overflow check
        try:
            if check_buffer_overflow(host, port):
                findings.append({
                    "port": port,
                    "type": "buffer_overflow",
                    "description": "Service may be susceptible to buffer overflow.",
                    "target": f"{host}:{port}",
                })
        except Exception:
            pass
    return findings


def generate_report(host: str, open_ports: Dict[int, Dict[str, str]], findings: List[Dict[str, str]], fmt: str) -> str:
    """Generate a report string in the specified format (text or json)."""
    timestamp = datetime.datetime.now().isoformat(timespec="seconds")
    report = {
        "host": host,
        "scanned_at": timestamp,
        "open_ports": [
            {"port": p, **info} for p, info in sorted(open_ports.items(), key=lambda x: x[0])
        ],
        "findings": findings,
    }
    if fmt == "json":
        return json.dumps(report, indent=2)
    # default to text format
    lines = [f"Scan report for {host} (generated {timestamp})\n"]
    lines.append("Open ports:")
    if open_ports:
        for port, info in sorted(open_ports.items(), key=lambda x: x[0]):
            service = info.get("service", "")
            product = info.get("product", "")
            lines.append(f"  {port}/tcp: {service} {product}".rstrip())
    else:
        lines.append("  None detected")
    lines.append("")
    if findings:
        lines.append("Potential vulnerabilities:")
        for f in findings:
            lines.append(f"  - Port {f['port']}: {f['type']} — {f['description']} (target: {f['target']})")
    else:
        lines.append("No vulnerabilities detected.")
    return "\n".join(lines)


def save_report(report_str: str, host: str, fmt: str) -> str:
    """Save the report to the reports directory and return the file path."""
    os.makedirs("reports", exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y-%m-%dT%H-%M-%S")
    filename = f"{host}_{timestamp}.{ 'json' if fmt == 'json' else 'txt' }"
    path = os.path.join("reports", filename)
    with open(path, "w", encoding="utf-8") as f:
        f.write(report_str)
    return path


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Simple network vulnerability scanner")
    parser.add_argument("--target", required=True, help="Target IP or hostname to scan")
    parser.add_argument("--scan-type", choices=["fast", "comprehensive", "custom"], default="fast", help="Type of scan to perform")
    parser.add_argument("--ports", help="Comma-separated list of ports for custom scans")
    parser.add_argument("--skip-vuln-checks", action="store_true", help="Skip vulnerability checks and only perform port scanning")
    parser.add_argument("--report", choices=["text", "json"], default="text", help="Report format")
    return parser.parse_args()


def main() -> None:
    args = parse_arguments()
    host = args.target
    print(f"Starting scan of {host} (type: {args.scan_type})...")
    # Run Nmap scan
    open_ports = run_nmap_scan(host, args.scan_type, args.ports)
    if not open_ports:
        print("No open ports detected or scan failed.")
    else:
        print("Open ports detected:")
        for port, info in sorted(open_ports.items(), key=lambda x: x[0]):
            service = info.get("service", "")
            product = info.get("product", "")
            print(f"  {port}/tcp: {service} {product}".rstrip())

    # Validate ports with scapy
    validation_results = validate_ports_with_scapy(host, list(open_ports.keys()))
    for port, valid in validation_results.items():
        if not valid:
            print(f"  [!] Port {port} did not respond to TCP SYN validation.")

    # Vulnerability checks
    findings: List[Dict[str, str]] = []
    if not args.skip_vuln_checks and open_ports:
        print("Performing vulnerability checks...")
        findings = perform_vulnerability_checks(host, open_ports)
        if findings:
            for f in findings:
                print(f"  [!] {f['type']} on port {f['port']}: {f['description']}")
        else:
            print("  No vulnerabilities detected.")

    # Generate and save report
    report_str = generate_report(host, open_ports, findings, args.report)
    report_path = save_report(report_str, host, args.report)
    print(f"Scan complete. Report saved to {report_path}")


if __name__ == "__main__":
    main()