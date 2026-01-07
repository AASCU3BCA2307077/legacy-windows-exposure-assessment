import socket
import argparse
import threading
import json
import csv
import time
import ipaddress
from datetime import datetime

# =====================================================
# Threat Intelligence Database
# =====================================================

SERVICE_DB = {
    445: {
        "service": "SMB",
        "risk": "MS17-010 (EternalBlue)",
        "severity": "CRITICAL",
        "attack_chain": "SMB → Kernel RCE → SYSTEM"
    },
    139: {
        "service": "NetBIOS",
        "risk": "Enumeration / Information Disclosure",
        "severity": "MEDIUM",
        "attack_chain": "NetBIOS → User / Share Enumeration"
    },
    3389: {
        "service": "RDP",
        "risk": "BlueKeep / Credential Attacks",
        "severity": "HIGH",
        "attack_chain": "RDP → Authentication Abuse / RCE"
    }
}

SEVERITY_WEIGHT = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 2,
    "LOW": 1
}

# =====================================================
# Exposure Scanner Class
# =====================================================

class ExposureScanner:
    """
    Performs non-intrusive exposure checks for legacy services.
    No exploitation or payload execution is performed.
    """

    def __init__(self, target):
        self.target = target
        self.findings = []
        self.score = 0
        self.lock = threading.Lock()

    def rate_limit(self):
        time.sleep(0.25)

    def banner_probe(self, port):
        """
        Safe banner grab (best-effort).
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((self.target, port))
            sock.send(b"\r\n")
            data = sock.recv(128)
            sock.close()
            return data.decode(errors="ignore").strip()
        except Exception:
            return "No banner information"

    def scan_port(self, port, meta):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)

            try:
                result = sock.connect_ex((self.target, port))
            except socket.gaierror:
                sock.close()
                return

            sock.close()

            if result == 0:
                banner = self.banner_probe(port)

                finding = {
                    "IP": self.target,
                    "Port": port,
                    "Service": meta["service"],
                    "Risk": meta["risk"],
                    "Severity": meta["severity"],
                    "Attack Chain": meta["attack_chain"],
                    "Evidence": f"Port reachable; Banner='{banner}'",
                    "Score": SEVERITY_WEIGHT.get(meta["severity"], 0)
                }

                with self.lock:
                    self.findings.append(finding)
                    self.score += finding["Score"]

        finally:
            self.rate_limit()

    def run(self):
        threads = []

        for port, meta in SERVICE_DB.items():
            t = threading.Thread(target=self.scan_port, args=(port, meta))
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

# =====================================================
# Reporting Functions
# =====================================================

def export_csv(scanner):
    filename = f"assessment_{scanner.target}.csv"
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=scanner.findings[0].keys())
        writer.writeheader()
        writer.writerows(scanner.findings)
    return filename

def export_json(scanner):
    filename = f"assessment_{scanner.target}.json"
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(scanner.findings, f, indent=4)
    return filename


def export_html(scanner):
    filename = f"assessment_{scanner.target}.html"
    with open(filename, "w", encoding="utf-8") as f:
        f.write("<html><head><title>Exposure Assessment Report</title></head><body>")
        f.write("<h1>Legacy System Exposure Assessment</h1>")
        f.write(f"<p><b>Target:</b> {scanner.target}</p>")
        f.write(f"<p><b>Timestamp:</b> {datetime.now()}</p>")
        f.write("<hr>")

        if not scanner.findings:
            f.write("<p>No exposed legacy services detected.</p>")
        else:
            for item in scanner.findings:
                f.write("<h3>Detected Exposure</h3><ul>")
                for k, v in item.items():
                    f.write(f"<li><b>{k}:</b> {v}</li>")
                f.write("</ul>")

        f.write("<hr>")
        f.write(f"<h2>Total Risk Score: {scanner.score}</h2>")
        f.write("<p><b>Assessment Type:</b> Exposure-Based</p>")
        f.write("<p><b>Limitations:</b> No exploitation or patch validation performed</p>")
        f.write("</body></html>")
    return filename

# =====================================================
# Main Execution
# =====================================================

def main():
    parser = argparse.ArgumentParser(
        description="Legacy System Exposure Assessment Tool"
    )
    parser.add_argument("target", help="Target IP address")
    args = parser.parse_args()

    # -------- INPUT VALIDATION --------
    try:
        ipaddress.ip_address(args.target)
    except ValueError:
        print(f"[!] Invalid IP address provided: {args.target}")
        print("[!] Please provide a valid IPv4 address.")
        return
    # --------------------------------

    print("\n[+] Starting Exposure Assessment")
    print(f"[+] Target: {args.target}")
    print("-" * 60)

    scanner = ExposureScanner(args.target)
    scanner.run()

    if not scanner.findings:
        print("[+] No exposed legacy services detected.")
    else:
        for f in scanner.findings:
            print(f"[!] {f['Service']} on port {f['Port']} ({f['Severity']})")
            print(f"    Risk: {f['Risk']}")
            print(f"    Evidence: {f['Evidence']}")
            print(f"    Attack Chain: {f['Attack Chain']}\n")

    html = export_html(scanner)
    csv_file = export_csv(scanner) if scanner.findings else None
    json_file = export_json(scanner) if scanner.findings else None

    print("-" * 60)
    print(f"[+] Overall Risk Score: {scanner.score}")
    print(f"[+] HTML Report: {html}")

    if csv_file:
        print(f"[+] CSV Report: {csv_file}")
    if json_file:
        print(f"[+] JSON Report: {json_file}")

    print("\n[DISCLAIMER] Non-intrusive exposure assessment only.\n")

if __name__ == "__main__":
    main()
