#!/usr/bin/env python3
"""
recon.py — Integrated multi-stage reconnaissance tool.
Part 4 of the SPTI Automation Lab.

Usage:
    python3 recon.py <target> [--mode domain|ip] [--output DIR] [--verbose]
"""

import argparse
import datetime
import ipaddress
import json
import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ET




def now_iso() -> str:
    return datetime.datetime.now().isoformat(timespec="seconds")


def detect_mode(target: str) -> str:
    """Return 'ip' if target looks like an IPv4/IPv6 address, else 'domain'."""
    try:
        ipaddress.ip_address(target)
        return "ip"
    except ValueError:
        return "domain"


def make_output_dir(target: str, base: str | None) -> str:
    if base:
        path = base
    else:
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        safe = re.sub(r"[^\w\-.]", "_", target)
        path = f"./recon_{safe}_{ts}"
    os.makedirs(path, exist_ok=True)
    return path




class AuditLog:
    def __init__(self, path: str):
        self.path = path
        with open(self.path, "w") as f:
            f.write(f"# Audit log — recon.py\n# Started: {now_iso()}\n\n")

    def log(self, action: str, status: str, detail: str = ""):
        entry = f"[{now_iso()}] [{status}] {action}"
        if detail:
            entry += f"\n  → {detail}"
        entry += "\n"
        with open(self.path, "a") as f:
            f.write(entry)


#

def run_cmd(
    cmd: list[str],
    audit: AuditLog,
    timeout: int = 30,
    verbose: bool = False,
) -> tuple[bool, str, str]:
    """
    Run a command and return (success, stdout, stderr).
    Always logs to audit regardless of outcome.
    """
    cmd_str = " ".join(cmd)
    if verbose:
        print(f"  [~] {cmd_str}", file=sys.stderr)
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        success = result.returncode == 0
        status = "OK" if success else f"RETURNCODE={result.returncode}"
        audit.log(cmd_str, status, result.stderr.strip()[:200] if result.stderr else "")
        return success, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        audit.log(cmd_str, "TIMEOUT", f"Exceeded {timeout}s")
        return False, "", "timeout"
    except FileNotFoundError as e:
        audit.log(cmd_str, "NOT_FOUND", str(e))
        return False, "", str(e)
    except Exception as e:
        audit.log(cmd_str, "ERROR", str(e))
        return False, "", str(e)




def step_whois_domain(target: str, audit: AuditLog, verbose: bool) -> dict:
    ok, out, _ = run_cmd(["whois", target], audit, timeout=20, verbose=verbose)
    result: dict = {"raw_available": ok}
    if not ok:
        return result

    fields = {
        "registrar": r"(?i)registrar:\s*(.+)",
        "creation_date": r"(?i)creation date:\s*(.+)",
        "expiry_date": r"(?i)(?:registry expiry date|expir\w+ date):\s*(.+)",
        "registrant_org": r"(?i)registrant organization:\s*(.+)",
    }
    for key, pattern in fields.items():
        m = re.search(pattern, out)
        result[key] = m.group(1).strip() if m else None
    return result


def step_dig(target: str, audit: AuditLog, verbose: bool) -> dict:
    records: dict = {}
    for rtype in ("A", "MX", "NS", "TXT"):
        ok, out, _ = run_cmd(
            ["dig", "+noall", "+answer", target, rtype],
            audit, timeout=10, verbose=verbose,
        )
        entries = []
        if ok:
            for line in out.splitlines():
                line = line.strip()
                if line and not line.startswith(";"):
                    entries.append(line)
        records[rtype] = entries
    return records


def step_curl_headers(target: str, audit: AuditLog, verbose: bool) -> dict:
    ok, out, _ = run_cmd(
        ["curl", "-I", "-s", "--max-time", "10", f"http://{target}"],
        audit, timeout=15, verbose=verbose,
    )
    result: dict = {"raw_available": ok}
    if not ok:
        return result

    interesting = [
        "server", "x-powered-by", "content-security-policy",
        "strict-transport-security", "x-frame-options",
        "x-content-type-options",
    ]
    for line in out.splitlines():
        if ":" in line:
            key, _, val = line.partition(":")
            k = key.strip().lower()
            if k in interesting:
                result[k] = val.strip()
    return result




def step_nmap(target: str, out_dir: str, audit: AuditLog, verbose: bool) -> dict:
    xml_path = os.path.join(out_dir, "nmap_scan.xml")
    ok, _, _ = run_cmd(
        ["nmap", "-sV", "--open", "--top-ports", "100", "-oX", xml_path, target],
        audit, timeout=120, verbose=verbose,
    )
    if not ok and not os.path.exists(xml_path):
        return {"error": "nmap failed or not installed", "hosts": []}

    return {"xml_path": xml_path, "hosts": _parse_nmap_xml(xml_path)}


def _parse_nmap_xml(xml_path: str) -> list[dict]:
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except Exception:
        return []

    hosts = []
    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue

        addr_el = host.find("address[@addrtype='ipv4']")
        if addr_el is None:
            continue
        ip = addr_el.get("addr")

        hostname_el = host.find("hostnames/hostname")
        hostname = hostname_el.get("name") if hostname_el is not None else None

        open_ports = []
        for port in host.findall(".//port"):
            state_el = port.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            svc = port.find("service")
            open_ports.append({
                "port": int(port.get("portid")),
                "service": svc.get("name") if svc is not None else None,
                "version": svc.get("version") if svc is not None else None,
            })

        hosts.append({"ip": ip, "hostname": hostname, "open_ports": open_ports})
    return hosts


def step_reverse_dns(target: str, audit: AuditLog, verbose: bool) -> dict:
    ok, out, _ = run_cmd(
        ["dig", "-x", target, "+short"],
        audit, timeout=10, verbose=verbose,
    )
    hostnames = [l.strip() for l in out.splitlines() if l.strip()] if ok else []
    return {"hostnames": hostnames}


def step_whois_ip(target: str, audit: AuditLog, verbose: bool) -> dict:
    ok, out, _ = run_cmd(["whois", target], audit, timeout=20, verbose=verbose)
    result: dict = {"raw_available": ok}
    if not ok:
        return result

    fields = {
        "organization": r"(?i)(?:org-name|organization|orgname):\s*(.+)",
        "country": r"(?i)country:\s*(.+)",
        "netrange": r"(?i)(?:netrange|inetnum):\s*(.+)",
    }
    for key, pattern in fields.items():
        m = re.search(pattern, out)
        result[key] = m.group(1).strip() if m else None
    return result



SECURITY_HEADERS = [
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
]


def missing_headers(headers: dict) -> list[str]:
    return [h for h in SECURITY_HEADERS if h not in headers]


def generate_report(results: dict, mode: str, target: str) -> str:
    lines = []
    ts = results.get("timestamp", "")

    lines += [
        f"# Recon Report: `{target}`",
        f"",
        f"**Mode:** {mode}  ",
        f"**Timestamp:** {ts}  ",
        f"",
        "---",
        "",
    ]

    
    lines += ["## Summary", "", "| Tool | Status |", "| ---- | ------ |"]
    for tool, data in results.get("findings", {}).items():
        status = "✅ OK" if data and "error" not in data else "⚠️  Error / No data"
        lines.append(f"| {tool} | {status} |")
    lines.append("")

    findings = results.get("findings", {})

    if mode == "domain":
        
        w = findings.get("whois", {})
        lines += ["## WHOIS", "", "| Field | Value |", "| ----- | ----- |"]
        for k in ("registrar", "creation_date", "expiry_date", "registrant_org"):
            lines.append(f"| {k} | {w.get(k) or '—'} |")
        lines.append("")

       
        dns = findings.get("dns", {})
        lines += ["## DNS Records", ""]
        for rtype in ("A", "MX", "NS", "TXT"):
            entries = dns.get(rtype, [])
            lines.append(f"### {rtype}")
            if entries:
                for e in entries:
                    lines.append(f"- `{e}`")
            else:
                lines.append("_No records found_")
            lines.append("")

    
        headers = findings.get("http_headers", {})
        lines += ["## HTTP Headers", "", "| Header | Value |", "| ------ | ----- |"]
        for k, v in headers.items():
            if k != "raw_available":
                lines.append(f"| {k} | {v} |")
        lines.append("")

    
        missing = missing_headers(headers)
        lines += ["## ⚠️  Missing Security Headers", ""]
        if missing:
            for h in missing:
                lines.append(f"- `{h}`")
        else:
            lines.append("_All checked security headers are present._")
        lines.append("")

    else:  # IP mode
        
        nmap = findings.get("nmap", {})
        hosts = nmap.get("hosts", [])
        lines += ["## Open Ports (nmap)", ""]
        if hosts:
            for h in hosts:
                lines.append(f"### {h['ip']} ({h.get('hostname') or 'no rDNS'})")
                if h["open_ports"]:
                    lines.append("| Port | Service | Version |")
                    lines.append("| ---- | ------- | ------- |")
                    for p in h["open_ports"]:
                        lines.append(
                            f"| {p['port']} | {p.get('service') or '—'} | {p.get('version') or '—'} |"
                        )
                else:
                    lines.append("_No open ports found_")
                lines.append("")
        else:
            lines.append("_No hosts found or nmap failed_")
            lines.append("")

        
        rdns = findings.get("reverse_dns", {})
        lines += ["## Reverse DNS", ""]
        for h in rdns.get("hostnames", []):
            lines.append(f"- `{h}`")
        if not rdns.get("hostnames"):
            lines.append("_No PTR records found_")
        lines.append("")

        # WHOIS IP
        w = findings.get("whois", {})
        lines += ["## WHOIS (IP)", "", "| Field | Value |", "| ----- | ----- |"]
        for k in ("organization", "country", "netrange"):
            lines.append(f"| {k} | {w.get(k) or '—'} |")
        lines.append("")

    lines += ["---", f"_Generated by recon.py at {ts}_"]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="recon.py — multi-stage reconnaissance tool",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("target", help="Domain name or IP address to recon")
    parser.add_argument(
        "--mode", choices=["domain", "ip"],
        help="Scan mode (auto-detected if omitted)",
    )
    parser.add_argument(
        "--output", metavar="DIR",
        help="Output directory (default: ./recon_<target>_<timestamp>/)",
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Print progress to stderr",
    )
    args = parser.parse_args()

    target = args.target
    mode = args.mode or detect_mode(target)
    out_dir = make_output_dir(target, args.output)
    verbose = args.verbose

    audit = AuditLog(os.path.join(out_dir, "audit.log"))
    audit.log(f"recon.py started: target={target} mode={mode}", "START")

    def vprint(msg: str):
        if verbose:
            print(f"[*] {msg}", file=sys.stderr)

    vprint(f"Target: {target}")
    vprint(f"Mode:   {mode}")
    vprint(f"Output: {out_dir}")

    findings: dict = {}

    if mode == "domain":
        vprint("Running whois...")
        findings["whois"] = step_whois_domain(target, audit, verbose)

        vprint("Running dig (A, MX, NS, TXT)...")
        findings["dns"] = step_dig(target, audit, verbose)

        vprint("Running curl -I (HTTP headers)...")
        findings["http_headers"] = step_curl_headers(target, audit, verbose)

    else:  # ip
        vprint("Running nmap (top 100 ports, service detection)...")
        findings["nmap"] = step_nmap(target, out_dir, audit, verbose)

        vprint("Running reverse DNS lookup...")
        findings["reverse_dns"] = step_reverse_dns(target, audit, verbose)

        vprint("Running whois (IP)...")
        findings["whois"] = step_whois_ip(target, audit, verbose)

    # Build results.json
    results = {
        "target": target,
        "mode": mode,
        "timestamp": now_iso(),
        "findings": findings,
    }

    results_path = os.path.join(out_dir, "results.json")
    with open(results_path, "w") as f:
        json.dump(results, f, indent=2)
    audit.log(f"results.json written to {results_path}", "OK")
    vprint(f"results.json → {results_path}")

    # Generate report.md
    report_md = generate_report(results, mode, target)
    report_path = os.path.join(out_dir, "report.md")
    with open(report_path, "w") as f:
        f.write(report_md)
    audit.log(f"report.md written to {report_path}", "OK")
    vprint(f"report.md    → {report_path}")

    audit.log("recon.py finished", "DONE")
    print(f"\n[+] Done. Output in: {out_dir}")
    print(f"    results.json  → {results_path}")
    print(f"    report.md     → {report_path}")
    print(f"    audit.log     → {os.path.join(out_dir, 'audit.log')}")


if __name__ == "__main__":
    main()