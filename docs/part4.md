# Integrated reconnaissance tool
Build `recon.py` — a single-file command-line tool that performs multi-stage reconnaissance on a domain or IP address and produces a structured report.

**Requirements:**

1. CLI interface via `argparse`:

    - `target:` domain name or IP address (required)
    - `--mode:` `domain` or `ip`, auto-detected if omitted
    - `--output:` directory for output files (default: `./recon_<target>_<timestamp>/`)
    - `--verbose:` print progress to stderr as the tool runs

2. Audit log — every action the tool takes must be logged to `audit.log` inside the output directory with a timestamp. This includes: what command was run, what it returned (success/error), and the timestamp. This is non-negotiable.

3. Domain mode — when `target` is a domain name:

    - `whois:` extract registrar, registration date, expiry date, registrant organization
    - `dig:` query and save A, MX, NS, and TXT records
    - `curl -I:` extract HTTP response headers (server, X-Powered-By, Content-Security-Policy, Strict-Transport-Security)
    - Each step runs independently; a failure in one must not stop the others

4. IP mode — when `target` is an IP address:

    - `nmap -sV --open -oX:` scan common ports (use the `--top-ports 100` flag to keep it fast), parse the XML output as in Part 2
    - Reverse DNS lookup via `dig -x`
    - `whois` on the IP to extract the owning organization and country

5. Structured output — write `results.json` with all findings in a single dict keyed by tool name.

6. Markdown report — generate `report.md` from `results.json`. The report must include: a summary table of findings, open ports (if IP mode), DNS records (if domain mode), and any notable security headers that are missing (CSP, HSTS, X-Frame-Options).


Question

Your tool performs active reconnaissance: it sends packets to the target. Shodan performs passive reconnaissance: it has already scanned the internet, and you query its database without touching the target at all. From the perspective of an attacker, what are the operational differences between these two approaches? From the perspective of a defender with network monitoring in place, which approach is harder to detect, and why? In what scenarios would each be more appropriate?


Passive reconnaissance with Shodan is virtually undetectable by the defender. Shodan already scanned the target hours or days ago; when the attacker queries its database, the traffic flows from their machine to Shodan's servers — never to the target. No IDS, firewall, or SIEM on the target's network will see that query. The defender has zero visibility into who is researching their infrastructure on Shodan.
Active reconnaissance leaves clear traces: SYN packets across multiple ports within seconds, DNS queries from unknown external IPs, HTTP requests appearing in access logs. An IDS with port-scanning signatures detects this in real time. A SOC with geo-anomaly alerts will flag an unknown IP running whois and curl against their servers.

In practice, the correct sequence is passive first, active only when necessary: Shodan and OSINT to collect as much as possible without touching the target, and active reconnaissance only to validate specific information that Shodan doesn't have or that may be outdated. Active reconnaissance is unavoidable when you need to confirm the current state of a port or service in real time, but it should be performed with the smallest possible footprint — low concurrency, long timeouts, legitimate User-Agent strings — and always with documented authorization in a legal penetration testing context.