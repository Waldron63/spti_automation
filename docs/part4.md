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