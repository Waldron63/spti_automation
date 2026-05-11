import re
import math
from collections import Counter, defaultdict

# Regex patterns (extended)
ATTACK_PATTERNS = {
    "SQL Injection": re.compile(
        r"(union\s+select|select\s+.*from|or\s+1=1|"
        r"drop\s+table|insert\s+into|--|'|\bexec\b)",
        re.IGNORECASE
    ),

    "Path Traversal": re.compile(
        r"(\.\./|\.\.\\|/etc/passwd|boot\.ini|"
        r"windows/system32|%2e%2e%2f)",
        re.IGNORECASE
    ),

    "XSS": re.compile(
        r"(<script>|</script>|alert\s*\(|"
        r"javascript:|onerror=|onload=)",
        re.IGNORECASE
    ),

    "Command Injection": re.compile(
        r"(cmd=|;|\||&&|\b(cat|whoami|id|ls|pwd|wget|curl)\b)",
        re.IGNORECASE
    )
}

# Log line parser
log_pattern = re.compile(
    r'(\d+\.\d+\.\d+\.\d+) .* '
    r'\[(.*?)\] '
    r'"GET (.*?) HTTP/1\.1" '
    r'(\d{3})'
)

# Counters
ip_counter = Counter()
status_counter = Counter()
hourly_requests = defaultdict(int)
attack_matches = []

# Read log file
with open("./sample_output/access.log", "r") as file:
    for line in file:
        match = log_pattern.search(line)

        if not match:
            continue

        ip, timestamp, path, status = match.groups()

        # Count IP requests
        ip_counter[ip] += 1

        # Count status codes
        status_counter[status] += 1

        # Hour extraction
        # Example: 09/May/2026:03:12:45 +0000
        hour = int(timestamp.split(":")[1])
        hourly_requests[hour] += 1

        # Detect attacks
        for attack_type, pattern in ATTACK_PATTERNS.items():
            if pattern.search(path):
                attack_matches.append({
                    "type": attack_type,
                    "ip": ip,
                    "path": path,
                    "status": status
                })
                break


# C. Suspicious requests
print("SUSPICIOUS REQUESTS")

for attack in attack_matches:
    print(
        f"[{attack['type']}] "
        f"IP={attack['ip']} "
        f"STATUS={attack['status']} "
        f"PATH={attack['path']}"
    )

# Top 5 IPs
print("")
print("TOP 5 IPs BY REQUEST VOLUME")

for ip, count in ip_counter.most_common(5):
    print(f"{ip}: {count} requests")

# HTTP Status distribution
print("")
print("HTTP STATUS CODE DISTRIBUTION")

for status, count in sorted(status_counter.items()):
    print(f"{status}: {count}")

# D. 3-Sigma anomaly detector
print("")
print("HOURLY TRAFFIC ANOMALY DETECTION")

hour_counts = list(hourly_requests.values())

mean = sum(hour_counts) / len(hour_counts)

variance = sum((x - mean) ** 2 for x in hour_counts) / len(hour_counts)
std_dev = math.sqrt(variance)

THRESHOLD = 3.0

for hour in sorted(hourly_requests):
    count = hourly_requests[hour]

    if std_dev == 0:
        continue

    z_score = (count - mean) / std_dev

    if abs(z_score) >= THRESHOLD:
        print(
            f"[ANOMALY] {hour:02d}:00 — "
            f"{count} requests "
            f"(z={z_score:.1f}σ, "
            f"threshold={THRESHOLD:.1f}σ)"
        )