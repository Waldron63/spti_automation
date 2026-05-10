import re
from collections import Counter

# Regex patterns
failed_pattern = re.compile(
    r"Failed password for (\w+) from (\d+\.\d+\.\d+\.\d+)"
)

success_pattern = re.compile(
    r"Accepted \w+ for (\w+) from (\d+\.\d+\.\d+\.\d+)"
)

# Counters
failed_ip_counts = Counter()
targeted_users = Counter()

failed_logins = 0
successful_logins = 0

# Read auth.log
with open("auth.log", "r") as file:
    for line in file:
        # Failed login
        failed_match = failed_pattern.search(line)
        if failed_match:
            username, ip = failed_match.groups()

            failed_ip_counts[ip] += 1
            targeted_users[username] += 1
            failed_logins += 1
            continue

        # Successful login
        success_match = success_pattern.search(line)
        if success_match:
            successful_logins += 1

# 1. IPs with >10 failed attempts sorted descending
suspicious_ips = [
    (ip, count)
    for ip, count in failed_ip_counts.items()
    if count > 10
]

suspicious_ips.sort(key=lambda x: x[1], reverse=True)

# Output
print("IPs with more than 10 failed login attempts")

for ip, count in suspicious_ips:
    print(f"{ip}: {count} failed attempts")

print("")
print("Targeted user accounts")

for user, count in targeted_users.most_common():
    print(f"{user}: {count} attempts")

print("")
print("Failed to successful login ratio")

if successful_logins > 0:
    ratio = failed_logins / successful_logins
    print(
        f"Failed logins: {failed_logins}, "
        f"Successful logins: {successful_logins}"
    )
    print(f"Ratio (failed/successful): {ratio:.2f}:1")
else:
    print("No successful logins found.")