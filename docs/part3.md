# Log analysis and anomaly detection


Generate a synthetic auth log for testing:
> Archivo sintetico generado y guardado en [auth.log](../sample_output/auth.log)

**A. Write `auth_analysis.py` that reads `auth.log` and produces:**

- A list of IPs that have more than 10 failed login attempts, sorted descending by attempt count
- The list of user accounts being targeted (which usernames are attackers guessing?)
- The ratio of failed to successful logins overall


```bash
python3 auth_analysis.py
```

espected output:

```bash
IPs with more than 10 failed login attempts
185.220.101.5: 275 failed attempts
45.33.32.156: 192 failed attempts
10.0.0.2: 15 failed attempts
192.168.1.50: 11 failed attempts

Targeted user accounts
daniel: 136 attempts
admin: 124 attempts
root: 124 attempts
ubuntu: 116 attempts

Failed to successful login ratio
Failed logins: 500, Successful logins: 20
Ratio (failed/successful): 25.00:1
```

**B. Generate a synthetic web access log (or use a real one if available):**

> Archivo sintetico generado y guardado en [access.log](../sample_output/access.log)

**C. Write `log_analysis.py` that reads `access.log` and produces:**

- All requests matching SQL injection, path traversal, XSS, or command injection patterns (use the regex from the theory section as a starting point, but extend it)
- Top 5 IPs by request volume
- HTTP status code distribution


```bash
python3 log_analysis.py
```

espected output:

```bash
SUSPICIOUS REQUESTS
[Path Traversal] IP=10.0.0.1 STATUS=403 PATH=/admin/../../../etc/passwd
[Path Traversal] IP=192.168.1.50 STATUS=403 PATH=/admin/../../../etc/passwd
[XSS] IP=10.0.0.1 STATUS=200 PATH=/search?q=<script>alert(1)</script>
...
...
...
[Path Traversal] IP=185.220.101.5 STATUS=500 PATH=/admin/../../../etc/passwd
[Command Injection] IP=10.0.0.1 STATUS=200 PATH=/cgi-bin/test.cgi?cmd=id
[Path Traversal] IP=10.0.0.1 STATUS=500 PATH=/admin/../../../etc/passwd

TOP 5 IPs BY REQUEST VOLUME
10.0.0.1: 1844 requests
66.249.66.1: 625 requests
45.33.32.156: 320 requests
185.220.101.5: 315 requests
192.168.1.50: 177 requests

HTTP STATUS CODE DISTRIBUTION
200: 3171
403: 49
500: 61
```

**D. Implement the 3-sigma anomaly detector on hourly request counts. Your output should identify anomalous hours and report their z-score:**

espected output:

```bash
HOURLY TRAFFIC ANOMALY DETECTION
[ANOMALY] 03:00 — 950 requests (z=4.8σ, threshold=3.0σ)
```

**Question**

The 3-sigma rule assumes data is approximately normally distributed. Web server traffic often has strong daily periodicity (high during business hours, low overnight). How does this periodicity affect the validity of a single global baseline? Describe a modified approach that would produce fewer false positives on a server with predictable daily traffic cycles.

A global baseline averages high-traffic hours (9am–6pm) together with low-traffic hours (2am–5am). The resulting standard deviation is artificially inflated because it mixes two distinct populations. This produces two problems: a moderately high spike at 3am may appear anomalous even if it is typical for that hour, while a real spike during peak hours may go undetected because the low overnight average pulls the z-score down.

The solution is a per-hour segmented baseline: instead of a single global mean, compute the mean and standard deviation for each hour of the day using historical data from multiple days (for example, the last 7 or 30 days). This way, 3am traffic is compared against the historical 3am baseline, not the daily average. This dramatically reduces false positives on servers with predictable daily cycles. A more sophisticated variant is EWMA (Exponentially Weighted Moving Average), which gives more weight to recent data and adapts to gradual behavioral shifts over time.