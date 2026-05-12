# From sequential to concurrent scanner

**A. Run this against `127.0.0.1` (localhost) and record the elapsed time. Then rewrite it using `ThreadPoolExecutor`. Test `max_workers` values of 50, 200, and 500 and record the elapsed time for each. Plot or tabulate the results.**

Before ThreadPoolExecutor:
```bash
python3 scanner.py
Open ports: [22, 631] (0.03751s)
```
After refactoring:
```bash
python3 scanner.py 127.0.0.1 --rate 50
Open ports: [22, 631] (0.15228s)

python3 scanner.py 127.0.0.1 --rate 200
Open ports: [22, 631] (0.14725s)

python3 scanner.py 127.0.0.1 --rate 500
Open ports: [22, 631] (0.18215s)
```


**B. Rewrite again using `asyncio + asyncio`.Semaphore to cap concurrency at a configurable limit. Measure its performance at the same concurrency levels and compare against the threaded version.**
```bash
python3 scanner.py 127.0.0.1 --rate 200 --mode async
Open ports: [22, 631] (0.0.2195s)
```

**C. Add a proper CLI to whichever version you prefer, using `argparse`:**

**D. Output results as JSON to the path given by `--output`:**

input:
```bash
python3 scanner.py 127.0.0.1 --ports 1-1024 --rate 200 --timeout 0.5 --mode thread
```
Output:
```bash
{
  "target": "127.0.0.1",
  "scan_time_seconds": 0.2195,
  "timestamp": "2026-05-10T15:03:12.166327",
  "open_ports": [
    22,
    631
  ]
}
```
> archivo [stdout.txt](../sample_output/stdout.txt) con la salida real del ejercicio

**Question**

At very high concurrency (e.g. `--rate 2000`), you may observe false negatives (open ports reported as closed). Explain the mechanism behind this. Why does this mean “the scanner did not detect it” is not the same claim as “the port is closed”? What does this imply about how you should interpret scan results from any tool, including nmap?

At very high concurrency levels, the operating system exhausts local resources such as file descriptors, socket buffers, and connection table entries. When this happens, the kernel silently drops outgoing connection attempts before they ever reach the target — the port may be perfectly open, but the connection attempt never completed. The timeout expires not because the port refused the connection, but because the local system failed to establish it in the first place.This means that a negative result from any scanner — including nmap — only means "no activity was detected under these specific conditions at this point in time", not that the port is definitively closed. Factors like firewall rate limiting, packet loss, or local resource exhaustion produce the exact same result as a genuinely closed port. This is why security professionals always validate suspicious results with a second pass at lower concurrency, or combine multiple tools for confirmation.