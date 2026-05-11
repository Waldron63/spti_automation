# Structured output and enrichment

**A. Run nmap against the lab network with service version detection and XML output:**
```bash
nmap -sV --open -oX scan.xml 192.168.1.0/24
```
> Nota: escaneo completado en la red de la universidad y guardado en [scan.xml](../sample_output/scan.xml)

**B. Write `parse_scan.py` that reads `scan.xml` and produces a structured Python object (dict) for each live host:**


```bash
python3 parse_scan.py
```

ejemplo de salida de 1 de las IP's
```json
    {
        "ip": "192.168.1.0",
        "hostname": null,
        "open_ports": [
            {
                "port": 443,
                "service": "https",
                "version": null
            },
            {
                "port": 1720,
                "service": "h323q931",
                "version": null
            },
            {
                "port": 5060,
                "service": "sip",
                "version": null
            },
            {
                "port": 5061,
                "service": "sip-tls",
                "version": null
            },
            {
                "port": 8080,
                "service": "http-proxy",
                "version": null
            }
        ]
    },
```

**C. For each host with port 22 open, run `ssh-keyscan` via subprocess and parse the output to extract the key type (e.g. `ecdsa-sha2-nistp256`, `ssh-ed25519`). Add a `"ssh_host_key_type"` field to that host’s dict. Handle the case where `ssh-keyscan` times out or the host does not respond.**

Para la ejecución del ejercicio, dentro del archivo [hosts.json](../sample_output/hosts.json) se muestran los casos donde aparece la linea `ssh_host_key_type`

**D. Write the enriched list of hosts to `hosts.json`. Your script should accept `--input` (XML file) and `--output` (JSON file) arguments.**


input:
```bash
python3 parse_scan.py --input ./sample_output/scan.xml --output hosts.json
```
Output:
```json
{
        "ip": "192.168.1.1",
        "hostname": null,
        "open_ports": [
            {
                "port": 443,
                "service": "https",
                "version": null
            },
            {
                "port": 1720,
                "service": "h323q931",
                "version": null
            },
            {
                "port": 5060,
                "service": "sip",
                "version": null
            },
            {
                "port": 5061,
                "service": "sip-tls",
                "version": null
            },
            {
                "port": 8080,
                "service": "http-proxy",
                "version": null
            }
        ],
        "ssh_host_key_type": null
    },
```
> archivo [hosts.json](../sample_output/hosts.json) con la salida real del ejercicio

**Question**

Service version detection (`-sV`) works by sending probe packets and matching responses against a signature database (`nmap-service-probes`). This makes the scan significantly slower and generates more network traffic than a plain port scan. From a defender’s perspective: why is the version string in a service banner valuable intelligence for an attacker? What is the security-relevant difference between `Apache httpd 2.4.54` and a server that returns no version string at all?