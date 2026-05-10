import xml.etree.ElementTree as ET
import json
import subprocess
import argparse


def get_ssh_host_key_type(ip: str) -> str | None:
    """
    Executes ssh-keyscan on a host and extracts
    the SSH key type.
    """
    try:
        result = subprocess.run(
            ["ssh-keyscan", ip],
            capture_output=True,
            text=True,
            timeout=5
        )

        for line in result.stdout.splitlines():

            if line.startswith("#"):
                continue

            parts = line.split()

            if len(parts) >= 2:
                return parts[1]

    except subprocess.TimeoutExpired:
        print(f"[!] ssh-keyscan timeout for {ip}")

    except Exception as e:
        print(f"[!] Error scanning SSH key for {ip}: {e}")

    return None


def parse_scan(xml_file: str) -> list[dict]:
    """
    Parses an nmap XML scan file and returns
    a list of dictionaries for each live host.
    """
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()

    except (ET.ParseError, FileNotFoundError) as e:
        print(f"Error reading or parsing XML file: {e}")
        return []

    hosts_data = []

    for host in root.findall("host"):

        if host.find("status").get("state") != "up":
            continue

        host_info = {}

        address_element = host.find(
            "address[@addrtype='ipv4']"
        )

        if address_element is not None:
            host_info["ip"] = address_element.get("addr")
        else:
            continue

        hostname_element = host.find(
            "hostnames/hostname"
        )

        if hostname_element is not None:
            host_info["hostname"] = (
                hostname_element.get("name")
            )
        else:
            host_info["hostname"] = None

        open_ports = []

        for port in host.findall(".//port"):

            if (
                port.find("state")
                .get("state")
                == "open"
            ):

                port_info = {
                    "port": int(
                        port.get("portid")
                    )
                }

                service = port.find("service")

                if service is not None:
                    port_info["service"] = (
                        service.get("name")
                    )
                    port_info["version"] = (
                        service.get("version")
                    )
                else:
                    port_info["service"] = None
                    port_info["version"] = None

                open_ports.append(
                    port_info
                )

        host_info["open_ports"] = open_ports

        ssh_open = any(
            p["port"] == 22
            for p in open_ports
        )

        if ssh_open:
            host_info[
                "ssh_host_key_type"
            ] = get_ssh_host_key_type(
                host_info["ip"]
            )
        else:
            host_info[
                "ssh_host_key_type"
            ] = None

        hosts_data.append(host_info)

    return hosts_data


def save_results(
    data: list[dict],
    output_file: str
):
    """
    Saves enriched results to JSON.
    """
    try:
        print(f"Writing JSON to: {output_file}")

        with open(output_file, "w") as f:
            json.dump(
                data,
                f,
                indent=4
            )

        print(
            f"[+] Results saved to {output_file}"
        )

    except Exception as e:
        print(
            f"[!] Error writing JSON: {e}"
        )


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="Parse nmap XML"
    )

    parser.add_argument(
        "--input",
        required=True,
        help="Input XML file"
    )

    parser.add_argument(
        "--output",
        required=True,
        help="Output JSON file"
    )

    args = parser.parse_args()

    scan_results = parse_scan(
        args.input
    )

    save_results(
        scan_results,
        args.output
    )