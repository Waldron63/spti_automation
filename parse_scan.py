import xml.etree.ElementTree as ET
import json

def parse_scan(xml_file: str) -> list[dict]:
    """
    Parses an nmap XML scan file and returns a list of dictionaries for each live host.

    Args:
        xml_file: The path to the nmap XML scan file.

    Returns:
        A list of dictionaries, where each dictionary represents a live host
        with its IP, hostname, and open ports.
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

        # Get IP address
        address_element = host.find("address[@addrtype='ipv4']")
        if address_element is not None:
            host_info["ip"] = address_element.get("addr")
        else:
            # Fallback for hosts that might only have ipv6 or other types
            address_element = host.find("address")
            if address_element is not None:
                host_info["ip"] = address_element.get("addr")
            else:
                continue # Cannot identify host without an address

        # Get hostname
        hostname_element = host.find("hostnames/hostname")
        if hostname_element is not None:
            host_info["hostname"] = hostname_element.get("name")
        else:
            host_info["hostname"] = None

        # Get open ports
        open_ports = []
        for port in host.findall(".//port"):
            if port.find("state").get("state") == "open":
                port_info = {}
                port_info["port"] = int(port.get("portid"))
                service = port.find("service")
                if service is not None:
                    port_info["service"] = service.get("name")
                    port_info["version"] = service.get("version")
                else:
                    port_info["service"] = None
                    port_info["version"] = None
                open_ports.append(port_info)
        
        host_info["open_ports"] = open_ports
        hosts_data.append(host_info)

    return hosts_data

if __name__ == "__main__":
    scan_results = parse_scan("scan.xml")
    print(json.dumps(scan_results, indent=4))
