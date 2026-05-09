import socket
import time
import json
import argparse
import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime


# código original
def scan_port(host: str, port: int, timeout: float = 1.0) -> bool:
    """
    Scanner básico secuencial.
    Intenta conexión TCP completa (connect scan).
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        try:
            s.connect((host, port))
            return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False


# A. ThreadPoolExecutor
def scan_threaded(host: str, ports: list[int], timeout: float, max_workers: int):
    """
    Refactor A:
    - Se introduce concurrencia con ThreadPoolExecutor
    - Mejora rendimiento en tareas I/O-bound
    """
    def task(port):
        return port if scan_port(host, port, timeout) else None

    start = time.perf_counter()

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = executor.map(task, ports)

    open_ports = sorted(p for p in results if p is not None)
    elapsed = time.perf_counter() - start

    return open_ports, elapsed


# B. asyncio + Semaphore
async def scan_port_async(host: str, port: int, timeout: float):
    """
    Versión async del escaneo de puertos
    """
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return port
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return None


async def scan_async(host: str, ports: list[int], timeout: float, rate: int):
    """
    Refactor B:
    - Uso de asyncio para alta concurrencia
    - Uso de Semaphore para limitar conexiones simultáneas
    """
    semaphore = asyncio.Semaphore(rate)

    async def limited_task(port):
        async with semaphore:
            return await scan_port_async(host, port, timeout)

    start = time.perf_counter()

    tasks = [limited_task(p) for p in ports]
    results = await asyncio.gather(*tasks)

    open_ports = sorted(p for p in results if p is not None)
    elapsed = time.perf_counter() - start

    return open_ports, elapsed


# C. CLI con argparse
def parse_ports(port_str: str) -> list[int]:
    """
    Refactor C:
    - Soporta:
        "1-1024"
        "22,80,443"
    """
    ports = set()

    for part in port_str.split(","):
        if "-" in part:
            start, end = map(int, part.split("-"))
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))

    return sorted(ports)


def parse_args():
    parser = argparse.ArgumentParser(description="Port Scanner")

    parser.add_argument("target", help="IP address to scan")
    parser.add_argument("--ports", default="1-1024")
    parser.add_argument("--rate", type=int, default=200)
    parser.add_argument("--timeout", type=float, default=0.5)
    parser.add_argument("--output", default=None)
    parser.add_argument("--mode", choices=["thread", "async"], default="thread")

    return parser.parse_args()


# D. Output JSON
def build_output(target, elapsed, open_ports):
    """
    Refactor D:
    - Genera salida estructurada en JSON
    """
    return {
        "target": target,
        "scan_time_seconds": round(elapsed, 2),
        "timestamp": datetime.now().isoformat(),
        "open_ports": open_ports,
    }


def write_output(data, output_path):
    """
    - Si no hay archivo, imprime en consola
    - Si hay archivo, guarda JSON
    """
    if output_path:
        with open(output_path, "w") as f:
            json.dump(data, f, indent=2)
    else:
        print(json.dumps(data, indent=2))


# MAIN (integra A, B, C, D)
def main():
    args = parse_args()
    ports = parse_ports(args.ports)

    if args.mode == "thread":
        open_ports, elapsed = scan_threaded(
            args.target, ports, args.timeout, args.rate
        )
    else:
        open_ports, elapsed = asyncio.run(
            scan_async(args.target, ports, args.timeout, args.rate)
        )

    result = build_output(args.target, elapsed, open_ports)
    write_output(result, args.output)


if __name__ == "__main__":
    main()