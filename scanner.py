import argparse
import asyncio
import datetime
import ipaddress
import json
import ssl
from typing import Dict, List, Optional, Tuple

HTTP_PORTS = {80, 8000, 8008, 8080, 8081, 8888}
TLS_HTTP_PORTS = {443, 8443}
BANNER_PORTS = {21, 22, 25, 110, 143, 587}

#Safer defaults (common + useful for demos)
SAFE_DEFAULT_PORTS = "22,80,443,445,3389,8080,8443,8000-8100"
SAFE_MAX_CONCURRENCY = 50
SAFE_MIN_TIMEOUT = 2.0
SAFE_DEFAULT_DELAY = 0.02  #20ms per attempt (global pacing)
SAFE_MAX_TARGETS_FROM_CIDR = 16  #prevent scanning large campus subnets accidentally


def utc_now_iso() -> str:
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def parse_ports(spec: str) -> List[int]:
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_s, end_s = part.split("-", 1)
            start = int(start_s)
            end = int(end_s)
            if start < 1 or end > 65535 or start > end:
                raise ValueError(f"Invalid port range: {part}")
            for p in range(start, end + 1):
                ports.add(p)
        else:
            p = int(part)
            if p < 1 or p > 65535:
                raise ValueError(f"Invalid port: {p}")
            ports.add(p)
    return sorted(ports)


def is_public_ip(host: str) -> bool:
    """Return True if host parses as an IP and is public-routable."""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        #hostname: treat as public by default (safer)
        return True

    #private/link-local/loopback/multicast/reserved/etc should NOT be treated as public
    return ip.is_global


def parse_targets(
    spec: str,
    safe: bool,
    allow_public: bool,
    max_targets_from_cidr: int,
) -> List[str]:
    targets: List[str] = []

    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue

        if "/" in part:
            net = ipaddress.ip_network(part, strict=False)
            hosts = list(net.hosts())

            if safe and len(hosts) > max_targets_from_cidr:
                raise ValueError(
                    f"Refusing CIDR {part} in --safe mode: expands to {len(hosts)} hosts "
                    f"(limit {max_targets_from_cidr}). Use a smaller subnet or disable --safe."
                )

            for host in hosts:
                h = str(host)
                if safe and (not allow_public) and is_public_ip(h):
                    raise ValueError(
                        f"Refusing public target {h} in --safe mode. "
                        f"Scan only private/local IPs or pass --allow-public (not recommended)."
                    )
                targets.append(h)
        else:
            if safe and (not allow_public) and is_public_ip(part):
                raise ValueError(
                    f"Refusing public target {part} in --safe mode. "
                    f"Scan only private/local IPs or pass --allow-public (not recommended)."
                )
            targets.append(part)

    return targets


async def read_banner(reader: asyncio.StreamReader, timeout: float) -> str:
    try:
        data = await asyncio.wait_for(reader.read(200), timeout=timeout)
    except asyncio.TimeoutError:
        return ""
    if not data:
        return ""
    text = data.decode("utf-8", errors="replace").strip()
    return " ".join(text.split())


async def try_http_probe(
    host: str,
    port: int,
    timeout: float,
    use_tls: bool,
) -> Tuple[str, str]:
    context = ssl.create_default_context() if use_tls else None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=context), timeout=timeout
        )
    except (OSError, asyncio.TimeoutError, ssl.SSLError):
        return "", ""

    try:
        req = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        writer.write(req.encode("ascii"))
        await writer.drain()
        data = await asyncio.wait_for(reader.read(300), timeout=timeout)
    except asyncio.TimeoutError:
        data = b""
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    if not data:
        return ("https" if use_tls else "http"), ""
    text = data.decode("utf-8", errors="replace").strip()
    return ("https" if use_tls else "http"), " ".join(text.split())


async def scan_port(
    host: str,
    port: int,
    timeout: float,
    detect: bool,
) -> Optional[Dict[str, str]]:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
    except (OSError, asyncio.TimeoutError):
        return None

    service = "unknown"
    banner = ""
    try:
        if detect:
            if port in HTTP_PORTS:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                service, banner = await try_http_probe(host, port, timeout, use_tls=False)
                return {
                    "port": port,
                    "protocol": "tcp",
                    "service": service,
                    "banner": banner,
                    "timestamp_utc": utc_now_iso(),
                }

            if port in TLS_HTTP_PORTS:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                service, banner = await try_http_probe(host, port, timeout, use_tls=True)
                return {
                    "port": port,
                    "protocol": "tcp",
                    "service": service,
                    "banner": banner,
                    "timestamp_utc": utc_now_iso(),
                }

            if port in BANNER_PORTS:
                banner = await read_banner(reader, timeout)
                if port == 21:
                    service = "ftp"
                elif port == 22:
                    service = "ssh"
                elif port in (25, 587):
                    service = "smtp"
                elif port == 110:
                    service = "pop3"
                elif port == 143:
                    service = "imap"

        return {
            "port": port,
            "protocol": "tcp",
            "service": service,
            "banner": banner,
            "timestamp_utc": utc_now_iso(),
        }
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def run_scan(
    targets: List[str],
    ports: List[int],
    timeout: float,
    concurrency: int,
    detect: bool,
    delay: float,
) -> Dict[str, Dict[str, List[Dict[str, str]]]]:
    results: Dict[str, Dict[str, List[Dict[str, str]]]] = {}
    lock = asyncio.Lock()
    queue: asyncio.Queue[Optional[Tuple[str, int]]] = asyncio.Queue()

    for host in targets:
        results[host] = {"open_ports": []}
        for port in ports:
            queue.put_nowait((host, port))

    async def worker() -> None:
        while True:
            item = await queue.get()
            if item is None:
                queue.task_done()
                break

            host, port = item

            #Global pacing: reduces IDS triggers and load
            if delay > 0:
                await asyncio.sleep(delay)

            record = await scan_port(host, port, timeout, detect)
            if record:
                async with lock:
                    results[host]["open_ports"].append(record)

            queue.task_done()

    workers = [asyncio.create_task(worker()) for _ in range(concurrency)]
    await queue.join()
    for _ in workers:
        queue.put_nowait(None)
    await asyncio.gather(*workers)

    #Stable ordering
    for host in results:
        results[host]["open_ports"].sort(key=lambda r: int(r["port"]))

    return results


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="TCP port scanner with detection (safe mode available)")
    parser.add_argument(
        "--targets",
        required=True,
        help="Comma-separated hosts or CIDR ranges (e.g. 192.168.1.10,192.168.1.0/28)",
    )
    parser.add_argument(
        "--ports",
        default=None,
        help=f"Comma-separated ports or ranges (default: {SAFE_DEFAULT_PORTS} in --safe, else 1-65535)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Connection timeout in seconds (default: 1.0; raised in --safe if too low)",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=500,
        help=f"Concurrent connection attempts (default: 500; capped to {SAFE_MAX_CONCURRENCY} in --safe)",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.0,
        help=f"Delay (seconds) between attempts per worker (default: 0.0; set to {SAFE_DEFAULT_DELAY} in --safe)",
    )
    parser.add_argument(
        "--out",
        default="scan.json",
        help="Output JSON file path (default: scan.json)",
    )
    parser.add_argument(
        "--no-detect",
        action="store_true",
        help="Disable service detection and banner grabbing",
    )

    #Safe mode guardrails
    parser.add_argument(
        "--safe",
        action="store_true",
        help="Enable safe mode: private targets only, small CIDR, low concurrency, common ports, pacing",
    )
    parser.add_argument(
        "--allow-public",
        action="store_true",
        help="Allow public targets (DISABLED by default in --safe). Not recommended.",
    )
    parser.add_argument(
        "--max-cidr-hosts",
        type=int,
        default=SAFE_MAX_TARGETS_FROM_CIDR,
        help=f"Max hosts expanded from a CIDR in --safe (default: {SAFE_MAX_TARGETS_FROM_CIDR})",
    )

    return parser.parse_args()


def main() -> None:
    args = parse_args()

    #Safe-mode adjustments
    if args.safe:
        if args.ports is None:
            args.ports = SAFE_DEFAULT_PORTS
        args.concurrency = min(args.concurrency, SAFE_MAX_CONCURRENCY)
        if args.timeout < SAFE_MIN_TIMEOUT:
            args.timeout = SAFE_MIN_TIMEOUT
        if args.delay <= 0:
            args.delay = SAFE_DEFAULT_DELAY
    else:
        if args.ports is None:
            args.ports = "1-65535"

    targets = parse_targets(
        args.targets,
        safe=args.safe,
        allow_public=args.allow_public,
        max_targets_from_cidr=args.max_cidr_hosts,
    )
    ports = parse_ports(args.ports)

    if not targets:
        raise SystemExit("No targets parsed")
    if not ports:
        raise SystemExit("No ports parsed")

    results = asyncio.run(
        run_scan(
            targets=targets,
            ports=ports,
            timeout=args.timeout,
            concurrency=args.concurrency,
            detect=not args.no_detect,
            delay=args.delay,
        )
    )

    payload = {
        "meta": {
            "timestamp_utc": utc_now_iso(),
            "targets": targets,
            "ports": args.ports,
            "timeout": args.timeout,
            "concurrency": args.concurrency,
            "delay": args.delay,
            "detection": not args.no_detect,
            "safe_mode": args.safe,
            "allow_public": args.allow_public,
            "max_cidr_hosts": args.max_cidr_hosts,
        },
        "results": results,
    }

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, sort_keys=True)


if __name__ == "__main__":
    main()

