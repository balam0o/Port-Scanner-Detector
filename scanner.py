import argparse
import asyncio
import datetime
import ipaddress
import json
import ssl
from typing import Any, Dict, List, Optional, Tuple

HTTP_PORTS = {80, 8000, 8008, 8080, 8081, 8888}
TLS_HTTP_PORTS = {443, 8443}
BANNER_PORTS = {21, 22, 25, 110, 143, 587}

# Safer defaults for demos and controlled environments.
SAFE_DEFAULT_PORTS = "22,80,443,445,3389,8080,8443,8000-8100"
SAFE_MAX_CONCURRENCY = 50
SAFE_MIN_TIMEOUT = 2.0
SAFE_DEFAULT_DELAY = 0.02
SAFE_MAX_TARGETS_FROM_CIDR = 16


def utc_now_iso() -> str:
    """Return a UTC timestamp in ISO 8601 format."""
    return (
        datetime.datetime.now(datetime.UTC)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def parse_ports(spec: str) -> List[int]:
    """Parse a comma-separated port specification.

    Examples:
        "22,80,443"
        "1-1024"
        "22,80,8000-8010"
    """
    if not spec or not spec.strip():
        raise ValueError("Port specification cannot be empty")

    ports = set()

    for part in spec.split(","):
        part = part.strip()

        if not part:
            continue

        if "-" in part:
            start_s, end_s = part.split("-", 1)

            try:
                start = int(start_s)
                end = int(end_s)
            except ValueError as exc:
                raise ValueError(f"Invalid port range: {part}") from exc

            if start < 1 or end > 65535 or start > end:
                raise ValueError(f"Invalid port range: {part}")

            ports.update(range(start, end + 1))
        else:
            try:
                port = int(part)
            except ValueError as exc:
                raise ValueError(f"Invalid port: {part}") from exc

            if port < 1 or port > 65535:
                raise ValueError(f"Invalid port: {port}")

            ports.add(port)

    if not ports:
        raise ValueError("No valid ports parsed")

    return sorted(ports)


def is_public_ip(host: str) -> bool:
    """Return True if host parses as a public-routable IP.

    Hostnames are treated as public by default because resolving them could point
    to external infrastructure.
    """
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return True

    return ip.is_global


def cidr_host_count(network: ipaddress._BaseNetwork) -> int:
    """Estimate usable hosts without materializing a large CIDR range."""
    if network.version == 4 and network.prefixlen < 31:
        return max(network.num_addresses - 2, 0)

    return network.num_addresses


def parse_targets(
    spec: str,
    safe: bool,
    allow_public: bool,
    max_targets_from_cidr: int,
) -> List[str]:
    """Parse comma-separated hosts or CIDR ranges."""
    if not spec or not spec.strip():
        raise ValueError("Target specification cannot be empty")

    targets: List[str] = []

    for part in spec.split(","):
        part = part.strip()

        if not part:
            continue

        if "/" in part:
            try:
                network = ipaddress.ip_network(part, strict=False)
            except ValueError as exc:
                raise ValueError(f"Invalid CIDR target: {part}") from exc

            host_count = cidr_host_count(network)

            if safe and host_count > max_targets_from_cidr:
                raise ValueError(
                    f"Refusing CIDR {part} in safe mode: expands to approximately "
                    f"{host_count} hosts, limit is {max_targets_from_cidr}. "
                    "Use a smaller subnet or disable --safe only for authorized testing."
                )

            for host in network.hosts():
                host_str = str(host)

                if safe and not allow_public and is_public_ip(host_str):
                    raise ValueError(
                        f"Refusing public target {host_str} in safe mode. "
                        "Scan only private/local IPs or pass --allow-public only "
                        "for authorized testing."
                    )

                targets.append(host_str)
        else:
            if safe and not allow_public and is_public_ip(part):
                raise ValueError(
                    f"Refusing public target {part} in safe mode. "
                    "Scan only private/local IPs or pass --allow-public only "
                    "for authorized testing."
                )

            targets.append(part)

    if not targets:
        raise ValueError("No valid targets parsed")

    return targets


def validate_args(args: argparse.Namespace) -> None:
    """Validate CLI arguments before running the scanner."""
    if args.concurrency < 1:
        raise ValueError("--concurrency must be >= 1")

    if args.timeout <= 0:
        raise ValueError("--timeout must be > 0")

    if args.delay < 0:
        raise ValueError("--delay must be >= 0")

    if args.max_cidr_hosts < 1:
        raise ValueError("--max-cidr-hosts must be >= 1")


async def read_banner(reader: asyncio.StreamReader, timeout: float) -> str:
    """Try to read a short service banner from an open TCP connection."""
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
    """Send a simple HTTP HEAD request to identify HTTP/HTTPS services."""
    context = ssl.create_default_context() if use_tls else None

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=context),
            timeout=timeout,
        )
    except (OSError, asyncio.TimeoutError, ssl.SSLError):
        return "", ""

    try:
        request = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        writer.write(request.encode("ascii"))
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

    service = "https" if use_tls else "http"

    if not data:
        return service, ""

    text = data.decode("utf-8", errors="replace").strip()
    return service, " ".join(text.split())


async def scan_port(
    host: str,
    port: int,
    timeout: float,
    detect: bool,
) -> Optional[Dict[str, Any]]:
    """Scan a single TCP port and optionally detect the service."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
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

                service, banner = await try_http_probe(
                    host,
                    port,
                    timeout,
                    use_tls=False,
                )

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

                service, banner = await try_http_probe(
                    host,
                    port,
                    timeout,
                    use_tls=True,
                )

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
) -> Dict[str, Dict[str, List[Dict[str, Any]]]]:
    """Run the asynchronous TCP scan."""
    results: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}
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

            # Per-worker pacing. This reduces burstiness, but it is not a global rate limiter.
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

    for host in results:
        results[host]["open_ports"].sort(key=lambda record: int(record["port"]))

    return results


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Safe asynchronous TCP port scanner with basic service detection."
    )

    parser.add_argument(
        "--targets",
        required=True,
        help="Comma-separated hosts or CIDR ranges, for example: 127.0.0.1,192.168.1.0/28",
    )

    parser.add_argument(
        "--ports",
        default=None,
        help=(
            f"Comma-separated ports or ranges. Default: {SAFE_DEFAULT_PORTS} "
            "in --safe mode, otherwise 1-65535."
        ),
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Connection timeout in seconds. Default: 1.0. Raised in --safe mode if too low.",
    )

    parser.add_argument(
        "--concurrency",
        type=int,
        default=500,
        help=(
            "Concurrent connection attempts. Default: 500. "
            f"Capped to {SAFE_MAX_CONCURRENCY} in --safe mode."
        ),
    )

    parser.add_argument(
        "--delay",
        type=float,
        default=0.0,
        help=(
            "Delay in seconds between attempts per worker. Default: 0.0. "
            f"Set to {SAFE_DEFAULT_DELAY} in --safe mode."
        ),
    )

    parser.add_argument(
        "--out",
        default="scan.json",
        help="Output JSON file path. Default: scan.json.",
    )

    parser.add_argument(
        "--no-detect",
        action="store_true",
        help="Disable service detection and banner grabbing.",
    )

    parser.add_argument(
        "--safe",
        action="store_true",
        help=(
            "Enable safe mode: private targets only, small CIDR ranges, "
            "lower concurrency, common ports, and pacing."
        ),
    )

    parser.add_argument(
        "--allow-public",
        action="store_true",
        help="Allow public targets. Disabled by default in --safe mode. Not recommended.",
    )

    parser.add_argument(
        "--max-cidr-hosts",
        type=int,
        default=SAFE_MAX_TARGETS_FROM_CIDR,
        help=f"Maximum hosts expanded from a CIDR in --safe mode. Default: {SAFE_MAX_TARGETS_FROM_CIDR}.",
    )

    return parser.parse_args()


def main() -> None:
    args = parse_args()

    try:
        validate_args(args)

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

    except ValueError as exc:
        raise SystemExit(f"Error: {exc}") from exc

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

    with open(args.out, "w", encoding="utf-8") as file:
        json.dump(payload, file, indent=2, sort_keys=True)

    total_open_ports = sum(len(host_result["open_ports"]) for host_result in results.values())

    print("Scan completed.")
    print(f"Targets scanned: {len(targets)}")
    print(f"Ports checked per target: {len(ports)}")
    print(f"Open ports found: {total_open_ports}")
    print(f"Output written to: {args.out}")


if __name__ == "__main__":
    main()
