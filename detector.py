import argparse
import csv
import datetime
import json
from collections import defaultdict, deque
from typing import Any, Deque, Dict, List, Tuple


def utc_now_iso() -> str:
    return (
        datetime.datetime.now(datetime.UTC)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def parse_timestamp(value: str) -> datetime.datetime:
    value = value.strip()
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    dt = datetime.datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.UTC)
    return dt.astimezone(datetime.UTC)


def load_connections(csv_path: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []

    with open(csv_path, "r", encoding="utf-8", newline="") as file:
        reader = csv.DictReader(file)

        required = {"timestamp", "source_ip", "target_ip", "target_port"}
        missing = required - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"Missing required CSV columns: {sorted(missing)}")

        for row in reader:
            rows.append(
                {
                    "timestamp": parse_timestamp(row["timestamp"]),
                    "source_ip": row["source_ip"].strip(),
                    "target_ip": row["target_ip"].strip(),
                    "target_port": int(row["target_port"]),
                }
            )

    rows.sort(key=lambda item: item["timestamp"])
    return rows


def detect_vertical_scans(
    connections: List[Dict[str, Any]],
    window_seconds: int,
    threshold: int,
) -> List[Dict[str, Any]]:
    grouped: Dict[Tuple[str, str], Deque[Dict[str, Any]]] = defaultdict(deque)
    alerts: List[Dict[str, Any]] = []
    seen_alert_keys = set()

    for event in connections:
        key = (event["source_ip"], event["target_ip"])
        window = grouped[key]
        window.append(event)

        cutoff = event["timestamp"] - datetime.timedelta(seconds=window_seconds)
        while window and window[0]["timestamp"] < cutoff:
            window.popleft()

        unique_ports = {item["target_port"] for item in window}

        if len(unique_ports) >= threshold:
            alert_key = (
                event["source_ip"],
                event["target_ip"],
                tuple(sorted(unique_ports)),
            )

            if alert_key in seen_alert_keys:
                continue

            seen_alert_keys.add(alert_key)

            alerts.append(
                {
                    "type": "vertical_port_scan",
                    "source_ip": event["source_ip"],
                    "target_ip": event["target_ip"],
                    "unique_ports": len(unique_ports),
                    "ports": sorted(unique_ports),
                    "window_seconds": window_seconds,
                    "severity": (
                        "high" if len(unique_ports) >= threshold * 2 else "medium"
                    ),
                    "first_seen_utc": window[0]["timestamp"]
                    .isoformat()
                    .replace("+00:00", "Z"),
                    "last_seen_utc": window[-1]["timestamp"]
                    .isoformat()
                    .replace("+00:00", "Z"),
                }
            )

    return alerts


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Detect suspicious vertical port scan behavior from CSV logs."
    )
    parser.add_argument(
        "--input",
        required=True,
        help="Path to CSV file with timestamp, source_ip, target_ip, target_port columns.",
    )
    parser.add_argument(
        "--window",
        type=int,
        default=60,
        help="Sliding window size in seconds. Default: 60.",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=10,
        help="Minimum number of unique ports within the window to trigger an alert.",
    )
    parser.add_argument(
        "--out",
        default="alerts.json",
        help="Output JSON path. Default: alerts.json.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.window <= 0:
        raise SystemExit("Error: --window must be > 0")

    if args.threshold < 2:
        raise SystemExit("Error: --threshold must be >= 2")

    try:
        connections = load_connections(args.input)
    except Exception as exc:
        raise SystemExit(f"Error: {exc}") from exc

    alerts = detect_vertical_scans(
        connections=connections,
        window_seconds=args.window,
        threshold=args.threshold,
    )

    payload = {
        "meta": {
            "timestamp_utc": utc_now_iso(),
            "input_file": args.input,
            "window_seconds": args.window,
            "threshold": args.threshold,
            "events_analyzed": len(connections),
            "alerts_found": len(alerts),
        },
        "alerts": alerts,
    }

    with open(args.out, "w", encoding="utf-8") as file:
        json.dump(payload, file, indent=2, sort_keys=True)

    print("Detection completed.")
    print(f"Events analyzed: {len(connections)}")
    print(f"Alerts found: {len(alerts)}")
    print(f"Output written to: {args.out}")


if __name__ == "__main__":
    main()