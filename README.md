# Port Scanner Detector

![CI](https://github.com/balam0o/Port-Scanner-Detector/actions/workflows/ci.yml/badge.svg)

Safe asynchronous TCP port scanner and vertical scan detector in Python with JSON reporting, tests, and CI.

> This project is intended for educational use, local labs, and authorized security testing only.

---

## Overview

This repository contains two small security-oriented tools written in Python:

- **Scanner**: an asynchronous TCP port scanner with basic service detection, banner grabbing, and structured JSON output
- **Detector**: a log-based detector for suspicious **vertical port scan** behavior from CSV connection data

The project is designed to show practical understanding of:

- TCP/IP and port scanning behavior
- asynchronous network programming with `asyncio`
- basic service fingerprinting
- secure-by-default tool design
- log-based scan detection
- automated testing and CI

The goal is not to build an aggressive offensive tool, but a clean, readable, and responsible portfolio project that demonstrates networking and cybersecurity fundamentals.

---

## Features

### Scanner

- Asynchronous TCP connect scanning using `asyncio`
- CIDR target support
- Custom port lists and ranges
- Basic service detection
  - HTTP / HTTPS probing
  - banner grabbing for common services
- JSON report output
- Safe Mode with:
  - rejection of public IPs by default
  - CIDR expansion limits
  - safer timeout and delay defaults
  - reduced concurrency
  - common-port defaults for controlled testing

### Detector

- Detects **vertical port scans** from CSV logs
- Sliding time-window analysis
- Threshold-based alert generation
- JSON alert output
- Example input and output files included

### Project Quality

- Unit tests with `pytest`
- Static checks with `ruff`
- GitHub Actions CI

---

## Requirements

- Python 3.10 or newer

---

## Installation

Clone the repository:

```bash
git clone https://github.com/balam0o/Port-Scanner-Detector.git
cd Port-Scanner-Detector
```

Install the project and development tools:

```bash
python -m pip install -e ".[dev]"
```

---

## Quick Start

### Run a safe scan against localhost

```bash
python -m scanner --safe --targets 127.0.0.1 --out safe_scan.json
```

### Scan specific ports

```bash
python -m scanner --safe --targets 127.0.0.1 --ports 22,80,443,8080 --out safe_scan.json
```

### Scan a small private subnet

```bash
python -m scanner --safe --targets 192.168.1.0/28 --ports 22,80,443 --out lan_scan.json
```

### Disable service detection

```bash
python -m scanner --safe --targets 127.0.0.1 --no-detect --out scan.json
```

### Run vertical scan detection on CSV logs

```bash
python detector.py --input examples/connections.csv --window 60 --threshold 10 --out examples/alerts.json
```

---

## Windows Note

On some Windows setups, generated console scripts may not be immediately available in `PATH` after installation.

If a command such as `port-scanner-detector` is not recognized, use:

```bash
python -m scanner --safe --targets 127.0.0.1 --out safe_scan.json
python detector.py --input examples/connections.csv --window 60 --threshold 10 --out examples/alerts.json
```

---

## Scanner Usage

### Main options

| Option | Description |
|---|---|
| `--targets` | Comma-separated hosts or CIDR ranges |
| `--ports` | Comma-separated ports or port ranges |
| `--timeout` | Connection timeout in seconds |
| `--concurrency` | Number of concurrent connection attempts |
| `--delay` | Delay between attempts per worker |
| `--out` | Output JSON file path |
| `--no-detect` | Disable service detection and banner grabbing |
| `--safe` | Enable safer defaults and public IP restrictions |
| `--allow-public` | Allow public targets even in safe mode |
| `--max-cidr-hosts` | Maximum CIDR-expanded hosts in safe mode |

### Example scanner output

```json
{
  "meta": {
    "timestamp_utc": "2026-04-23T10:30:00Z",
    "targets": ["127.0.0.1"],
    "ports": "22,80,443",
    "timeout": 2.0,
    "concurrency": 50,
    "delay": 0.02,
    "detection": true,
    "safe_mode": true,
    "allow_public": false,
    "max_cidr_hosts": 16
  },
  "results": {
    "127.0.0.1": {
      "open_ports": []
    }
  }
}
```

If open ports are found, each result includes:

- port
- protocol
- detected service
- optional banner
- UTC timestamp

---

## Safe Mode

Safe Mode is recommended by default.

When `--safe` is enabled, the scanner:

- rejects public IP addresses unless `--allow-public` is explicitly provided
- limits CIDR expansion
- reduces concurrency
- applies safer timeout and delay defaults
- uses a reduced set of common ports if no ports are provided

Example:

```bash
python -m scanner --safe --targets 127.0.0.1
```

Trying to scan a public IP in safe mode will be rejected:

```bash
python -m scanner --safe --targets 8.8.8.8
```

---

## Detector Usage

The detector analyzes CSV connection logs with the following required columns:

- `timestamp`
- `source_ip`
- `target_ip`
- `target_port`

### Expected CSV format

```csv
timestamp,source_ip,target_ip,target_port
2026-04-20T10:00:01Z,192.168.1.50,192.168.1.10,22
2026-04-20T10:00:05Z,192.168.1.50,192.168.1.10,23
2026-04-20T10:00:10Z,192.168.1.50,192.168.1.10,25
```

### Detector options

| Option | Description |
|---|---|
| `--input` | Path to CSV input file |
| `--window` | Sliding window size in seconds |
| `--threshold` | Minimum number of unique ports to trigger an alert |
| `--out` | Output JSON file path |

### Example detector output

```json
{
  "meta": {
    "timestamp_utc": "2026-04-23T10:40:00Z",
    "input_file": "examples/connections.csv",
    "window_seconds": 60,
    "threshold": 10,
    "events_analyzed": 12,
    "alerts_found": 1
  },
  "alerts": [
    {
      "type": "vertical_port_scan",
      "source_ip": "192.168.1.50",
      "target_ip": "192.168.1.10",
      "unique_ports": 10,
      "ports": [22, 23, 25, 53, 80, 110, 139, 143, 443, 445],
      "window_seconds": 60,
      "severity": "medium",
      "first_seen_utc": "2026-04-20T10:00:01Z",
      "last_seen_utc": "2026-04-20T10:00:45Z"
    }
  ]
}
```

### Current detection scope

The detector currently supports:

- **vertical port scan detection**:
  one source IP touches many different ports on the same target within a short time window

Planned future improvements:

- horizontal scan detection
- mixed scan heuristics
- richer severity scoring
- HTML reporting

---

## Project Structure

```text
.
├── .github/
│   └── workflows/
│       └── ci.yml
├── examples/
│   ├── alerts.json
│   ├── cli_scan.json
│   ├── connections.csv
│   └── safe_scan.json
├── tests/
│   ├── test_detector.py
│   ├── test_ports.py
│   └── test_targets.py
├── detector.py
├── LICENSE
├── pyproject.toml
├── README.md
└── scanner.py
```

---

## Running Tests

Run the test suite:

```bash
python -m pytest
```

Run static checks:

```bash
python -m ruff check .
```

---

## Ethical Use

Use this tool only on systems you own or systems where you have explicit permission to test.

Do not use this project to scan third-party systems, public IP ranges, university networks, company infrastructure, or cloud environments without authorization.

This project is intended for:

- personal learning
- local labs
- virtual machines
- defensive security practice
- authorized testing

---

## Roadmap

- [x] Add unit tests with `pytest`
- [x] Add GitHub Actions CI
- [x] Add `pyproject.toml`
- [x] Add example JSON reports
- [x] Add vertical port scan detection mode
- [ ] Add horizontal scan detection
- [ ] Improve detection scoring and alert metadata
- [ ] Refactor into a `src/` package
- [ ] Add richer service fingerprinting
- [ ] Add HTML report generation

---

## License

MIT License.