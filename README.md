# Port Scanner Detector

![CI](https://github.com/balam0o/Port-Scanner-Detector/actions/workflows/ci.yml/badge.svg)

Safe asynchronous TCP port scanner built in Python with basic service detection, banner grabbing, JSON reporting, and a safer scanning mode for controlled environments.

> This project is intended for educational use, local labs, and authorized security testing only.

---

## Overview

This project is a lightweight asynchronous TCP port scanner designed to demonstrate core networking and cybersecurity concepts in a readable and responsible way.

It focuses on:

- asynchronous scanning with `asyncio`
- safe defaults for local/private testing
- basic service detection
- structured JSON output
- simple, maintainable Python code
- automated tests and CI validation

The goal is not to build an aggressive scanner, but a clean portfolio project that shows practical understanding of network programming, TCP services, and safe tooling design.

---

## Features

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

Run a safe scan against localhost:

```bash
python -m scanner --safe --targets 127.0.0.1 --out safe_scan.json
```

Scan specific ports:

```bash
python -m scanner --safe --targets 127.0.0.1 --ports 22,80,443,8080 --out safe_scan.json
```

Scan a small private subnet:

```bash
python -m scanner --safe --targets 192.168.1.0/28 --ports 22,80,443 --out lan_scan.json
```

Disable service detection:

```bash
python -m scanner --safe --targets 127.0.0.1 --no-detect --out scan.json
```

---

## Windows Note

On some Windows setups, the generated console script may not be available in `PATH` immediately after installation.

If `port-scanner-detector` is not recognized, use:

```bash
python -m scanner --safe --targets 127.0.0.1 --out safe_scan.json
```

---

## CLI Options

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

---

## Example Output

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

## Project Structure

```text
.
├── .github/
│   └── workflows/
│       └── ci.yml
├── examples/
├── tests/
│   ├── test_ports.py
│   └── test_targets.py
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
- [ ] Refactor into a `src/` package
- [ ] Add richer service fingerprinting
- [ ] Add detection mode for scan patterns from logs
- [ ] Add horizontal and vertical scan detection rules
- [ ] Add HTML report generation

---

## License

MIT License.