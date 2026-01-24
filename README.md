# Port Scanner with Safe Mode and Service Detection

Asynchronous TCP port scanner with basic service detection, banner grabbing, and structured JSON output.  
Designed for educational use, controlled labs, and authorized security testing.

This project includes a **Safe Mode** that enforces low-impact scanning and prevents accidental scans of public or unauthorized networks.

---

## Features

- Asynchronous TCP connect scanning (asyncio)
- Per-host JSON output with timestamps
- Basic service detection:
  - HTTP / HTTPS probing (`HEAD /`)
  - Banner grabbing for common services (FTP, SSH, SMTP, POP3, IMAP)
- CIDR expansion support
- Configurable concurrency, timeout, and pacing
- **Safe Mode for academic networks**
  - Private targets only (blocks public IPs by default)
  - Small CIDR limits
  - Reduced concurrency
  - Global pacing (rate limiting)
  - Common ports only by default

---

## Quick start (Safe mode – recommended for campus / labs)

Scan your own machine or a controlled VM:

```powershell
python scanner.py --safe --targets 127.0.0.1 --out safe_scan.json
