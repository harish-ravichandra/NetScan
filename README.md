# NetScan

A lightweight, web-based network port scanner powered by Nmap. Add target networks, run scans, and view results through a clean browser interface with real-time updates.

## Features

- **Network Management via UI** — Add and remove target networks directly from the browser
- **Manual Scanning** — Trigger on-demand scans with real-time results via Server-Sent Events (SSE)
- **Scheduled Auto-Scan** — Set up periodic automatic scanning at configurable intervals
- **Parallel Scanning** — All networks are scanned simultaneously using thread pools
- **Live Results** — Watch open ports appear in real-time as Nmap discovers them
- **Export** — Download results as JSON or CSV for further analysis
- **Configurable Settings** — Port ranges, Nmap timing templates, and scan intervals adjustable via UI
- **Persistent Config** — All settings and network targets saved to a JSON file
- **Modern UI** — Clean, light-themed interface built with Tailwind CSS

## Quick Start

### Prerequisites

- Python 3.8+
- [Nmap](https://nmap.org/download.html) installed and in your PATH
- pip

### Installation

```bash
# Clone or download
cd netscan

# Install dependencies
pip install -r requirements.txt

# Verify nmap is available
nmap --version

# Run
python app.py
```

Open **http://localhost:5000** in your browser.

### Docker (optional)

```dockerfile
FROM python:3.12-slim
RUN apt-get update && apt-get install -y nmap && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
EXPOSE 5000
CMD ["python", "app.py"]
```

```bash
docker build -t netscan .
docker run -p 5000:5000 --cap-add=NET_RAW netscan
```

> Note: Nmap requires `NET_RAW` capability for SYN scans. Run with `--cap-add=NET_RAW` or use `--privileged`.

## Configuration

### Via the UI (gear icon)

| Setting | Default | Description |
|---------|---------|-------------|
| Ports to Scan | `--top-ports 1000` | Nmap port specification |
| Timing Template | T4 (Aggressive) | Nmap speed/stealth tradeoff (T0-T5) |
| Auto-Scan Interval | 30 minutes | Time between scheduled scans |

### Via Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `NETSCAN_HOST` | `0.0.0.0` | Server bind address |
| `NETSCAN_PORT` | `5000` | Server port |

All UI settings are persisted in `config.json`.

## Usage

### Adding Networks

1. Click **Add Network** in the Target Networks panel
2. Enter a descriptive name (e.g., "Office LAN") and CIDR range (e.g., `192.168.1.0/24`)
3. Click **Add** — the network appears in the list

### Scanning

- **Scan Now** — Runs an immediate scan of all configured networks. Results stream to the UI in real-time.
- **Auto-Scan** — Starts a background scheduler that runs scans at the configured interval.
- **Stop** — Terminates all running Nmap processes and stops the scheduler.
- **Clear Results** — Wipes all stored scan results.

### Exporting Results

Click **Export** and choose:
- **JSON** — Full structured data including timestamps
- **CSV** — Flat table format (Network, IP, Port, Status, Scan Time)

## Port Specification Examples

| Value | Description |
|-------|-------------|
| `--top-ports 100` | Top 100 most common ports |
| `--top-ports 1000` | Top 1000 most common ports |
| `22,80,443` | Specific ports only |
| `1-1024` | Port range |
| `22,80,443,8080-8090` | Mixed list and ranges |

## Timing Templates

| Template | Name | Use Case |
|----------|------|----------|
| T0 | Paranoid | IDS evasion |
| T1 | Sneaky | IDS evasion |
| T2 | Polite | Reduced bandwidth usage |
| T3 | Normal | Default Nmap behavior |
| T4 | Aggressive | Fast scans on reliable networks |
| T5 | Insane | Maximum speed, may miss results |

## Security Notes

- This tool is designed for **scanning networks you own or have authorization to scan**
- Unauthorized port scanning may be illegal in your jurisdiction
- Consider running behind a reverse proxy with HTTPS and authentication in production
- Nmap may require root/sudo privileges for SYN scans; TCP connect scans work without

## License

MIT — see [LICENSE](LICENSE)
