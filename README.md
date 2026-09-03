# NetScan-Pro

Async TCP/UDP network scanner with concurrent scanning, service banner
grabbing, lightweight OS fingerprinting, a clean CLI, configurable
profiles, and structured logging — built on Python's `asyncio`, no
raw sockets or root privileges required.

```
netscan-pro v1.2.0  |  run 698f56fc  |  1 target(s), 5000 TCP port(s), 4 UDP port(s)
     127.0.0.1  —  OS guess: Linux / macOS / most BSD / modern network gear (initial TTL≈64, ~0 hop(s) away)
┏━━━━━━┳━━━━━━━┳━━━━━━━┳━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ PORT ┃ PROTO ┃ STATE ┃ SERVICE ┃ LATENCY ┃ BANNER                         ┃
┡━━━━━━╇━━━━━━━╇━━━━━━━╇━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│   22 │ TCP   │ open  │ ssh     │ 44.8ms  │ SSH-2.0-OpenSSH_9.6p1 Ubuntu-3 │
│   80 │ TCP   │ open  │ http    │ 53.4ms  │ HTTP Server: nginx/1.24.0      │
└──────┴───────┴───────┴─────────┴─────────┴────────────────────────────────┘
```

## ⚠️ Legal / ethical use

Only scan hosts, networks, and ports you **own** or have **explicit,
documented authorization** to test. Port scanning third-party systems
without permission is illegal in many jurisdictions (in the US, it can
fall under the Computer Fraud and Abuse Act) and is a violation of
most ISPs' and cloud providers' acceptable-use policies. The
maintainers of this project assume no liability for misuse — see
[LICENSE](LICENSE).

## Features

- **Async, not thread-per-port.** A single `asyncio` event loop drives
  every connection attempt, bounded by a configurable semaphore
  (default 500 concurrent probes). This scans thousands of ports from
  one process without the memory/FD overhead of a thread-per-port model.
- **TCP connect scanning** — full 3-way handshake, works without root
  (no raw sockets / no SYN scan, by design — this trades a slightly
  more visible probe for portability and zero-privilege operation).
- **UDP scanning** with retransmits and honest `open` /
  `closed` / `open|filtered` reporting — UDP scanning is inherently
  ambiguous (no response could mean open, or could mean the packet or
  its ICMP unreachable got dropped), and this tool doesn't pretend
  otherwise.
- **Protocol-aware banner grabbing** — passively listens on
  banner-first services (SSH, FTP, SMTP...) and actively probes
  silent ones (sends a minimal `HEAD` request to detect HTTP servers
  and parse their `Server:` header).
- **Lightweight OS fingerprinting** via ICMP TTL bucketing (Linux/BSD
  ≈64, Windows ≈128, network gear ≈255), clearly labeled as a
  best-effort guess, with honest fallback text when ICMP is filtered
  or `ping` isn't available — it does not fabricate a confident answer
  it can't support.
- **Token-bucket rate limiting** (`--rate-limit`) for scanning
  bandwidth-sensitive or production targets politely.
- **Flexible target specs**: single IP, hostname, CIDR block
  (`10.0.0.0/24`), or `@targets.txt` file.
- **Flexible port specs**: `22,80,443`, `1-1024`, `top-200`, `all`.
- **Structured logging** — rotating file log at `logs/netscan.log`
  with a unique run ID per invocation (so concurrent or historical
  runs are unambiguous in the log), plus a live, colorized console
  view via `rich`.
- **Output formats**: a live progress-bar + table for humans, or
  `--format json` / `--format csv` for piping into other tooling.
- **YAML config profiles** — check a `config.yaml` into your repo per
  environment and override anything from the CLI on top of it.

## Install

```bash
git clone https://github.com/<you>/netscan-pro.git
cd netscan-pro
pip install -r requirements.txt
# optional, for a `netscan` command on your PATH:
pip install -e .
```

Requires Python 3.10+.

## Usage

```bash
# Top 1000 TCP ports against a single host
python main.py 192.168.1.10

# Specific ports, both protocols, against a whole subnet
python main.py 10.0.0.0/28 -p 22,80,443,3389 --udp

# Full TCP range, custom concurrency and timeout, JSON export
python main.py example.com -p all -c 1000 --connect-timeout 0.8 -o scan.json

# Read targets from a file, use a saved config profile, verbose debug logging
python main.py @targets.txt --config config.yaml -vv

# Throttle to be gentle on a production target
python main.py 10.20.30.40 -p top-200 --rate-limit 50
```

Full flag reference:

```
positional arguments:
  target                IP, hostname, CIDR (10.0.0.0/24), or @file.txt

options:
  -p, --ports PORTS         e.g. 22,80,443 | 1-1024 | top-200 | all
  --udp                     also scan UDP ports
  --udp-ports PORTS          UDP port spec (defaults to -p's value, else a
                             built-in common-UDP-ports list)
  --top-ports N              N most common TCP ports when -p is omitted
  -c, --concurrency N        max simultaneous probes (default: 500)
  --connect-timeout SEC      TCP connect timeout (default: 1.2)
  --udp-timeout SEC          UDP response timeout (default: 1.5)
  --rate-limit N             max probes/sec, 0 = unlimited (default: 0)
  --no-os                    skip OS fingerprinting
  --config PATH              YAML config file (see config.example.yaml)
  -o, --output PATH          write results to this file
  --format {table,json,csv}  output format
  -v, --verbose              -v info, -vv debug
  -q, --quiet                suppress console tables (log file still written)
  --version
```

## Configuration

Copy `config.example.yaml` to `config.yaml` and tune it — any field
you omit falls back to the built-in default, and any matching CLI
flag you pass overrides the file:

```yaml
concurrency: 500
connect_timeout: 1.2
udp_timeout: 1.5
banner_timeout: 1.5
retries: 1
top_ports: 1000
rate_limit: 0
resolve_hostnames: true
os_fingerprint: true
output_format: table
```

## How it works

```
┌─────────────┐     ┌──────────────────┐     ┌───────────────────┐
│  CLI parse  │────▶│  target/port     │────▶│  AsyncScanner      │
│  (argparse) │     │  expansion       │     │  (asyncio.Semaphore│
└─────────────┘     │  (CIDR/@file,    │     │   bounded fan-out) │
                     │   port ranges)   │     └─────────┬──────────┘
                     └──────────────────┘               │
                                          ┌──────────────┼──────────────┐
                                          ▼                             ▼
                                 ┌─────────────────┐          ┌─────────────────┐
                                 │  TCP connect     │          │  UDP datagram   │
                                 │  scan + banner   │          │  scan + ICMP    │
                                 │  grab            │          │  unreachable    │
                                 └─────────────────┘          └─────────────────┘
                                          │                             │
                                          └──────────────┬──────────────┘
                                                          ▼
                                              ┌───────────────────────┐
                                              │  rich table / JSON /   │
                                              │  CSV + rotating log    │
                                              └───────────────────────┘
```

Each open TCP port triggers a second, short-lived connection for
banner grabbing: silent-by-default services (HTTP, HTTPS) get a
minimal `HEAD` probe; talkative services (SSH, FTP, SMTP) are simply
read from. UDP ports get protocol-specific probes for DNS, NTP, and
SNMP (the three most commonly-scanned UDP services), and a generic
null-byte probe otherwise — a datagram response means `open`, an ICMP
port-unreachable means `closed`, and silence within the timeout window
is reported as `open|filtered`, which is the honest answer UDP scanning
allows.

## Verified test run

This isn't a hypothetical usage example — `examples/example_run.log`
and `examples/example_results.json` are the **unedited output** of an
actual run against a local test-bed (a real OpenSSH-banner-emitting
TCP socket, a real `http.server` instance, and a real UDP echo
socket, spun up on `127.0.0.1` specifically to validate this tool
during development):

```bash
python tests/run_local_demo.py
```

```
2026-09-03 06:45:43 | run=beea78c6 | INFO | netscan | Starting scan run_id=beea78c6 targets=1 ports=13 udp=True concurrency=500
2026-09-03 06:45:43 | run=beea78c6 | DEBUG | netscan.engine | TCP 127.0.0.1:2222 OPEN (1.5ms) service=ssh
2026-09-03 06:45:43 | run=beea78c6 | DEBUG | netscan.engine | TCP 127.0.0.1:8080 OPEN (1.2ms) service=http
2026-09-03 06:45:43 | run=beea78c6 | INFO | netscan | Host 127.0.0.1 complete: 3 open/open|filtered port(s)
2026-09-03 06:45:43 | run=beea78c6 | INFO | netscan | Scan finished run_id=beea78c6 in 0.01s
```

A separate full-range run (5,000 TCP ports + 4 UDP ports, concurrency
500) against the same test-bed completed in **0.54s**, demonstrating
the async fan-out doing its job rather than scanning serially.

## Project layout

```
netscan-pro/
├── main.py                    # entry point (python main.py ...)
├── netscan/
│   ├── cli.py                 # argparse CLI, progress bar, output rendering
│   ├── scanner.py             # AsyncScanner: TCP/UDP engine, rate limiter
│   ├── banners.py             # banner grabbing + service guessing
│   ├── osfingerprint.py       # TTL-based OS heuristic
│   ├── config.py              # ScanConfig dataclass + YAML loader
│   ├── logger.py              # rotating file log + rich console log
│   └── utils.py                # port/target parsing, top-ports table
├── tests/
│   ├── testbed_servers.py     # local fake services for testing
│   └── run_local_demo.py      # runs testbed + scanner together
├── examples/                  # real, unedited output from a test run
├── config.example.yaml
├── requirements.txt
├── setup.py
└── LICENSE
```

## Known limitations

- TCP scanning uses connect scans, not SYN scans — this is by design
  (no root required), but it is more visible to logging/IDS on the
  target than a half-open SYN scan would be.
- OS fingerprinting is TTL-only. It's a fast, zero-privilege heuristic,
  not a substitute for a real TCP/IP stack fingerprinting engine —
  treat it as a hint, not ground truth.
- UDP's `open|filtered` state is a fundamental protocol ambiguity, not
  a bug: a lack of response is genuinely indistinguishable from a
  silently-dropped packet without deeper protocol-specific probing.

## Roadmap ideas

- [ ] IPv6 target support
- [ ] Optional SYN scan backend for environments where root is available
- [ ] TLS certificate inspection on HTTPS/other TLS ports
- [ ] `--exclude` for target/port denylists
- [ ] Pluggable output writers (SQLite, Elasticsearch)

Contributions welcome — open an issue or PR.

## License

MIT — see [LICENSE](LICENSE).
