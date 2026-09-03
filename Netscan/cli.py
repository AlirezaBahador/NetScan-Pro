"""
Command-line interface.

Examples:
    netscan 192.168.1.10 -p 1-1024
    netscan 10.0.0.0/28 --udp --top-ports 100 -o results.json
    netscan @targets.txt -p top-200 --config config.yaml -vv
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import json
import sys
import time
from pathlib import Path

from rich.console import Console
from rich.progress import (
    BarColumn, MofNCompleteColumn, Progress, SpinnerColumn,
    TextColumn, TimeElapsedColumn, TimeRemainingColumn,
)
from rich.table import Table

from . import __version__
from .config import ScanConfig
from .logger import get_run_id, setup_logging
from .osfingerprint import fingerprint_os
from .scanner import AsyncScanner, HostResult, PortState
from .utils import expand_targets, parse_ports

console = Console()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="netscan",
        description="netscan-pro — async TCP/UDP scanner with banner grabbing "
                     "and OS fingerprinting. Use only against hosts you are "
                     "authorized to test.",
    )
    p.add_argument("target", help="IP, hostname, CIDR (10.0.0.0/24), or @file.txt")
    p.add_argument("-p", "--ports", help="e.g. 22,80,443 | 1-1024 | top-200 | all")
    p.add_argument("--udp", action="store_true", help="also scan UDP ports")
    p.add_argument("--udp-ports", help="UDP port spec, same syntax as -p. "
                                        "Defaults to the -p value if set, else a built-in common-UDP-ports list")
    p.add_argument("--tcp-only", action="store_true", help="skip UDP even if --udp is set elsewhere")
    p.add_argument("--top-ports", type=int, help="use the N most common TCP ports when -p is omitted")
    p.add_argument("-c", "--concurrency", type=int, help="max simultaneous probes")
    p.add_argument("--connect-timeout", type=float, help="TCP connect timeout (s)")
    p.add_argument("--udp-timeout", type=float, help="UDP response timeout (s)")
    p.add_argument("--rate-limit", type=int, help="max probes/sec (0 = unlimited)")
    p.add_argument("--no-os", action="store_true", help="skip OS fingerprinting")
    p.add_argument("--config", help="path to a YAML config file")
    p.add_argument("-o", "--output", help="write results to this file")
    p.add_argument("--format", choices=["table", "json", "csv"], help="output format")
    p.add_argument("-v", "--verbose", action="count", default=1, help="-v info, -vv debug")
    p.add_argument("-q", "--quiet", action="store_true", help="suppress console tables (log file still written)")
    p.add_argument("--version", action="version", version=f"netscan-pro {__version__}")
    return p


def _state_style(state: PortState) -> str:
    return {
        PortState.OPEN: "bold green",
        PortState.CLOSED: "dim red",
        PortState.FILTERED: "yellow",
        PortState.OPEN_FILTERED: "cyan",
    }[state]


def render_table(results: list[HostResult]) -> None:
    for host_result in results:
        table = Table(
            title=f"[bold]{host_result.host}[/bold]"
            + (f"  —  OS guess: {host_result.os_guess}" if host_result.os_guess else ""),
            show_lines=False,
        )
        table.add_column("PORT", justify="right")
        table.add_column("PROTO")
        table.add_column("STATE")
        table.add_column("SERVICE")
        table.add_column("LATENCY")
        table.add_column("BANNER", overflow="fold", max_width=60)

        rows = sorted(host_result.tcp + host_result.udp, key=lambda r: (r.proto, r.port))
        shown = [r for r in rows if r.state != PortState.CLOSED]
        if not shown:
            console.print(f"[dim]{host_result.host}: no open or filtered ports found in scanned range[/dim]")
            continue

        for r in shown:
            style = _state_style(r.state)
            table.add_row(
                str(r.port), r.proto.upper(),
                f"[{style}]{r.state.value}[/{style}]",
                r.service,
                f"{r.latency_ms:.1f}ms" if r.latency_ms is not None else "-",
                r.banner or "-",
            )
        console.print(table)


def write_output(results: list[HostResult], path: str, fmt: str) -> None:
    out = Path(path)
    payload = [
        {
            "host": hr.host,
            "os_guess": hr.os_guess,
            "ports": [
                {
                    "port": r.port, "proto": r.proto, "state": r.state.value,
                    "service": r.service, "banner": r.banner, "latency_ms": r.latency_ms,
                }
                for r in (hr.tcp + hr.udp)
            ],
        }
        for hr in results
    ]

    if fmt == "json":
        out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    elif fmt == "csv":
        with out.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(["host", "port", "proto", "state", "service", "latency_ms", "banner"])
            for hr in results:
                for r in hr.tcp + hr.udp:
                    writer.writerow([hr.host, r.port, r.proto, r.state.value, r.service, r.latency_ms, r.banner])
    else:
        raise ValueError(f"Unsupported output format for file export: {fmt}")


async def _run_host(host: str, ports: list[int], udp_ports: list[int],
                     scanner: AsyncScanner, cfg: ScanConfig, do_udp: bool) -> HostResult:
    hr = HostResult(host=host)
    if cfg.os_fingerprint:
        hr.os_guess = await fingerprint_os(host, timeout=1.5)
    hr.tcp = await scanner.scan_tcp(host, ports)
    if do_udp:
        hr.udp = await scanner.scan_udp(host, udp_ports)
    return hr


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    logger = setup_logging(verbosity=args.verbose)
    run_id = get_run_id()

    try:
        cfg = ScanConfig.load(args.config)
        cfg = cfg.apply_overrides(
            concurrency=args.concurrency,
            connect_timeout=args.connect_timeout,
            udp_timeout=args.udp_timeout,
            rate_limit=args.rate_limit,
            top_ports=args.top_ports,
            output_format=args.format,
            os_fingerprint=(False if args.no_os else None),
        )
    except FileNotFoundError as exc:
        console.print(f"[bold red]Config error:[/bold red] {exc}")
        return 2

    try:
        targets = expand_targets(args.target)
    except FileNotFoundError as exc:
        console.print(f"[bold red]{exc}[/bold red]")
        return 2

    try:
        ports = parse_ports(args.ports, top_n=cfg.top_ports)
    except ValueError as exc:
        console.print(f"[bold red]Invalid port spec:[/bold red] {exc}")
        return 2

    from .utils import COMMON_UDP_PORTS
    if args.udp_ports:
        udp_ports = parse_ports(args.udp_ports, top_n=cfg.top_ports)
    elif args.ports:
        # User gave an explicit -p spec: honor it for UDP too, that's
        # almost always what "scan these ports on both protocols" means.
        udp_ports = ports
    else:
        udp_ports = COMMON_UDP_PORTS

    logger.info(
        "Starting scan run_id=%s targets=%d ports=%d udp=%s concurrency=%d",
        run_id, len(targets), len(ports), args.udp, cfg.concurrency,
    )
    console.print(
        f"[bold]netscan-pro[/bold] v{__version__}  |  run [cyan]{run_id}[/cyan]  |  "
        f"{len(targets)} target(s), {len(ports)} TCP port(s)"
        + (f", {len(udp_ports)} UDP port(s)" if args.udp else "")
    )

    scanner = None
    total_units = len(targets) * (len(ports) + (len(udp_ports) if args.udp else 0))
    started = time.monotonic()
    results: list[HostResult] = []

    async def run_all():
        nonlocal scanner
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            console=console,
            disable=args.quiet,
        )
        with progress:
            task_id = progress.add_task("scanning", total=total_units)
            scanner = AsyncScanner(cfg, on_progress=lambda: progress.advance(task_id))
            for host in targets:
                hr = await _run_host(host, ports, udp_ports, scanner, cfg, args.udp)
                results.append(hr)
                open_count = len(hr.open_ports)
                logger.info(
                    "Host %s complete: %d open/open|filtered port(s) — os_guess=%s",
                    host, open_count, hr.os_guess,
                )

    try:
        asyncio.run(run_all())
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user.[/yellow]")
        logger.warning("Scan interrupted by user (run_id=%s)", run_id)
        return 130

    elapsed = time.monotonic() - started
    logger.info("Scan finished run_id=%s in %.2fs", run_id, elapsed)

    if not args.quiet:
        render_table(results)
        console.print(f"[dim]Completed in {elapsed:.2f}s — full log: logs/netscan.log (run_id={run_id})[/dim]")

    if args.output:
        fmt = args.format or ("json" if args.output.endswith(".json") else "csv" if args.output.endswith(".csv") else "json")
        write_output(results, args.output, fmt)
        console.print(f"[green]Results written to[/green] {args.output}")
        logger.info("Results exported to %s (%s)", args.output, fmt)

    return 0


if __name__ == "__main__":
    sys.exit(main())
