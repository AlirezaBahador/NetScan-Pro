"""
Core scan engine.

Design notes:
  * TCP scanning uses asyncio.open_connection (a real 3-way handshake
    "connect scan" — no raw sockets, so it runs without root, unlike a
    classic SYN scan).
  * UDP scanning uses asyncio DatagramProtocol. UDP has no handshake,
    so "open" is inferred from *either* a response payload, *or* the
    absence of an ICMP port-unreachable within the timeout window
    (open|filtered — the same ambiguity every UDP scanner has to
    report honestly).
  * Concurrency is bounded by an asyncio.Semaphore sized from config,
    not by spawning one OS thread per port — this is what lets a single
    process comfortably probe thousands of ports without exhausting
    file descriptors or RAM.
  * An optional token-bucket rate limiter throttles total packets/sec
    when scanning against sensitive or low-bandwidth targets.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import time
from dataclasses import dataclass, field
from enum import Enum

from .banners import grab_banner, guess_service
from .config import ScanConfig

logger = logging.getLogger("netscan.engine")


class PortState(str, Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    OPEN_FILTERED = "open|filtered"


@dataclass
class PortResult:
    host: str
    port: int
    proto: str
    state: PortState
    service: str = "unknown"
    banner: str | None = None
    latency_ms: float | None = None


@dataclass
class HostResult:
    host: str
    tcp: list[PortResult] = field(default_factory=list)
    udp: list[PortResult] = field(default_factory=list)
    os_guess: str | None = None

    @property
    def open_ports(self) -> list[PortResult]:
        return [p for p in self.tcp + self.udp if p.state in (PortState.OPEN, PortState.OPEN_FILTERED)]


class _RateLimiter:
    """Simple token-bucket limiter; no-op when rate <= 0."""

    def __init__(self, rate_per_sec: int):
        self.rate = rate_per_sec
        self._lock = asyncio.Lock()
        self._tokens = float(rate_per_sec)
        self._last = time.monotonic()

    async def acquire(self):
        if self.rate <= 0:
            return
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last
            self._last = now
            self._tokens = min(self.rate, self._tokens + elapsed * self.rate)
            if self._tokens < 1:
                wait = (1 - self._tokens) / self.rate
                await asyncio.sleep(wait)
                self._tokens = 0
            else:
                self._tokens -= 1


class AsyncScanner:
    def __init__(self, cfg: ScanConfig, on_progress=None):
        self.cfg = cfg
        self.sem = asyncio.Semaphore(cfg.concurrency)
        self.limiter = _RateLimiter(cfg.rate_limit)
        self.on_progress = on_progress or (lambda: None)

    # ---------------------------------------------------------------- TCP

    async def _scan_tcp_port(self, host: str, port: int) -> PortResult:
        async with self.sem:
            await self.limiter.acquire()
            start = time.monotonic()
            try:
                fut = asyncio.open_connection(host, port)
                reader, writer = await asyncio.wait_for(fut, timeout=self.cfg.connect_timeout)
                latency = (time.monotonic() - start) * 1000
                writer.close()
                try:
                    await writer.wait_closed()
                except (OSError, asyncio.CancelledError):
                    pass

                banner = await grab_banner(host, port, self.cfg.banner_timeout)
                service = guess_service(port, banner)
                logger.debug("TCP %s:%d OPEN (%.1fms) service=%s", host, port, latency, service)
                result = PortResult(
                    host=host, port=port, proto="tcp", state=PortState.OPEN,
                    service=service, banner=banner, latency_ms=round(latency, 1),
                )
            except asyncio.TimeoutError:
                result = PortResult(host=host, port=port, proto="tcp", state=PortState.FILTERED)
            except ConnectionRefusedError:
                result = PortResult(host=host, port=port, proto="tcp", state=PortState.CLOSED)
            except OSError as exc:
                logger.debug("TCP %s:%d error: %s", host, port, exc)
                result = PortResult(host=host, port=port, proto="tcp", state=PortState.FILTERED)
            self.on_progress()
            return result

    async def scan_tcp(self, host: str, ports: list[int]) -> list[PortResult]:
        tasks = [self._scan_tcp_port(host, p) for p in ports]
        return await asyncio.gather(*tasks)

    # ---------------------------------------------------------------- UDP

    async def _scan_udp_port(self, host: str, port: int) -> PortResult:
        async with self.sem:
            await self.limiter.acquire()
            loop = asyncio.get_running_loop()

            class _Proto(asyncio.DatagramProtocol):
                def __init__(self):
                    self.data: bytes | None = None
                    self.done = asyncio.Event()
                    self.refused = False

                def datagram_received(self, data, addr):
                    self.data = data
                    self.done.set()

                def error_received(self, exc):
                    # ICMP port-unreachable surfaces here on most platforms
                    self.refused = True
                    self.done.set()

            probe = _UDP_PROBES.get(port, b"\x00")
            state = PortState.OPEN_FILTERED
            banner = None

            for attempt in range(self.cfg.retries + 1):
                try:
                    transport, proto = await loop.create_datagram_endpoint(
                        _Proto, remote_addr=(host, port)
                    )
                except OSError:
                    return PortResult(host=host, port=port, proto="udp", state=PortState.FILTERED)

                try:
                    transport.sendto(probe)
                    try:
                        await asyncio.wait_for(proto.done.wait(), timeout=self.cfg.udp_timeout)
                    except asyncio.TimeoutError:
                        continue  # retry or fall through to open|filtered
                    if proto.refused:
                        state = PortState.CLOSED
                    elif proto.data is not None:
                        state = PortState.OPEN
                        banner = proto.data.decode("utf-8", errors="replace").strip()[:200]
                    break
                finally:
                    transport.close()

            service = guess_service(port, banner)
            self.on_progress()
            return PortResult(
                host=host, port=port, proto="udp", state=state,
                service=service, banner=banner,
            )

    async def scan_udp(self, host: str, ports: list[int]) -> list[PortResult]:
        tasks = [self._scan_udp_port(host, p) for p in ports]
        return await asyncio.gather(*tasks)


# A handful of well-known UDP services actually reply to a specific
# payload; sending 0x00 to everything else just tests reachability.
_UDP_PROBES: dict[int, bytes] = {
    53: bytes.fromhex(
        "0001010000010000000000000000060676657273696f6e0462696e640000100003"
    ),  # DNS "version.bind" CHAOS TXT query — widely used, harmless
    123: b"\x1b" + b"\x00" * 47,  # NTP client request
    161: bytes.fromhex(
        "302602010004067075626c6963a019020400000000020100020100300b300906052b0601020101"
    ),  # minimal SNMP v1 GetRequest for sysDescr-ish OID probing
}
