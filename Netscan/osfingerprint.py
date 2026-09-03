"""
Lightweight OS fingerprinting.

This is intentionally *not* a full TCP/IP stack fingerprinting engine
(that's what nmap's -O / p0f exist for, and requires raw sockets +
root). Instead we use a cheap, portable, unprivileged heuristic:

  1. Send an ICMP echo (ping) and read the reply TTL.
  2. Compare against the initial-TTL values operating systems typically
     ship with (they hop-decrement from a fixed starting value, so the
     *observed* TTL plus a small margin tells us the likely starting
     value even a few hops away).

This is a best-effort guess, not ground truth — real networks have
asymmetric routing, TTL-rewriting middleboxes, and custom sysctls that
will fool any TTL-only heuristic. We label the result "guess" in the
UI for that reason.
"""

from __future__ import annotations

import asyncio
import re
import shutil

# Common default initial TTLs. Observed TTL will be initial - hop_count,
# so we bucket by "nearest initial value at or above observed".
_INITIAL_TTL_TABLE = [
    (255, "Cisco IOS / Solaris / older network gear"),
    (128, "Windows"),
    (64, "Linux / macOS / most BSD / modern network gear"),
    (32, "Legacy Windows (very old) / some embedded devices"),
]

_TTL_RE = re.compile(r"ttl[=\s](\d+)", re.IGNORECASE)


def _bucket_ttl(observed: int) -> str:
    for initial, label in _INITIAL_TTL_TABLE:
        if observed <= initial:
            hops = initial - observed
            return f"{label} (initial TTL≈{initial}, ~{hops} hop(s) away)"
    return f"Unknown stack (raw TTL={observed})"


async def fingerprint_os(host: str, timeout: float = 1.5) -> str:
    """
    Best-effort OS guess using ICMP TTL. Falls back gracefully (and
    honestly) when ping is unavailable or ICMP is filtered/blocked,
    which is extremely common on hardened hosts and most cloud
    firewalls — that is reported as a real outcome, not an error.
    """
    ping_bin = shutil.which("ping")
    if not ping_bin:
        return "unavailable (no 'ping' binary on this system)"

    cmd = [ping_bin, "-c", "1", "-W", str(max(1, int(timeout))), host]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout + 1)
    except (asyncio.TimeoutError, PermissionError, OSError):
        return "no ICMP reply (filtered, unreachable, or ping lacks raw-socket privilege)"

    text = stdout.decode(errors="ignore")
    match = _TTL_RE.search(text)
    if not match:
        return "no ICMP reply (host filters ping or is unreachable)"

    return _bucket_ttl(int(match.group(1)))
