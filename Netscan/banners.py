"""
Active banner grabbing.

Some services announce themselves the moment a TCP connection opens
(SSH, FTP, SMTP...). Others are silent until spoken to (HTTP, and many
custom TCP protocols). We keep a small table of "nudge" probes for the
silent ones and otherwise just listen for the first bytes sent.
"""

from __future__ import annotations

import asyncio
import re

# Ports that expect a request before they'll say anything.
_ACTIVE_PROBES: dict[int, bytes] = {
    80: b"HEAD / HTTP/1.1\r\nHost: %HOST%\r\nConnection: close\r\n\r\n",
    8080: b"HEAD / HTTP/1.1\r\nHost: %HOST%\r\nConnection: close\r\n\r\n",
    8000: b"HEAD / HTTP/1.1\r\nHost: %HOST%\r\nConnection: close\r\n\r\n",
    8443: b"HEAD / HTTP/1.1\r\nHost: %HOST%\r\nConnection: close\r\n\r\n",
    443: b"HEAD / HTTP/1.1\r\nHost: %HOST%\r\nConnection: close\r\n\r\n",
    443: b"",  # TLS handshake needed for a clean banner; left silent on purpose
}

_SERVER_HEADER_RE = re.compile(rb"^Server:\s*(.+?)\r?$", re.IGNORECASE | re.MULTILINE)


def _clean(raw: bytes, limit: int = 200) -> str:
    text = raw.decode("utf-8", errors="replace").strip()
    text = text.replace("\r", " ").replace("\n", " | ")
    return text[:limit]


async def grab_banner(host: str, port: int, timeout: float) -> str | None:
    """
    Attempt to retrieve a service banner from an already-known-open port.
    Returns a cleaned, single-line string, or None if nothing was read.
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
    except (asyncio.TimeoutError, OSError):
        return None

    try:
        probe = _ACTIVE_PROBES.get(port)
        if probe:
            writer.write(probe.replace(b"%HOST%", host.encode()))
            await writer.drain()

        try:
            data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
        except asyncio.TimeoutError:
            data = b""

        if not data:
            return None

        match = _SERVER_HEADER_RE.search(data)
        if match:
            return f"HTTP Server: {_clean(match.group(1))}"
        return _clean(data)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (OSError, asyncio.CancelledError):
            pass


def guess_service(port: int, banner: str | None) -> str:
    """Best-effort service label combining a well-known port table with
    keyword hints found in the banner."""
    well_known = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
        80: "http", 110: "pop3", 111: "rpcbind", 123: "ntp", 135: "msrpc",
        139: "netbios-ssn", 143: "imap", 161: "snmp", 179: "bgp",
        389: "ldap", 443: "https", 445: "microsoft-ds", 465: "smtps",
        587: "smtp-submission", 631: "ipp", 636: "ldaps", 993: "imaps",
        995: "pop3s", 1433: "mssql", 1521: "oracle", 2049: "nfs",
        27017: "mongodb", 3000: "dev-http", 3306: "mysql", 3389: "rdp",
        5000: "dev-http", 5432: "postgresql", 5900: "vnc", 5985: "winrm",
        6379: "redis", 6443: "kubernetes-api", 8000: "dev-http",
        8080: "http-proxy", 8443: "https-alt", 9200: "elasticsearch",
        27018: "mongodb",
    }
    label = well_known.get(port, "unknown")
    if banner:
        b = banner.lower()
        if "ssh-" in b:
            return "ssh"
        if "220" in b and ("ftp" in b or "smtp" in b):
            return "ftp/smtp"
        if "http" in b or "server:" in b:
            return "http"
        if "mysql" in b:
            return "mysql"
    return label
