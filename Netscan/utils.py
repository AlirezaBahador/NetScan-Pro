"""
Parsing helpers: port ranges, target specs (single IP, CIDR, hostname, file list).
"""

from __future__ import annotations

import ipaddress
import socket
from pathlib import Path

# The 1000 most commonly open TCP ports, condensed (nmap-style "top ports"
# philosophy without shipping nmap's exact proprietary frequency table).
TOP_1000_TCP = sorted(set(
    list(range(1, 26)) + [
        37, 42, 43, 49, 53, 67, 68, 69, 70, 79, 80, 81, 82, 88, 100, 106,
        109, 110, 111, 113, 119, 123, 135, 137, 138, 139, 143, 144, 179,
        199, 209, 210, 211, 212, 213, 214, 220, 259, 264, 311, 366, 389,
        406, 407, 416, 417, 425, 427, 443, 444, 445, 458, 464, 465, 481,
        497, 500, 512, 513, 514, 515, 524, 541, 543, 544, 545, 548, 554,
        556, 587, 593, 616, 617, 625, 631, 636, 646, 648, 666, 667, 668,
        683, 687, 691, 700, 705, 711, 714, 720, 722, 726, 749, 765, 777,
        783, 787, 800, 801, 808, 843, 873, 880, 888, 898, 900, 901, 902,
        903, 911, 912, 981, 987, 990, 992, 993, 995, 999, 1000, 1001,
        1010, 1023, 1024, 1025, 1026, 1027, 1028, 1029, 1080, 1099, 1109,
        1194, 1200, 1201, 1234, 1241, 1248, 1300, 1311, 1352, 1433, 1434,
        1521, 1720, 1723, 1755, 1801, 1900, 1935, 1998, 2000, 2001, 2049,
        2082, 2083, 2100, 2103, 2121, 2181, 2222, 2323, 2375, 2376, 2379,
        2401, 2404, 2601, 2717, 2725, 2869, 2967, 3000, 3001, 3128, 3260,
        3268, 3269, 3283, 3306, 3307, 3389, 3390, 3396, 3689, 3690, 3703,
        3986, 4000, 4001, 4045, 4111, 4443, 4444, 4500, 4567, 4664, 4712,
        4899, 5000, 5001, 5002, 5060, 5061, 5222, 5269, 5354, 5357, 5432,
        5555, 5601, 5666, 5672, 5800, 5900, 5901, 5984, 5985, 5986, 6000,
        6001, 6379, 6443, 6446, 6465, 6500, 6566, 6646, 6666, 6667, 6668,
        6669, 6679, 6697, 6699, 6881, 6969, 7000, 7001, 7070, 7077, 7080,
        7100, 7170, 7443, 7474, 7547, 7777, 7778, 8000, 8001, 8008, 8009,
        8010, 8020, 8025, 8060, 8080, 8081, 8082, 8083, 8086, 8087, 8088,
        8089, 8090, 8091, 8093, 8098, 8140, 8180, 8181, 8222, 8243, 8280,
        8281, 8333, 8383, 8443, 8500, 8530, 8531, 8600, 8649, 8686, 8765,
        8834, 8880, 8888, 8899, 8983, 9000, 9001, 9002, 9009, 9042, 9043,
        9090, 9091, 9092, 9100, 9151, 9200, 9300, 9418, 9443, 9500, 9535,
        9575, 9600, 9800, 9898, 9900, 9917, 9929, 9943, 9944, 9968, 9999,
        10000, 10001, 10009, 10050, 10051, 10250, 10255, 10999, 11211,
        12000, 12345, 13456, 14000, 15000, 16000, 16992, 16993, 17000,
        18000, 18081, 19000, 19132, 20000, 20005, 21571, 22105, 22222,
        24444, 24800, 25000, 25105, 25565, 27000, 27015, 27017, 27018,
        27019, 28017, 30000, 31337, 32400, 32764, 32768, 33060, 33389,
        34571, 34572, 34573, 37777, 40000, 41795, 44134, 44818, 45554,
        49152, 49153, 49154, 49155, 49156, 49157, 50000, 50030, 50060,
        50070, 50075, 54321, 55553, 60000, 61616, 62078,
    ]
))[:1000]

COMMON_UDP_PORTS = sorted([
    7, 9, 17, 19, 49, 53, 67, 68, 69, 88, 111, 120, 123, 135, 136, 137,
    138, 139, 161, 162, 177, 213, 260, 315, 316, 500, 514, 517, 518, 520,
    623, 626, 631, 996, 997, 998, 999, 1022, 1023, 1025, 1026, 1027, 1028,
    1029, 1030, 1433, 1434, 1645, 1646, 1701, 1812, 1813, 1900, 2000,
    2048, 2049, 2222, 3283, 3389, 3456, 3703, 4444, 4500, 5000, 5060,
    5353, 5632, 5683, 6481, 9200, 10000, 17185, 20031, 30718, 31337,
    32768, 32815, 33281,
])


def parse_ports(spec: str | None, top_n: int = 1000) -> list[int]:
    """
    Parse a port spec like '22,80,443' or '1-1024' or '1-65535' or
    'top-100'. Returns a sorted, de-duplicated list.
    """
    if not spec:
        return TOP_1000_TCP[:top_n]

    spec = spec.strip().lower()
    if spec in ("all", "1-65535"):
        return list(range(1, 65536))
    if spec.startswith("top-"):
        n = int(spec.split("-", 1)[1])
        return TOP_1000_TCP[: min(n, len(TOP_1000_TCP))]

    ports: set[int] = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start, end = chunk.split("-", 1)
            start_i, end_i = int(start), int(end)
            if not (0 < start_i <= end_i <= 65535):
                raise ValueError(f"Invalid port range: {chunk}")
            ports.update(range(start_i, end_i + 1))
        else:
            p = int(chunk)
            if not (0 < p <= 65535):
                raise ValueError(f"Invalid port: {p}")
            ports.add(p)
    return sorted(ports)


def expand_targets(spec: str) -> list[str]:
    """
    Expand a target spec into a flat list of IP strings.
    Accepts: single IP, hostname, CIDR (e.g. 10.0.0.0/28), or an
    '@filename' pointing at a newline-delimited target list.
    """
    spec = spec.strip()

    if spec.startswith("@"):
        path = Path(spec[1:])
        if not path.exists():
            raise FileNotFoundError(f"Target list file not found: {path}")
        targets: list[str] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                targets.extend(expand_targets(line))
        return targets

    try:
        network = ipaddress.ip_network(spec, strict=False)
        if network.num_addresses > 1:
            return [str(ip) for ip in network.hosts()] or [str(network.network_address)]
        return [str(network.network_address)]
    except ValueError:
        pass

    # Hostname -> resolve to an IP (kept as-is if resolution fails; the
    # scanner will surface the connection error).
    try:
        resolved = socket.gethostbyname(spec)
        return [resolved]
    except socket.gaierror:
        return [spec]
