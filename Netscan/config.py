"""
Configuration handling.

Precedence (highest wins): CLI flags > config file (--config) > defaults.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

import yaml

DEFAULTS: dict[str, Any] = {
    "concurrency": 500,          # max simultaneous connection attempts
    "connect_timeout": 1.2,      # seconds, per-port TCP connect
    "udp_timeout": 1.5,          # seconds, per-port UDP response wait
    "banner_timeout": 1.5,       # seconds, waiting for a service banner
    "retries": 1,                # UDP retransmits (UDP is unreliable)
    "top_ports": 1000,           # used when --ports is omitted
    "rate_limit": 0,             # packets/sec throttle, 0 = unlimited
    "resolve_hostnames": True,
    "os_fingerprint": True,
    "output_format": "table",    # table | json | csv
}


@dataclass
class ScanConfig:
    concurrency: int = DEFAULTS["concurrency"]
    connect_timeout: float = DEFAULTS["connect_timeout"]
    udp_timeout: float = DEFAULTS["udp_timeout"]
    banner_timeout: float = DEFAULTS["banner_timeout"]
    retries: int = DEFAULTS["retries"]
    top_ports: int = DEFAULTS["top_ports"]
    rate_limit: int = DEFAULTS["rate_limit"]
    resolve_hostnames: bool = DEFAULTS["resolve_hostnames"]
    os_fingerprint: bool = DEFAULTS["os_fingerprint"]
    output_format: str = DEFAULTS["output_format"]

    @classmethod
    def load(cls, path: str | None) -> "ScanConfig":
        data = dict(DEFAULTS)
        if path:
            p = Path(path)
            if not p.exists():
                raise FileNotFoundError(f"Config file not found: {path}")
            with p.open("r", encoding="utf-8") as fh:
                user_cfg = yaml.safe_load(fh) or {}
            data.update({k: v for k, v in user_cfg.items() if k in DEFAULTS})
        return cls(**data)

    def apply_overrides(self, **overrides: Any) -> "ScanConfig":
        """Return a new ScanConfig with non-None overrides applied (CLI wins)."""
        current = asdict(self)
        for k, v in overrides.items():
            if v is not None and k in current:
                current[k] = v
        return ScanConfig(**current)
