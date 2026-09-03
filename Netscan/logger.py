"""
Centralized logging setup.

Provides a rotating file log (for audit/history) plus a colorized
console handler powered by `rich`. Every scan run gets a unique
correlation id so parallel runs / log greps stay unambiguous.
"""

from __future__ import annotations

import logging
import uuid
from logging.handlers import RotatingFileHandler
from pathlib import Path

from rich.logging import RichHandler

LOG_DIR = Path("logs")
LOG_FILE = LOG_DIR / "netscan.log"

_RUN_ID = uuid.uuid4().hex[:8]


class RunIdFilter(logging.Filter):
    """Injects the current run id into every log record."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.run_id = _RUN_ID
        return True


def get_run_id() -> str:
    return _RUN_ID


def setup_logging(verbosity: int = 1, log_file: Path | None = None) -> logging.Logger:
    """
    Configure and return the root 'netscan' logger.

    verbosity: 0 = warnings only, 1 = info, 2+ = debug
    """
    log_file = log_file or LOG_FILE
    log_file.parent.mkdir(parents=True, exist_ok=True)

    level = logging.WARNING
    if verbosity == 1:
        level = logging.INFO
    elif verbosity >= 2:
        level = logging.DEBUG

    logger = logging.getLogger("netscan")
    logger.setLevel(logging.DEBUG)  # handlers below filter individually
    logger.handlers.clear()

    # NOTE: the filter is attached to each *handler*, not the logger.
    # Records from child loggers (e.g. "netscan.engine") propagate up
    # and are dispatched straight to the ancestor's handlers, bypassing
    # the ancestor logger's own .filter() step — so a logger-level
    # filter would silently never run for child-logger records.
    run_id_filter = RunIdFilter()

    file_fmt = logging.Formatter(
        "%(asctime)s | run=%(run_id)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    file_handler = RotatingFileHandler(
        log_file, maxBytes=2_000_000, backupCount=5, encoding="utf-8"
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(file_fmt)
    file_handler.addFilter(run_id_filter)
    logger.addHandler(file_handler)

    console_handler = RichHandler(
        show_time=False, show_path=False, markup=True, rich_tracebacks=True
    )
    console_handler.setLevel(level)
    console_handler.setFormatter(logging.Formatter("%(message)s"))
    console_handler.addFilter(run_id_filter)
    logger.addHandler(console_handler)

    logger.debug("Logging initialized (run_id=%s, level=%s)", _RUN_ID, level)
    return logger
