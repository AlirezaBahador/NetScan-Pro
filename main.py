#!/usr/bin/env python3
"""Thin entry point so the tool can be run as `python main.py ...`."""
import sys

from netscan.cli import main

if __name__ == "__main__":
    sys.exit(main())

