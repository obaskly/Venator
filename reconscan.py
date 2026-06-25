#!/usr/bin/env python3
"""Entry shim so the tool can be run as `python3 reconscan.py <target>`."""
from reconscan.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
