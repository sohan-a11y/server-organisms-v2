#!/usr/bin/env python3
"""Adopt helper (thin wrapper). Prefer:  python -m organisms init <repo>

Scans a repo and prints its APIs; writes the adoption kit via the CLI.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from organisms.cli import main as _cli_main  # noqa: E402


def scan(root):
    from organisms import scanner

    return scanner.scan(root)


if __name__ == "__main__":
    # `tools/adopt.py <repo> [--out adoption]` -> `organisms init <repo>`
    argv = ["init"] + [a for a in sys.argv[1:] if a != "--out" and not a.startswith("adoption")]
    sys.exit(_cli_main(argv))
