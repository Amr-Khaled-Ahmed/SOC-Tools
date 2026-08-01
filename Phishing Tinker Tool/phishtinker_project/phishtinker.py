#!/usr/bin/env python3
"""Convenience launcher for the phishtinker package.

Behavior:
- If given one or more .eml files as arguments, runs in headless CLI mode (safe for servers).
- If run with no arguments, launches the GUI (python -m phishtinker behavior) — but only when a display is available and not running as root.

This launcher adds helpful checks so running the GUI as root or in a headless environment prints a clear message instead of crashing.
"""

import os
import sys
import runpy


def _print_env_advice():
    print("Refusing to launch the GUI in this environment.")
    print()
    print("Likely reasons:")
    print(
        " - Running as root (sudo). GUI apps should not be run as root; run without sudo instead."
    )
    print(
        " - No DISPLAY available (headless environment). Use the CLI mode instead: 'python3 phishtinker.py samples/sample_phish.eml'"
    )
    print()
    print("Examples:")
    print(
        "  # Run headless analysis on a sample email:\n  python3 phishtinker.py samples/sample_phish.eml"
    )
    print(
        "  # Launch GUI on a desktop session (do NOT use sudo):\n  python3 phishtinker.py"
    )


if __name__ == "__main__":
    # If files provided, run package as module (CLI mode will run when __main__ is executed)
    if len(sys.argv) > 1:
        runpy.run_module("phishtinker", run_name="__main__")
        sys.exit(0)

    # No args: intend to launch GUI. Check for environment suitability.
    is_root = False
    try:
        is_root = os.geteuid() == 0
    except AttributeError:
        # Windows or platform without geteuid
        is_root = False

    display = os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")

    if is_root or not display:
        _print_env_advice()
        sys.exit(1)

    # Otherwise safe to call package main which launches GUI
    runpy.run_module("phishtinker", run_name="__main__")
