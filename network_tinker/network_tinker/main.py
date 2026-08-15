"""GUI entry point.

Usage:
    python -m network_tinker.main
    python -m network_tinker.main capture.pcap    # opens it immediately
"""
import sys


def main():
    from .gui.app import launch
    initial = sys.argv[1] if len(sys.argv) > 1 else None
    launch(initial_pcap=initial)


if __name__ == "__main__":
    main()
