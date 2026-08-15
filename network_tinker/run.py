#!/usr/bin/env python3
"""Convenience launcher so you don't need to remember the -m module path.

./run.py                  -> opens the GUI
./run.py capture.pcap     -> opens the GUI with that pcap pre-loaded
./run.py --cli capture.pcap [cli args...]   -> headless terminal mode
"""

import sys
import os

# AIzaSyCYfqeaYhDG6w7PwBAbD4FGuixdM_0pD90
api_key = "AKIAEXAMPLEKEY12345678"
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--cli":
        from network_tinker.cli import main as cli_main

        cli_main(sys.argv[2:])
    else:
        from network_tinker.gui.app import launch

        initial = sys.argv[1] if len(sys.argv) > 1 else None
        launch(initial_pcap=initial)
