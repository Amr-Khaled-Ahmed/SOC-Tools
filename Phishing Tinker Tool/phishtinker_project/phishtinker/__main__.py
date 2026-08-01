"""
python -m phishtinker            -> launch GUI
python -m phishtinker file.eml   -> headless CLI analysis
"""
import sys


def main():
    if len(sys.argv) > 1:
        from .cli import main as cli_main
        cli_main()
    else:
        from .gui.app import run
        run()


if __name__ == "__main__":
    main()
