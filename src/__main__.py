"""Entry point for `python -m src <command>` — delegates to the CLI dispatcher."""

import sys

from src.cli import main

if __name__ == "__main__":
	raise SystemExit(main(sys.argv[1:]))
