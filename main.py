#!/usr/bin/env python3
"""iVCS - Intelligent Visual Coding System entry point."""

import sys

from src.gui.app import iVCSApp


def main():
	app = iVCSApp(sys.argv)
	return app.exec_()


if __name__ == "__main__":
	sys.exit(main())
