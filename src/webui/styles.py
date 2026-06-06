"""Static presentation assets: the page stylesheet location and the ASCII logo.

The CSS lives in `static/app.css` (a real stylesheet, served once via
`GET /static/app.css`) rather than a Python string re-sent inline on every page.
"""

from __future__ import annotations

from pathlib import Path

STATIC_DIR = Path(__file__).parent / "static"
APP_CSS_PATH = STATIC_DIR / "app.css"
APP_CSS_HREF = "/static/app.css"

LOGO = """\
 ┌──────────────────────────────────────────┐
 │  ░▒▓  i V C S  ▓▒░    matching-decomp    │
 │  └─ xbe · carver · coff · agent-loop ─┘  │
 └──────────────────────────────────────────┘"""
