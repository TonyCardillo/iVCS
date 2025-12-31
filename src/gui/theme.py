"""tech theme"""

BG_DARK = "#050508"  # Deep space black
BG_PANEL = "#0a0a12"  # Panel background
BG_HIGHLIGHT = "#12121f"  # Highlighted panels
CYAN = "#00d4ff"  # Primary accent
CYAN_BRIGHT = "#00e5ff"  # Brighter cyan for emphasis
CYAN_GLOW = "#00d4ff80"  # Cyan glow (50% opacity)
CYAN_DIM = "#00d4ff20"  # Dim cyan for subtle elements
ORANGE = "#ff6b35"  # Alert/secondary accent
ORANGE_GLOW = "#ff6b3560"  # Orange glow
TEXT = "#e8e8e8"  # Bright text
TEXT_DIM = "#6a7a8a"  # Dimmed text
BORDER = "#1a2030"  # Subtle borders
GRID = "#0f1520"  # Grid lines


def get_stylesheet():
	"""Get Qt stylesheet for interface."""
	return f"""
QMainWindow {{
	background-color: {BG_DARK};
}}

QWidget {{
	font-family: "Consolas", "Courier New", "DejaVu Sans Mono", monospace;
	font-size: 11pt;
	letter-spacing: 0.3px;
}}

QTextEdit, QPlainTextEdit {{
	background-color: {BG_PANEL};
	color: {TEXT};
	border-left: 3px solid {CYAN};
	border-top: 1px solid {BORDER};
	border-right: 1px solid {BORDER};
	border-bottom: 1px solid {BORDER};
	border-radius: 0px;
	padding: 10px 12px;
	font-family: "Consolas", "Courier New", monospace;
	font-size: 10pt;
	selection-background-color: {CYAN};
	selection-color: {BG_DARK};
	line-height: 1.5;
}}

QTextEdit:focus, QPlainTextEdit:focus {{
	border-left: 3px solid {CYAN_BRIGHT};
	background-color: {BG_HIGHLIGHT};
}}

QLineEdit {{
	background-color: {BG_PANEL};
	color: {CYAN_BRIGHT};
	border: 1px solid {CYAN};
	border-left: 3px solid {CYAN};
	border-radius: 0px;
	padding: 8px 12px;
	font-family: "Consolas", "Courier New", monospace;
	font-size: 11pt;
	font-weight: bold;
	letter-spacing: 1px;
}}

QLineEdit:focus {{
	border-left: 3px solid {CYAN_BRIGHT};
	background-color: {BG_HIGHLIGHT};
	color: {CYAN_BRIGHT};
}}

QPushButton {{
	background: qlineargradient(
		x1:0, y1:0, x2:0, y2:1,
		stop:0 {BG_HIGHLIGHT}, stop:1 {BG_PANEL}
	);
	color: {CYAN};
	border: 2px solid {CYAN};
	border-radius: 0px;
	padding: 10px 24px;
	font-family: "Consolas", "Courier New", monospace;
	font-size: 10pt;
	font-weight: bold;
	text-transform: uppercase;
	letter-spacing: 2px;
	min-height: 20px;
}}

QPushButton:hover {{
	background: {CYAN};
	color: {BG_DARK};
	border: 2px solid {CYAN_BRIGHT};
}}

QPushButton:pressed {{
	background: {CYAN_BRIGHT};
	color: {BG_DARK};
	border: 2px solid {CYAN_BRIGHT};
}}

QLabel {{
	color: {TEXT_DIM};
	font-family: "Consolas", "Courier New", monospace;
	font-size: 9pt;
	font-weight: bold;
	text-transform: uppercase;
	letter-spacing: 2px;
	background: transparent;
}}

QListWidget {{
	background-color: {BG_PANEL};
	color: {TEXT};
	border-left: 3px solid {CYAN};
	border-top: 1px solid {BORDER};
	border-right: 1px solid {BORDER};
	border-bottom: 1px solid {BORDER};
	padding: 6px;
	font-family: "Consolas", "Courier New", monospace;
	font-size: 10pt;
}}

QListWidget::item {{
	padding: 6px;
	border-bottom: 1px solid {BORDER};
}}

QListWidget::item:selected {{
	background-color: {CYAN_GLOW};
	color: {TEXT};
	border-left: 3px solid {CYAN_BRIGHT};
}}

QListWidget::item:hover {{
	background-color: {CYAN_DIM};
}}

QScrollBar:vertical {{
	background-color: {BG_DARK};
	width: 10px;
	border: none;
	margin: 0px;
}}

QScrollBar::handle:vertical {{
	background-color: {CYAN};
	min-height: 30px;
	border-radius: 0px;
	margin: 2px;
}}

QScrollBar::handle:vertical:hover {{
	background-color: {CYAN_BRIGHT};
}}

QScrollBar::handle:vertical:pressed {{
	background-color: {ORANGE};
}}

QScrollBar:horizontal {{
	background-color: {BG_DARK};
	height: 10px;
	border: none;
	margin: 0px;
}}

QScrollBar::handle:horizontal {{
	background-color: {CYAN};
	min-width: 30px;
	border-radius: 0px;
	margin: 2px;
}}

QScrollBar::handle:horizontal:hover {{
	background-color: {CYAN_BRIGHT};
}}

QScrollBar::handle:horizontal:pressed {{
	background-color: {ORANGE};
}}

QScrollBar::add-line, QScrollBar::sub-line {{
	background: none;
	border: none;
	width: 0px;
	height: 0px;
}}

QScrollBar::add-page, QScrollBar::sub-page {{
	background: none;
}}

QStatusBar {{
	background-color: {BG_PANEL};
	color: {TEXT_DIM};
	border-top: 1px solid {CYAN};
	font-family: "Consolas", "Courier New", monospace;
	font-size: 9pt;
	padding: 4px;
}}
"""
