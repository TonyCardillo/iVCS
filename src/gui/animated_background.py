"""Animated grid background widget."""

import math

from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QColor, QPainter, QPen
from PyQt5.QtWidgets import QWidget


class AnimatedGridBackground(QWidget):
	"""Animated grid background with pulse effect."""

	def __init__(self, parent=None):
		super().__init__(parent)
		self.grid_size = 30  # Smaller grid for more visibility
		self.offset = 0
		self.pulse_phase = 0

		# Grid colors - much brighter
		self.grid_color = QColor(26, 35, 50, 100)  # Brighter base grid
		self.grid_accent = QColor(0, 212, 255, 80)  # Brighter cyan accent

		# Make widget transparent for mouse events
		self.setAttribute(Qt.WA_TransparentForMouseEvents)
		self.setAutoFillBackground(False)

		# Animation timer
		self.timer = QTimer()
		self.timer.timeout.connect(self._animate)
		self.timer.start(50)  # 20 FPS

	def _animate(self):
		"""Update animation state."""
		self.offset = (self.offset + 0.3) % self.grid_size  # Slower movement
		self.pulse_phase = (self.pulse_phase + 0.03) % (math.pi * 2)
		self.update()

	def paintEvent(self, event):
		"""Paint animated grid."""
		painter = QPainter(self)
		painter.setRenderHint(QPainter.Antialiasing, False)

		width = self.width()
		height = self.height()

		# Calculate pulse intensity
		pulse = 0.7 + 0.3 * math.sin(self.pulse_phase)

		# Draw base grid lines
		pen = QPen(self.grid_color)
		pen.setWidth(1)
		painter.setPen(pen)

		# Vertical lines - start from negative offset
		x = -self.offset
		while x <= width:
			painter.drawLine(int(x), 0, int(x), height)
			x += self.grid_size

		# Horizontal lines - start from negative offset
		y = -self.offset
		while y <= height:
			painter.drawLine(0, int(y), width, int(y))
			y += self.grid_size

		# Draw accent lines (every 4th line with pulse)
		accent_alpha = int(80 * pulse)
		accent_color = QColor(0, 212, 255, accent_alpha)
		pen = QPen(accent_color)
		pen.setWidth(1)
		painter.setPen(pen)

		# Vertical accents
		x = -self.offset
		i = 0
		while x <= width:
			if i % 4 == 0:
				painter.drawLine(int(x), 0, int(x), height)
			x += self.grid_size
			i += 1

		# Horizontal accents
		y = -self.offset
		i = 0
		while y <= height:
			if i % 4 == 0:
				painter.drawLine(0, int(y), width, int(y))
			y += self.grid_size
			i += 1

		painter.end()
