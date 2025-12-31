"""Corner bracket overlay widget."""

from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QColor, QPainter, QPen
from PyQt5.QtWidgets import QWidget


class CornerBrackets(QWidget):
	"""Animated corner brackets overlay."""

	def __init__(self, parent=None):
		super().__init__(parent)
		self.bracket_size = 20
		self.animation_progress = 0
		self.max_size = 20

		# Bracket color
		self.color = QColor(0, 212, 255, 180)

		# Make transparent for mouse events
		self.setAttribute(Qt.WA_TransparentForMouseEvents)
		self.setAutoFillBackground(False)

		# Animation timer
		self.timer = QTimer()
		self.timer.timeout.connect(self._animate)
		self.timer.start(30)  # ~33 FPS

	def _animate(self):
		"""Animate bracket drawing."""
		if self.animation_progress < 1.0:
			self.animation_progress += 0.05
			self.update()

	def reset_animation(self):
		"""Reset bracket animation."""
		self.animation_progress = 0

	def paintEvent(self, event):
		"""Paint corner brackets."""
		painter = QPainter(self)
		painter.setRenderHint(QPainter.Antialiasing, True)

		pen = QPen(self.color)
		pen.setWidth(2)
		painter.setPen(pen)

		width = self.width()
		height = self.height()
		size = int(self.bracket_size * min(1.0, self.animation_progress))

		# Top-left corner
		painter.drawLine(0, size, 0, 0)
		painter.drawLine(0, 0, size, 0)

		# Top-right corner
		painter.drawLine(width - size, 0, width, 0)
		painter.drawLine(width, 0, width, size)

		# Bottom-left corner
		painter.drawLine(0, height - size, 0, height)
		painter.drawLine(0, height, size, height)

		# Bottom-right corner
		painter.drawLine(width - size, height, width, height)
		painter.drawLine(width, height, width, height - size)

		painter.end()
