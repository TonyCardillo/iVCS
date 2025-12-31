"""Grid background widget"""

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor, QPainter, QPen
from PyQt5.QtWidgets import QWidget


class GridBackgroundWidget(QWidget):
	"""Widget that paints a grid background."""

	def __init__(self, parent=None):
		super().__init__(parent)
		self.grid_size = 20
		self.grid_color = QColor(26, 26, 46, 80)  # #1a1a2e with alpha
		self.setAutoFillBackground(False)
		self.setAttribute(Qt.WA_TransparentForMouseEvents)

	def paintEvent(self, event):
		"""Paint the grid background."""
		painter = QPainter(self)
		painter.setRenderHint(QPainter.Antialiasing, False)

		pen = QPen(self.grid_color)
		pen.setWidth(1)
		painter.setPen(pen)

		width = self.width()
		height = self.height()

		# Draw vertical lines
		for x in range(0, width, self.grid_size):
			painter.drawLine(x, 0, x, height)

		# Draw horizontal lines
		for y in range(0, height, self.grid_size):
			painter.drawLine(0, y, width, y)

		painter.end()
