"""Main iVCS application window."""

import math
from enum import Enum

from PyQt5.QtCore import QThread, QTimer, pyqtSignal
from PyQt5.QtGui import QColor, QTextCharFormat, QTextCursor
from PyQt5.QtWidgets import (
	QApplication,
	QFileDialog,
	QHBoxLayout,
	QLabel,
	QLineEdit,
	QMainWindow,
	QPushButton,
	QTextEdit,
	QVBoxLayout,
	QWidget,
)

from src.agent import DecompilationAgent, DecompilationResult
from src.cfg import CFGExtractor
from src.decoder import Decoder
from src.gui.animated_background import AnimatedGridBackground
from src.gui.corner_brackets import CornerBrackets
from src.gui.theme import get_stylesheet
from src.loader import BinaryLoader
from src.verifier import BinaryVerifier


class AppState(Enum):
	"""Application state for status indicator."""

	ANALYZING = ("◉ ANALYZING...", "#ff6b35")
	ACTIVE = ("◉ ACTIVE", "#00d4ff")
	DECOMPILING = ("◉ DECOMPILING...", "#ff6b35")
	SUCCESS = ("◉ SUCCESS", "#00ff00")
	PARTIAL = ("◉ PARTIAL", "#ffaa00")
	ERROR = ("◉ ERROR", "#ff0000")

	def __init__(self, label: str, color: str):
		self.label = label
		self.color = color


class DecompilationWorker(QThread):
	"""Worker thread for running decompilation without blocking GUI."""

	progress = pyqtSignal(int, int)
	iteration_complete = pyqtSignal(int, str, object)
	finished = pyqtSignal(object)
	error = pyqtSignal(str)

	def __init__(self, agent: DecompilationAgent, binary: bytes, base_address: int, max_iterations: int = 2):
		"""Initialize worker.

		Args:
			agent: DecompilationAgent instance
			binary: Binary data to decompile
			base_address: Base address for disassembly
			max_iterations: Maximum refinement iterations
		"""
		super().__init__()
		self.agent = agent
		self.binary = binary
		self.base_address = base_address
		self.max_iterations = max_iterations

	def run(self):
		"""Run decompilation in background thread."""
		try:
			self.progress.emit(0, self.max_iterations)

			def on_iteration(iteration, c_code, verification):
				self.iteration_complete.emit(iteration, c_code, verification)

			result = self.agent.decompile(
				self.binary,
				max_iterations=self.max_iterations,
				base_address=self.base_address,
				progress_callback=on_iteration,
			)

			self.finished.emit(result)

		except Exception as e:
			self.error.emit(str(e))


class iVCSApp(QApplication):
	"""Main application class."""

	def __init__(self, argv):
		super().__init__(argv)
		self.setStyleSheet(get_stylesheet())
		self.main_window = MainWindow()
		self.main_window.show()


class MainWindow(QMainWindow):
	"""Main application window with animated interface."""

	def __init__(self):
		super().__init__()
		self.setWindowTitle("iVCS - Intelligent VCS")
		self.setGeometry(100, 100, 1400, 800)

		self.loader = BinaryLoader()
		self.decoder = Decoder()
		self.cfg_extractor = CFGExtractor()
		self.agent = DecompilationAgent()

		self.current_binary = None
		self.current_instructions = None
		self.instruction_to_line_map = {}
		self.worker = None

		self.status_pulse_phase = 0
		self.app_state = AppState.ANALYZING

		self._setup_ui()

		self.pulse_timer = QTimer()
		self.pulse_timer.timeout.connect(self._pulse_status)
		self.pulse_timer.start(100)

	def _set_state(self, state: AppState):
		"""Set application state and update status indicator."""
		self.app_state = state
		if hasattr(self, "status_indicator"):
			self.status_indicator.setText(state.label)
			self.status_indicator.setStyleSheet(f"color: {state.color}; font-size: 10pt;")

	def _pulse_status(self):
		"""Animate status indicator pulse."""
		if hasattr(self, "status_indicator"):
			self.status_pulse_phase = (self.status_pulse_phase + 0.1) % (math.pi * 2)
			pulse = 0.6 + 0.4 * math.sin(self.status_pulse_phase)

			if self.app_state == AppState.ACTIVE:
				r, g, b = int(0 * pulse), int(212 * pulse), int(255 * pulse)
				color = f"#{r:02x}{g:02x}{b:02x}"
				self.status_indicator.setStyleSheet(f"color: {color}; font-size: 10pt;")
			elif self.app_state == AppState.ANALYZING:
				r, g, b = int(255 * pulse), int(107 * pulse), int(53 * pulse)
				color = f"#{r:02x}{g:02x}{b:02x}"
				self.status_indicator.setStyleSheet(f"color: {color}; font-size: 10pt;")

	def _setup_ui(self):
		"""Initialize the user interface with animations."""
		from PyQt5.QtWidgets import QStatusBar

		central_widget = QWidget()
		self.setCentralWidget(central_widget)

		self.grid_bg = AnimatedGridBackground(central_widget)
		self.grid_bg.lower()

		main_layout = QVBoxLayout()
		main_layout.setContentsMargins(20, 20, 20, 10)
		main_layout.setSpacing(18)
		central_widget.setLayout(main_layout)

		header_layout = QHBoxLayout()
		header_layout.setSpacing(0)

		title_label = QLabel("╔ INTELLIGENT VISUAL CODING SYSTEM")
		title_label.setStyleSheet("color: #00d4ff; font-size: 12pt; font-weight: bold; letter-spacing: 3px;")
		header_layout.addWidget(title_label)
		header_layout.addStretch()

		status_label = QLabel("◉ READY")
		status_label.setStyleSheet("color: #00d4ff; font-size: 10pt;")
		header_layout.addWidget(status_label)
		self.status_indicator = status_label
		main_layout.addLayout(header_layout)

		controls_layout = QHBoxLayout()
		controls_layout.setSpacing(15)

		base_label = QLabel("▌BASE ADDR")
		controls_layout.addWidget(base_label)
		self.base_addr_input = QLineEdit("0x0")
		self.base_addr_input.setFixedWidth(130)
		controls_layout.addWidget(self.base_addr_input)

		controls_layout.addSpacing(15)

		offset_label = QLabel("▌OFFSET")
		controls_layout.addWidget(offset_label)
		self.offset_input = QLineEdit("0x0")
		self.offset_input.setFixedWidth(130)
		controls_layout.addWidget(self.offset_input)

		controls_layout.addSpacing(15)

		size_label = QLabel("▌SIZE")
		controls_layout.addWidget(size_label)
		self.max_bytes_input = QLineEdit("16384")
		self.max_bytes_input.setFixedWidth(110)
		controls_layout.addWidget(self.max_bytes_input)

		controls_layout.addSpacing(25)

		load_btn = QPushButton("⟨ LOAD BINARY ⟩")
		load_btn.clicked.connect(self._load_binary)
		load_btn.setMinimumWidth(180)
		controls_layout.addWidget(load_btn)

		controls_layout.addSpacing(15)

		self.decompile_btn = QPushButton("⟨ DECOMPILE ⟩")
		self.decompile_btn.clicked.connect(self._decompile_binary)
		self.decompile_btn.setMinimumWidth(180)
		self.decompile_btn.setEnabled(False)
		controls_layout.addWidget(self.decompile_btn)

		controls_layout.addStretch()
		main_layout.addLayout(controls_layout)

		divider = QLabel("═" * 150)
		divider.setStyleSheet("color: #1a2030; font-size: 8pt; max-height: 5px; margin: 5px 0px;")
		main_layout.addWidget(divider)

		panes_layout = QHBoxLayout()
		panes_layout.setSpacing(20)

		left_layout = QVBoxLayout()
		left_layout.setSpacing(8)
		left_label = QLabel("┏━━ DISASSEMBLY ANALYSIS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		left_label.setStyleSheet("color: #00d4ff; font-size: 10pt; font-weight: bold; letter-spacing: 1px;")
		left_layout.addWidget(left_label)

		left_container = QWidget()
		left_container_layout = QVBoxLayout()
		left_container_layout.setContentsMargins(0, 0, 0, 0)
		left_container.setLayout(left_container_layout)

		self.disasm_pane = QTextEdit()
		self.disasm_pane.setReadOnly(True)
		left_container_layout.addWidget(self.disasm_pane)

		self.disasm_brackets = CornerBrackets(left_container)
		self.disasm_brackets.raise_()

		left_layout.addWidget(left_container)
		panes_layout.addLayout(left_layout)

		right_layout = QVBoxLayout()
		right_layout.setSpacing(8)
		right_label = QLabel("┏━━ C CODE DECOMPILATION ━━━━━━━━━━━━━━━━━━━━━━━━━━")
		right_label.setStyleSheet("color: #00d4ff; font-size: 10pt; font-weight: bold; letter-spacing: 1px;")
		right_layout.addWidget(right_label)

		right_container = QWidget()
		right_container_layout = QVBoxLayout()
		right_container_layout.setContentsMargins(0, 0, 0, 0)
		right_container.setLayout(right_container_layout)

		self.c_code_pane = QTextEdit()
		self.c_code_pane.setReadOnly(True)
		right_container_layout.addWidget(self.c_code_pane)

		self.c_code_brackets = CornerBrackets(right_container)
		self.c_code_brackets.raise_()

		right_layout.addWidget(right_container)
		panes_layout.addLayout(right_layout)

		main_layout.addLayout(panes_layout)

		status_bar = QStatusBar()
		status_bar.showMessage("◢ SYSTEM INITIALIZED | AWAITING BINARY INPUT")
		self.setStatusBar(status_bar)
		self.status_bar = status_bar

		self._setup_highlighting()

	def resizeEvent(self, event):
		"""Handle window resize to update background and brackets."""
		super().resizeEvent(event)
		if hasattr(self, "grid_bg"):
			self.grid_bg.setGeometry(0, 0, self.width(), self.height())
		if hasattr(self, "disasm_brackets"):
			self.disasm_brackets.setGeometry(
				0,
				0,
				self.disasm_pane.width(),
				self.disasm_pane.height(),
			)
		if hasattr(self, "c_code_brackets"):
			self.c_code_brackets.setGeometry(
				0,
				0,
				self.c_code_pane.width(),
				self.c_code_pane.height(),
			)

	def _setup_highlighting(self):
		"""Setup click handlers for bidirectional highlighting."""
		self.disasm_pane.cursorPositionChanged.connect(self._on_disasm_cursor_changed)
		self.c_code_pane.cursorPositionChanged.connect(self._on_c_code_cursor_changed)

	def _on_disasm_cursor_changed(self):
		"""Handle cursor change in disassembly pane."""
		# Highlight current line in disassembly
		self._highlight_line(self.disasm_pane, self.disasm_pane.textCursor().blockNumber())

		# TODO: Map to C code and highlight corresponding line

	def _on_c_code_cursor_changed(self):
		"""Handle cursor change in C code pane."""
		# Highlight current line in C code
		self._highlight_line(self.c_code_pane, self.c_code_pane.textCursor().blockNumber())

		# TODO: Map to assembly and highlight corresponding lines

	def _highlight_line(self, text_edit: QTextEdit, line_number: int):
		"""Highlight a specific line in a text edit widget."""
		highlight_format = QTextCharFormat()
		highlight_format.setBackground(QColor(0, 212, 255, 40))  # Cyan
		highlight_format.setProperty(QTextCharFormat.FullWidthSelection, True)

		cursor = QTextCursor(text_edit.document())
		cursor.movePosition(QTextCursor.Start)
		cursor.movePosition(QTextCursor.Down, QTextCursor.MoveAnchor, line_number)
		cursor.movePosition(QTextCursor.EndOfBlock, QTextCursor.KeepAnchor)

		selection = QTextEdit.ExtraSelection()
		selection.cursor = cursor
		selection.format = highlight_format

		text_edit.setExtraSelections([selection])

	def _load_binary(self):
		"""Load binary file and display analysis."""
		filepath, _ = QFileDialog.getOpenFileName(
			self,
			"◢ LOAD BINARY TARGET",
			"",
			"Binary Files (*.bin *.rom);;All Files (*)",
		)

		if not filepath:
			return

		self._set_state(AppState.ANALYZING)
		self.status_bar.showMessage("◢ DECODING BINARY | INITIALIZING ANALYSIS")

		try:
			base_addr = int(self.base_addr_input.text(), 16)
		except ValueError:
			base_addr = 0

		full_data = self.loader.load(filepath)

		verifier = BinaryVerifier()
		text_section = verifier._extract_text_section(full_data)

		if text_section is not None:
			data = text_section
			offset = 0
			is_elf = True
			self.status_bar.showMessage(
				f"◢ EXTRACTED .TEXT SECTION | {len(text_section)} bytes from {len(full_data)} byte ELF"
			)
		else:
			try:
				offset = int(self.offset_input.text(), 16)
			except ValueError:
				offset = 0

			try:
				max_bytes = int(self.max_bytes_input.text())
			except ValueError:
				max_bytes = 16384

			data = self.loader.load(filepath, offset=offset, size=max_bytes)
			is_elf = False
			self.status_bar.showMessage(f"◢ LOADED RAW BINARY | {len(data)} bytes from offset 0x{offset:x}")

		self.decoder = Decoder(base_address=base_addr)
		instructions = self.decoder.decode(data)

		self.current_binary = data
		self.current_instructions = instructions

		disasm_lines = []
		data_count = 0

		for instr in instructions:
			if instr.mnemonic.startswith(".byte"):
				disasm_lines.append(f"{instr.address:08x}  ║ [DATA]       {instr.op_str}")
				data_count += 1
			else:
				disasm_lines.append(f"{instr.address:08x}  ║ {instr.mnemonic:<8} {instr.op_str}")

		if hasattr(self, "disasm_brackets"):
			self.disasm_brackets.reset_animation()
		if hasattr(self, "c_code_brackets"):
			self.c_code_brackets.reset_animation()

		self.disasm_pane.setPlainText("\n".join(disasm_lines))

		cfg = self.cfg_extractor.extract(instructions)

		cfg_display = ["// STEP 0: CONTROL FLOW ANALYSIS", "//", ""]

		if cfg.blocks:
			cfg_display.append("/*")
			cfg_display.append("CONTROL FLOW GRAPH:")
			cfg_display.append("")
			cfg_display.append(f"Entry: 0x{cfg.entry_address:08x}")
			cfg_display.append("")

			sorted_blocks = sorted(cfg.blocks.items())
			for addr, block in sorted_blocks:
				end_addr = block.end_address
				num_instrs = len(block.instructions)

				if not block.instructions:
					block_type = "empty"
					successor_lines = []
				else:
					last_instr = block.instructions[-1]

					if last_instr.mnemonic == "ret":
						block_type = "returns"
						successor_lines = []
					elif last_instr.mnemonic.startswith("j") and last_instr.mnemonic != "jmp":
						block_type = "conditional branch"
						if len(block.successors) == 2:
							target = self.cfg_extractor._parse_jump_target(last_instr)
							if target is not None and target in block.successors:
								fall_through = [s for s in block.successors if s != target][0]
								successor_lines = [
									f"    → if taken: 0x{target:08x}",
									f"    → if not taken: 0x{fall_through:08x}",
								]
							else:
								succ_str = ", ".join(f"0x{s:08x}" for s in block.successors)
								successor_lines = [f"    → successors: {succ_str}"]
						else:
							succ_str = ", ".join(f"0x{s:08x}" for s in block.successors)
							successor_lines = [f"    → successors: {succ_str}"]
					elif last_instr.mnemonic == "jmp":
						block_type = "unconditional jump"
						succ_str = ", ".join(f"0x{s:08x}" for s in block.successors)
						successor_lines = [f"    → target: {succ_str}"]
					elif last_instr.mnemonic == "call":
						block_type = "call"
						succ_str = ", ".join(f"0x{s:08x}" for s in block.successors)
						successor_lines = [f"    → continues at: {succ_str}"]
					else:
						block_type = "fall-through"
						if block.successors:
							succ_str = ", ".join(f"0x{s:08x}" for s in block.successors)
							successor_lines = [f"    → next: {succ_str}"]
						else:
							successor_lines = []

				entry_marker = " (ENTRY)" if addr == cfg.entry_address else ""
				exit_marker = " (EXIT)" if not block.successors and block.instructions else ""

				block_info = f"  Block [{addr:08x}-{end_addr:08x}]: {num_instrs} instructions"
				cfg_display.append(f"{block_info}, {block_type}{entry_marker}{exit_marker}")
				cfg_display.extend(successor_lines)

			cfg_display.append("")
			if len(cfg.blocks) == 1:
				cfg_display.append("  Graph: Single basic block")
			else:
				cfg_display.append(f"  Graph: {len(cfg.blocks)} basic blocks")

				exit_count = sum(1 for block in cfg.blocks.values() if not block.successors)
				if exit_count == 1:
					cfg_display.append("  Exits: Single exit point")
				else:
					cfg_display.append(f"  Exits: {exit_count} exit points")

				back_edges = []
				for addr, block in cfg.blocks.items():
					for succ in block.successors:
						if succ <= addr:
							back_edges.append((addr, succ))

				if back_edges:
					cfg_display.append(f"  Loops: {len(back_edges)} backward edge(s) detected")
					for from_addr, to_addr in back_edges:
						cfg_display.append(f"    - 0x{from_addr:08x} → 0x{to_addr:08x}")

			cfg_display.append("*/")

		cfg_display.append("")
		cfg_display.append("// Click ⟨ DECOMPILE ⟩ to start LLM iterations")

		self.c_code_pane.setPlainText("\n".join(cfg_display))

		self.decompile_btn.setEnabled(True)

		filename = filepath.split("/")[-1]
		instr_count = len(instructions) - data_count
		self._set_state(AppState.ACTIVE)
		self.setWindowTitle(f"iVCS ═ {filename}")

		if is_elf:
			self.status_bar.showMessage(
				f"◢ BINARY LOADED | {instr_count} INSTRUCTIONS | "
				f"{data_count} DATA SEGMENTS | .TEXT SECTION ({len(data)} bytes) | READY TO DECOMPILE"
			)
		else:
			self.status_bar.showMessage(
				f"◢ BINARY LOADED | {instr_count} INSTRUCTIONS | "
				f"{data_count} DATA SEGMENTS | BASE: 0x{base_addr:X} | "
				f"OFFSET: 0x{offset:X} | READY TO DECOMPILE"
			)

	def _decompile_binary(self):
		"""Decompile loaded binary using LLM agent in background thread."""
		if self.current_binary is None:
			self.status_bar.showMessage("◢ ERROR | NO BINARY LOADED")
			return

		try:
			base_addr = int(self.base_addr_input.text(), 16)
		except ValueError:
			base_addr = 0

		self.decompile_btn.setEnabled(False)

		self._set_state(AppState.DECOMPILING)
		self.status_bar.showMessage("◢ DECOMPILING | CALLING LLM | ITERATION 0/2")

		self.c_code_pane.setPlainText("// Decompiling... Please wait\n// Iteration 0/2")

		self.worker = DecompilationWorker(self.agent, self.current_binary, base_addr, max_iterations=2)

		self.worker.progress.connect(self._on_decompile_progress)
		self.worker.iteration_complete.connect(self._on_iteration_complete)
		self.worker.finished.connect(self._on_decompile_finished)
		self.worker.error.connect(self._on_decompile_error)

		self.worker.start()

	def _on_decompile_progress(self, current: int, maximum: int):
		"""Handle progress updates from decompilation worker."""
		self.status_bar.showMessage(f"◢ DECOMPILING | ITERATION {current}/{maximum}")

	def _on_iteration_complete(self, iteration: int, c_code: str, verification):
		"""Handle completion of a single iteration."""
		if verification.matches:
			status = "PERFECT MATCH!"
		elif verification.compilation_result.success:
			status = f"Compiled, Match: {verification.match_percentage:.1f}%"
		else:
			status = "Compilation failed"

		output = f"// Iteration {iteration} - {status}\n"
		if verification.compilation_result.success:
			output += f"// Match: {verification.match_percentage:.1f}%\n"
		output += f"// Compiled: {'Yes' if verification.compilation_result.success else 'No'}\n\n"
		output += c_code

		if not verification.compilation_result.success and verification.compilation_result.stderr:
			output += "\n\n// Compilation errors:\n"
			for line in verification.compilation_result.stderr.split("\n")[:5]:
				output += f"// {line}\n"

		self.c_code_pane.setPlainText(output)
		self.status_bar.showMessage(f"◢ ITERATION {iteration} COMPLETE | {status}")

	def _on_decompile_finished(self, result: DecompilationResult):
		"""Handle completion of decompilation."""
		if result.success:
			self.c_code_pane.setPlainText(result.c_code)
			self._set_state(AppState.SUCCESS)
			self.status_bar.showMessage(
				f"◢ DECOMPILATION SUCCESS | {result.iterations} ITERATIONS | MATCH: 100% | BINARY VERIFIED"
			)
		else:
			output = result.c_code
			if result.error:
				output = f"// {result.error}\n\n{output}"

			if result.verification:
				match_pct = result.verification.match_percentage
				compiled = result.verification.compilation_result.success

				output = (
					f"// Decompilation incomplete after {result.iterations} iterations\n"
					f"// Match: {match_pct:.1f}%\n"
					f"// Compiled: {'Yes' if compiled else 'No'}\n\n"
				) + output

				if not compiled and result.verification.compilation_result.stderr:
					output += "\n\n// Compilation errors:\n"
					for line in result.verification.compilation_result.stderr.split("\n")[:10]:
						output += f"// {line}\n"

			self.c_code_pane.setPlainText(output)
			self._set_state(AppState.PARTIAL)

			match_info = ""
			if result.verification:
				match_info = f"MATCH: {result.verification.match_percentage:.1f}% | "

			self.status_bar.showMessage(
				f"◢ DECOMPILATION INCOMPLETE | {result.iterations} ITERATIONS | "
				f"{match_info}{result.error or 'See C code pane for details'}"
			)

		self.decompile_btn.setEnabled(True)
		self.worker = None

	def _on_decompile_error(self, error_msg: str):
		"""Handle decompilation error."""
		self.c_code_pane.setPlainText(f"// Decompilation failed\n// Error: {error_msg}")
		self._set_state(AppState.ERROR)
		self.status_bar.showMessage(f"◢ ERROR | {error_msg}")
		self.decompile_btn.setEnabled(True)
		self.worker = None
