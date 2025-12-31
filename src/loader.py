"""Binary file loader for x86 executables and firmware."""

from pathlib import Path


class BinaryLoader:
	"""Loads binary files for disassembly."""

	def load(self, filepath, offset=0, size=None):
		"""Load binary file from disk."""
		path = Path(filepath)

		if not path.exists():
			raise FileNotFoundError(f"File not found: {filepath}")

		with path.open("rb") as f:
			if offset > 0:
				f.seek(offset)

			if size is not None:
				return f.read(size)
			return f.read()

	def get_size(self, filepath):
		"""Get file size in bytes."""
		return Path(filepath).stat().st_size
