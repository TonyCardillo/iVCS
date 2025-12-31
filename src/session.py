"""Session manager for saving/loading analysis state."""

import json
from pathlib import Path


class SessionManager:
	"""Manages session state including comments and binary info."""

	def __init__(self):
		self.binary_path = None
		self.base_address = 0
		self.comments = {}

	def set_binary(self, path, base_address=0):
		"""Set binary file path and base address."""
		self.binary_path = path
		self.base_address = base_address

	def add_comment(self, address, comment):
		"""Add comment at specific address."""
		self.comments[address] = comment

	def get_comment(self, address):
		"""Get comment at address, or None if no comment."""
		return self.comments.get(address)

	def save(self, filepath):
		"""Save session to JSON file."""
		# Convert integer addresses to hex strings for JSON
		comments_hex = {hex(addr): comment for addr, comment in self.comments.items()}

		session_data = {
			"binary_path": self.binary_path,
			"base_address": self.base_address,
			"comments": comments_hex,
		}

		Path(filepath).write_text(json.dumps(session_data, indent=2))

	def load(self, filepath):
		"""Load session from JSON file."""
		session_data = json.loads(Path(filepath).read_text())

		self.binary_path = session_data["binary_path"]
		self.base_address = session_data["base_address"]

		# Convert hex string addresses back to integers
		self.comments = {int(addr, 16): comment for addr, comment in session_data["comments"].items()}
