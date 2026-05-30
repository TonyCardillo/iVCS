"""Per-function free-text notes, stored as `notes.md` in the workspace dir.

Notes are about the *function*, not one scratch attempt, so they live in the
workspace directory (keyed by VA-name) and survive re-runs. Plain markdown keeps
them git-diffable.
"""

from pathlib import Path

_NOTES_FILE = "notes.md"


def notes_load(workspace_dir: Path | str) -> str:
	path = Path(workspace_dir) / _NOTES_FILE
	return path.read_text() if path.is_file() else ""


def notes_save(workspace_dir: Path | str, text: str) -> None:
	"""Write `text` to the workspace's notes file; a blank note removes it."""
	path = Path(workspace_dir) / _NOTES_FILE
	if text.strip():
		path.parent.mkdir(parents=True, exist_ok=True)
		path.write_text(text)
	elif path.exists():
		path.unlink()
