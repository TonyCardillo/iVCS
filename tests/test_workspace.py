"""Tests for FunctionWorkspace — the per-function filesystem layout.

The workspace is purely a path manager; it doesn't produce target.obj
or ctx.h (those are caller responsibilities) and doesn't run the loop
(that's agent_loop.py's job). These tests verify the path contract and
the directory-creation behavior.
"""

import pytest

from src.workspace import FunctionWorkspace


class TestPaths:
	def test_target_obj_path(self, tmp_path):
		ws = FunctionWorkspace(root=tmp_path, function_name="_Foo@8")
		assert ws.target_obj == tmp_path / "target.obj"

	def test_ctx_h_path(self, tmp_path):
		ws = FunctionWorkspace(root=tmp_path, function_name="_Foo@8")
		assert ws.ctx_h == tmp_path / "ctx.h"

	def test_history_dir_path(self, tmp_path):
		ws = FunctionWorkspace(root=tmp_path, function_name="_Foo@8")
		assert ws.history_dir == tmp_path / "history"

	def test_best_c_path(self, tmp_path):
		ws = FunctionWorkspace(root=tmp_path, function_name="_Foo@8")
		assert ws.best_c == tmp_path / "best.c"

	def test_result_json_path(self, tmp_path):
		ws = FunctionWorkspace(root=tmp_path, function_name="_Foo@8")
		assert ws.result_json == tmp_path / "result.json"


class TestAttemptPaths:
	def test_attempt_paths_zero_padded(self, tmp_path):
		ws = FunctionWorkspace(root=tmp_path, function_name="_Foo@8")
		paths = ws.attempt_paths(1)
		assert paths.c == tmp_path / "history" / "0001.c"
		assert paths.obj == tmp_path / "history" / "0001.obj"
		assert paths.diff_json == tmp_path / "history" / "0001.diff.json"

	def test_attempt_paths_large_number(self, tmp_path):
		ws = FunctionWorkspace(root=tmp_path, function_name="_Foo@8")
		paths = ws.attempt_paths(1234)
		assert paths.c.name == "1234.c"

	def test_attempt_paths_zero_allowed_for_baselines(self, tmp_path):
		ws = FunctionWorkspace(root=tmp_path, function_name="_Foo@8")
		paths = ws.attempt_paths(0)
		assert paths.c == tmp_path / "history" / "0000.c"

	def test_attempt_paths_negative_not_allowed(self, tmp_path):
		ws = FunctionWorkspace(root=tmp_path, function_name="_Foo@8")
		with pytest.raises(ValueError):
			ws.attempt_paths(-1)

	def test_attempt_model_path_sidecar(self, tmp_path):
		ws = FunctionWorkspace(root=tmp_path, function_name="_Foo@8")
		assert ws.attempt_model_path(7) == tmp_path / "history" / "0007.model"


class TestInitialize:
	def test_creates_workspace_dirs(self, tmp_path):
		root = tmp_path / "fresh"
		ws = FunctionWorkspace(root=root, function_name="_Foo@8")
		ws.initialize()
		assert root.is_dir()
		assert ws.history_dir.is_dir()

	def test_initialize_idempotent(self, tmp_path):
		ws = FunctionWorkspace(root=tmp_path / "ws", function_name="_Foo@8")
		ws.initialize()
		ws.initialize()  # should not raise
		assert ws.history_dir.is_dir()


class TestValidate:
	def test_missing_target_obj_raises(self, tmp_path):
		ws = FunctionWorkspace(root=tmp_path, function_name="_Foo@8")
		ws.initialize()
		ws.ctx_h.write_text("// ok\n")
		with pytest.raises(FileNotFoundError, match="target.obj"):
			ws.validate_inputs()

	def test_missing_ctx_h_raises(self, tmp_path):
		ws = FunctionWorkspace(root=tmp_path, function_name="_Foo@8")
		ws.initialize()
		ws.target_obj.write_bytes(b"\x00")
		with pytest.raises(FileNotFoundError, match="ctx.h"):
			ws.validate_inputs()

	def test_valid_inputs_pass(self, tmp_path):
		ws = FunctionWorkspace(root=tmp_path, function_name="_Foo@8")
		ws.initialize()
		ws.target_obj.write_bytes(b"\x00")
		ws.ctx_h.write_text("// ok\n")
		ws.validate_inputs()  # should not raise


class TestAttemptsExisting:
	def test_empty_history(self, tmp_path):
		ws = FunctionWorkspace(root=tmp_path, function_name="_Foo@8")
		ws.initialize()
		assert ws.attempts_existing() == []

	def test_attempts_found_and_sorted(self, tmp_path):
		ws = FunctionWorkspace(root=tmp_path, function_name="_Foo@8")
		ws.initialize()
		for n in [3, 1, 2]:
			ws.attempt_paths(n).c.write_text(f"// attempt {n}\n")
		assert ws.attempts_existing() == [1, 2, 3]

	def test_attempts_ignores_non_c_files(self, tmp_path):
		ws = FunctionWorkspace(root=tmp_path, function_name="_Foo@8")
		ws.initialize()
		ws.attempt_paths(1).c.write_text("// ok\n")
		ws.attempt_paths(2).obj.write_bytes(b"\x00")
		(ws.history_dir / "README.txt").write_text("notes")
		assert ws.attempts_existing() == [1]

	def test_next_attempt_number(self, tmp_path):
		ws = FunctionWorkspace(root=tmp_path, function_name="_Foo@8")
		ws.initialize()
		assert ws.next_attempt_number() == 1
		ws.attempt_paths(1).c.write_text("// ok\n")
		assert ws.next_attempt_number() == 2
		ws.attempt_paths(2).c.write_text("// ok\n")
		ws.attempt_paths(5).c.write_text("// ok\n")
		assert ws.next_attempt_number() == 6
