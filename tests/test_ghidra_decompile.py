"""Unit tests for the Ghidra warm-start wrapper.

We mock subprocess so these tests don't need Ghidra installed. A separate
integration test (test_ghidra_integration.py, gated on IVCS_GHIDRA_INTEGRATION)
exercises the real binary.
"""

import subprocess
from pathlib import Path

import pytest

from src.ghidra_decompile import (
    GhidraConfig,
    GhidraError,
    _decompile_argv,
    _import_argv,
    ghidra_decompile_function,
    ghidra_project_ensure,
)


def _make_config(tmp_path: Path) -> GhidraConfig:
    return GhidraConfig(
        ghidra_home=tmp_path / "ghidra",
        project_dir=tmp_path / "projects",
        xbe_path=tmp_path / "halo2_default.xbe",
        project_name="halo2",
    )


def _completed(returncode: int, stdout: str = "", stderr: str = ""):
    return subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout=stdout, stderr=stderr
    )


class TestImportArgv:
    def test_argv_uses_xbe_loader(self, tmp_path):
        cfg = _make_config(tmp_path)
        argv = _import_argv(cfg)
        assert "-loader" in argv
        assert argv[argv.index("-loader") + 1] == "XbeLoader"

    def test_argv_passes_project_dir_and_name_positionally(self, tmp_path):
        cfg = _make_config(tmp_path)
        argv = _import_argv(cfg)
        # Ghidra positional order: <project_dir> <project_name>
        assert argv[1] == str(cfg.project_dir)
        assert argv[2] == cfg.project_name

    def test_argv_includes_overwrite(self, tmp_path):
        cfg = _make_config(tmp_path)
        assert "-overwrite" in _import_argv(cfg)


class TestDecompileArgv:
    def test_argv_targets_program_by_filename(self, tmp_path):
        cfg = _make_config(tmp_path)
        argv = _decompile_argv(cfg, 0x00012000, tmp_path / "out.c")
        assert argv[argv.index("-process") + 1] == "halo2_default.xbe"

    def test_argv_skips_analysis(self, tmp_path):
        cfg = _make_config(tmp_path)
        argv = _decompile_argv(cfg, 0x00012000, tmp_path / "out.c")
        assert "-noanalysis" in argv

    def test_argv_passes_va_as_hex_and_out_path(self, tmp_path):
        cfg = _make_config(tmp_path)
        out = tmp_path / "out.c"
        argv = _decompile_argv(cfg, 0x002D0CF5, out)
        post = argv.index("-postScript")
        # -postScript DecompileOne.java 0xVVVVVVVV /path/to/out.c
        assert argv[post + 1] == "DecompileOne.java"
        assert argv[post + 2] == "0x002d0cf5"
        assert argv[post + 3] == str(out)

    def test_script_path_points_at_repo_ghidra_scripts(self, tmp_path):
        cfg = _make_config(tmp_path)
        argv = _decompile_argv(cfg, 0x1000, tmp_path / "out.c")
        script_dir = argv[argv.index("-scriptPath") + 1]
        assert script_dir.endswith("ghidra_scripts")


class TestProjectEnsure:
    def test_noop_when_gpr_already_exists(self, tmp_path):
        cfg = _make_config(tmp_path)
        cfg.project_dir.mkdir(parents=True)
        cfg.project_gpr.write_text("")  # marker file

        called = {"n": 0}

        def fake(argv):
            called["n"] += 1
            return _completed(0, "REPORT: Analysis succeeded")

        ghidra_project_ensure(cfg, analyze_headless_fn=fake)
        assert called["n"] == 0

    def test_invokes_when_gpr_missing(self, tmp_path):
        cfg = _make_config(tmp_path)
        captured = {}

        def fake(argv):
            captured["argv"] = argv
            return _completed(0, "stuff\nREPORT: Analysis succeeded\nmore")

        ghidra_project_ensure(cfg, analyze_headless_fn=fake)
        assert "argv" in captured
        assert "-import" in captured["argv"]

    def test_raises_on_nonzero_return(self, tmp_path):
        cfg = _make_config(tmp_path)
        def fake(argv):
            return _completed(1, stderr="java.lang.RuntimeException: boom")

        with pytest.raises(GhidraError, match="bootstrap failed"):
            ghidra_project_ensure(cfg, analyze_headless_fn=fake)

    def test_raises_when_success_marker_absent(self, tmp_path):
        cfg = _make_config(tmp_path)
        def fake(argv):
            # rc=0 but no success marker (e.g. analyzer hung mid-way)
            return _completed(0, stdout="INFO some stuff but never finished")

        with pytest.raises(GhidraError, match="bootstrap failed"):
            ghidra_project_ensure(cfg, analyze_headless_fn=fake)


class TestDecompileFunction:
    def test_raises_when_project_missing(self, tmp_path):
        cfg = _make_config(tmp_path)
        with pytest.raises(GhidraError, match="not bootstrapped"):
            ghidra_decompile_function(0x1000, cfg, analyze_headless_fn=lambda a: _completed(0))

    def test_returns_c_source_on_success(self, tmp_path):
        cfg = _make_config(tmp_path)
        cfg.project_dir.mkdir(parents=True)
        cfg.project_gpr.write_text("")

        def fake(argv):
            # Last argv entry is the out_path; the real script writes to it.
            out_path = Path(argv[-1])
            out_path.write_text("/* Ghidra draft */\nvoid fn_X(void) { return; }\n")
            return _completed(0, "INFO Decompile completed")

        c = ghidra_decompile_function(0x12000, cfg, analyze_headless_fn=fake)
        assert "fn_X" in c
        assert c.startswith("/* Ghidra draft */")

    def test_raises_when_output_file_empty(self, tmp_path):
        cfg = _make_config(tmp_path)
        cfg.project_dir.mkdir(parents=True)
        cfg.project_gpr.write_text("")

        def fake(argv):
            Path(argv[-1]).write_text("")  # empty output
            return _completed(0)

        with pytest.raises(GhidraError, match="no output"):
            ghidra_decompile_function(0x12000, cfg, analyze_headless_fn=fake)

    def test_raises_on_nonzero_return(self, tmp_path):
        cfg = _make_config(tmp_path)
        cfg.project_dir.mkdir(parents=True)
        cfg.project_gpr.write_text("")

        def fake(argv):
            return _completed(1, stderr="no function at 0x00012000")

        with pytest.raises(GhidraError, match="decompile failed"):
            ghidra_decompile_function(0x12000, cfg, analyze_headless_fn=fake)

    def test_temp_file_cleaned_up_on_success(self, tmp_path):
        cfg = _make_config(tmp_path)
        cfg.project_dir.mkdir(parents=True)
        cfg.project_gpr.write_text("")

        captured = {}

        def fake(argv):
            out_path = Path(argv[-1])
            captured["out_path"] = out_path
            out_path.write_text("void f(void){}")
            return _completed(0)

        ghidra_decompile_function(0x12000, cfg, analyze_headless_fn=fake)
        assert not captured["out_path"].exists()

    def test_temp_file_cleaned_up_on_failure(self, tmp_path):
        cfg = _make_config(tmp_path)
        cfg.project_dir.mkdir(parents=True)
        cfg.project_gpr.write_text("")

        captured = {}

        def fake(argv):
            out_path = Path(argv[-1])
            captured["out_path"] = out_path
            out_path.write_text("partial")
            return _completed(1, stderr="boom")

        with pytest.raises(GhidraError):
            ghidra_decompile_function(0x12000, cfg, analyze_headless_fn=fake)
        assert not captured["out_path"].exists()
