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
    _run_with_lock_retry,
    ghidra_config_from_env,
    ghidra_decompile_function,
    ghidra_project_ensure,
    ghidra_pseudo_c_normalize,
    ghidra_pseudo_c_normalize_for_prompt,
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


class TestPseudoCNormalize:
    def test_undefined_types_to_real_types(self):
        out = ghidra_pseudo_c_normalize(
            "undefined1 a; undefined2 b; undefined4 c; undefined8 d; undefined *p;"
        )
        assert "char a" in out
        assert "short b" in out
        assert "int c" in out
        assert "__int64 d" in out
        assert "void *p" in out  # bare `undefined` → void

    def test_undefined_does_not_swallow_numbered_variant(self):
        # Order in the alternation matters: undefined4 must match before bare undefined.
        out = ghidra_pseudo_c_normalize("undefined4 x;")
        assert "int x" in out
        assert "void" not in out

    def test_lowercase_type_aliases(self):
        out = ghidra_pseudo_c_normalize("byte x; ushort y; uint z; dword w;")
        assert "BYTE x" in out
        assert "USHORT y" in out
        assert "UINT z" in out
        assert "DWORD w" in out

    def test_fun_renamed_to_fn_with_uppercase_hex(self):
        out = ghidra_pseudo_c_normalize("FUN_002d0cf5(x); FUN_abcdef01(y);")
        assert "fn_002D0CF5" in out
        assert "fn_ABCDEF01" in out
        assert "FUN_" not in out

    def test_preserves_identifiers_that_contain_type_names(self):
        # `bytes` and `_byte` shouldn't be touched.
        out = ghidra_pseudo_c_normalize("int bytes = 0; int my_byte = 0;")
        assert "int bytes = 0" in out
        assert "int my_byte = 0" in out
        assert "BYTE" not in out  # nothing matched

    def test_leaves_DAT_and_LAB_references_alone(self):
        # Those still need typed decls / are valid labels; not our job.
        src = "x = &DAT_004618c8; goto LAB_002d0d7c;"
        assert ghidra_pseudo_c_normalize(src) == src

    def test_realistic_excerpt(self):
        src = """\
void FUN_002d0cf5(int param_1, undefined4 param_2)
{
  byte local_42c [520];
  undefined4 local_1c;
  ushort local_10 [2];
  iVar1 = FUN_002d0979(param_1, local_42c);
  return;
}
"""
        out = ghidra_pseudo_c_normalize(src)
        assert "fn_002D0CF5" in out
        assert "BYTE local_42c" in out
        assert "int local_1c" in out
        assert "USHORT local_10" in out
        assert "fn_002D0979" in out


class TestPseudoCNormalizeForPrompt:
    def test_renames_fun_to_fn_with_uppercase_hex(self):
        out = ghidra_pseudo_c_normalize_for_prompt(
            "FUN_002d0cf5(); FUN_abcdef01();"
        )
        assert "fn_002D0CF5" in out
        assert "fn_ABCDEF01" in out
        assert "FUN_" not in out

    def test_strips_xapilib_namespace(self):
        out = ghidra_pseudo_c_normalize_for_prompt(
            "XAPILIB::CloseHandle(DAT_004e0354);"
        )
        assert out == "CloseHandle(DAT_004e0354);"

    def test_drops_globals_warning_line(self):
        src = (
            "/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */\n"
            "\n"
            "void FUN_00012080(void) {}\n"
        )
        out = ghidra_pseudo_c_normalize_for_prompt(src)
        assert "WARNING: Globals" not in out
        assert "fn_00012080" in out

    def test_keeps_undefined_types(self):
        # We deliberately don't strip placeholder types; the LLM should see
        # them as a signal that Ghidra was uncertain.
        out = ghidra_pseudo_c_normalize_for_prompt(
            "undefined4 x; byte y; FUN_00012080();"
        )
        assert "undefined4 x" in out
        assert "byte y" in out
        assert "fn_00012080" in out

    def test_keeps_dat_and_lab_references(self):
        # DAT_/LAB_ stay; the prompt-side cleaner doesn't try to fix them.
        src = "x = &DAT_004618c8; goto LAB_002d0d7c;"
        assert ghidra_pseudo_c_normalize_for_prompt(src) == src


class TestConfigFromEnv:
    def test_default_project_name_is_xbe_stem(self, tmp_path, monkeypatch):
        monkeypatch.delenv("IVCS_GHIDRA_PROJECT_NAME", raising=False)
        cfg = ghidra_config_from_env(tmp_path / "halo2_default.xbe")
        assert cfg.project_name == "halo2_default"

    def test_env_var_overrides_project_name(self, tmp_path, monkeypatch):
        monkeypatch.setenv("IVCS_GHIDRA_PROJECT_NAME", "custom")
        cfg = ghidra_config_from_env(tmp_path / "halo2_default.xbe")
        assert cfg.project_name == "custom"


class TestLockRetry:
    def test_passes_through_on_first_success(self):
        calls = {"n": 0}

        def fake(argv):
            calls["n"] += 1
            return _completed(0, stdout="all good")

        result = _run_with_lock_retry(["fake"], fake, sleep_fn=lambda _: None)
        assert result.returncode == 0
        assert calls["n"] == 1

    def test_retries_on_lock_error(self):
        attempts = {"n": 0}

        def fake(argv):
            attempts["n"] += 1
            if attempts["n"] < 3:
                return _completed(1, stdout="ERROR Unable to lock project! /tmp/foo")
            return _completed(0, stdout="done")

        sleeps = []
        result = _run_with_lock_retry(
            ["fake"], fake, sleep_fn=lambda s: sleeps.append(s)
        )
        assert result.returncode == 0
        assert attempts["n"] == 3
        # Two sleeps between three attempts; exponential backoff.
        assert len(sleeps) == 2
        assert sleeps[0] < sleeps[1]

    def test_returns_final_result_if_all_attempts_locked(self):
        def fake(argv):
            return _completed(1, stdout="ERROR Unable to lock project!")

        result = _run_with_lock_retry(
            ["fake"], fake, attempts=2, backoff_seconds=0, sleep_fn=lambda _: None
        )
        assert result.returncode == 1
        assert "Unable to lock project" in result.stdout


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
