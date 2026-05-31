"""Unit tests for the Ghidra warm-start wrapper.

We mock subprocess so these tests don't need Ghidra installed. A separate
integration test (test_ghidra_integration.py, gated on IVCS_GHIDRA_INTEGRATION)
exercises the real binary.
"""

import subprocess
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from src import ghidra_decompile
from src.ghidra_decompile import (
	_PSEUDO_C_TYPE_MAP,
	GhidraConfig,
	GhidraError,
	_count_top_level_args,
	_decompile_argv,
	_dump_structs_argv,
	_import_argv,
	_pad_call_args,
	_run_with_lock_retry,
	ghidra_config_from_env,
	ghidra_decompile_function,
	ghidra_project_ensure,
	ghidra_pseudo_c_normalize,
	ghidra_pseudo_c_normalize_for_prompt,
	ghidra_struct_names,
	ghidra_structs_dump,
)


def _make_config(tmp_path: Path) -> GhidraConfig:
	return GhidraConfig(
		ghidra_home=tmp_path / "ghidra",
		project_dir=tmp_path / "projects",
		xbe_path=tmp_path / "halo2_default.xbe",
		project_name="halo2",
	)


def _completed(returncode: int, stdout: str = "", stderr: str = ""):
	return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


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


class TestDumpStructsArgv:
	def test_argv_targets_program_and_skips_analysis(self, tmp_path):
		cfg = _make_config(tmp_path)
		argv = _dump_structs_argv(cfg, tmp_path / "structs.h")
		assert argv[argv.index("-process") + 1] == "halo2_default.xbe"
		assert "-noanalysis" in argv

	def test_argv_uses_dump_structs_postscript_with_out_path(self, tmp_path):
		cfg = _make_config(tmp_path)
		out = tmp_path / "structs.h"
		argv = _dump_structs_argv(cfg, out)
		post = argv.index("-postScript")
		# -postScript DumpStructs.java /path/to/structs.h
		assert argv[post + 1] == "DumpStructs.java"
		assert argv[post + 2] == str(out)

	def test_script_path_points_at_repo_ghidra_scripts(self, tmp_path):
		cfg = _make_config(tmp_path)
		argv = _dump_structs_argv(cfg, tmp_path / "structs.h")
		assert argv[argv.index("-scriptPath") + 1].endswith("ghidra_scripts")


class TestStructsDump:
	def _bootstrapped(self, tmp_path):
		cfg = _make_config(tmp_path)
		cfg.project_dir.mkdir(parents=True)
		cfg.project_gpr.write_text("")  # marker
		return cfg

	def test_raises_when_project_missing_and_no_cache(self, tmp_path):
		cfg = _make_config(tmp_path)  # no project_dir, no gpr, no cache
		with pytest.raises(GhidraError, match="not bootstrapped"):
			ghidra_structs_dump(cfg, analyze_headless_fn=lambda a: _completed(0))

	def test_returns_and_caches_struct_source(self, tmp_path):
		cfg = self._bootstrapped(tmp_path)
		header = "typedef struct { int x; } XBE_FILE_HEADER;\n"

		def fake(argv):
			Path(argv[-1]).write_text(header)
			return _completed(0, "INFO done")

		out = ghidra_structs_dump(cfg, analyze_headless_fn=fake)
		assert "XBE_FILE_HEADER" in out
		# Cached for reuse across functions.
		assert cfg.structs_h.is_file()
		assert cfg.structs_h.read_text() == header

	def test_second_call_uses_cache_without_invoking(self, tmp_path):
		cfg = self._bootstrapped(tmp_path)
		cfg.structs_h.write_text("typedef struct { int x; } CACHED;\n")

		def fake(argv):  # pragma: no cover — must not run
			raise AssertionError("should have hit the cache")

		out = ghidra_structs_dump(cfg, analyze_headless_fn=fake)
		assert "CACHED" in out

	def test_force_rebuilds_even_with_cache(self, tmp_path):
		cfg = self._bootstrapped(tmp_path)
		cfg.structs_h.write_text("typedef struct { int x; } STALE;\n")

		def fake(argv):
			Path(argv[-1]).write_text("typedef struct { int y; } FRESH;\n")
			return _completed(0)

		out = ghidra_structs_dump(cfg, analyze_headless_fn=fake, force=True)
		assert "FRESH" in out
		assert "STALE" not in cfg.structs_h.read_text()

	def test_raises_when_output_empty(self, tmp_path):
		cfg = self._bootstrapped(tmp_path)

		def fake(argv):
			Path(argv[-1]).write_text("")
			return _completed(0)

		with pytest.raises(GhidraError, match="no output"):
			ghidra_structs_dump(cfg, analyze_headless_fn=fake)

	def test_raises_on_nonzero_return(self, tmp_path):
		cfg = self._bootstrapped(tmp_path)

		def fake(argv):
			return _completed(1, stderr="java.lang.RuntimeException: boom")

		with pytest.raises(GhidraError, match="struct dump failed"):
			ghidra_structs_dump(cfg, analyze_headless_fn=fake)


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

	def test_bool_and_code_types_mapped(self):
		# Ghidra emits C99 `bool` and the `code` function-pointer type; neither
		# parses under MSVC 7.1 /TC (C89).
		out = ghidra_pseudo_c_normalize("bool bVar1; code *pcVar2;")
		assert "int bVar1" in out
		assert "void *pcVar2" in out
		assert "bool" not in out and "code" not in out

	def test_strips_xapilib_namespace(self):
		out = ghidra_pseudo_c_normalize("XAPILIB::CloseHandle(h);")
		assert out == "CloseHandle(h);"

	def test_dat_value_becomes_absolute_deref(self):
		# Xbox images load at a fixed base, so DAT_<addr> globals are absolute
		# references with no reloc in target.obj. Rewrite to absolute derefs so
		# the draft compiles and can match the baked disp32.
		out = ghidra_pseudo_c_normalize("DAT_00485aa0 = 1;")
		assert out == "(*(int *)0x00485aa0) = 1;"

	def test_dat_address_of_becomes_pointer_cast(self):
		# &DAT_x must become a plain pointer cast, not &(*(int *)x).
		out = ghidra_pseudo_c_normalize("p = &DAT_004618c8;")
		assert out == "p = ((int *)0x004618c8);"

	def test_dat_underscore_and_ptr_variants(self):
		# Ghidra's _DAT_ (overlap) and PTR_DAT_ (pointer-at-addr) name variants.
		assert ghidra_pseudo_c_normalize("_DAT_005107fc = 0;") == "(*(int *)0x005107fc) = 0;"
		assert ghidra_pseudo_c_normalize("x = PTR_DAT_0043e86c;") == "x = (*(int *)0x0043e86c);"

	def test_c99_bool_literals_mapped(self):
		out = ghidra_pseudo_c_normalize("bVar1 = true; bVar2 = false;")
		assert out == "bVar1 = 1; bVar2 = 0;"

	def test_leaves_LAB_references_alone(self):
		# LAB_ are valid local goto labels; leave them untouched.
		src = "goto LAB_002d0d7c;"
		assert ghidra_pseudo_c_normalize(src) == src

	def test_preserves_identifiers_that_contain_DAT(self):
		# A 6-hex-digit or non-DAT_ token must not be rewritten.
		src = "int my_DAT_thing = 0; DAT_12ab = 0;"
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


class TestStructNames:
	def test_parses_struct_and_union_names_in_order(self):
		header = (
			"#pragma pack(push, 1)\n"
			"typedef struct {\n\tint x;\n} XBE_FILE_HEADER;\n\n"
			"typedef union {\n\tint y;\n} SOME_UNION;\n"
			"#pragma pack(pop)\n"
		)
		assert ghidra_struct_names(header) == ("XBE_FILE_HEADER", "SOME_UNION")

	def test_empty_header_has_no_names(self):
		assert ghidra_struct_names("/* nothing here */\n") == ()


class TestStructInstanceRewrite:
	# Ghidra names a recognized struct instance at a fixed address
	# `<TypeName>_<8hex>`. Xbox images load at a fixed base, so that instance is
	# an absolute reference with no reloc — rewrite to a typed absolute deref so
	# member offsets resolve against the harvested layout AND the disp32 matches.
	NAMES = ("XBE_FILE_HEADER", "XBE_CERTIFICATE_HEADER")

	def test_instance_value_becomes_typed_deref(self):
		out = ghidra_pseudo_c_normalize(
			"XBE_FILE_HEADER_00010000.CertificateHeader = 1;", struct_names=self.NAMES
		)
		assert out == "(*(XBE_FILE_HEADER *)0x00010000).CertificateHeader = 1;"

	def test_instance_address_of_becomes_typed_cast(self):
		out = ghidra_pseudo_c_normalize("p = &XBE_FILE_HEADER_00010000;", struct_names=self.NAMES)
		assert out == "p = ((XBE_FILE_HEADER *)0x00010000);"

	def test_no_struct_names_leaves_instance_untouched(self):
		# Default (no harvested names) must not invent a rewrite.
		src = "XBE_FILE_HEADER_00010000.x = 1;"
		assert ghidra_pseudo_c_normalize(src) == src

	def test_unharvested_identifier_not_rewritten(self):
		# A name we didn't harvest is left alone even if it looks like an instance.
		src = "WIDGET_00010000.x = 1;"
		assert ghidra_pseudo_c_normalize(src, struct_names=self.NAMES) == src

	def test_longest_matching_name_wins(self):
		# XBE_CERTIFICATE_HEADER must not be clipped to a shorter prefix.
		out = ghidra_pseudo_c_normalize(
			"XBE_CERTIFICATE_HEADER_001d0000.TitleID;", struct_names=self.NAMES
		)
		assert out == "(*(XBE_CERTIFICATE_HEADER *)0x001d0000).TitleID;"


class TestStdcallTargetRewrite:
	# Ghidra emits the function definition with no convention keyword (and often
	# a `void` return); ctx.h forward-declares stdcall targets as
	# `int __stdcall <name>(...)`. Left alone the two collide (MSVC C2373/C2371).
	def test_void_definition_pinned_to_int_stdcall(self):
		out = ghidra_pseudo_c_normalize(
			"void fn_X(int a, int b, int c)\n{\n  return;\n}\n", stdcall_target="fn_X"
		)
		assert "int __stdcall fn_X(int a, int b, int c)" in out
		assert "void fn_X(" not in out

	def test_call_sites_left_untouched(self):
		# Only the definition header (followed by `{`) is rewritten; the
		# recursive call must keep its original form.
		draft = "void fn_X(int a)\n{\n  if (a) fn_X(a - 1);\n  return;\n}\n"
		out = ghidra_pseudo_c_normalize(draft, stdcall_target="fn_X")
		assert "int __stdcall fn_X(int a)" in out
		assert "fn_X(a - 1)" in out
		assert out.count("__stdcall") == 1

	def test_fun_renamed_form_is_matched(self):
		# Rewrite runs after FUN_xxxxxxxx -> fn_XXXXXXXX, so the caller passes the
		# post-rename name.
		out = ghidra_pseudo_c_normalize(
			"void FUN_00012080(void)\n{\n}\n", stdcall_target="fn_00012080"
		)
		assert "int __stdcall fn_00012080(void)" in out

	def test_no_target_leaves_definition_as_is(self):
		# cdecl targets get no ctx.h forward decl, so nothing to reconcile.
		src = "void fn_X(int a)\n{\n  return;\n}\n"
		assert "void fn_X(int a)" in ghidra_pseudo_c_normalize(src)
		assert "__stdcall" not in ghidra_pseudo_c_normalize(src)

	def test_other_function_definition_not_touched(self):
		out = ghidra_pseudo_c_normalize("void fn_OTHER(int a)\n{\n}\n", stdcall_target="fn_X")
		assert "void fn_OTHER(int a)" in out
		assert "__stdcall" not in out

	def test_rewrite_is_idempotent(self):
		# Applying the pin twice must not stack a second `int __stdcall` prefix.
		# It doesn't: the match starts at `^` and its lazy prefix swallows the
		# existing `int __stdcall ` too, so the sub replaces the whole header
		# wholesale rather than prepending to it.
		src = "void fn_X(int a, int b)\n{\n  return;\n}\n"
		once = ghidra_pseudo_c_normalize(src, stdcall_target="fn_X")
		twice = ghidra_pseudo_c_normalize(once, stdcall_target="fn_X")
		assert once == twice
		assert once.count("__stdcall") == 1


class TestStdcallCallPadding:
	# Ghidra under-counts call args; our `@N`-pinned stdcall callee decls are
	# strict, so a short call fails to compile (MSVC C2198). Pad the call up to
	# the callee's inferred arity with `0` so the stack arg count matches.
	ARITIES = {"fn_0012C090": 2, "fn_AAAA0001": 3}

	def test_zero_arg_call_padded_to_arity(self):
		out = ghidra_pseudo_c_normalize("fn_0012C090();", callee_arities=self.ARITIES)
		assert out == "fn_0012C090(0, 0);"

	def test_partial_call_padded(self):
		out = ghidra_pseudo_c_normalize("fn_AAAA0001(x);", callee_arities=self.ARITIES)
		assert out == "fn_AAAA0001(x, 0, 0);"

	def test_exact_count_unchanged(self):
		src = "fn_0012C090(a, b);"
		assert ghidra_pseudo_c_normalize(src, callee_arities=self.ARITIES) == src

	def test_over_count_left_alone(self):
		# Too-many args is a different (rare) problem; don't drop expressions.
		src = "fn_0012C090(a, b, c);"
		assert ghidra_pseudo_c_normalize(src, callee_arities=self.ARITIES) == src

	def test_nested_call_arg_counts_as_one(self):
		out = ghidra_pseudo_c_normalize("fn_0012C090(g(a, b));", callee_arities=self.ARITIES)
		assert out == "fn_0012C090(g(a, b), 0);"

	def test_multiple_call_sites_each_padded(self):
		out = ghidra_pseudo_c_normalize(
			"fn_0012C090(); x = fn_0012C090(p);", callee_arities=self.ARITIES
		)
		assert out == "fn_0012C090(0, 0); x = fn_0012C090(p, 0);"

	def test_unknown_callee_untouched(self):
		src = "some_other_fn();"
		assert ghidra_pseudo_c_normalize(src, callee_arities=self.ARITIES) == src

	def test_no_arities_is_noop(self):
		src = "fn_0012C090();"
		assert ghidra_pseudo_c_normalize(src) == src


class TestPseudoCNormalizeForPrompt:
	def test_renames_fun_to_fn_with_uppercase_hex(self):
		out = ghidra_pseudo_c_normalize_for_prompt("FUN_002d0cf5(); FUN_abcdef01();")
		assert "fn_002D0CF5" in out
		assert "fn_ABCDEF01" in out
		assert "FUN_" not in out

	def test_strips_xapilib_namespace(self):
		out = ghidra_pseudo_c_normalize_for_prompt("XAPILIB::CloseHandle(DAT_004e0354);")
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
		out = ghidra_pseudo_c_normalize_for_prompt("undefined4 x; byte y; FUN_00012080();")
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
		result = _run_with_lock_retry(["fake"], fake, sleep_fn=lambda s: sleeps.append(s))
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


class TestDefaultRunTimeout:
	"""The public functions accept timeout_seconds; it must reach subprocess.run."""

	def _patch_subprocess_run(self, monkeypatch, captured, stdout=""):
		def fake_run(argv, **kwargs):
			captured.update(kwargs)
			return _completed(0, stdout=stdout)

		monkeypatch.setattr(ghidra_decompile.subprocess, "run", fake_run)

	def test_default_run_passes_timeout_to_subprocess_example(self, monkeypatch):
		captured = {}
		self._patch_subprocess_run(monkeypatch, captured)
		ghidra_decompile._default_run(["x"], timeout_seconds=42.0)
		assert captured["timeout"] == 42.0

	def test_default_run_timeout_defaults_to_600_example(self, monkeypatch):
		captured = {}
		self._patch_subprocess_run(monkeypatch, captured)
		ghidra_decompile._default_run(["x"])
		assert captured["timeout"] == 600.0

	def test_project_ensure_threads_timeout_into_default_run_example(self, monkeypatch, tmp_path):
		cfg = _make_config(tmp_path)
		captured = {}
		self._patch_subprocess_run(monkeypatch, captured, stdout="REPORT: Analysis succeeded")
		ghidra_project_ensure(cfg, timeout_seconds=123.0)
		assert captured["timeout"] == 123.0

	def test_decompile_threads_timeout_into_default_run_example(self, monkeypatch, tmp_path):
		cfg = _make_config(tmp_path)
		cfg.project_dir.mkdir(parents=True)
		cfg.project_gpr.write_text("")
		captured = {}

		def fake_run(argv, **kwargs):
			captured.update(kwargs)
			Path(argv[-1]).write_text("void f(void){}")
			return _completed(0)

		monkeypatch.setattr(ghidra_decompile.subprocess, "run", fake_run)
		ghidra_decompile_function(0x12000, cfg, timeout_seconds=77.0)
		assert captured["timeout"] == 77.0


# --- Property tests --------------------------------------------------------
# The TestPseudoCNormalize examples each pin one rewrite on one hand-picked
# token; these assert the laws those witnesses are arbitrary instances of, so
# a regex tweak or rewrite-order change is caught wherever it drifts.

_HEX8 = st.text(alphabet="0123456789abcdef", min_size=8, max_size=8)


@st.composite
def _normalize_atom(draw):
	"""A Ghidra token paired with the form `normalize` must rewrite it to.

	Every atom is self-delimiting (a bare token), so on the default path the
	rewrites are independent word-boundary substitutions.
	"""
	kind = draw(st.sampled_from(["type", "fun", "dat_val", "dat_addr", "bool", "passthrough"]))
	if kind == "type":
		key = draw(st.sampled_from(sorted(_PSEUDO_C_TYPE_MAP)))
		return key, _PSEUDO_C_TYPE_MAP[key]
	if kind == "fun":
		h = draw(_HEX8)
		return f"FUN_{h}", f"fn_{h.upper()}"  # FUN hex is upper-cased
	if kind == "dat_val":
		h = draw(_HEX8)
		return f"DAT_{h}", f"(*(int *)0x{h})"  # DAT hex kept verbatim
	if kind == "dat_addr":
		h = draw(_HEX8)
		return f"&DAT_{h}", f"((int *)0x{h})"
	if kind == "bool":
		lit = draw(st.sampled_from(["true", "false"]))
		return lit, ("1" if lit == "true" else "0")
	# An identifier that dodges every rewrite (no type/FUN/DAT/bool token in it).
	ident = f"loc_{draw(st.integers(0, 99999))}"
	return ident, ident


class TestNormalizeProperties:
	@given(atoms=st.lists(_normalize_atom(), min_size=1, max_size=10))
	def test_normalize_distributes_over_separated_atoms_oracle(self, atoms):
		# normalize is a per-token homomorphism: rewriting ` ; `-joined atoms
		# equals joining each atom's own rewrite. Generalizes the type/FUN/DAT/
		# bool example tests into one law.
		src = " ; ".join(a for a, _ in atoms)
		expected = " ; ".join(b for _, b in atoms)
		assert ghidra_pseudo_c_normalize(src) == expected

	@given(c=st.text(max_size=200))
	def test_normalize_is_idempotent(self, c):
		# Re-normalizing already-normalized C is a no-op — no rewrite's output
		# re-triggers another. (The stdcall_target path holds too; see
		# TestStdcallTargetRewrite.test_rewrite_is_idempotent for why.)
		once = ghidra_pseudo_c_normalize(c)
		assert ghidra_pseudo_c_normalize(once) == once


class TestCallPaddingProperties:
	NAME = "fn_0012C090"

	def _arg_list(self, k: int) -> str:
		return ", ".join(f"a{i}" for i in range(k))

	@given(k=st.integers(0, 6), arity=st.integers(0, 8))
	def test_padding_brings_arg_count_up_to_arity_conservation(self, k, arity):
		# A call ends with max(original, arity) args: short calls are filled with
		# `0`; calls already at/over arity are left untouched.
		call = f"{self.NAME}({self._arg_list(k)});"
		out = ghidra_pseudo_c_normalize(call, callee_arities={self.NAME: arity})
		inner = out[out.index("(") + 1 : out.rindex(")")]
		assert _count_top_level_args(inner) == max(k, arity)

	@given(k=st.integers(0, 6), arity=st.integers(1, 8))
	def test_padding_is_idempotent(self, k, arity):
		call = f"{self.NAME}({self._arg_list(k)});"
		once = _pad_call_args(call, self.NAME, arity)
		assert _pad_call_args(once, self.NAME, arity) == once

	@given(
		groups=st.lists(st.integers(0, 4), min_size=1, max_size=5),
		flat=st.integers(0, 4),
	)
	def test_top_level_arg_count_ignores_nesting_invariant(self, groups, flat):
		# A parenthesised group counts as one argument regardless of its inner
		# commas; flat args each count once.
		nested = [f"g({self._arg_list(n)})" for n in groups]
		flat_args = [f"a{i}" for i in range(flat)]
		args = ", ".join(nested + flat_args)
		assert _count_top_level_args(args) == len(nested) + flat
