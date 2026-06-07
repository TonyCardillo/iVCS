"""Tests for src.drivers.launcher.

We exercise the pure helpers here, plus one end-to-end test of the Ghidra
warm-start preparation (TestLocalRunWarmstartE2E) — the model-independent
front half every "local" run drives. The full launch flow's back half
(a real LLM client + Wine + objdiff) is still covered by manual smoke-testing
through the web UI, not the test suite.
"""

import subprocess
from pathlib import Path

from hypothesis import given
from hypothesis import strategies as st

from src.core.project import FunctionEntry, Project
from src.core.workspace import FunctionWorkspace
from src.decomp import ghidra_decompile
from src.drivers.launcher import (
	_callee_alias_line,
	_compose_ctx_h,
	_format_callee_decl,
	_format_kernel_decl,
	_format_target_forward_decl,
	_infer_mangled_name,
	_mirror_warmstart_as_attempt_zero,
	_prepare_ghidra_warmstart,
	_rel32_callee_vas_from_sites,
	_select_referenced_structs,
	_stdcall_arglist,
	_wipe_workspace_history,
)
from src.formats.relocs import RelocKind, RelocSite


class TestStdcallArglist:
	# The single source of truth the three decl formatters share. The example
	# tests below (forward/callee/kernel) are witnesses of these laws.
	def test_zero_bytes_is_void_example(self):
		assert _stdcall_arglist(0) == ("void", False)

	@given(n=st.integers(min_value=1, max_value=64))
	def test_multiple_of_four_is_n_ints_invariant(self, n):
		# byte_count = 4n ⇒ exactly n `int` placeholders, not flagged irregular.
		assert _stdcall_arglist(4 * n) == (", ".join(["int"] * n), False)

	@given(byte_count=st.integers(min_value=1, max_value=256).filter(lambda b: b % 4 != 0))
	def test_non_multiple_of_four_flags_irregular_and_falls_back_to_one_int(self, byte_count):
		assert _stdcall_arglist(byte_count) == ("int", True)


def test_infer_mangled_cdecl_ret_zero():
	# ret (0xC3) → no args popped → cdecl-style mangling
	body = b"\xb8\x00\x00\x00\x00\xc3"
	assert _infer_mangled_name(body, "fn_002D1D94") == "_fn_002D1D94"


def test_infer_mangled_stdcall_one_arg():
	# push esi; mov esi, ecx; xor eax, eax; pop esi; ret 4 (c2 04 00)
	body = b"\x56\x8b\xf1\x33\xc0\x5e\xc2\x04\x00"
	assert _infer_mangled_name(body, "fn_002D1D94") == "_fn_002D1D94@4"


def test_infer_mangled_stdcall_three_args():
	# ret 0xC (c2 0c 00)
	body = b"\xb8\x00\x00\x00\x00\xc2\x0c\x00"
	assert _infer_mangled_name(body, "fn_X") == "_fn_X@12"


def test_infer_mangled_first_ret_wins():
	# early ret (c3) before a later stdcall ret would still pick the first.
	# cmp eax, eax; jne +2; ret; ret 8 (c3 then c2 08 00)
	body = b"\x39\xc0\x75\x01\xc3\xb8\x00\x00\x00\x00\xc2\x08\x00"
	assert _infer_mangled_name(body, "fn_X") == "_fn_X"


def test_infer_mangled_no_ret_falls_back():
	# data-like bytes that don't decode to a ret
	body = b"\x00" * 16
	assert _infer_mangled_name(body, "fn_X") == "_fn_X"


def test_forward_decl_cdecl_returns_none():
	assert _format_target_forward_decl("fn_X", "_fn_X") is None


def test_forward_decl_stdcall_zero_args():
	assert _format_target_forward_decl("fn_X", "_fn_X@0") == "int __stdcall fn_X(void);"


def test_forward_decl_stdcall_one_arg():
	assert (
		_format_target_forward_decl("fn_002D1D94", "_fn_002D1D94@4")
		== "int __stdcall fn_002D1D94(int);"
	)


def test_forward_decl_stdcall_three_args():
	assert _format_target_forward_decl("fn_X", "_fn_X@12") == "int __stdcall fn_X(int, int, int);"


def test_forward_decl_unusual_byte_count_warns_and_uses_one_int():
	out = _format_target_forward_decl("fn_X", "_fn_X@6")
	assert out is not None
	assert "WARNING" in out
	assert "pops 6 bytes" in out
	assert "int __stdcall fn_X(int);" in out


def test_compose_ctx_h_cdecl_matches_default_stub():
	from src.drivers.launcher import _DEFAULT_CTX_H

	assert _compose_ctx_h("fn_X", "_fn_X") == _DEFAULT_CTX_H


def test_compose_ctx_h_typedefs_code_as_callable():
	# Ghidra emits `code *` for function pointers; ctx.h must typedef `code` as a
	# function type so an indirect call `(**(code **)x)()` compiles.
	from src.drivers.launcher import _DEFAULT_CTX_H

	assert "code(" in _DEFAULT_CTX_H or "code (" in _DEFAULT_CTX_H
	assert "typedef" in _DEFAULT_CTX_H


def test_compose_ctx_h_stdcall_appends_forward_decl():
	out = _compose_ctx_h("fn_002D1D94", "_fn_002D1D94@4")
	assert "int __stdcall fn_002D1D94(int);" in out
	assert "typedef unsigned long" in out  # baseline typedefs still present


def test_wipe_workspace_history_clears_attempts_and_result(tmp_path):
	ws = FunctionWorkspace(root=tmp_path / "fn", function_name="_fn_X")
	ws.initialize()
	(ws.history_dir / "0001.c").write_text("/* attempt 1 */")
	(ws.history_dir / "0001.obj").write_bytes(b"OBJ")
	(ws.history_dir / "0001.diff.json").write_text("{}")
	ws.result_json.write_text('{"success": false}')
	ws.best_c.write_text("/* best */")
	ws.target_obj.write_bytes(b"TARGET")
	ws.ctx_h.write_text("/* user-edited */")

	_wipe_workspace_history(ws)

	assert list(ws.history_dir.iterdir()) == []
	assert not ws.result_json.exists()
	assert not ws.best_c.exists()
	# Inputs preserved:
	assert ws.target_obj.read_bytes() == b"TARGET"
	assert ws.ctx_h.read_text() == "/* user-edited */"


def test_wipe_workspace_history_is_idempotent_on_empty(tmp_path):
	ws = FunctionWorkspace(root=tmp_path / "fn", function_name="_fn_X")
	ws.initialize()
	_wipe_workspace_history(ws)  # nothing to delete; must not raise
	assert ws.history_dir.is_dir()


def test_callee_filter_keeps_executable_rel32_only():
	sites = [
		RelocSite(imm_offset=1, kind=RelocKind.REL32, target_va=0x00020000),  # exec
		RelocSite(imm_offset=6, kind=RelocKind.REL32, target_va=0x00500000),  # data
		RelocSite(imm_offset=11, kind=RelocKind.DIR32, target_va=0x00020000),  # not REL32
	]

	def is_exec(va: int) -> bool:
		return 0x00010000 <= va < 0x00100000

	assert _rel32_callee_vas_from_sites(sites, is_exec, self_va=0) == (0x00020000,)


def test_callee_filter_dedupes_and_sorts():
	sites = [
		RelocSite(imm_offset=1, kind=RelocKind.REL32, target_va=0x00030000),
		RelocSite(imm_offset=6, kind=RelocKind.REL32, target_va=0x00020000),
		RelocSite(imm_offset=11, kind=RelocKind.REL32, target_va=0x00030000),  # dup
	]
	assert _rel32_callee_vas_from_sites(sites, lambda _va: True, self_va=0) == (
		0x00020000,
		0x00030000,
	)


def test_callee_filter_drops_self_recursion():
	sites = [
		RelocSite(imm_offset=1, kind=RelocKind.REL32, target_va=0x00040000),  # self
		RelocSite(imm_offset=6, kind=RelocKind.REL32, target_va=0x00020000),
	]
	assert _rel32_callee_vas_from_sites(sites, lambda _va: True, self_va=0x00040000) == (
		0x00020000,
	)


def test_callee_filter_empty():
	assert _rel32_callee_vas_from_sites([], lambda v: True, self_va=0) == ()


def test_compose_ctx_h_emits_callee_forward_decls():
	out = _compose_ctx_h(
		"fn_X",
		"_fn_X",
		callee_decls=("int fn_AAAA0001();", "int __stdcall fn_BBBB0002(int);"),
	)
	assert "int fn_AAAA0001();" in out
	assert "int __stdcall fn_BBBB0002(int);" in out
	assert "Same-binary callees" in out  # the section heading
	assert "use these names verbatim" not in out  # old comment-style is gone


def test_compose_ctx_h_no_callees_no_block():
	out = _compose_ctx_h("fn_X", "_fn_X", callee_decls=())
	assert "Same-binary callees" not in out


def test_compose_ctx_h_stdcall_target_and_callee_decls_coexist():
	out = _compose_ctx_h(
		"fn_002D1D94",
		"_fn_002D1D94@4",
		callee_decls=("int __stdcall fn_002D1D66(int, int);",),
	)
	assert "int __stdcall fn_002D1D94(int);" in out  # target
	assert "int __stdcall fn_002D1D66(int, int);" in out  # callee


def test_wipe_preserves_ctx_h_even_when_caller_wants_history_gone(tmp_path):
	"""The wipe helper itself never touches ctx.h — that's a separate axis
	(reset_ctx_h on launch_decomp_job). Locks the contract in place."""
	ws = FunctionWorkspace(root=tmp_path / "fn", function_name="_fn_X")
	ws.initialize()
	ws.ctx_h.write_text("/* hand-edited typedefs */")
	(ws.history_dir / "0001.c").write_text("// attempt")

	_wipe_workspace_history(ws)

	assert ws.ctx_h.read_text() == "/* hand-edited typedefs */"
	assert not (ws.history_dir / "0001.c").exists()


class TestKernelDecl:
	def test_known_function_uses_curated_signature(self):
		decl = _format_kernel_decl("NtClose")
		assert decl == "__declspec(dllimport) NTSTATUS __stdcall NtClose(HANDLE);"

	def test_zero_arg_function_uses_void(self):
		decl = _format_kernel_decl("AvGetSavedDataAddress")
		assert decl == ("__declspec(dllimport) PVOID __stdcall AvGetSavedDataAddress(void);")

	def test_variable_export_uses_extern_form(self):
		decl = _format_kernel_decl("KeTickCount")
		assert decl == ("extern __declspec(dllimport) volatile ULONG KeTickCount;")

	def test_varargs_function_omits_stdcall(self):
		# DbgPrint is variadic and unmangled.
		decl = _format_kernel_decl("DbgPrint")
		assert "__stdcall" not in decl
		assert "..." in decl
		assert decl.startswith("__declspec(dllimport) ULONG DbgPrint(")

	def test_uncurated_function_falls_back_to_int_placeholders(self):
		# An export with @N but no curated signature should fall back.
		# ExAcquireReadWriteLockShared@4 (ordinal 12 in xbdm_gdb_bridge):
		# it's in xboxkrnl_ordinals.json but we did NOT curate it.
		decl = _format_kernel_decl("ExAcquireReadWriteLockShared")
		# Curated entries take precedence; uncurated => int fallback.
		# If we later curate this one the test must be retargeted to a
		# still-uncurated export.
		assert decl.startswith("__declspec(dllimport) int __stdcall ")
		assert decl.endswith(");")
		assert "ExAcquireReadWriteLockShared" in decl

	def test_unknown_kernel_name_falls_back_to_knr(self):
		# No ordinal, no signature — bare K&R-style decl with no prototype.
		decl = _format_kernel_decl("NotARealKernelExport")
		assert decl == "__declspec(dllimport) int NotARealKernelExport();"


class TestFormatCalleeDecl:
	def test_cdecl_kr_style(self):
		assert _format_callee_decl("fn_X", "cdecl", 0) == "int fn_X();"

	def test_stdcall_zero_args_uses_void(self):
		assert _format_callee_decl("fn_X", "stdcall", 0) == "int __stdcall fn_X(void);"

	def test_stdcall_one_arg(self):
		assert _format_callee_decl("fn_X", "stdcall", 4) == "int __stdcall fn_X(int);"

	def test_stdcall_three_args(self):
		assert _format_callee_decl("fn_X", "stdcall", 12) == "int __stdcall fn_X(int, int, int);"

	def test_stdcall_unusual_byte_count_emits_warning(self):
		out = _format_callee_decl("fn_X", "stdcall", 6)
		assert "WARN" in out
		assert "pops 6 bytes" in out
		assert "int __stdcall fn_X(int);" in out

	def test_label_appended_as_comment(self):
		# The machine symbol stays fn_X (compile/diff anchor); the human label
		# rides along as a trailing comment so the model reads the real name.
		out = _format_callee_decl("fn_00175F40", "cdecl", 0, label="CPlayer__Update")
		assert out == "int fn_00175F40();  // CPlayer__Update"

	def test_label_on_stdcall_decl(self):
		out = _format_callee_decl("fn_X", "stdcall", 4, label="DoThing")
		assert out == "int __stdcall fn_X(int);  // DoThing"

	def test_default_label_adds_no_comment(self):
		# A label equal to the machine name is the default — no noise.
		assert _format_callee_decl("fn_X", "cdecl", 0, label="fn_X") == "int fn_X();"

	def test_no_label_unchanged(self):
		assert _format_callee_decl("fn_X", "cdecl", 0, label=None) == "int fn_X();"


class TestCalleeAliasLine:
	def test_real_label_becomes_define(self):
		# The model can call unit_enter_vehicle(...); preprocessor rewrites it to
		# fn_0009EBE0(...), so the compiled call still emits the matching symbol.
		assert (
			_callee_alias_line("unit_enter_vehicle", "fn_0009EBE0")
			== "#define unit_enter_vehicle fn_0009EBE0"
		)

	def test_none_when_label_equals_machine_name(self):
		assert _callee_alias_line("fn_0009EBE0", "fn_0009EBE0") is None

	def test_none_when_no_label(self):
		assert _callee_alias_line(None, "fn_X") is None
		assert _callee_alias_line("", "fn_X") is None

	def test_none_for_non_identifier_label(self):
		# A C++-ish display label can't be a macro name; the comment still carries it.
		assert _callee_alias_line("CPlayer::Update", "fn_X") is None
		assert _callee_alias_line("has space", "fn_X") is None

	def test_none_for_c_keyword(self):
		assert _callee_alias_line("int", "fn_X") is None
		assert _callee_alias_line("struct", "fn_X") is None

	def test_none_for_ctx_h_typedef(self):
		# Aliasing a ctx.h type (DWORD, HANDLE, …) would corrupt the header.
		assert _callee_alias_line("DWORD", "fn_X") is None
		assert _callee_alias_line("HANDLE", "fn_X") is None


class TestWarmstartMirror:
	def test_noop_when_no_warmstart_file(self, tmp_path):
		ws = FunctionWorkspace(root=tmp_path / "fn", function_name="_fn_X")
		ws.initialize()
		_mirror_warmstart_as_attempt_zero(ws)
		assert not (ws.history_dir / "0000.c").exists()

	def test_writes_attempt_zero_with_ctx_h_prepended(self, tmp_path):
		ws = FunctionWorkspace(root=tmp_path / "fn", function_name="_fn_X")
		ws.initialize()
		ws.ctx_h.write_text("typedef int TYPE;\n")
		ws.ghidra_warmstart.write_text("void fn_X(void){}\n")
		_mirror_warmstart_as_attempt_zero(ws)
		# Same shape as LLM attempts: ctx.h then the function body.
		zero = (ws.history_dir / "0000.c").read_text()
		assert "typedef int TYPE;" in zero
		assert "void fn_X(void){}" in zero
		assert zero.index("typedef") < zero.index("void fn_X")

	def test_attempt_zero_uses_canonical_path(self, tmp_path):
		ws = FunctionWorkspace(root=tmp_path / "fn", function_name="_fn_X")
		ws.initialize()
		ws.ghidra_warmstart.write_text("void fn_X(void){}\n")
		_mirror_warmstart_as_attempt_zero(ws)
		# attempt_paths(0).c is the canonical destination.
		assert ws.attempt_paths(0).c.is_file()

	def test_idempotent_when_content_matches(self, tmp_path):
		ws = FunctionWorkspace(root=tmp_path / "fn", function_name="_fn_X")
		ws.initialize()
		ws.ghidra_warmstart.write_text("void fn_X(void){}\n")
		_mirror_warmstart_as_attempt_zero(ws)
		# A second mirror with identical normalized content leaves artifacts alone.
		ws.attempt_paths(0).obj.write_bytes(b"\x90")  # pretend the baseline compiled
		_mirror_warmstart_as_attempt_zero(ws)
		assert ws.attempt_paths(0).obj.read_bytes() == b"\x90"  # not invalidated

	def test_regenerates_when_normalized_content_differs(self, tmp_path):
		# A stale 0000.c (e.g. from before a normalizer fix) must refresh, and its
		# compiled/diffed artifacts must be invalidated so the baseline recompiles.
		ws = FunctionWorkspace(root=tmp_path / "fn", function_name="_fn_X")
		ws.initialize()
		ws.ghidra_warmstart.write_text("void fn_X(void){ DAT_00485aa0 = 1; }\n")
		ws.attempt_paths(0).c.write_text("stale — DAT_00485aa0 = 1;")
		ws.attempt_paths(0).obj.write_bytes(b"\x90")
		ws.attempt_paths(0).diff_json.write_text("{}")

		_mirror_warmstart_as_attempt_zero(ws)

		regenerated = ws.attempt_paths(0).c.read_text()
		assert "DAT_" not in regenerated  # normalizer's DAT_ rewrite reached it
		assert "(*(int *)0x00485aa0)" in regenerated
		assert not ws.attempt_paths(0).obj.exists()  # stale obj invalidated
		assert not ws.attempt_paths(0).diff_json.exists()


class TestSelectReferencedStructs:
	HEADER = (
		"/* harvested */\n"
		"#pragma pack(push, 1)\n\n"
		"typedef struct {\n\tunsigned long a;\n} XBE_FILE_HEADER;\n\n"
		"typedef struct {\n\tunsigned long b;\n} XBE_CERTIFICATE_HEADER;\n\n"
		"typedef struct {\n\tunsigned long c;\n} UNREFERENCED;\n\n"
		"#pragma pack(pop)\n"
	)

	def test_selects_only_referenced_blocks(self):
		# The draft names the instance form; selection still picks the type.
		text, names = _select_referenced_structs(self.HEADER, "x = XBE_FILE_HEADER_00010000.a;")
		assert names == ("XBE_FILE_HEADER",)
		assert "} XBE_FILE_HEADER;" in text
		assert "UNREFERENCED" not in text

	def test_rewraps_selection_in_pack1(self):
		# Offsets only hold under pack(1); the selected slice must carry it.
		text, _ = _select_referenced_structs(self.HEADER, "XBE_FILE_HEADER_00010000.a;")
		assert "#pragma pack(push, 1)" in text
		assert "#pragma pack(pop)" in text

	def test_no_reference_yields_empty(self):
		assert _select_referenced_structs(self.HEADER, "int unrelated_code(void);") == ("", ())

	def test_empty_header_yields_empty(self):
		assert _select_referenced_structs("", "XBE_FILE_HEADER_00010000.a;") == ("", ())

	def test_pulls_in_by_value_dependency_closure(self):
		# draft references only OUTER; INNER is a by-value member and must be
		# carried along, declared before OUTER (harvest emits deps first).
		header = (
			"#pragma pack(push, 1)\n\n"
			"typedef struct {\n\tunsigned long a;\n} INNER;\n\n"
			"typedef struct {\n\tINNER nested;\n} OUTER;\n\n"
			"#pragma pack(pop)\n"
		)
		text, names = _select_referenced_structs(header, "OUTER_00020000.nested;")
		assert set(names) == {"OUTER", "INNER"}
		assert text.index("} INNER;") < text.index("} OUTER;")


class TestWarmstartMirrorStructRewrite:
	def test_struct_names_drive_attempt_zero_rewrite(self, tmp_path):
		ws = FunctionWorkspace(root=tmp_path / "fn", function_name="_fn_X")
		ws.initialize()
		ws.ctx_h.write_text("typedef struct { int x; } XBE_FILE_HEADER;\n")
		ws.ghidra_warmstart.write_text("void fn_X(void){ int y = XBE_FILE_HEADER_00010000.x; }\n")
		_mirror_warmstart_as_attempt_zero(ws, struct_names=("XBE_FILE_HEADER",))
		zero = (ws.history_dir / "0000.c").read_text()
		assert "(*(XBE_FILE_HEADER *)0x00010000).x" in zero
		assert "XBE_FILE_HEADER_00010000" not in zero

	def test_without_struct_names_instance_is_left_raw(self, tmp_path):
		ws = FunctionWorkspace(root=tmp_path / "fn", function_name="_fn_X")
		ws.initialize()
		ws.ghidra_warmstart.write_text("void fn_X(void){ XBE_FILE_HEADER_00010000.x; }\n")
		_mirror_warmstart_as_attempt_zero(ws)  # no struct_names
		zero = (ws.history_dir / "0000.c").read_text()
		assert "XBE_FILE_HEADER_00010000" in zero

	def test_stdcall_target_pins_definition_in_attempt_zero(self, tmp_path):
		ws = FunctionWorkspace(root=tmp_path / "fn", function_name="_fn_X@12")
		ws.initialize()
		ws.ghidra_warmstart.write_text("void fn_X(int a, int b, int c)\n{\n  return;\n}\n")
		_mirror_warmstart_as_attempt_zero(ws, stdcall_target="fn_X")
		zero = (ws.history_dir / "0000.c").read_text()
		assert "int __stdcall fn_X(int a, int b, int c)" in zero

	def test_callee_arities_pad_attempt_zero_call_sites(self, tmp_path):
		ws = FunctionWorkspace(root=tmp_path / "fn", function_name="_fn_X")
		ws.initialize()
		ws.ghidra_warmstart.write_text("void fn_X(void)\n{\n  fn_0012C090();\n}\n")
		_mirror_warmstart_as_attempt_zero(ws, callee_arities={"fn_0012C090": 2})
		zero = (ws.history_dir / "0000.c").read_text()
		assert "fn_0012C090(0, 0);" in zero


class TestStructDeclsInCtxH:
	def test_struct_block_injected_after_typedefs(self):
		structs = (
			"#pragma pack(push, 1)\ntypedef struct { int a; } XBE_FILE_HEADER;\n#pragma pack(pop)\n"
		)
		out = _compose_ctx_h("fn_X", "_fn_X", struct_decls=structs)
		assert "XBE_FILE_HEADER" in out
		assert "Ghidra-harvested struct layouts" in out
		# Baseline typedefs precede the harvested layouts.
		assert out.index("typedef unsigned char") < out.index("XBE_FILE_HEADER")

	def test_no_struct_decls_no_section(self):
		out = _compose_ctx_h("fn_X", "_fn_X")
		assert "Ghidra-harvested" not in out


class TestKernelImportsInCtxH:
	def test_kernel_imports_section_present(self):
		out = _compose_ctx_h("fn_X", "_fn_X", (), ("NtClose", "DbgPrint"))
		assert "/* xboxkrnl imports. */" in out
		assert "NtClose(HANDLE)" in out
		assert "DbgPrint" in out

	def test_kernel_imports_render_in_caller_order(self):
		# The composer preserves caller order verbatim — it does NOT sort (that
		# is _extract_kernel_imports' job). Feeding *reverse*-sorted names proves
		# it: a sorting composer would flip them, an order-preserving one won't.
		out = _compose_ctx_h("fn_X", "_fn_X", (), ("NtClose", "DbgPrint"))
		assert out.index("NtClose") < out.index("DbgPrint")

	def test_no_kernel_imports_section_when_empty(self):
		out = _compose_ctx_h("fn_X", "_fn_X", (), ())
		assert "/* xboxkrnl imports." not in out

	def test_typedef_block_includes_kernel_types(self):
		# ULONG, HANDLE, NTSTATUS, PVOID must all be in the default ctx.h
		# so that any kernel decl that uses them parses.
		out = _compose_ctx_h("fn_X", "_fn_X", (), ())
		for t in (
			"ULONG",
			"USHORT",
			"UCHAR",
			"CHAR",
			"ACCESS_MASK",
			"LARGE_INTEGER",
			"PLARGE_INTEGER",
			"PHANDLE",
			"POBJECT_ATTRIBUTES",
			"PIO_STATUS_BLOCK",
			"PULONG",
			"ULONG_PTR",
			"ULONGLONG",
			"SIZE_T",
		):
			assert f" {t};" in out or f"{t} " in out, f"missing typedef {t}"


class TestLocalRunWarmstartE2E:
	"""End-to-end coverage of the Ghidra warm-start prep a local-model run
	drives, stubbing only the analyzeHeadless subprocess boundary so the real
	ghidra_project_ensure -> decompile -> structs_dump path runs.

	Regression guard for the partial-import bug: a crashed run (or a cancelled
	sweep) leaves a `.rep` data dir holding no committed program, beside a
	marker `.gpr` (which is legitimately 0 bytes). Ghidra refuses to import over
	an existing `.rep`, so a naive `.gpr` is_file() check trusts the partial
	project, the bootstrap silently no-ops, and every decompile then dies with
	"project not bootstrapped" / "produced no output". ensure() must detect the
	missing program, clear the stale data, and verify a real program lands.
	"""

	def _fake_ghidra(self):
		"""A fake analyzeHeadless modeling the real binary's behavior: a
		successful import writes an empty marker `.gpr` and commits a program
		under `.rep/idata/`, but REFUSES (commits nothing) when a `.rep` already
		exists; the post-scripts write their out-file (last argv)."""

		def fake_run(argv, **_kwargs):
			project_dir = Path(argv[1])
			name = argv[2]
			gpr = project_dir / f"{name}.gpr"
			rep = project_dir / f"{name}.rep"
			if "-import" in argv:
				if rep.exists():
					# Ghidra won't recreate an existing .rep: marker prints,
					# but no program is committed — the exact failure mode.
					return subprocess.CompletedProcess(
						argv, 0, stdout="REPORT: Analysis succeeded", stderr=""
					)
				gpr.write_text("")  # marker file is legitimately empty
				bucket = rep / "idata" / "00"
				bucket.mkdir(parents=True, exist_ok=True)
				(bucket / "00000000.prp").write_text("program")  # committed program
				ok = "REPORT: Import succeeded\nREPORT: Analysis succeeded"
				return subprocess.CompletedProcess(argv, 0, stdout=ok, stderr="")
			out_path = Path(argv[-1])
			if ghidra_decompile._DUMP_STRUCTS_SCRIPT in argv:
				out_path.write_text("typedef struct { int x; } FOO;\n")
			else:  # decompile post-script
				out_path.write_text("int fn_00430D9B(void) { FOO_00485000.x = 1; return 0; }\n")
			return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

		return fake_run

	def _setup(self, monkeypatch, tmp_path):
		monkeypatch.setattr(ghidra_decompile, "_default_run", self._fake_ghidra())
		project_dir = tmp_path / "ghidra-projects"
		monkeypatch.setenv("IVCS_GHIDRA_PROJECT_DIR", str(project_dir))
		monkeypatch.setenv("IVCS_GHIDRA_HOME", str(tmp_path / "ghidra"))
		xbe_path = tmp_path / "halo2_default.xbe"  # stem -> project name
		project = Project(
			name="halo2",
			xbe_path=xbe_path,
			workspace_root=tmp_path / "functions",
			functions=(),
		)
		fn = FunctionEntry(name="fn_00430D9B", va=0x430D9B, size=64)
		workspace = FunctionWorkspace(root=project.workspace_for(fn), function_name="fn_00430D9B")
		workspace.initialize()
		return project, fn, workspace, project_dir

	def test_clean_slate_produces_warmstart_draft_and_structs(self, monkeypatch, tmp_path):
		project, fn, workspace, _ = self._setup(monkeypatch, tmp_path)

		struct_decls, struct_names = _prepare_ghidra_warmstart(workspace, project, fn)

		assert workspace.ghidra_warmstart.is_file()
		assert "fn_00430D9B" in workspace.ghidra_warmstart.read_text()
		# The draft references FOO_00485000, so its layout is harvested into ctx.h.
		assert "FOO" in struct_names
		assert "FOO" in struct_decls

	def test_recovers_from_orphaned_rep_without_gpr(self, monkeypatch, tmp_path):
		# A .rep survives (no committed program) but the .gpr marker is gone.
		project, fn, workspace, project_dir = self._setup(monkeypatch, tmp_path)
		orphan_rep = project_dir / "halo2_default.rep"
		(orphan_rep / "versioned").mkdir(parents=True)
		(orphan_rep / "project.prp").write_text("stale")
		assert not (project_dir / "halo2_default.gpr").exists()

		struct_decls, struct_names = _prepare_ghidra_warmstart(workspace, project, fn)

		# Before the fix this returned ("", ()) with no draft written, because
		# ensure() trusted the success marker and decompile hit "not bootstrapped".
		assert workspace.ghidra_warmstart.is_file()
		assert "fn_00430D9B" in workspace.ghidra_warmstart.read_text()
		assert "FOO" in struct_names
		assert (project_dir / "halo2_default.rep" / "idata" / "00").is_dir()

	def test_recovers_from_partial_rep_with_marker(self, monkeypatch, tmp_path):
		# The actually-observed on-disk state: an empty marker `.gpr` left beside
		# a `.rep` that holds no committed program (import killed mid-write).
		# is_file() on the marker passes, so before the fix ensure() skipped the
		# rebuild and every sweep function failed with "decompile produced no
		# output". ensure() must notice the missing program and rebuild.
		project, fn, workspace, project_dir = self._setup(monkeypatch, tmp_path)
		rep = project_dir / "halo2_default.rep"
		(rep / "idata").mkdir(parents=True)
		(rep / "idata" / "~index.dat").write_text("")  # stub only, no program bucket
		gpr = project_dir / "halo2_default.gpr"
		gpr.write_text("")  # marker, legitimately empty

		struct_decls, struct_names = _prepare_ghidra_warmstart(workspace, project, fn)

		assert workspace.ghidra_warmstart.is_file()
		assert "fn_00430D9B" in workspace.ghidra_warmstart.read_text()
		assert "FOO" in struct_names
		assert (rep / "idata" / "00").is_dir()  # rebuilt into a real project

	def test_cached_warmstart_rebootstraps_project_for_structs(self, monkeypatch, tmp_path):
		# A prior session cached the warm-start draft, but the Ghidra data dir was
		# then evicted (a /tmp wipe on reboot). Because the draft is on disk, the
		# old code skipped ensure() and the struct dump died with "not bootstrapped",
		# silently dropping every cached function's type context. Prep must re-ensure
		# the project even when the draft is cached — without regenerating the draft.
		project, fn, workspace, project_dir = self._setup(monkeypatch, tmp_path)
		cached = "int fn_00430D9B(void) { FOO_00485000.x = 7; return 0; }\n"
		workspace.ghidra_warmstart.write_text(cached)
		assert not (project_dir / "halo2_default.gpr").exists()  # project evicted

		struct_decls, struct_names = _prepare_ghidra_warmstart(workspace, project, fn)

		assert workspace.ghidra_warmstart.read_text() == cached  # draft preserved, not rebuilt
		assert "FOO" in struct_names  # structs harvested after the re-bootstrap
		assert "FOO" in struct_decls
		assert (project_dir / "halo2_default.rep" / "idata" / "00").is_dir()
