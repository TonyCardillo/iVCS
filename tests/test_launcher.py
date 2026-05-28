"""Tests for src.launcher.

We only exercise the pure helpers here. The end-to-end launch flow
spawns a real LLM client + Wine + objdiff and is covered by manual
smoke-testing through the web UI, not the test suite.
"""

from src.launcher import (
	_compose_ctx_h,
	_format_callee_decl,
	_format_kernel_decl,
	_format_target_forward_decl,
	_infer_convention_from_bytes,
	_infer_mangled_name,
	_mirror_warmstart_as_attempt_zero,
	_rel32_callee_vas_from_sites,
	_wipe_workspace_history,
)
from src.relocs import RelocKind, RelocSite
from src.workspace import FunctionWorkspace


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
	from src.launcher import _DEFAULT_CTX_H

	assert _compose_ctx_h("fn_X", "_fn_X") == _DEFAULT_CTX_H


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
	is_exec = lambda va: 0x00010000 <= va < 0x00100000
	assert _rel32_callee_vas_from_sites(sites, is_exec, self_va=0) == (0x00020000,)


def test_callee_filter_dedupes_and_sorts():
	sites = [
		RelocSite(imm_offset=1, kind=RelocKind.REL32, target_va=0x00030000),
		RelocSite(imm_offset=6, kind=RelocKind.REL32, target_va=0x00020000),
		RelocSite(imm_offset=11, kind=RelocKind.REL32, target_va=0x00030000),  # dup
	]
	is_exec = lambda va: True
	assert _rel32_callee_vas_from_sites(sites, is_exec, self_va=0) == (
		0x00020000,
		0x00030000,
	)


def test_callee_filter_drops_self_recursion():
	sites = [
		RelocSite(imm_offset=1, kind=RelocKind.REL32, target_va=0x00040000),  # self
		RelocSite(imm_offset=6, kind=RelocKind.REL32, target_va=0x00020000),
	]
	is_exec = lambda va: True
	assert _rel32_callee_vas_from_sites(sites, is_exec, self_va=0x00040000) == (0x00020000,)


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


class TestInferConvention:
	def test_cdecl_when_first_ret_has_no_immediate(self):
		body = b"\xb8\x00\x00\x00\x00\xc3"  # mov eax, 0; ret
		assert _infer_convention_from_bytes(body) == ("cdecl", 0)

	def test_stdcall_with_byte_count(self):
		body = b"\xc2\x08\x00"  # ret 8
		assert _infer_convention_from_bytes(body) == ("stdcall", 8)

	def test_stdcall_with_one_arg(self):
		body = b"\x56\x8b\xf1\x5e\xc2\x04\x00"  # ret 4
		assert _infer_convention_from_bytes(body) == ("stdcall", 4)

	def test_no_ret_falls_back_to_cdecl(self):
		body = b"\x00" * 8
		assert _infer_convention_from_bytes(body) == ("cdecl", 0)

	def test_first_ret_wins(self):
		# ret (c3) then later ret 8 — first wins.
		body = b"\xc3\xc2\x08\x00"
		assert _infer_convention_from_bytes(body) == ("cdecl", 0)


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

	def test_idempotent_does_not_overwrite_existing_zero(self, tmp_path):
		ws = FunctionWorkspace(root=tmp_path / "fn", function_name="_fn_X")
		ws.initialize()
		ws.ghidra_warmstart.write_text("new draft")
		(ws.history_dir / "0000.c").write_text("pre-existing")
		_mirror_warmstart_as_attempt_zero(ws)
		# Pre-existing 0000.c must not be clobbered; user may have hand-edited.
		assert (ws.history_dir / "0000.c").read_text() == "pre-existing"


class TestKernelImportsInCtxH:
	def test_kernel_imports_section_present(self):
		out = _compose_ctx_h("fn_X", "_fn_X", (), ("NtClose", "DbgPrint"))
		assert "/* xboxkrnl imports. */" in out
		assert "NtClose(HANDLE)" in out
		assert "DbgPrint" in out

	def test_kernel_imports_sorted(self):
		# Composer trusts caller-provided order; the extractor produces
		# sorted tuples, so the rendered block is sorted too.
		out = _compose_ctx_h("fn_X", "_fn_X", (), ("DbgPrint", "NtClose"))
		d_pos = out.index("DbgPrint")
		n_pos = out.index("NtClose")
		assert d_pos < n_pos

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
