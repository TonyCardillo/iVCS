"""Tests for src.launcher.

We only exercise the pure helpers here. The end-to-end launch flow
spawns a real LLM client + Wine + objdiff and is covered by manual
smoke-testing through the web UI, not the test suite.
"""

from src.launcher import (
    _compose_ctx_h,
    _extract_rel32_callee_names,
    _format_target_forward_decl,
    _infer_mangled_name,
    _rel32_callee_names_from_sites,
    _wipe_workspace_history,
)
from src.relocs import RelocKind, RelocSite
from src.workspace import FunctionWorkspace


def test_infer_mangled_cdecl_ret_zero():
    # ret (0xC3) → no args popped → cdecl-style mangling
    body = b"\xb8\x00\x00\x00\x00\xc3"
    assert _infer_mangled_name(body, "sub_002D1D94") == "_sub_002D1D94"


def test_infer_mangled_stdcall_one_arg():
    # push esi; mov esi, ecx; xor eax, eax; pop esi; ret 4 (c2 04 00)
    body = b"\x56\x8b\xf1\x33\xc0\x5e\xc2\x04\x00"
    assert _infer_mangled_name(body, "sub_002D1D94") == "_sub_002D1D94@4"


def test_infer_mangled_stdcall_three_args():
    # ret 0xC (c2 0c 00)
    body = b"\xb8\x00\x00\x00\x00\xc2\x0c\x00"
    assert _infer_mangled_name(body, "sub_X") == "_sub_X@12"


def test_infer_mangled_first_ret_wins():
    # early ret (c3) before a later stdcall ret would still pick the first.
    # cmp eax, eax; jne +2; ret; ret 8 (c3 then c2 08 00)
    body = b"\x39\xc0\x75\x01\xc3\xb8\x00\x00\x00\x00\xc2\x08\x00"
    assert _infer_mangled_name(body, "sub_X") == "_sub_X"


def test_infer_mangled_no_ret_falls_back():
    # data-like bytes that don't decode to a ret
    body = b"\x00" * 16
    assert _infer_mangled_name(body, "sub_X") == "_sub_X"


def test_forward_decl_cdecl_returns_none():
    assert _format_target_forward_decl("sub_X", "_sub_X") is None


def test_forward_decl_stdcall_zero_args():
    assert _format_target_forward_decl("sub_X", "_sub_X@0") == "int __stdcall sub_X(void);"


def test_forward_decl_stdcall_one_arg():
    assert (
        _format_target_forward_decl("sub_002D1D94", "_sub_002D1D94@4")
        == "int __stdcall sub_002D1D94(int);"
    )


def test_forward_decl_stdcall_three_args():
    assert (
        _format_target_forward_decl("sub_X", "_sub_X@12")
        == "int __stdcall sub_X(int, int, int);"
    )


def test_forward_decl_unusual_byte_count_warns_and_uses_one_int():
    out = _format_target_forward_decl("sub_X", "_sub_X@6")
    assert out is not None
    assert "WARNING" in out
    assert "pops 6 bytes" in out
    assert "int __stdcall sub_X(int);" in out


def test_compose_ctx_h_cdecl_matches_default_stub():
    from src.launcher import _DEFAULT_CTX_H
    assert _compose_ctx_h("sub_X", "_sub_X") == _DEFAULT_CTX_H


def test_compose_ctx_h_stdcall_appends_forward_decl():
    out = _compose_ctx_h("sub_002D1D94", "_sub_002D1D94@4")
    assert "int __stdcall sub_002D1D94(int);" in out
    assert "typedef unsigned long" in out  # baseline typedefs still present


def test_wipe_workspace_history_clears_attempts_and_result(tmp_path):
    ws = FunctionWorkspace(root=tmp_path / "fn", function_name="_sub_X")
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
    ws = FunctionWorkspace(root=tmp_path / "fn", function_name="_sub_X")
    ws.initialize()
    _wipe_workspace_history(ws)  # nothing to delete; must not raise
    assert ws.history_dir.is_dir()


def test_callee_filter_keeps_executable_rel32_only():
    sites = [
        RelocSite(imm_offset=1, kind=RelocKind.REL32, target_va=0x00020000),  # exec
        RelocSite(imm_offset=6, kind=RelocKind.REL32, target_va=0x00500000),  # data
        RelocSite(imm_offset=11, kind=RelocKind.DIR32, target_va=0x00020000), # not REL32
    ]
    is_exec = lambda va: 0x00010000 <= va < 0x00100000
    assert _rel32_callee_names_from_sites(sites, is_exec) == ("sub_00020000",)


def test_callee_filter_dedupes_and_sorts():
    sites = [
        RelocSite(imm_offset=1, kind=RelocKind.REL32, target_va=0x00030000),
        RelocSite(imm_offset=6, kind=RelocKind.REL32, target_va=0x00020000),
        RelocSite(imm_offset=11, kind=RelocKind.REL32, target_va=0x00030000),  # dup
    ]
    is_exec = lambda va: True
    assert _rel32_callee_names_from_sites(sites, is_exec) == (
        "sub_00020000",
        "sub_00030000",
    )


def test_callee_filter_empty():
    assert _rel32_callee_names_from_sites([], lambda v: True) == ()


def test_compose_ctx_h_emits_callee_externs():
    out = _compose_ctx_h("sub_X", "_sub_X", callee_names=("sub_AAAA0001", "sub_BBBB0002"))
    assert "extern void sub_AAAA0001(void);" in out
    assert "extern void sub_BBBB0002(void);" in out
    assert "Callees:" in out


def test_compose_ctx_h_no_callees_no_extern_block():
    out = _compose_ctx_h("sub_X", "_sub_X", callee_names=())
    assert "extern void" not in out
    assert "Callees:" not in out


def test_compose_ctx_h_stdcall_and_callees_coexist():
    out = _compose_ctx_h(
        "sub_002D1D94",
        "_sub_002D1D94@4",
        callee_names=("sub_002D1D66",),
    )
    assert "int __stdcall sub_002D1D94(int);" in out
    assert "extern void sub_002D1D66(void);" in out


def test_wipe_preserves_ctx_h_even_when_caller_wants_history_gone(tmp_path):
    """The wipe helper itself never touches ctx.h — that's a separate axis
    (reset_ctx_h on launch_decomp_job). Locks the contract in place."""
    ws = FunctionWorkspace(root=tmp_path / "fn", function_name="_sub_X")
    ws.initialize()
    ws.ctx_h.write_text("/* hand-edited typedefs */")
    (ws.history_dir / "0001.c").write_text("// attempt")

    _wipe_workspace_history(ws)

    assert ws.ctx_h.read_text() == "/* hand-edited typedefs */"
    assert not (ws.history_dir / "0001.c").exists()
