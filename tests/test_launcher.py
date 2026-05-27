"""Tests for src.launcher.

We only exercise the pure helpers here. The end-to-end launch flow
spawns a real LLM client + Wine + objdiff and is covered by manual
smoke-testing through the web UI, not the test suite.
"""

from src.launcher import _infer_mangled_name


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
