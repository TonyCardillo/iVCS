"""Tests for the xboxkrnl ordinal database.

The MVP exposes ordinal-to-name and ordinal-to-mangled-name lookups.
We don't need to test the JSON file's contents exhaustively — spot
checks plus structural invariants (range, parseability) are enough to
catch a corrupted/regenerated DB.
"""

from src.xboxkrnl import (
    XBOXKRNL_ORDINAL_MAX,
    XBOXKRNL_ORDINAL_MIN,
    KernelFunctionSig,
    KernelVariableSig,
    xboxkrnl_mangled_byte_count,
    xboxkrnl_mangled_get,
    xboxkrnl_name_get,
    xboxkrnl_ordinals_known,
    xboxkrnl_signature_get,
)

# Known stable anchors lifted from the Cxbx-Reloaded / xbdm_gdb_bridge tables.
# These ordinals have been published consistently for years.
KNOWN_ANCHORS = {
    1: "AvGetSavedDataAddress",
    8: "DbgPrint",
    156: "KeTickCount",
    256: "PsQueryStatistics",
}


class TestNameLookup:
    def test_known_ordinals_resolve(self):
        for ordinal, expected in KNOWN_ANCHORS.items():
            assert xboxkrnl_name_get(ordinal) == expected, f"ordinal {ordinal}"

    def test_unknown_ordinal_returns_none(self):
        # 0 is never assigned in the xboxkrnl table; 999 is past the end.
        assert xboxkrnl_name_get(0) is None
        assert xboxkrnl_name_get(999) is None

    def test_gap_ordinal_returns_none(self):
        # Ordinals 367-373 are documented gaps in the xboxkrnl table.
        for gap in range(367, 374):
            assert xboxkrnl_name_get(gap) is None, f"gap ordinal {gap}"


class TestMangledLookup:
    def test_mangled_includes_stdcall_suffix(self):
        # AvGetSavedDataAddress takes 0 bytes of args (no params).
        assert xboxkrnl_mangled_get(1) == "AvGetSavedDataAddress@0"

    def test_mangled_for_unmangled_export(self):
        # DbgPrint is variadic and exported without stdcall mangling.
        assert xboxkrnl_mangled_get(8) == "DbgPrint"

    def test_unknown_ordinal_mangled_is_none(self):
        assert xboxkrnl_mangled_get(0) is None


class TestStructuralInvariants:
    def test_ordinal_range_is_published(self):
        # Ordinals 1..378, no zero, no negatives.
        ordinals = xboxkrnl_ordinals_known()
        assert min(ordinals) == XBOXKRNL_ORDINAL_MIN == 1
        assert max(ordinals) == XBOXKRNL_ORDINAL_MAX == 378

    def test_mangled_corresponds_to_name(self):
        # Mangled form should always start with the clean name (possibly
        # preceded by '@' for fastcall) and may carry an '@N' suffix.
        for ordinal in xboxkrnl_ordinals_known():
            name = xboxkrnl_name_get(ordinal)
            mangled = xboxkrnl_mangled_get(ordinal)
            assert name is not None and mangled is not None
            # Strip optional fastcall '@' prefix and optional '@N' suffix.
            core = mangled.lstrip("@").rsplit("@", 1)[0] if "@" in mangled.lstrip("@") else mangled.lstrip("@")
            assert core == name, f"ordinal {ordinal}: mangled {mangled!r} doesn't carry name {name!r}"


class TestSignatureLookup:
    def test_function_signature_resolves(self):
        sig = xboxkrnl_signature_get("NtClose")
        assert isinstance(sig, KernelFunctionSig)
        assert sig.return_type == "NTSTATUS"
        assert sig.arg_types == ("HANDLE",)
        assert sig.varargs is False

    def test_varargs_signature_marked(self):
        sig = xboxkrnl_signature_get("DbgPrint")
        assert isinstance(sig, KernelFunctionSig)
        assert sig.varargs is True

    def test_variable_signature_resolves(self):
        sig = xboxkrnl_signature_get("KeTickCount")
        assert isinstance(sig, KernelVariableSig)
        assert sig.var_type == "volatile ULONG"

    def test_unknown_name_returns_none(self):
        assert xboxkrnl_signature_get("NotARealKernelExport") is None

    def test_meta_key_is_filtered_out(self):
        # The JSON file carries a "_meta" key for human-readable notes.
        # It must not be exposed as a signature lookup result.
        assert xboxkrnl_signature_get("_meta") is None


class TestMangledByteCount:
    def test_known_stdcall_count(self):
        # NtClose@4 → 4 bytes popped.
        assert xboxkrnl_mangled_byte_count("NtClose") == 4

    def test_zero_arg_function(self):
        assert xboxkrnl_mangled_byte_count("AvGetSavedDataAddress") == 0

    def test_unmangled_export_returns_none(self):
        # DbgPrint is exported without @N (variadic).
        assert xboxkrnl_mangled_byte_count("DbgPrint") is None

    def test_unknown_name_returns_none(self):
        assert xboxkrnl_mangled_byte_count("NotARealKernelExport") is None
