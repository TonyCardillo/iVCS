"""Tests for the xboxkrnl ordinal database.

The MVP exposes ordinal-to-name and ordinal-to-mangled-name lookups.
We don't need to test the JSON file's contents exhaustively — spot
checks plus structural invariants (range, parseability) are enough to
catch a corrupted/regenerated DB.
"""

from src.xboxkrnl import (
    XBOXKRNL_ORDINAL_MAX,
    XBOXKRNL_ORDINAL_MIN,
    xboxkrnl_mangled_get,
    xboxkrnl_name_get,
    xboxkrnl_ordinals_known,
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
