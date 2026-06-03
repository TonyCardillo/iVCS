"""Tests for the library signature matcher (relocation-invariant)."""

from src.analysis.fingerprint import function_fingerprint
from src.analysis.libmatch import (
	LibMatch,
	library_signatures,
	match_fingerprints,
	sdk_manifest_load,
	sdk_manifest_write,
	signature_index,
)
from src.formats.coff import coff_object_build
from tests.formats._archive_helpers import ar_blob

# A non-trivial leaf so opcode/equiv hashes are specific (5 instructions).
LIB_BODY = b"\x55\x8b\xec\xb8\x01\x00\x00\x00\x5d\xc3"  # push ebp;mov ebp,esp;mov eax,1;pop ebp;ret
SAME_SKELETON_DIFFERENT_IMM = b"\x55\x8b\xec\xb8\x99\x00\x00\x00\x5d\xc3"  # imm 0x99 not 1


def _lib(*funcs: tuple[str, bytes]) -> bytes:
	# Member names are arbitrary (kept short to fit the 16-byte field); the
	# function name lives in the COFF symbol table inside each object.
	members = [
		(f"m{i}.obj/", coff_object_build(body, name, relocations=[]))
		for i, (name, body) in enumerate(funcs)
	]
	return ar_blob(members)


class TestLibrarySignatures:
	def test_extracts_named_function(self):
		sigs = library_signatures(_lib(("_libfunc", LIB_BODY)))
		assert len(sigs) == 1
		assert sigs[0].name == "_libfunc"
		assert sigs[0].size == len(LIB_BODY)

	def test_signature_matches_fingerprint_hashes(self):
		sig = library_signatures(_lib(("_libfunc", LIB_BODY)))[0]
		fp = function_fingerprint("_libfunc", 0, len(LIB_BODY), LIB_BODY)
		assert sig.opcode_hash == fp.opcode_hash
		assert sig.equiv_hash == fp.equiv_hash


class TestMatching:
	def test_relocation_invariant_match_by_operand_shape(self):
		# The game's copy has a different immediate (as if a constant changed),
		# but the same opcodes and operand types → an exact (equiv) match.
		index = signature_index(library_signatures(_lib(("_memset_like", LIB_BODY))))
		game = function_fingerprint(
			"fn_00400000", 0x00400000, len(SAME_SKELETON_DIFFERENT_IMM), SAME_SKELETON_DIFFERENT_IMM
		)
		matches = match_fingerprints([game], index, min_size=4)
		assert len(matches) == 1
		assert matches[0].names == ("_memset_like",)
		assert matches[0].is_confident
		assert matches[0].confidence == "exact"

	def test_tiny_functions_skipped(self):
		index = signature_index(library_signatures(_lib(("_ret", b"\xc3"))))
		game = function_fingerprint("fn_1", 0x1000, 1, b"\xc3")
		assert match_fingerprints([game], index, min_size=16) == []

	def test_unmatched_function_reported_nowhere(self):
		index = signature_index(library_signatures(_lib(("_libfunc", LIB_BODY))))
		# A clearly different function (longer, different opcodes).
		other = b"\x53\x56\x57\x33\xc0\x40\x40\x5f\x5e\x5b\xc3"
		game = function_fingerprint("fn_1", 0x1000, len(other), other)
		assert match_fingerprints([game], index, min_size=4) == []

	def test_manifest_round_trip_keeps_only_confident(self, tmp_path):
		matches = [
			LibMatch("fn_00400000", 0x00400000, 40, ("_memcpy",), "exact"),
			LibMatch("fn_00400100", 0x00400100, 20, ("_a", "_b"), "skeleton"),  # ambiguous
		]
		path = tmp_path / "sdk.json"
		written = sdk_manifest_write(path, matches)
		assert written == 1  # ambiguous one excluded
		loaded = sdk_manifest_load(path)
		assert loaded == {0x00400000: "_memcpy"}

	def test_ambiguous_signature_lists_all_names(self):
		# Two library functions with the same skeleton but different names.
		index = signature_index(
			library_signatures(_lib(("_alpha", LIB_BODY), ("_beta", SAME_SKELETON_DIFFERENT_IMM)))
		)
		game = function_fingerprint("fn_1", 0x1000, len(LIB_BODY), LIB_BODY)
		matches = match_fingerprints([game], index, min_size=4)
		assert len(matches) == 1
		assert matches[0].names == ("_alpha", "_beta")
		assert not matches[0].is_confident
