"""Tests for x86 structural function fingerprints + clustering + similarity.

A coddog-style index: each function gets an exact hash (raw bytes), an opcode
hash (instruction skeleton, operands stripped), and an equiv hash (operand types
kept, register/immediate identity abstracted). Clusters group equal-hash
functions; similarity is edit distance over the opcode sequence.
"""

from hypothesis import given
from hypothesis import strategies as st

from src.fingerprint import (
	Fingerprint,
	fingerprint_clusters,
	fingerprint_similarity,
	fingerprints_similar_to,
	function_fingerprint,
)

# Hand-built x86-32 snippets (Capstone CS_MODE_32).
PUSH_MOV_POP_RET = b"\x55\x8b\xec\x5d\xc3"  # push ebp; mov ebp,esp; pop ebp; ret
RET = b"\xc3"
# mov eax, imm32 ; ret  — same opcodes as a different-immediate variant below.
MOV_EAX_1_RET = b"\xb8\x01\x00\x00\x00\xc3"
MOV_EAX_2_RET = b"\xb8\x02\x00\x00\x00\xc3"
# mov ecx, imm32 ; ret — same opcode skeleton, different register.
MOV_ECX_1_RET = b"\xb9\x01\x00\x00\x00\xc3"


def _fp(name, va, body) -> Fingerprint:
	return function_fingerprint(name, va, len(body), body)


class TestFunctionFingerprint:
	def test_identical_bytes_share_all_hashes(self):
		a = _fp("a", 0x1000, PUSH_MOV_POP_RET)
		b = _fp("b", 0x2000, PUSH_MOV_POP_RET)
		assert a.exact_hash == b.exact_hash
		assert a.opcode_hash == b.opcode_hash
		assert a.equiv_hash == b.equiv_hash

	def test_different_immediate_keeps_opcode_hash_but_not_exact(self):
		a = _fp("a", 0x1000, MOV_EAX_1_RET)
		b = _fp("b", 0x2000, MOV_EAX_2_RET)
		assert a.exact_hash != b.exact_hash
		assert a.opcode_hash == b.opcode_hash  # same mnemonic skeleton

	def test_different_register_same_opcode_skeleton(self):
		# mov eax,1 vs mov ecx,1: same Capstone opcode id (MOV), same skeleton.
		a = _fp("a", 0x1000, MOV_EAX_1_RET)
		b = _fp("b", 0x2000, MOV_ECX_1_RET)
		assert a.opcode_hash == b.opcode_hash

	def test_opcode_sequence_recorded(self):
		fp = _fp("a", 0x1000, PUSH_MOV_POP_RET)
		assert len(fp.opcodes) == 4  # push, mov, pop, ret

	def test_distinct_functions_differ(self):
		a = _fp("a", 0x1000, PUSH_MOV_POP_RET)
		b = _fp("b", 0x2000, RET)
		assert a.opcode_hash != b.opcode_hash


class TestSimilarity:
	def test_identical_opcodes_exact_match_is_one(self):
		a = _fp("a", 0x1000, PUSH_MOV_POP_RET)
		b = _fp("b", 0x2000, PUSH_MOV_POP_RET)
		assert fingerprint_similarity(a, b) == 1.0

	def test_same_skeleton_different_bytes_is_near_one(self):
		# Identical opcode sequence but different raw bytes (immediate) → 0.9999,
		# coddog's "structurally identical but not byte-identical" sentinel.
		a = _fp("a", 0x1000, MOV_EAX_1_RET)
		b = _fp("b", 0x2000, MOV_EAX_2_RET)
		assert fingerprint_similarity(a, b) == 0.9999

	def test_dissimilar_functions_score_low(self):
		a = _fp("a", 0x1000, PUSH_MOV_POP_RET)
		b = _fp("b", 0x2000, RET)
		assert fingerprint_similarity(a, b) < 0.5

	def test_threshold_short_circuits_to_zero(self):
		# Very different lengths can't beat a high threshold.
		a = _fp("a", 0x1000, PUSH_MOV_POP_RET)
		b = _fp("b", 0x2000, RET)
		assert fingerprint_similarity(a, b, threshold=0.9) == 0.0


class TestClustering:
	def test_groups_equal_opcode_hash(self):
		fps = [
			_fp("a", 0x1000, MOV_EAX_1_RET),
			_fp("b", 0x2000, MOV_EAX_2_RET),  # same skeleton as a
			_fp("c", 0x3000, RET),  # alone
		]
		clusters = fingerprint_clusters(fps, by="opcode", min_size=2)
		assert len(clusters) == 1
		assert {m.name for m in clusters[0].members} == {"a", "b"}

	def test_exact_clustering_splits_immediate_variants(self):
		fps = [
			_fp("a", 0x1000, MOV_EAX_1_RET),
			_fp("b", 0x2000, MOV_EAX_1_RET),  # byte-identical to a
			_fp("c", 0x3000, MOV_EAX_2_RET),  # differs by immediate
		]
		clusters = fingerprint_clusters(fps, by="exact", min_size=2)
		assert len(clusters) == 1
		assert {m.name for m in clusters[0].members} == {"a", "b"}

	def test_clusters_sorted_largest_first(self):
		fps = [
			_fp("a", 0x1000, MOV_EAX_1_RET),
			_fp("b", 0x2000, MOV_EAX_2_RET),
			_fp("c", 0x3000, MOV_ECX_1_RET),
			_fp("d", 0x4000, PUSH_MOV_POP_RET),
			_fp("e", 0x5000, PUSH_MOV_POP_RET),
		]
		clusters = fingerprint_clusters(fps, by="opcode", min_size=2)
		assert clusters[0].size >= clusters[-1].size
		assert clusters[0].size == 3  # the three mov;ret skeletons


class TestSimilarTo:
	def test_ranks_most_similar_first_and_excludes_self(self):
		query = _fp("q", 0x1000, MOV_EAX_1_RET)
		candidates = [
			query,
			_fp("near", 0x2000, MOV_EAX_2_RET),  # same skeleton
			_fp("far", 0x3000, RET),
		]
		ranked = fingerprints_similar_to(query, candidates, threshold=0.1, top_k=5)
		names = [fp.name for fp, _ in ranked]
		assert "q" not in names
		assert names[0] == "near"


# --- Property tests --------------------------------------------------------
# The example tests above each pin one intent; these assert the laws those
# examples are arbitrary witnesses of, so codegen/hashing drift is caught.


def _mov_eax_imm_ret(imm: int) -> bytes:
	"""`mov eax, imm32 ; ret` — same skeleton for any immediate."""
	return b"\xb8" + imm.to_bytes(4, "little") + b"\xc3"


_BYTES = st.binary(min_size=0, max_size=48)
_KEY = {
	"exact": lambda f: f.exact_hash,
	"opcode": lambda f: f.opcode_hash,
	"equiv": lambda f: f.equiv_hash,
}


class TestFingerprintProperties:
	@given(
		body=st.binary(min_size=1, max_size=48),
		va_a=st.integers(0, 2**32 - 1),
		va_b=st.integers(0, 2**32 - 1),
	)
	def test_hashes_depend_only_on_bytes_not_va_or_name_invariant(self, body, va_a, va_b):
		# Determinism + VA/name independence: the bytes alone decide the hashes.
		a = function_fingerprint("a", va_a, len(body), body)
		b = function_fingerprint("b", va_b, len(body), body)
		assert (a.exact_hash, a.opcode_hash, a.equiv_hash) == (
			b.exact_hash,
			b.opcode_hash,
			b.equiv_hash,
		)

	@given(imm_a=st.integers(0, 2**32 - 1), imm_b=st.integers(0, 2**32 - 1))
	def test_immediate_change_preserves_skeleton_metamorphic(self, imm_a, imm_b):
		# Same opcode skeleton + same operand shape regardless of the immediate;
		# the raw-byte hash differs iff the immediates differ.
		a = _fp("a", 0x1000, _mov_eax_imm_ret(imm_a))
		b = _fp("b", 0x1000, _mov_eax_imm_ret(imm_b))
		assert a.opcode_hash == b.opcode_hash
		assert a.equiv_hash == b.equiv_hash
		assert (a.exact_hash == b.exact_hash) == (imm_a == imm_b)

	@given(n=st.integers(0, 40))
	def test_opcode_count_equals_instruction_count_invariant(self, n):
		# n single-byte nops then a ret decode to exactly n+1 instructions.
		fp = _fp("a", 0x1000, b"\x90" * n + b"\xc3")
		assert len(fp.opcodes) == n + 1

	@given(
		bodies=st.lists(st.binary(min_size=1, max_size=24), max_size=12),
		by=st.sampled_from(["exact", "opcode", "equiv"]),
	)
	def test_clusters_partition_input_invariant(self, bodies, by):
		fps = [_fp(f"f{i}", i * 0x10, b) for i, b in enumerate(bodies)]
		clusters = fingerprint_clusters(fps, by=by, min_size=1)
		members = [m for c in clusters for m in c.members]
		# Every input lands in exactly one cluster (distinct VAs ⇒ compare by VA).
		assert sorted(m.va for m in members) == sorted(fp.va for fp in fps)
		# Members of a cluster all share the selecting hash.
		key = _KEY[by]
		for c in clusters:
			assert len({key(m) for m in c.members}) == 1
		# Largest first, with each cluster's lowest member VA as the tie-break.
		assert [(-c.size, c.members[0].va) for c in clusters] == sorted(
			(-c.size, c.members[0].va) for c in clusters
		)

	@given(a=_BYTES, b=_BYTES)
	def test_similarity_is_symmetric_commutation(self, a, b):
		fa, fb = _fp("a", 0x1000, a), _fp("b", 0x2000, b)
		assert fingerprint_similarity(fa, fb) == fingerprint_similarity(fb, fa)

	@given(body=_BYTES)
	def test_similarity_reflexive_and_bounded_invariant(self, body):
		fp = _fp("a", 0x1000, body)
		assert fingerprint_similarity(fp, fp) == 1.0
		twin = _fp("b", 0x2000, body)
		assert 0.0 <= fingerprint_similarity(fp, twin) <= 1.0
