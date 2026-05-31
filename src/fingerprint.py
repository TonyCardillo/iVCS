"""Structural function fingerprints for x86 — a coddog-style codebase index.

coddog (github.com/ethteck/coddog) finds duplicate and near-duplicate functions
so one decompilation can cover many; its arch backends are MIPS/PPC/ARM, so this
ports the *technique* to the Xbox's x86 over the Capstone disassembler iVCS
already carries. Each function gets three hashes, mirroring coddog's Symbol:

  - exact_hash : the raw bytes — byte-identical functions
  - opcode_hash: the Capstone instruction-id sequence, operands stripped — the
                 same instruction skeleton regardless of registers/immediates
  - equiv_hash : opcode ids plus operand *types* (reg/imm/mem), so register and
                 immediate identity is abstracted but operand shape is kept

Clusters group equal-hash functions (O(n)); similarity is a bounded Levenshtein
edit distance over the opcode sequence (coddog's `diff_symbols`), used for
ranked "find functions like this one" retrieval.
"""

import hashlib
import struct
from dataclasses import dataclass

import capstone
import capstone.x86

from src.project import Project
from src.xbe import ParsedXbe, XbeFormatError, xbe_function_carve

_OP_TYPE_TOKEN = {
	capstone.x86.X86_OP_REG: 1,
	capstone.x86.X86_OP_IMM: 2,
	capstone.x86.X86_OP_MEM: 3,
}


@dataclass(frozen=True)
class Fingerprint:
	name: str
	va: int
	size: int
	exact_hash: int
	opcode_hash: int
	equiv_hash: int
	opcodes: tuple[int, ...]  # Capstone instruction ids, for edit-distance similarity


def _hash64(data: bytes) -> int:
	return int.from_bytes(hashlib.blake2b(data, digest_size=8).digest(), "big")


def function_fingerprint(name: str, va: int, size: int, body: bytes) -> Fingerprint:
	"""Fingerprint one function from its raw bytes."""
	md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
	md.detail = True

	opcodes: list[int] = []
	equiv_tokens: list[int] = []
	for insn in md.disasm(body, va):
		opcodes.append(insn.id)
		equiv_tokens.append(insn.id)
		equiv_tokens.extend(_OP_TYPE_TOKEN.get(op.type, 0) for op in insn.operands)
		equiv_tokens.append(0xFFFF)  # operand-list terminator, so arity matters

	return Fingerprint(
		name=name,
		va=va,
		size=size,
		exact_hash=_hash64(body),
		opcode_hash=_hash64(struct.pack(f"<{len(opcodes)}I", *opcodes)),
		equiv_hash=_hash64(struct.pack(f"<{len(equiv_tokens)}I", *equiv_tokens)),
		opcodes=tuple(opcodes),
	)


def project_fingerprints(project: Project, parsed: ParsedXbe) -> list[Fingerprint]:
	"""Fingerprint every enumerated function, carving its bytes from the image.

	Functions that can't be carved (outside a section, past raw bytes) are
	skipped rather than aborting the whole index.
	"""
	out: list[Fingerprint] = []
	for fn in project.functions:
		try:
			body = xbe_function_carve(parsed, fn.va, fn.size)
		except XbeFormatError:
			continue
		out.append(function_fingerprint(fn.name, fn.va, fn.size, body))
	return out


@dataclass(frozen=True)
class Cluster:
	key_hash: int
	members: tuple[Fingerprint, ...]

	@property
	def size(self) -> int:
		return len(self.members)


_CLUSTER_KEY = {
	"exact": lambda fp: fp.exact_hash,
	"opcode": lambda fp: fp.opcode_hash,
	"equiv": lambda fp: fp.equiv_hash,
}


def fingerprint_clusters(
	fingerprints: list[Fingerprint], *, by: str = "opcode", min_size: int = 2
) -> list[Cluster]:
	"""Group functions sharing a hash into clusters, largest first.

	`by` selects which hash defines a duplicate: "exact" (byte-identical),
	"opcode" (same instruction skeleton), or "equiv" (same skeleton + operand
	shape). Only clusters with at least `min_size` members are returned.
	"""
	key = _CLUSTER_KEY[by]
	buckets: dict[int, list[Fingerprint]] = {}
	for fp in fingerprints:
		buckets.setdefault(key(fp), []).append(fp)

	clusters = [
		Cluster(key_hash=h, members=tuple(sorted(members, key=lambda f: f.va)))
		for h, members in buckets.items()
		if len(members) >= min_size
	]
	# ties broken by lowest member VA for determinism
	clusters.sort(key=lambda c: (-c.size, c.members[0].va))
	return clusters


def _levenshtein_bounded(a: tuple[int, ...], b: tuple[int, ...], bound: int) -> int | None:
	"""Edit distance between two int sequences, or None if it exceeds `bound`.

	Standard two-row DP with a per-row minimum check for the early-out.
	"""
	if abs(len(a) - len(b)) > bound:
		return None
	previous = list(range(len(b) + 1))
	for i, ai in enumerate(a, start=1):
		current = [i] + [0] * len(b)
		row_min = current[0]
		for j, bj in enumerate(b, start=1):
			cost = 0 if ai == bj else 1
			current[j] = min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + cost)
			row_min = min(row_min, current[j])
		if row_min > bound:
			return None
		previous = current
	return previous[-1]


def fingerprint_similarity(a: Fingerprint, b: Fingerprint, *, threshold: float = 0.0) -> float:
	"""Opcode-sequence similarity in [0, 1] (coddog's `diff_symbols`).

	Edit distance over the opcode ids, normalized by the summed length. A length
	gap that can't beat `threshold` short-circuits to 0; an exact opcode match on
	functions whose raw bytes differ returns 0.9999 (structurally identical, not
	byte-identical).
	"""
	l1, l2 = len(a.opcodes), len(b.opcodes)
	max_edit = float(l1 + l2)
	if max_edit == 0.0:
		return 1.0
	if (abs(l1 - l2) / max_edit) > (1.0 - threshold):
		return 0.0

	bound = int(max_edit - (max_edit * threshold))
	distance = _levenshtein_bounded(a.opcodes, b.opcodes, bound)
	if distance is None:
		return 0.0

	normalized = (max_edit - distance) / max_edit
	if normalized == 1.0 and a.exact_hash != b.exact_hash:
		return 0.9999
	return normalized


def fingerprints_similar_to(
	query: Fingerprint,
	candidates: list[Fingerprint],
	*,
	threshold: float = 0.5,
	top_k: int = 10,
) -> list[tuple[Fingerprint, float]]:
	"""Rank candidates by opcode similarity to `query`, best first.

	The query itself (matched by name) is excluded; only candidates scoring at or
	above `threshold` are returned, capped at `top_k`.
	"""
	scored: list[tuple[Fingerprint, float]] = []
	for fp in candidates:
		if fp.name == query.name:
			continue
		score = fingerprint_similarity(query, fp, threshold=threshold)
		if score >= threshold:
			scored.append((fp, score))
	scored.sort(key=lambda pair: (-pair[1], pair[0].va))
	return scored[:top_k]
