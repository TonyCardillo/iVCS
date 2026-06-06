"""Synthetic Project / ParsedXbe / compile-fn builders shared across the
src.verify test modules — no real XBE on disk, no Wine."""

import types
from pathlib import Path

from src.core.project import FunctionStatus, Project
from src.formats.xbe import SECTION_FLAG_EXECUTABLE, ParsedXbe, XbeHeader, XbeSection


def _ok_compile(c_source, out_obj, workspace_root):
	return types.SimpleNamespace(success=True)


def _fail_compile(c_source, out_obj, workspace_root):
	return types.SimpleNamespace(success=False)


def _section(name, va, vsize, flags=SECTION_FLAG_EXECUTABLE):
	return XbeSection(
		name=name,
		flags=flags,
		virtual_address=va,
		virtual_size=vsize,
		raw_address=0,
		raw_size=vsize,
	)


def _parsed(*sections):
	header = XbeHeader(0x10000, 0, 0, 0, len(sections), 0, 0, 0)
	return ParsedXbe(header=header, sections=tuple(sections), data=b"")


def _project(functions, src_root=Path("/proj/src_tree")):
	return Project(
		name="t",
		xbe_path=Path("/x.xbe"),
		workspace_root=Path("/ws"),
		functions=tuple(functions),
		src_root=src_root,
	)


def _fstatus(va, size, state, *, name="fn"):
	return FunctionStatus(
		name=name,
		va=va,
		size=size,
		state=state,
		best_match_percent=None,
		iterations=0,
		workspace_path=Path("/ws") / name,
		termination_reason=None,
	)
