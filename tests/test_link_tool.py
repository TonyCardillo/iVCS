"""Tests for the Link.Exe wrapper's argv construction (Wine-free).

The real link runs under Wine and is exercised by a manual smoke; here we pin
the command line the wrapper builds so flag regressions are caught cheaply.
"""

from src.link_tool import link_argv

LINK = "Z:\\link\\Link.Exe"
OBJS = ["Z:\\a.obj", "Z:\\b.obj"]
OUT = "Z:\\out.dll"


class TestLinkArgv:
	def test_fixed_base_is_hex_encoded(self):
		argv = link_argv(LINK, OBJS, OUT, base_address=0x00011000)
		assert "/BASE:0x11000" in argv
		assert "/FIXED" in argv

	def test_resource_dll_has_noentry_and_nodefaultlib(self):
		argv = link_argv(LINK, OBJS, OUT, base_address=0x10000)
		assert "/DLL" in argv
		assert "/NOENTRY" in argv
		assert "/NODEFAULTLIB" in argv

	def test_explicit_entry_replaces_noentry(self):
		argv = link_argv(LINK, OBJS, OUT, base_address=0x10000, entry="start")
		assert "/ENTRY:start" in argv
		assert "/NOENTRY" not in argv

	def test_out_flag_and_objects_present(self):
		argv = link_argv(LINK, OBJS, OUT, base_address=0x10000)
		assert f"/OUT:{OUT}" in argv
		for obj in OBJS:
			assert obj in argv

	def test_link_exe_is_first(self):
		argv = link_argv(LINK, OBJS, OUT, base_address=0x10000)
		assert argv[0] == LINK

	def test_extra_flags_appended(self):
		argv = link_argv(LINK, OBJS, OUT, base_address=0x10000, extra_flags=("/MAP",))
		assert "/MAP" in argv
