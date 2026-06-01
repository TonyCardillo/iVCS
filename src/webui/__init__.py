"""iVCS Web UI — a thin visual surface over the XBE loader, carver, and decomp workspace.

Stdlib-only. Run:  python -m src.webui [--port 8765]
Then open:         http://127.0.0.1:8765/

A package decomposed from a single module. `bootstrap` is imported first for its
import-time side effect (the bundled objdiff-cli env default). The submodules are
re-exported here so the public surface is flat, and `diff` is exposed as an
attribute so its `_objdiff_cli_path`/`subprocess` can be monkeypatched in tests.
"""

from src.webui import bootstrap as bootstrap  # noqa: F401  (import first: env side effect)
from src.webui import diff as diff  # noqa: F401  (exposed for monkeypatching)
from src.webui.diff import (
	_asm_dual_columns,
	_attempt_info,
	_attempt_model_label,
	_attempts_listing,
	_best_attempt,
	_diff_json_is_stale,
	_ensure_diff_json,
	_guess_function_name,
	_objdiff_cli_path,
	_va_from_workspace,
)
from src.webui.server import Handler, main
from src.webui.state import (
	JobsAtCapacity,
	SweepState,
	VerifyState,
	_register_sweep,
	_register_verify,
	xbe_cached_load,
)
from src.webui.templates import _progress_bar, crumbs, page, panel, view_error
from src.webui.views_decomp import (
	_attempt_status_labels,
	_path_query_suffix,
	_project_crumb,
	_run_action_bar,
	_run_interrupted,
	view_decomp_attempt,
	view_decomp_run,
)
from src.webui.views_index import view_index
from src.webui.views_launch import (
	_handle_notes_save,
	_handle_symbol_rename,
	view_launch_form,
)
from src.webui.views_progress import (
	_pager_window,
	_sweep_section,
	view_progress,
	view_progress_index,
)
from src.webui.views_stats import view_stats
from src.webui.workers import (
	autoname_run,
	launch_job_from_form,
	sweep_launch,
	sweep_stop,
	verify_launch,
)

# Re-exported flat surface (the helpers the test suite pins, plus the public
# views/workers/server entry points). `bootstrap` and `diff` are module
# attributes (imported above) so tests can patch `webui.diff.*`.
__all__ = [
	"Handler",
	"JobsAtCapacity",
	"SweepState",
	"VerifyState",
	"_asm_dual_columns",
	"_attempt_info",
	"_attempt_model_label",
	"_attempt_status_labels",
	"_attempts_listing",
	"_best_attempt",
	"_diff_json_is_stale",
	"_ensure_diff_json",
	"_guess_function_name",
	"_handle_notes_save",
	"_handle_symbol_rename",
	"_objdiff_cli_path",
	"_pager_window",
	"_path_query_suffix",
	"_progress_bar",
	"_project_crumb",
	"_register_sweep",
	"_register_verify",
	"_run_action_bar",
	"_run_interrupted",
	"_sweep_section",
	"_va_from_workspace",
	"autoname_run",
	"crumbs",
	"launch_job_from_form",
	"main",
	"page",
	"panel",
	"sweep_launch",
	"sweep_stop",
	"verify_launch",
	"view_decomp_attempt",
	"view_decomp_run",
	"view_error",
	"view_index",
	"view_launch_form",
	"view_progress",
	"view_progress_index",
	"view_stats",
	"xbe_cached_load",
]
