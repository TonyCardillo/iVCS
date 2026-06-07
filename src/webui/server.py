"""HTTP plumbing: the request handler with GET/POST routing, and main()."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import traceback
from http.server import (
	BaseHTTPRequestHandler,
	ThreadingHTTPServer,
)
from urllib.parse import (
	parse_qs,
	quote,
	urlsplit,
)

from src.formats.xbe import XbeFormatError
from src.webui.state import JobsAtCapacity
from src.webui.styles import APP_CSS_HREF, APP_CSS_PATH
from src.webui.templates import view_error
from src.webui.views_decomp import (
	view_decomp_attempt,
	view_decomp_run,
)
from src.webui.views_extract import (
	handle_extract_run,
	view_extract,
)
from src.webui.views_index import view_index
from src.webui.views_launch import (
	_handle_notes_save,
	_handle_symbol_rename,
	view_launch_form,
)
from src.webui.views_progress import (
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

# The stylesheet is static for the life of the process, so read it (and its ETag)
# once at startup and serve from memory — no per-request disk I/O.
_APP_CSS_BYTES = APP_CSS_PATH.read_bytes()
_APP_CSS_ETAG = f'"{hashlib.sha256(_APP_CSS_BYTES).hexdigest()[:16]}"'


def _is_post_origin_allowed(origin: str | None, host: str) -> bool:
	"""Whether a state-changing POST may proceed (CSRF guard for the local UI).

	The UI is same-origin, so when the browser sends an Origin it must equal our
	own http://<Host>; a cross-site fetch/form-POST from another page carries that
	page's Origin and is refused. A request with no Origin (same-origin form
	navigations, curl) is allowed — a browser CSRF attack cannot suppress Origin,
	and a local non-browser client is outside the threat model for a loopback app.
	"""
	if origin is None:
		return True
	return origin == f"http://{host}"


class Handler(BaseHTTPRequestHandler):
	def log_message(self, _fmt, *_args):
		sys.stderr.write(f"  {self.command} {self.path}\n")

	def do_POST(self):
		parts = urlsplit(self.path)
		q = {k: v[0] for k, v in parse_qs(parts.query).items()}
		route = parts.path

		length = int(self.headers.get("Content-Length", "0") or "0")
		raw = self.rfile.read(length).decode("utf-8") if length else ""
		form = {k: v[0] for k, v in parse_qs(raw).items()}

		# Refuse browser CSRF before mutating anything (the body is already drained).
		if not _is_post_origin_allowed(self.headers.get("Origin"), self.headers.get("Host", "")):
			self._send(403, view_error("cross-origin POST refused"))
			return

		try:
			if route == "/decomp/launch":
				redirect, _job = launch_job_from_form(
					q.get("path", ""),
					q.get("va", "0"),
					form,
				)
				self._redirect(redirect)
				return
			if route == "/symbol/rename":
				self._redirect(_handle_symbol_rename(form))
				return
			if route == "/notes/save":
				self._redirect(_handle_notes_save(form))
				return
			if route == "/sweep/launch":
				path = q.get("path", "") or form.get("path", "")
				sweep_launch(path)
				self._redirect(f"/progress?path={quote(path)}")
				return
			if route == "/sweep/stop":
				path = q.get("path", "") or form.get("path", "")
				sweep_stop(path)
				self._redirect(f"/progress?path={quote(path)}")
				return
			if route == "/autoname":
				path = q.get("path", "") or form.get("path", "")
				named = autoname_run(path)
				self._redirect(f"/progress?path={quote(path)}&named={named}")
				return
			if route == "/verify/launch":
				path = q.get("path", "") or form.get("path", "")
				verify_launch(path)
				self._redirect(f"/stats?path={quote(path)}")
				return
			if route == "/extract/run":
				self._redirect(handle_extract_run(q.get("image", ""), form))
				return
			self._send(404, view_error(f"unknown POST route: {route}"))
		except JobsAtCapacity as e:
			self._send(429, view_error(f"jobs at capacity: {e}"))
		except (FileNotFoundError, KeyError, ValueError) as e:
			self._send(400, view_error(f"{type(e).__name__}: {e}"))
		except Exception:  # noqa: BLE001 — last-resort net for the UI
			self._send_500()

	def do_GET(self):
		parts = urlsplit(self.path)
		q = {k: v[0] for k, v in parse_qs(parts.query).items()}
		route = parts.path
		try:
			if route == "/":
				html_out = view_index()
			elif route == "/decomp/run":
				html_out = view_decomp_run(q["root"], current_path=q.get("path") or None)
			elif route == "/decomp/attempt":
				html_out = view_decomp_attempt(
					q["root"], int(q["n"]), current_path=q.get("path") or None
				)
			elif route == "/decomp/launch":
				html_out = view_launch_form(q.get("path", ""), q.get("va", "0"))
			elif route == "/progress":
				project_path = q.get("path", "").strip()
				if not project_path:
					html_out = view_progress_index(current_path=None)
				else:
					page_n = max(1, int(q.get("page", "1") or "1"))
					size_n = max(10, min(500, int(q.get("page_size", "100") or "100")))
					named_q = q.get("named", "")
					html_out = view_progress(
						project_path,
						current_path=None,
						page_n=page_n,
						page_size=size_n,
						named=int(named_q) if named_q.isdigit() else None,
						filters={
							"state": q.get("state", ""),
							"q": q.get("q", ""),
							"min_size": q.get("min_size", ""),
							"max_size": q.get("max_size", ""),
							"sort": q.get("sort", "va"),
							"order": q.get("order", "asc"),
						},
					)
			elif route == "/extract":
				html_out = view_extract(q.get("image", ""), status=q.get("status", ""))
			elif route == "/stats":
				project_path = q.get("path", "").strip()
				if not project_path:
					html_out = view_progress_index(current_path=None)
				else:
					html_out = view_stats(project_path)
			elif route == APP_CSS_HREF:
				self._send_app_css()
				return
			elif route == "/healthz":
				self._send_json(200, {"ok": True})
				return
			else:
				self._send(404, view_error(f"unknown route: {route}"))
				return
			self._send(200, html_out)
		except FileNotFoundError as e:
			self._send(404, view_error(f"file not found: {e}"))
		except (XbeFormatError, KeyError, ValueError) as e:
			self._send(400, view_error(f"{type(e).__name__}: {e}"))
		except Exception:  # noqa: BLE001 — last-resort net for the UI
			self._send_500()

	def _send(self, status: int, body: str) -> None:
		encoded = body.encode("utf-8")
		self.send_response(status)
		self.send_header("Content-Type", "text/html; charset=utf-8")
		self.send_header("Content-Length", str(len(encoded)))
		self.end_headers()
		self.wfile.write(encoded)

	def _send_app_css(self) -> None:
		"""Serve the stylesheet with an ETag so the browser revalidates cheaply: a
		304 (empty body) replaces re-sending the whole sheet on every page load."""
		if self.headers.get("If-None-Match") == _APP_CSS_ETAG:
			self.send_response(304)
			self.send_header("ETag", _APP_CSS_ETAG)
			self.end_headers()
			return
		self.send_response(200)
		self.send_header("Content-Type", "text/css; charset=utf-8")
		self.send_header("Content-Length", str(len(_APP_CSS_BYTES)))
		self.send_header("ETag", _APP_CSS_ETAG)
		self.send_header("Cache-Control", "no-cache")
		self.end_headers()
		self.wfile.write(_APP_CSS_BYTES)

	def _send_500(self) -> None:
		"""Log the traceback server-side; show the client a generic message so no
		internal paths or stack frames leak into the browser."""
		sys.stderr.write(traceback.format_exc())
		self._send(500, view_error("internal server error — see server logs"))

	def _redirect(self, location: str) -> None:
		self.send_response(302)
		self.send_header("Location", location)
		self.send_header("Content-Length", "0")
		self.end_headers()

	def _send_json(self, status: int, obj) -> None:
		encoded = json.dumps(obj).encode("utf-8")
		self.send_response(status)
		self.send_header("Content-Type", "application/json")
		self.send_header("Content-Length", str(len(encoded)))
		self.end_headers()
		self.wfile.write(encoded)


def main() -> int:
	parser = argparse.ArgumentParser()
	parser.add_argument("--host", default="127.0.0.1")
	parser.add_argument("--port", type=int, default=8765)
	args = parser.parse_args()

	server = ThreadingHTTPServer((args.host, args.port), Handler)
	url = f"http://{args.host}:{args.port}/"
	sys.stderr.write(f"iVCS web UI listening at {url}\n")
	sys.stderr.write("  ctrl-c to stop\n\n")
	try:
		server.serve_forever()
	except KeyboardInterrupt:
		sys.stderr.write("\nshutting down\n")
		server.shutdown()
	return 0
