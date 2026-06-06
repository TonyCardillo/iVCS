"""Page scaffold + shared presentation primitives: the HTML document shell,
breadcrumbs, panel cards, the progress bar widget, and the error page."""

from __future__ import annotations

import html

from src.webui.styles import APP_CSS_HREF


def page(
	title: str,
	body: str,
	current_path: str | None,
	refresh_seconds: int | None = None,
) -> str:
	nav_html = '<a href="/">overview</a>'
	path_chip = (
		f'<span class="muted tight">[ xbe ]</span> '
		f'<span style="color: var(--amber);">{html.escape(current_path)}</span>'
		if current_path
		else ""
	)
	# Swap only <main> (no flicker, keeps scroll); server drops data-live to stop the poller.
	live_attr = f' data-live="{refresh_seconds}"' if refresh_seconds else ""
	live_script = (
		"""
<script>
(function(){
  function ms(el){ return el ? parseInt(el.getAttribute('data-live'), 10) : NaN; }
  function tick(){
    fetch(location.href).then(function(r){ return r.text(); }).then(function(t){
      var next = new DOMParser().parseFromString(t, 'text/html').querySelector('main');
      var cur = document.querySelector('main');
      if (next && cur) cur.innerHTML = next.innerHTML;
      var n = ms(next);
      if (n > 0) setTimeout(tick, n * 1000);
    }).catch(function(){ setTimeout(tick, 3000); });
  }
  var n = ms(document.querySelector('main'));
  if (n > 0) setTimeout(tick, n * 1000);
})();
</script>"""
		if refresh_seconds
		else ""
	)
	return f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<title>{html.escape(title)} · iVCS</title>
<link rel="stylesheet" href="{APP_CSS_HREF}">
</head><body>
<header>
  <div class="brand">◇ &nbsp;i&middot;V&middot;C&middot;S<span class="dot">●</span></div>
  <div>{path_chip}</div>
  <nav>{nav_html}</nav>
</header>
<main{live_attr}>{body}</main>
{live_script}
</body></html>"""


def crumbs(*items: tuple[str, str | None]) -> str:
	parts = []
	for i, (label, href) in enumerate(items):
		if i:
			parts.append('<span class="sep">/</span>')
		if href:
			parts.append(f'<a href="{href}">{html.escape(label)}</a>')
		else:
			parts.append(f"<span>{html.escape(label)}</span>")
	return f'<div class="crumbs">{"".join(parts)}</div>'


def panel(head: str, body: str, meta: str = "") -> str:
	meta_html = f'<span class="meta">{html.escape(meta)}</span>' if meta else ""
	return (
		f'<div class="panel"><div class="panel-head">'
		f"<span>{html.escape(head)}</span>{meta_html}"
		f'</div><div class="panel-body">{body}</div></div>'
	)


def badge(cls: str, text: str) -> str:
	"""A status pill: `<span class="badge {cls}">{text}</span>`, text escaped."""
	return f'<span class="badge {cls}">{html.escape(text)}</span>'


def sweep_bar(pct: float) -> str:
	"""The thin animated live-progress bar used by sweep/verify/autoname runs."""
	return (
		f'<div class="sweep-bar"><div class="sweep-bar-fill" style="width:{pct:.1f}%"></div></div>'
	)


def _progress_bar(value: float | None) -> str:
	pct = value if isinstance(value, (int, float)) else 0.0
	pct = max(0.0, min(100.0, pct))
	label = f"{value:.2f}%" if isinstance(value, (int, float)) else "—"
	return (
		f'<div class="progress">'
		f'<div class="fill" style="width: {pct:.2f}%;"></div>'
		f'<div class="label">{label}</div>'
		f"</div>"
	)


def view_error(message: str, current_path: str | None = None) -> str:
	body = (
		crumbs(("home", "/"), ("error", None))
		+ f'<div class="error">{html.escape(message)}</div>'
		+ '<p class="muted">Go <a href="/">back to the index</a>.</p>'
	)
	return page("error", body, current_path=current_path)
