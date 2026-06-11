"""Reverse-proxy subpath support.

When ProcSentry is served behind a proxy under a subpath (e.g. nginx maps
``/pkill/`` -> ``127.0.0.1:42496/``), the proxy strips the prefix before the
request reaches the app, so routing sees the bare path (``/static/app.css``,
``/top``) and works unchanged. But the HTML we emit still needs to point links
back at ``/pkill/...`` so the browser resolves them against the right base.

The proxy advertises the stripped prefix via the ``X-Forwarded-Prefix`` header.
The ``url`` Jinja global reads that header off the request and prepends it to
app-relative paths. We deliberately do NOT mutate Starlette's ``root_path``:
that value drives the router/Mount matching, and changing it would make the
stripped incoming path stop matching the ``/static`` mount. URL generation and
route matching are kept separate.

With no proxy (or direct access at the bare port) the header is absent and
links stay at ``/``.
"""

from __future__ import annotations


def _prefix_from_request(request) -> str:
    """Return the proxy prefix (e.g. ``/pkill``) for this request, or ``""``."""

    prefix = request.headers.get("x-forwarded-prefix", "")
    return prefix.rstrip("/")


def prefixed_url(request, path: str) -> str:
    """Return ``path`` prefixed with the active reverse-proxy prefix.

    ``url("/top")`` -> ``/pkill/top`` behind the proxy, ``/top`` without one.
    Non-app-relative values (``http://...``, ``//cdn``, ``#anchor``) are
    returned unchanged.
    """

    if not isinstance(path, str) or not path.startswith("/") or path.startswith("//"):
        return path
    prefix = _prefix_from_request(request)
    return f"{prefix}{path}" if prefix else path
