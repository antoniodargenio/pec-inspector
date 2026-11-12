"""Small HTTP(S) helper that refuses to talk to non-public hosts.

Certificates and e-mails are untrusted input: a malicious certificate can list an OCSP/CRL/AIA URL that
points at ``http://127.0.0.1/...`` or at a cloud metadata address. Every URL fetched by this tool goes
through :func:`http_get`, which

* only allows ``http``/``https``,
* refuses hosts that resolve to loopback, private, link-local or otherwise non-global addresses
  (unless :func:`set_allow_private` was called, e.g. for tests or an intranet PKI),
* re-checks every redirect target,
* caps the size of the response.

DNS rebinding between the check and the connection is not prevented; this is defence in depth,
not a sandbox.
"""
from __future__ import annotations

import ipaddress
import socket
import urllib.error
import urllib.parse
import urllib.request

USER_AGENT = "pec-inspector"
_allow_private = False


def set_allow_private(value: bool) -> None:
    global _allow_private
    _allow_private = bool(value)


def host_is_public(host: str) -> bool:
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return False
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0].split("%")[0])
        except ValueError:
            return False
        if not ip.is_global:
            return False
    return bool(infos)


def url_allowed(url: str, schemes=("http", "https")) -> bool:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme.lower() not in schemes or not parsed.hostname:
        return False
    return _allow_private or host_is_public(parsed.hostname)


class _CheckedRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not url_allowed(newurl):
            raise urllib.error.URLError("redirect to a disallowed URL")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def http_get(url: str, max_bytes: int = 30_000_000, timeout: float = 15, schemes=("http", "https")):
    """Return the response body, or ``None`` if the URL is disallowed, unreachable or too large."""
    if not url_allowed(url, schemes):
        return None
    opener = urllib.request.build_opener(_CheckedRedirects)
    try:
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with opener.open(request, timeout=timeout) as response:
            data = response.read(max_bytes + 1)
    except Exception:
        return None
    return data if len(data) <= max_bytes else None
