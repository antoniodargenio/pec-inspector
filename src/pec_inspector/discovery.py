"""Find the IMAP server of a mailbox from its address.

Methods, tried in this order until one yields a result:

1. **DNS SRV records** (RFC 6186): ``_imaps._tcp.<domain>`` (implicit TLS) and ``_imap._tcp.<domain>``
   (STARTTLS).  Needs the optional ``dnspython`` package.
2. **Mozilla autoconfig** published by the mail provider:
   ``https://autoconfig.<domain>/mail/config-v1.1.xml`` and
   ``https://<domain>/.well-known/autoconfig/mail/config-v1.1.xml`` (HTTPS only).
3. The same autoconfig lookup on the domains of the **MX hosts** (a PEC address often lives on a custom
   domain whose mail is hosted by a provider that publishes the configuration).  Needs ``dnspython``.
4. The **Thunderbird ISP database** (``https://autoconfig.thunderbird.net/v1.1/<domain>``), for the address
   domain and the MX domains.  Only the domain name is sent, never the address.  Disable with ``use_ispdb=False``.
5. Optionally (``probe=True``) guessing common host names (``imap.<d>``, ``imaps.<d>``, ``mail.<d>``,
   ``pec.<d>``) and checking for a TLS IMAP server on port 993.

Microsoft Autodiscover (POX/SCP) is not implemented.

Security note: DNS and autoconfig data decide where your password is sent.  Servers are always contacted
with TLS and certificate/host-name verification, but you should check the discovered host (it is printed
before logging in; ``--discover-only`` stops there) and prefer ``--imap-host`` for sensitive accounts.
"""
from __future__ import annotations

import re
import socket
import ssl
import urllib.parse
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Callable, List, Optional

from . import netsafe

try:                                    # optional dependency
    import dns.resolver as _dns_resolver
except ImportError:                     # pragma: no cover
    _dns_resolver = None


@dataclass
class ImapServer:
    host: str
    port: int
    security: str                       # "ssl" (implicit TLS) | "starttls"
    source: str                         # how it was found, for the user
    username: Optional[str] = None      # login name suggested by the provider, if any

    def describe(self) -> str:
        return f"{self.host}:{self.port} ({self.security}) via {self.source}"


# ---------------------------------------------------------------------------------------------
def split_address(address: str):
    if address.count("@") != 1:
        raise ValueError(f"not an e-mail address: {address!r}")
    local, domain = address.rsplit("@", 1)
    if not local or not re.fullmatch(r"[A-Za-z0-9.-]+\.[A-Za-z0-9-]{2,}", domain):
        raise ValueError(f"not an e-mail address: {address!r}")
    return local, domain.lower().rstrip(".")


def parent_domains(host: str, minimum_labels: int = 2) -> List[str]:
    """``mx1.mail.example.net`` -> ``mail.example.net``, ``example.net`` (never a bare TLD)."""
    labels = host.lower().rstrip(".").split(".")
    return [".".join(labels[i:]) for i in range(1, len(labels) - minimum_labels + 1)]


def parse_autoconfig(xml: bytes, address: str, source: str) -> List[ImapServer]:
    """Parse a Mozilla autoconfig ``config-v1.1.xml`` document (untrusted input)."""
    if len(xml) > 300_000 or re.search(rb"<!(DOCTYPE|ENTITY)", xml, re.I):
        return []                       # no DTDs/entities: avoids entity-expansion tricks
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return []
    local, domain = split_address(address)
    servers: List[ImapServer] = []
    for node in root.iter("incomingServer"):
        if node.get("type") != "imap":
            continue
        host = (node.findtext("hostname") or "").strip()
        socket_type = (node.findtext("socketType") or "").strip().upper()
        try:
            port = int((node.findtext("port") or "").strip())
        except ValueError:
            continue
        security = {"SSL": "ssl", "STARTTLS": "starttls"}.get(socket_type)
        if not host or not security or not 0 < port < 65536:
            continue                    # plain-text IMAP is never used
        host = host.replace("%EMAILDOMAIN%", domain)
        if not re.fullmatch(r"[A-Za-z0-9.-]+", host):
            continue
        user = (node.findtext("username") or "").strip()
        user = (user.replace("%EMAILADDRESS%", address).replace("%EMAILLOCALPART%", local)
                    .replace("%EMAILDOMAIN%", domain)) or None
        if user and "%" in user:
            user = None
        servers.append(ImapServer(host, port, security, source, user))
    servers.sort(key=lambda s: s.security != "ssl")   # prefer implicit TLS
    return servers


# ---------------------------------------------------------------------------------------------
def _srv(name: str, timeout: float):
    if _dns_resolver is None:
        return []
    try:
        answers = _dns_resolver.resolve(name, "SRV", lifetime=timeout)
    except Exception:
        return []
    ordered = sorted(answers, key=lambda r: (r.priority, -r.weight))
    return [(str(r.target).rstrip("."), r.port) for r in ordered if str(r.target) != "."]


def _mx_hosts(domain: str, timeout: float):
    if _dns_resolver is None:
        return []
    try:
        answers = _dns_resolver.resolve(domain, "MX", lifetime=timeout)
    except Exception:
        return []
    return [str(r.exchange).rstrip(".") for r in sorted(answers, key=lambda r: r.preference)]


def _autoconfig_urls(domain: str, address: Optional[str]):
    query = f"?emailaddress={urllib.parse.quote(address)}" if address else ""
    return [f"https://autoconfig.{domain}/mail/config-v1.1.xml{query}",
            f"https://{domain}/.well-known/autoconfig/mail/config-v1.1.xml{query}"]


def _fetch_autoconfig(domain, address, source, timeout, send_address=True):
    for url in _autoconfig_urls(domain, address if send_address else None):
        body = netsafe.http_get(url, max_bytes=300_000, timeout=timeout, schemes=("https",))
        if body:
            servers = parse_autoconfig(body, address, source)
            if servers:
                return servers
    return []


def _probe(domains, timeout):
    context = ssl.create_default_context()
    for domain in domains:
        for prefix in ("imap", "imaps", "mail", "pec"):
            host = f"{prefix}.{domain}"
            if not netsafe.host_is_public(host):
                continue
            try:
                with socket.create_connection((host, 993), timeout=timeout) as raw:
                    with context.wrap_socket(raw, server_hostname=host) as tls:
                        if tls.recv(64).startswith(b"* OK"):
                            return [ImapServer(host, 993, "ssl", "probe of common host names")]
            except OSError:
                continue
    return []


def discover(address: str, timeout: float = 8, use_ispdb: bool = True, probe: bool = False,
             log: Callable[[str], None] = lambda message: None) -> List[ImapServer]:
    """Return candidate IMAP servers for ``address`` (best first); an empty list if nothing was found."""
    _, domain = split_address(address)

    # 1. RFC 6186 SRV records
    if _dns_resolver is None:
        log("dnspython not installed: SRV and MX lookups are skipped (pip install dnspython)")
    found: List[ImapServer] = []
    for label, security in (("_imaps._tcp", "ssl"), ("_imap._tcp", "starttls")):
        for host, port in _srv(f"{label}.{domain}", timeout):
            found.append(ImapServer(host, port, security, f"DNS SRV {label}.{domain}"))
    if found:
        log(f"SRV records found for {domain}")
        return found
    log(f"no usable SRV records for {domain}")

    # 2. autoconfig published by the address domain
    found = _fetch_autoconfig(domain, address, f"autoconfig of {domain}", timeout)
    if found:
        return found
    log(f"no autoconfig published by {domain}")

    # 3. autoconfig of the MX domains
    mx_domains: List[str] = []
    for mx in _mx_hosts(domain, timeout):
        for parent in parent_domains(mx):
            if parent != domain and parent not in mx_domains:
                mx_domains.append(parent)
    mx_domains = mx_domains[:4]
    for candidate in mx_domains:
        found = _fetch_autoconfig(candidate, address, f"autoconfig of MX domain {candidate}", timeout,
                                  send_address=False)
        if found:
            return found
    if mx_domains:
        log("no autoconfig on MX domains: " + ", ".join(mx_domains))

    # 4. Thunderbird ISP database (domain only)
    if use_ispdb:
        for candidate in [domain] + mx_domains:
            body = netsafe.http_get(f"https://autoconfig.thunderbird.net/v1.1/{urllib.parse.quote(candidate)}",
                                    max_bytes=300_000, timeout=timeout, schemes=("https",))
            found = parse_autoconfig(body, address, f"Thunderbird ISP database ({candidate})") if body else []
            if found:
                return found
        log("not in the Thunderbird ISP database")

    # 5. educated guesses
    if probe:
        found = _probe([domain] + mx_domains, min(timeout, 5))
        if found:
            return found
        log("no IMAP server found by probing")
    return []
