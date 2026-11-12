"""Mailbox credentials: command line > environment variables > credentials file.

One mailbox: environment variables
----------------------------------
``PEC_ADDRESS``           mailbox address (e-mail address of the PEC account)
``PEC_USERNAME``          IMAP login name, if different from the address
``PEC_PASSWORD``          password
``PEC_CREDENTIALS_FILE``  path of a credentials file (see below)
``PEC_IMAP_HOST``, ``PEC_IMAP_PORT``, ``PEC_IMAP_SECURITY``  (``ssl`` | ``starttls``)  skip auto-discovery

Several mailboxes
-----------------
Use a credentials file (one line per mailbox) and choose the mailbox with ``--address``.  For secret stores
and CI, where files are awkward, the password can also be given per mailbox in a variable named after the
address: ``PEC_PASSWORD_<ADDRESS>`` with every non-alphanumeric character replaced by ``_`` and upper-cased,
e.g. ``PEC_PASSWORD_USER_EXAMPLE_PEC_TEST`` for ``user@example-pec.test``.  Precedence of the password:
``PEC_PASSWORD_<ADDRESS>`` > ``PEC_PASSWORD`` > credentials file > interactive prompt.

Credentials file
----------------
Plain text, one account per line, fields separated by a TAB::

    # address <TAB> password [<TAB> imap_host [<TAB> imap_port]]
    user@example-pec.test    s3cret
    other@example.test       hunter2    imap.example.test    993

Blank lines and lines starting with ``#`` are ignored; an optional header line whose first field is
``address``/``username``/``user``/``email`` is skipped. Keep the file out of version control and readable
only by you (``chmod 600``); on POSIX a warning is printed if it is group/world readable.

The password is never accepted on the command line (it would be visible in the process list and in the
shell history). If none is found and a terminal is available, it is asked interactively.
"""
from __future__ import annotations

import getpass
import os
import stat
import sys
from dataclasses import dataclass
from typing import Dict, Optional

_HEADER_WORDS = {"address", "username", "user", "email", "e-mail", "mailbox"}


class CredentialsError(Exception):
    pass


def account_variable(prefix: str, address: str) -> str:
    """Per-account variable name: ``PEC_PASSWORD`` + ``user@example.test`` -> ``PEC_PASSWORD_USER_EXAMPLE_TEST``."""
    slug = "".join(ch if ch.isalnum() else "_" for ch in address).upper()
    return f"{prefix}_{slug}"


@dataclass
class Credentials:
    address: str
    username: str
    password: str = ""
    host: Optional[str] = None
    port: Optional[int] = None
    security: Optional[str] = None

    def __repr__(self) -> str:   # never leak the password in logs/tracebacks
        return f"Credentials(address={self.address!r}, username={self.username!r}, password=<hidden>)"


def read_credentials_file(path: str) -> Dict[str, Credentials]:
    try:
        mode = os.stat(path).st_mode
    except OSError as exc:
        raise CredentialsError(f"cannot read credentials file {path!r}: {exc}") from None
    if os.name == "posix" and mode & (stat.S_IRWXG | stat.S_IRWXO):
        print(f"warning: {path} is accessible by other users; run: chmod 600 {path}", file=sys.stderr)
    entries: Dict[str, Credentials] = {}
    with open(path, encoding="utf-8-sig") as handle:
        for number, line in enumerate(handle, 1):
            line = line.rstrip("\r\n")
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            fields = line.split("\t")
            if number == 1 and fields[0].strip().lower() in _HEADER_WORDS:
                continue
            if len(fields) < 2 or not fields[0].strip() or not fields[1]:
                raise CredentialsError(f"{path}:{number}: expected 'address<TAB>password[<TAB>host[<TAB>port]]'")
            address = fields[0].strip()
            cred = Credentials(address=address, username=address, password=fields[1])
            if len(fields) > 2 and fields[2].strip():
                cred.host = fields[2].strip()
            if len(fields) > 3 and fields[3].strip():
                try:
                    cred.port = int(fields[3])
                except ValueError:
                    raise CredentialsError(f"{path}:{number}: invalid port {fields[3]!r}") from None
            entries[address.lower()] = cred
    return entries


def resolve_credentials(address: Optional[str] = None, username: Optional[str] = None,
                        credentials_file: Optional[str] = None, env=None, prompt: bool = True) -> Credentials:
    env = os.environ if env is None else env
    address = address or env.get("PEC_ADDRESS")
    path = credentials_file or env.get("PEC_CREDENTIALS_FILE")
    entries = read_credentials_file(path) if path else {}

    if not address:
        if len(entries) == 1:
            address = next(iter(entries.values())).address
        elif entries:
            raise CredentialsError("several accounts in the credentials file, choose one with --address: "
                                   + ", ".join(sorted(e.address for e in entries.values())))
        else:
            raise CredentialsError("no mailbox address: use --address, PEC_ADDRESS or a credentials file")

    entry = entries.get(address.lower())
    cred = Credentials(address=address, username=username or env.get("PEC_USERNAME") or address)
    if entry:
        cred.host, cred.port = entry.host, entry.port
        if not (username or env.get("PEC_USERNAME")):
            cred.username = entry.username
    # password precedence: per-account variable > generic variable > credentials file
    cred.password = (env.get(account_variable("PEC_PASSWORD", address)) or env.get("PEC_PASSWORD")
                     or (entry.password if entry else ""))
    if env.get("PEC_IMAP_HOST"):
        cred.host = env["PEC_IMAP_HOST"]
    if env.get("PEC_IMAP_PORT"):
        try:
            cred.port = int(env["PEC_IMAP_PORT"])
        except ValueError:
            raise CredentialsError("PEC_IMAP_PORT must be a number") from None
    cred.security = env.get("PEC_IMAP_SECURITY") or None

    if not cred.password and prompt and sys.stdin and sys.stdin.isatty():
        cred.password = getpass.getpass(f"Password for {address}: ")
    if not cred.password:
        raise CredentialsError(f"no password for {address}: set PEC_PASSWORD, use a credentials file "
                               "or run from a terminal to be prompted")
    return cred
