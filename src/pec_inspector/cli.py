"""Command line interface: fetch PEC/REM messages (read-only IMAP), unpack and check them."""
from __future__ import annotations

import argparse
import email
import imaplib
import os
import ssl
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from email import policy
from typing import List, Optional

from . import __version__, formats, netsafe, pki
from .credentials import CredentialsError, resolve_credentials
from .discovery import ImapServer, discover


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pec-inspector",
        description="Download PEC / REM messages over IMAP (read-only), unpack them according to the standard "
                    "PEC structure and check receipts, signatures, certificate chains and revocation.",
        epilog="Credentials: environment (PEC_ADDRESS, PEC_PASSWORD, PEC_CREDENTIALS_FILE, ...) or a credentials "
               "file; see the README. The password is never taken from the command line.")
    p.add_argument("out_dir", help="directory where messages and attachments are unpacked (created if needed)")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    acc = p.add_argument_group("mailbox")
    acc.add_argument("--address", help="mailbox address (default: PEC_ADDRESS, or the only account of the credentials file)")
    acc.add_argument("--username", help="IMAP login name if different from the address (default: PEC_USERNAME)")
    acc.add_argument("--credentials-file", metavar="FILE", help="TAB-separated 'address<TAB>password[<TAB>host[<TAB>port]]'"
                                                                 " (default: PEC_CREDENTIALS_FILE)")
    acc.add_argument("--mailbox", default="INBOX", help="IMAP folder to read (default: INBOX)")

    srv = p.add_argument_group("IMAP server (default: auto-discovery from the address)")
    srv.add_argument("--imap-host", help="server host name (skips auto-discovery)")
    srv.add_argument("--imap-port", type=int, help="server port (default: 993 for ssl, 143 for starttls)")
    srv.add_argument("--imap-security", choices=("ssl", "starttls"), help="ssl = implicit TLS (default), starttls")
    srv.add_argument("--discover-only", action="store_true", help="print the discovered server and exit (no login)")
    srv.add_argument("--no-ispdb", action="store_true", help="do not query the Thunderbird ISP database during discovery")
    srv.add_argument("--probe", action="store_true", help="as a last resort, probe common host names (imap.<domain>, ...)")
    srv.add_argument("--timeout", type=float, default=40, help="network timeout in seconds (default: 40)")

    sel = p.add_argument_group("message selection (default: the last --limit messages)")
    sel.add_argument("--search", metavar="TEXT", help="IMAP TEXT search (ASCII only)")
    sel.add_argument("--from", dest="sender", metavar="TEXT", help="IMAP FROM search (ASCII only)")
    sel.add_argument("--last", type=int, metavar="N", help="the last N messages of the folder")
    sel.add_argument("--limit", type=int, default=10, help="process at most this many messages (default: 10)")
    sel.add_argument("--eml", metavar="FILE", help="analyse this saved .eml (PEC or REM) offline; no IMAP access")

    chk = p.add_argument_group("checks")
    chk.add_argument("--ca", metavar="PEM", help="PEM file with the root/intermediate certificates to trust "
                                                  "(e.g. the AgID CA for PEC providers)")
    chk.add_argument("--index", metavar="FILE", help="export of the PEC provider index (LDAP/text, base o=postacert) "
                                                      "containing the providerCertificateHash values")
    chk.add_argument("--xsd-dir", metavar="DIR", help="directory with the ETSI EN 319 522-3 XSDs to validate REM evidence")
    chk.add_argument("--no-revocation", action="store_true",
                     help="skip OCSP/CRL checks (by default the servers named in the certificates are contacted)")
    chk.add_argument("--allow-private-urls", action="store_true",
                     help="allow OCSP/CRL/AIA URLs on private or loopback addresses (intranet PKI, tests)")
    p.add_argument("-v", "--verbose", action="store_true", help="show discovery details on stderr")
    return p


def eprint(*args):
    print(*args, file=sys.stderr)


def quote_imap(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def connect(server: ImapServer, username: str, password: str, timeout: float):
    context = ssl.create_default_context()            # certificate and host name are verified
    if server.security == "ssl":
        conn = imaplib.IMAP4_SSL(server.host, server.port, ssl_context=context, timeout=timeout)
    else:
        conn = imaplib.IMAP4(server.host, server.port, timeout=timeout)
        conn.starttls(ssl_context=context)
    conn.login(username, password)
    return conn


def pick_server(args, cred) -> Optional[ImapServer]:
    host = args.imap_host or cred.host
    if host:
        security = args.imap_security or cred.security or "ssl"
        port = args.imap_port or cred.port or (993 if security == "ssl" else 143)
        return ImapServer(host, port, security, "command line / environment / credentials file")
    log = eprint if args.verbose else (lambda message: None)
    found = discover(cred.address, timeout=min(args.timeout, 10), use_ispdb=not args.no_ispdb,
                     probe=args.probe, log=log)
    if not found:
        return None
    server = found[0]
    if args.imap_port or args.imap_security:
        server = ImapServer(server.host, args.imap_port or server.port, args.imap_security or server.security,
                            server.source, server.username)
    return server


def select_messages(conn, args) -> List[bytes]:
    if args.sender:
        _, data = conn.search(None, "FROM", quote_imap(args.sender))
        ids = data[0].split()
    elif args.search:
        _, data = conn.search(None, "TEXT", quote_imap(args.search))
        ids = data[0].split()
    else:
        _, data = conn.search(None, "ALL")
        ids = data[0].split()[-(args.last or args.limit):]
    return ids[-args.limit:]


# ---------------------------------------------------------------------------------------------
def analyse_message(num: str, raw: bytes, args) -> None:
    out_dir = args.out_dir
    msg = email.message_from_bytes(raw, policy=policy.default)
    envelope = os.path.join(out_dir, f"msg_{num}.eml")
    Path(envelope).write_bytes(raw)

    x_transport, x_receipt = msg.get("X-Trasporto", ""), msg.get("X-Ricevuta", "")
    rem = {k: str(v) for k, v in msg.items() if k.upper().startswith("REM-")}
    evidences: list = []
    inner_names: list = []
    print(f"\n=== msg {num} | {msg['Date']} | {msg['Subject']}")
    if rem:
        print("TYPE: REM (ETSI EN 319 532 / REM-Policy-IT)")
        for key, value in rem.items():
            print(f"  {key}: {value}")
        mtype, event = rem.get("REM-MessageType", ""), rem.get("REM-EventIdentifier", "")
        if mtype and mtype.startswith(formats.MESSAGE_TYPE_URI) and \
                mtype[len(formats.MESSAGE_TYPE_URI):] not in formats.REM_MESSAGE_TYPES:
            print(f"!! unexpected REM-MessageType: {mtype}")
        if event.startswith(formats.EVENT_URI):
            if event[len(formats.EVENT_URI):] not in formats.REM_EVENTS:
                print(f"  (event not among those named in the specifications consulted: {event[len(formats.EVENT_URI):]})")
        elif event:
            print(f"!! REM-EventIdentifier with an unexpected URI: {event}")
        for header in ("REM-MetadataVersion", "REM-MessageType", "REM-DigestAlgorithm", "REM-DigestValue",
                       "REM-UAMessageIdentifier"):
            if header not in rem and (mtype.endswith("dispatch") or "receipt" in mtype):
                print(f"!! mandatory REM header missing: {header}")
        if "Bcc" in msg:
            print("!! Bcc header present: not allowed by REM-Policy-IT (I-FBCC)")
        if x_transport or x_receipt:
            print(f"  (also present: X-Trasporto={x_transport or '-'} / X-Ricevuta={x_receipt or '-'}: "
                  "encapsulated classic PEC envelope?)")
    else:
        print(f"X-Trasporto: {x_transport or '-'} | X-Ricevuta: {x_receipt or '-'}")
    # DM 2/11/2005 sec. 6.4.2: anomaly envelope = "X-Trasporto: errore" + Subject "ANOMALIA MESSAGGIO: ..."
    if not rem:
        if x_transport == "errore" or (msg.get("Subject", "") or "").upper().startswith("ANOMALIA MESSAGGIO"):
            print("!! ANOMALY ENVELOPE (sec. 6.4.2): the message was NOT certified (ordinary mail or provider error).")
            print("   It only wraps the message as received, without daticert.xml: no certification value.")
        elif not x_transport and not x_receipt:
            print("!! no PEC headers: the message did not go through the certified circuit")
        elif x_transport and x_transport != "posta-certificata":
            print(f"!! unexpected X-Trasporto: {x_transport}")
    if x_receipt and x_receipt not in formats.RECEIPT_TYPES:
        print(f"!! X-Ricevuta not allowed by the rules: {x_receipt}")

    smime_signatures: List[bytes] = []
    original_attachments: dict = {}

    def explore(part, prefix, level=0):
        content_type, filename = part.get_content_type(), part.get_filename()
        section = part.get("REM-Section-Type")
        if section and section not in formats.REM_SECTIONS:
            print(f"!! unexpected REM-Section-Type: {section}")
        if content_type == "message/rfc822":
            inner = part.get_payload(0)
            name = pki.safe_filename(filename or "inner.eml")        # PEC: postacert.eml | REM: AttachedMimeMessage
            if not name.lower().endswith(".eml"):
                name += ".eml"
            inner_names.append(filename)
            Path(out_dir, prefix + name).write_bytes(inner.as_bytes())
            print(f"original message: {filename} | From: {inner['From']} | Subject: {inner['Subject']}")
            explore(inner, prefix + "orig_", level + 1)
        elif part.is_multipart():
            for sub in part.iter_parts():
                explore(sub, prefix, level)
        elif filename:
            payload = part.get_payload(decode=True)
            if payload is None:
                return
            Path(out_dir, prefix + pki.safe_filename(filename)).write_bytes(payload)
            print(f"attachment: {filename} ({len(payload)} bytes)")
            lower = filename.lower()
            if lower == "smime.p7s" and not level:
                smime_signatures.append(payload)
            elif level and lower != "daticert.xml":
                original_attachments[filename] = payload              # for the signature checks
            if lower == "daticert.xml":
                try:
                    data = formats.read_daticert(payload)
                    print("daticert.xml:")
                    for key, value in data.items():
                        if key != "_issues":
                            print(f"  {key}: {value}")
                    for issue in data["_issues"]:
                        print("  !!", issue)
                    if x_receipt and data["type"] != x_receipt and x_transport != "posta-certificata":
                        print(f"  !! X-Ricevuta ({x_receipt}) differs from daticert type ({data['type']})")
                except ET.ParseError as exc:
                    print("!! invalid daticert.xml:", exc)
            elif content_type == "application/xml" and not level:
                # REM: ERDS evidence attached as "<Event>.xml" (EN 319 532-3 sec. 6.2.6.2)
                try:
                    evidence = formats.read_evidence(payload)
                except ET.ParseError as exc:
                    print(f"!! {filename}: invalid XML: {exc}")
                else:
                    evidences.append(evidence)
                    print(f"ERDS evidence ({filename}):")
                    for key, value in evidence.items():
                        if value not in ("", [], False):
                            print(f"  {key}: {value}")
                    if not evidence["xmldsig_signed"]:
                        print("  !! evidence without XML signature (ds:Signature): EN 319 522-3 5.2.2.28 requires it")
                    ok, errors = formats.validate_evidence(payload, args.xsd_dir)
                    if ok is None:
                        print("  XSD validation:", errors[0])
                    elif ok:
                        print("  XSD validation (EN 319 522-3): VALID")
                    else:
                        print("  XSD validation (EN 319 522-3): INVALID")
                        for error in errors:
                            print("    -", error[:200])
        elif content_type == "text/plain" and level:
            print("original text:\n", part.get_content()[:3000])

    explore(msg, f"{num}_")
    revocation = not args.no_revocation
    if original_attachments:
        pki.check_attachment_signatures(original_attachments, f"{num}_orig_", msg["Date"], args.ca, out_dir,
                                        revocation, print)

    if rem:
        # consistency of REM headers vs evidence (REM-Policy-IT PP2, PP3o, I-HFC; EN 319 532-4 table 7)
        for ev in evidences:
            if rem.get("REM-EventIdentifier") and ev["event"] and rem["REM-EventIdentifier"] != ev["event"]:
                print(f"!! REM-EventIdentifier ({rem['REM-EventIdentifier']}) != ERDSEventId ({ev['event']})")
            if ev["evidence_id"] and "REM-Evidence-ID" in rem and \
                    formats.normalize_id(rem["REM-Evidence-ID"]) != formats.normalize_id(ev["evidence_id"]):
                print("!! REM-Evidence-ID != EvidenceIdentifier of the evidence")
            if ev["app_layer_id"] and "REM-UAMessageIdentifier" in rem and \
                    formats.normalize_id(rem["REM-UAMessageIdentifier"]) != formats.normalize_id(ev["app_layer_id"]):
                print("!! REM-UAMessageIdentifier != AppLayerIdentifier of the evidence")
        if not evidences and "receipt" in rem.get("REM-MessageType", ""):
            print("!! REM receipt without an attached XML evidence")
        algorithm = formats.REM_DIGESTS.get(rem.get("REM-DigestAlgorithm", ""))
        if rem.get("REM-DigestValue") and algorithm and any(inner_names):
            matches = rem["REM-DigestValue"].strip() in formats.original_digests(raw, algorithm)
            print(f"digest of the original message ({algorithm}): "
                  f"{'MATCHES REM-DigestValue' if matches else 'NOT verified (the provider normalisation may differ)'}")
        elif rem.get("REM-DigestAlgorithm") and not algorithm:
            print(f"  unsupported digest algorithm: {rem['REM-DigestAlgorithm']}")
        if "AttachedMimeMessage" not in [n for n in inner_names if n] and "dispatch" in rem.get("REM-MessageType", ""):
            print("!! dispatch without the message/rfc822 part 'AttachedMimeMessage'")

    if smime_signatures:
        ok, result, chain, lines = pki.verify_envelope_signature(envelope, smime_signatures[0], msg["Date"],
                                                                 args.ca, args.index, revocation)
        print(f"S/MIME signature (integrity): {'VALID' if ok else 'INVALID'} - {result}")
        for line in lines:
            print("  " + line)
        print("  trust chain: " + ("NOT verified (no --ca)" if chain is None
                                    else f"{'VERIFIED' if chain else 'NOT verified'} against --ca"))
    else:
        print("!! smime.p7s missing: unsigned envelope")


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    netsafe.set_allow_private(args.allow_private_urls)
    os.makedirs(args.out_dir, exist_ok=True)

    conn = None
    try:
        if args.eml:
            ids = [b"file"]
        else:
            try:
                cred = resolve_credentials(args.address, args.username, args.credentials_file)
            except CredentialsError as exc:
                eprint(f"error: {exc}")
                return 2
            server = pick_server(args, cred)
            if server is None:
                eprint(f"error: no IMAP server found for {cred.address}; pass --imap-host (and --imap-port / "
                       "--imap-security), or install dnspython (pip install dnspython) for DNS discovery")
                return 2
            eprint(f"IMAP server: {server.describe()}")
            if args.discover_only:
                return 0
            username = args.username or (cred.username if cred.username != cred.address else None) \
                or server.username or cred.address
            try:
                conn = connect(server, username, cred.password, args.timeout)
                conn.select(quote_imap(args.mailbox), readonly=True)       # read-only: nothing is flagged as read
                ids = select_messages(conn, args)
            except (imaplib.IMAP4.error, OSError, ssl.SSLError) as exc:
                eprint(f"error: IMAP connection failed: {exc}")
                return 1
        print("messages found:", len(ids))
        for item in ids:
            if conn is None:
                raw = Path(args.eml).read_bytes()
            else:
                _, data = conn.fetch(item, "(BODY.PEEK[])")                # PEEK: do not mark as read
                raw = data[0][1]
            analyse_message(item.decode(), raw, args)
    finally:
        if conn is not None:
            try:
                conn.logout()
            except Exception:
                pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
