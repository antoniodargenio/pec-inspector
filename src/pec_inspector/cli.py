"""Command line interface: fetch PEC/REM messages (read-only IMAP), unpack and check them."""
from __future__ import annotations

import argparse
import email
import imaplib
import importlib.util
import json
import os
import ssl
import sys
import tempfile
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from email import policy
from pathlib import Path
from typing import List, Optional

from . import __version__, export, formats, netsafe, pdfexport, pki, threads
from .credentials import CredentialsError, resolve_credentials
from .discovery import ImapServer, discover

SCHEMA_VERSION = 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pec-inspector",
        description="Download PEC / REM messages over IMAP (read-only), unpack them according to the standard "
                    "PEC structure and check receipts, signatures, certificate chains and revocation.",
        epilog="Credentials: environment (PEC_ADDRESS, PEC_PASSWORD, PEC_CREDENTIALS_FILE, ...) or a credentials "
               "file; see the README. The password is never taken from the command line.")
    p.add_argument("out_dir", nargs="?", metavar="OUT_DIR",
                   help="root directory for everything that is downloaded (created if needed; may also be set with "
                        "PEC_OUT_DIR). If omitted, a new private directory is created in the system temporary "
                        "directory (TMPDIR / TEMP / TMP) and its link is printed")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    acc = p.add_argument_group("mailbox")
    acc.add_argument("--address", help="mailbox address (default: PEC_ADDRESS, or the only account of the credentials file)")
    acc.add_argument("--username", help="IMAP login name if different from the address (default: PEC_USERNAME)")
    acc.add_argument("--credentials-file", metavar="FILE", help="TAB-separated 'address<TAB>password[<TAB>host[<TAB>port]]'"
                                                                 " (default: PEC_CREDENTIALS_FILE)")
    acc.add_argument("--mailbox", action="append", metavar="FOLDER",
                     help="IMAP folder to read (default: INBOX); repeat it to read several, e.g. --mailbox INBOX "
                          "--mailbox 'Sent' (the selection options apply to each folder)")

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

    exp = p.add_argument_group("export and output format")
    exp.add_argument("--export", action="store_true",
                     help="also save each message in the clear (decoded text/HTML body) with all its attachments, "
                          "and print the link of the folder (default folder: <out_dir>/export)")
    exp.add_argument("--export-dir", metavar="DIR", help="export folder (implies --export)")
    exp.add_argument("--thread", action="store_true",
                     help="group the messages into conversations: sent messages, received messages and their "
                          "receipts together (linked by Message-ID / X-Riferimento-Message-ID / In-Reply-To); "
                          "read the Sent folder too with a second --mailbox")
    exp.add_argument("--thread-pdf", action="store_true",
                     help="save each conversation as one A4 PDF, messages in chronological order (implies --thread; "
                          "needs reportlab: pip install 'pec-inspector[pdf]')")
    exp.add_argument("--pdf-dir", metavar="DIR", help="folder for the conversation PDFs (default: <out_dir>/threads; "
                                                      "implies --thread-pdf)")
    exp.add_argument("--json", action="store_true",
                     help="print ONE machine-readable JSON document on stdout instead of the text report "
                          "(progress and diagnostics go to stderr; errors are reported as JSON too); "
                          "schema documented in JSON_OUTPUT.md")
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


class Reporter:
    """Prints the text report (unless disabled) and collects the warnings for the JSON report."""

    def __init__(self, text: bool):
        self.text = text
        self.warnings: List[str] = []

    def say(self, *args):
        if self.text:
            print(*args)

    def lines(self, lines):
        for line in lines:
            self.say(line)

    def warn(self, message: str, indent: str = ""):
        self.warnings.append(message)
        self.say(f"{indent}!! {message}")


# ---------------------------------------------------------------------------------------------
def analyse_message(num: str, raw: bytes, args, text: bool = True, folder: Optional[str] = None) -> dict:
    """Unpack and check one message. Prints the text report when ``text`` and always returns the
    structured report (the JSON ``messages[]`` entry)."""
    out_dir = args.out_dir
    R = Reporter(text)
    msg = email.message_from_bytes(raw, policy=policy.default)
    envelope = os.path.join(out_dir, f"msg_{num}.eml")
    Path(envelope).write_bytes(raw)

    x_transport, x_receipt = msg.get("X-Trasporto", ""), msg.get("X-Ricevuta", "")
    rem = {k: str(v) for k, v in msg.items() if k.upper().startswith("REM-")}
    evidences: list = []
    inner_names: list = []
    report: dict = {
        "id": num, "folder": folder, "date": str(msg["Date"] or ""), "subject": str(msg["Subject"] or ""),
        "from": str(msg["From"] or ""), "to": str(msg["To"] or ""),
        "kind": None,
        "headers": {"x_trasporto": x_transport or None, "x_ricevuta": x_receipt or None},
        "rem": rem or None, "rem_checks": {}, "original_message": None, "daticert": None, "evidence": [],
        "attachments": [], "attachment_signatures": [], "envelope_signature": None,
        "files": {"envelope_eml": envelope}, "export": None, "threading": None, "warnings": R.warnings,
    }
    inner_threading: dict = {}

    R.say(f"\n=== msg {num} | {msg['Date']} | {msg['Subject']}")
    if rem:
        report["kind"] = "rem"
        R.say("TYPE: REM (ETSI EN 319 532 / REM-Policy-IT)")
        for key, value in rem.items():
            R.say(f"  {key}: {value}")
        mtype, event = rem.get("REM-MessageType", ""), rem.get("REM-EventIdentifier", "")
        if mtype and mtype.startswith(formats.MESSAGE_TYPE_URI) and \
                mtype[len(formats.MESSAGE_TYPE_URI):] not in formats.REM_MESSAGE_TYPES:
            R.warn(f"unexpected REM-MessageType: {mtype}")
        if event.startswith(formats.EVENT_URI):
            if event[len(formats.EVENT_URI):] not in formats.REM_EVENTS:
                R.say(f"  (event not among those named in the specifications consulted: {event[len(formats.EVENT_URI):]})")
        elif event:
            R.warn(f"REM-EventIdentifier with an unexpected URI: {event}")
        for header in ("REM-MetadataVersion", "REM-MessageType", "REM-DigestAlgorithm", "REM-DigestValue",
                       "REM-UAMessageIdentifier"):
            if header not in rem and (mtype.endswith("dispatch") or "receipt" in mtype):
                R.warn(f"mandatory REM header missing: {header}")
        if "Bcc" in msg:
            R.warn("Bcc header present: not allowed by REM-Policy-IT (I-FBCC)")
        if x_transport or x_receipt:
            R.say(f"  (also present: X-Trasporto={x_transport or '-'} / X-Ricevuta={x_receipt or '-'}: "
                  "encapsulated classic PEC envelope?)")
    else:
        R.say(f"X-Trasporto: {x_transport or '-'} | X-Ricevuta: {x_receipt or '-'}")
        # DM 2/11/2005 sec. 6.4.2: anomaly envelope = "X-Trasporto: errore" + Subject "ANOMALIA MESSAGGIO: ..."
        if x_transport == "errore" or (msg.get("Subject", "") or "").upper().startswith("ANOMALIA MESSAGGIO"):
            report["kind"] = "anomaly"
            R.warn("ANOMALY ENVELOPE (sec. 6.4.2): the message was NOT certified (ordinary mail or provider error).")
            R.say("   It only wraps the message as received, without daticert.xml: no certification value.")
        elif not x_transport and not x_receipt:
            report["kind"] = "not_certified"
            R.warn("no PEC headers: the message did not go through the certified circuit")
        else:
            report["kind"] = "pec"
            if x_transport and x_transport != "posta-certificata":
                R.warn(f"unexpected X-Trasporto: {x_transport}")
    if x_receipt and x_receipt not in formats.RECEIPT_TYPES:
        R.warn(f"X-Ricevuta not allowed by the rules: {x_receipt}")

    smime_signatures: List[bytes] = []
    original_attachments: dict = {}

    def explore(part, prefix, level=0):
        content_type, filename = part.get_content_type(), part.get_filename()
        section = part.get("REM-Section-Type")
        if section and section not in formats.REM_SECTIONS:
            R.warn(f"unexpected REM-Section-Type: {section}")
        if content_type == "message/rfc822":
            inner = part.get_payload(0)
            name = pki.safe_filename(filename or "inner.eml")        # PEC: postacert.eml | REM: AttachedMimeMessage
            if not name.lower().endswith(".eml"):
                name += ".eml"
            inner_names.append(filename)
            Path(out_dir, prefix + name).write_bytes(inner.as_bytes())
            if report["original_message"] is None:
                inner_threading.update(id=str(inner["Message-ID"] or ""),
                                       refs=threads.ids_in(inner["In-Reply-To"]) + threads.ids_in(inner["References"]))
                report["original_message"] = {"filename": filename, "from": str(inner["From"] or ""),
                                              "to": str(inner["To"] or ""), "subject": str(inner["Subject"] or ""),
                                              "date": str(inner["Date"] or ""), "saved_as": os.path.join(out_dir, prefix + name)}
            R.say(f"original message: {filename} | From: {inner['From']} | Subject: {inner['Subject']}")
            explore(inner, prefix + "orig_", level + 1)
        elif part.is_multipart():
            for sub in part.iter_parts():
                explore(sub, prefix, level)
        elif filename:
            payload = part.get_payload(decode=True)
            if payload is None:
                return
            saved = Path(out_dir, prefix + pki.safe_filename(filename))
            saved.write_bytes(payload)
            report["attachments"].append({"name": filename, "size": len(payload), "saved_as": str(saved),
                                          "role": "original" if level else "pec"})
            R.say(f"attachment: {filename} ({len(payload)} bytes)")
            lower = filename.lower()
            if lower == "smime.p7s" and not level:
                smime_signatures.append(payload)
            elif level and lower != "daticert.xml":
                original_attachments[filename] = payload              # for the signature checks
            if lower == "daticert.xml":
                try:
                    data = formats.read_daticert(payload)
                    R.say("daticert.xml:")
                    for key, value in data.items():
                        if key != "_issues":
                            R.say(f"  {key}: {value}")
                    for issue in data["_issues"]:
                        R.warn(issue, indent="  ")
                    if x_receipt and data["type"] != x_receipt and x_transport != "posta-certificata":
                        R.warn(f"X-Ricevuta ({x_receipt}) differs from daticert type ({data['type']})", indent="  ")
                    report["daticert"] = {**{k: v for k, v in data.items() if k != "_issues"}, "issues": data["_issues"]}
                except ET.ParseError as exc:
                    R.warn(f"invalid daticert.xml: {exc}")
            elif content_type == "application/xml" and not level:
                # REM: ERDS evidence attached as "<Event>.xml" (EN 319 532-3 sec. 6.2.6.2)
                try:
                    evidence = formats.read_evidence(payload)
                except ET.ParseError as exc:
                    R.warn(f"{filename}: invalid XML: {exc}")
                else:
                    evidences.append(evidence)
                    R.say(f"ERDS evidence ({filename}):")
                    for key, value in evidence.items():
                        if value not in ("", [], False):
                            R.say(f"  {key}: {value}")
                    if not evidence["xmldsig_signed"]:
                        R.warn("evidence without XML signature (ds:Signature): EN 319 522-3 5.2.2.28 requires it",
                               indent="  ")
                    ok, errors = formats.validate_evidence(payload, args.xsd_dir)
                    if ok is None:
                        R.say("  XSD validation:", errors[0])
                        xsd = {"status": "skipped", "messages": errors}
                    elif ok:
                        R.say("  XSD validation (EN 319 522-3): VALID")
                        xsd = {"status": "valid", "messages": []}
                    else:
                        R.say("  XSD validation (EN 319 522-3): INVALID")
                        for error in errors:
                            R.say("    -", error[:200])
                        xsd = {"status": "invalid", "messages": errors}
                    report["evidence"].append({"file": filename, **evidence, "xsd": xsd})
        elif content_type == "text/plain" and level:
            R.say("original text:\n", part.get_content()[:3000])

    explore(msg, f"{num}_")
    if not inner_threading:                       # no enclosed original: the message itself (e.g. a copy in Sent)
        inner_threading.update(id="", refs=threads.ids_in(msg["In-Reply-To"]) + threads.ids_in(msg["References"]))
    report["threading"] = threads.threading_info(
        str(msg["Message-ID"] or ""), inner_threading["id"], (report["daticert"] or {}).get("msgid", ""),
        str(msg.get("X-Riferimento-Message-ID", "") or ""), inner_threading["refs"])
    revocation = not args.no_revocation
    if original_attachments:
        results = pki.check_attachment_signatures(original_attachments, f"{num}_orig_", msg["Date"], args.ca, out_dir,
                                                  revocation)
        report["attachment_signatures"] = results
        R.lines(pki.attachment_lines(results))

    if rem:
        # consistency of REM headers vs evidence (REM-Policy-IT PP2, PP3o, I-HFC; EN 319 532-4 table 7)
        for ev in evidences:
            if rem.get("REM-EventIdentifier") and ev["event"] and rem["REM-EventIdentifier"] != ev["event"]:
                R.warn(f"REM-EventIdentifier ({rem['REM-EventIdentifier']}) != ERDSEventId ({ev['event']})")
            if ev["evidence_id"] and "REM-Evidence-ID" in rem and \
                    formats.normalize_id(rem["REM-Evidence-ID"]) != formats.normalize_id(ev["evidence_id"]):
                R.warn("REM-Evidence-ID != EvidenceIdentifier of the evidence")
            if ev["app_layer_id"] and "REM-UAMessageIdentifier" in rem and \
                    formats.normalize_id(rem["REM-UAMessageIdentifier"]) != formats.normalize_id(ev["app_layer_id"]):
                R.warn("REM-UAMessageIdentifier != AppLayerIdentifier of the evidence")
        if not evidences and "receipt" in rem.get("REM-MessageType", ""):
            R.warn("REM receipt without an attached XML evidence")
        algorithm = formats.REM_DIGESTS.get(rem.get("REM-DigestAlgorithm", ""))
        if rem.get("REM-DigestValue") and algorithm and any(inner_names):
            matches = rem["REM-DigestValue"].strip() in formats.original_digests(raw, algorithm)
            report["rem_checks"]["original_digest"] = {"algorithm": algorithm, "matches": matches}
            R.say(f"digest of the original message ({algorithm}): "
                  f"{'MATCHES REM-DigestValue' if matches else 'NOT verified (the provider normalisation may differ)'}")
        elif rem.get("REM-DigestAlgorithm") and not algorithm:
            R.say(f"  unsupported digest algorithm: {rem['REM-DigestAlgorithm']}")
        if "AttachedMimeMessage" not in [n for n in inner_names if n] and "dispatch" in rem.get("REM-MessageType", ""):
            R.warn("dispatch without the message/rfc822 part 'AttachedMimeMessage'")

    if smime_signatures:
        sig = pki.verify_envelope_signature(envelope, smime_signatures[0], msg["Date"], args.ca, args.index, revocation)
        report["envelope_signature"] = sig
        R.lines(pki.envelope_lines(sig))
    else:
        R.warn("smime.p7s missing: unsigned envelope")

    if args.export_root is not None:
        folder, count = export.export_message(num, msg, args.export_root, raw)
        report["export"] = {"folder": str(folder), "attachments": count}
        R.say(f"exported: {folder} ({count} attachment{'s' if count != 1 else ''})")
    return report


def summarise(reports: List[dict]) -> dict:
    problems = 0
    for r in reports:
        if r["envelope_signature"] and not r["envelope_signature"]["integrity_ok"]:
            problems += 1
        problems += sum(1 for s in r["attachment_signatures"] if s.get("integrity_ok") is False)
    return {"messages": len(reports), "messages_with_warnings": sum(1 for r in reports if r["warnings"]),
            "invalid_signatures": problems}


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    as_json = args.json
    if as_json and hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")        # JSON is always UTF-8, whatever the console code page

    def info(*parts):                                    # human messages: stdout in text mode, stderr with --json
        (eprint if as_json else print)(*parts)

    def fail(code: str, message: str, status: int) -> int:
        eprint(f"error: {message}")
        if as_json:
            print(json.dumps({"schema_version": SCHEMA_VERSION, "tool": "pec-inspector", "version": __version__,
                              "error": {"code": code, "message": message}}, ensure_ascii=False, indent=2))
        return status

    netsafe.set_allow_private(args.allow_private_urls)
    temporary = False
    if not args.out_dir:
        args.out_dir = os.environ.get("PEC_OUT_DIR") or ""
    if args.out_dir:
        args.out_dir = os.path.abspath(args.out_dir)
        os.makedirs(args.out_dir, exist_ok=True)
    else:                                    # system temp directory; mkdtemp creates it private (mode 0700 on POSIX)
        args.out_dir = tempfile.mkdtemp(prefix="pec-inspector-")
        temporary = True
    args.out_dir = str(Path(args.out_dir).resolve())   # canonical path (e.g. no 8.3 short names on Windows)
    eprint(f"download folder: {args.out_dir}" + (" (temporary)" if temporary else ""))
    args.mailbox = args.mailbox or ["INBOX"]
    if args.pdf_dir:
        args.thread_pdf = True
    if args.thread_pdf:
        args.thread = True
        if importlib.util.find_spec("reportlab") is None:
            return fail("pdf_unavailable", "PDF export needs reportlab: pip install 'pec-inspector[pdf]'", 2)
    args.export_root = None
    if args.export or args.export_dir:
        args.export_root = Path(args.export_dir or os.path.join(args.out_dir, "export")).resolve()
        args.export_root.mkdir(parents=True, exist_ok=True)

    conn = None
    address = None
    mailbox_info = None
    reports: List[dict] = []
    try:
        if args.eml:
            mailbox_info = {"source": "eml", "file": os.path.abspath(args.eml)}
        else:
            try:
                cred = resolve_credentials(args.address, args.username, args.credentials_file)
            except CredentialsError as exc:
                return fail("credentials", str(exc), 2)
            server = pick_server(args, cred)
            if server is None:
                return fail("no_imap_server",
                            f"no IMAP server found for {cred.address}; pass --imap-host (and --imap-port / "
                            "--imap-security), or install dnspython (pip install dnspython) for DNS discovery", 2)
            eprint(f"IMAP server: {server.describe()}")
            mailbox_info = {"source": "imap", "address": cred.address, "folder": args.mailbox[0], "folders": args.mailbox,
                            "server": {"host": server.host, "port": server.port, "security": server.security,
                                       "found_by": server.source}}
            if args.discover_only:
                if as_json:
                    print(json.dumps({"schema_version": SCHEMA_VERSION, "tool": "pec-inspector", "version": __version__,
                                      "mailbox": mailbox_info}, ensure_ascii=False, indent=2))
                return 0
            username = args.username or (cred.username if cred.username != cred.address else None) \
                or server.username or cred.address
            try:
                conn = connect(server, username, cred.password, args.timeout)
            except (imaplib.IMAP4.error, OSError, ssl.SSLError) as exc:
                return fail("imap", f"IMAP connection failed: {exc}", 1)
            address = cred.address
            for folder in args.mailbox:
                try:
                    status, detail = conn.select(quote_imap(folder), readonly=True)   # read-only: nothing is flagged as read
                    if status != "OK":
                        raise imaplib.IMAP4.error(f"cannot open folder {folder!r}: {detail}")
                    ids = select_messages(conn, args)
                    info(f"messages found in {folder}:", len(ids))
                    for item in ids:
                        _, data = conn.fetch(item, "(BODY.PEEK[])")             # PEEK: do not mark as read
                        label = item.decode() if len(args.mailbox) == 1 else f"{export.slug(folder)}-{item.decode()}"
                        reports.append(analyse_message(label, data[0][1], args, text=not as_json, folder=folder))
                except (imaplib.IMAP4.error, OSError, ssl.SSLError) as exc:
                    return fail("imap", f"IMAP connection failed: {exc}", 1)
        if args.eml:
            info("messages found:", 1)
            reports.append(analyse_message("file", Path(args.eml).read_bytes(), args, text=not as_json))
        conversations = threads.build_threads(reports, address) if args.thread else None
        pdf_root = None
        if conversations is not None and args.thread_pdf:
            pdf_root = Path(args.pdf_dir or os.path.join(args.out_dir, "threads")).resolve()
            pdf_root.mkdir(parents=True, exist_ok=True)
            by_id = {r["id"]: r for r in reports}
            for conversation in conversations:
                target = pdf_root / f"{conversation['id']}_{export.slug(conversation['subject'])}.pdf"
                conversation["pdf"] = str(pdfexport.write_thread_pdf(conversation, by_id, target))
        if conversations is not None and not as_json:
            for line in threads.thread_lines(conversations):
                print(line)
        if as_json:
            print(json.dumps({
                "schema_version": SCHEMA_VERSION, "tool": "pec-inspector", "version": __version__,
                "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "mailbox": mailbox_info,
                "options": {"ca_file": bool(args.ca), "revocation_checked": not args.no_revocation},
                "download_dir": args.out_dir,
                "export_dir": str(args.export_root) if args.export_root else None,
                "messages": reports, "summary": summarise(reports),
                **({"threads": conversations} if conversations is not None else {}),
            }, ensure_ascii=False, indent=2, default=str))
        else:
            print(f"\nDownload folder: {args.out_dir}\nLink: {Path(args.out_dir).as_uri()}")
            if pdf_root is not None:
                print(f"PDF folder: {pdf_root}\nLink: {pdf_root.as_uri()}")
            if args.export_root is not None:
                print(f"Export folder: {args.export_root}\nLink: {args.export_root.as_uri()}")
    finally:
        if conn is not None:
            try:
                conn.logout()
            except Exception:
                pass
        if temporary:
            try:
                os.rmdir(args.out_dir)           # nothing was downloaded (error, --discover-only): no empty leftovers
            except OSError:
                pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
