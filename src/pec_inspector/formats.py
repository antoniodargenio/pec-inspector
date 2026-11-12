"""Parsers and structural checks for Italian PEC (certified e-mail) and REM (ETSI EN 319 532) messages.

References
----------
* PEC: DPR 68/2005, DM 2 Nov 2005 (technical rules, incl. the DTD of ``daticert.xml``, sec. 7.4),
  AgID technical rules.
* REM: ETSI EN 319 532-3 (formats) and -4 (profiles), ETSI EN 319 522-3 (ERDS evidence schema),
  AgID "REM-Policy-IT" technical annex v2.0.

A REM message is recognised by its ``REM-*`` headers; a classic PEC by ``X-Trasporto`` / ``X-Ricevuta``.
"""
from __future__ import annotations

import base64
import email
import hashlib
import html
import os
import xml.etree.ElementTree as ET

# DM 2/11/2005, sec. 7.4 (daticert.xml). The values are the strings used on the wire.
RECEIPT_TYPES = {"accettazione", "non-accettazione", "presa-in-carico", "avvenuta-consegna",
                 "errore-consegna", "preavviso-errore-consegna", "rilevazione-virus"}
DATICERT_TYPES = RECEIPT_TYPES | {"posta-certificata"}
DATICERT_ERRORS = {"nessuno", "no-dest", "no-dominio", "virus", "altro"}

# REM
EVENT_URI = "http://uri.etsi.org/19522/Event/"
MESSAGE_TYPE_URI = "http://uri.etsi.org/19522/v1#/ERDMessageType/"
REM_MESSAGE_TYPES = {"dispatch", "receipt"}                      # REM-Policy-IT I-MD13
REM_EVENTS = {"SubmissionAcceptance", "SubmissionRejection", "RelayAcceptance", "RelayRejection",
              "RelayFailure", "ContentConsignment", "ReceivedFromNonERDS"}
REM_SECTIONS = {"rem_message/introduction", "rem_message/original", "rem_message/xml_evidence",
                "rem_message/pdf_evidence", "rem_message/extension"}
REM_DIGESTS = {"http://www.w3.org/2001/04/xmlenc#sha256": "sha256"}   # REM-Policy-IT PP1

XSD_MAIN_FILE = "1952203xmlSchema.xsd"


def local_name(element) -> str:
    return element.tag.rsplit("}", 1)[-1]


def normalize_id(value) -> str:
    """Message/evidence ids may appear as ``&lt;id&gt;``, ``<id>`` or bare (AgID PP3o)."""
    return html.unescape(value or "").strip().strip("<>").strip()


def _reject_dtd(raw: bytes) -> None:
    if b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
        raise ET.ParseError("DTD/entity declarations are not accepted")


# ---------------------------------------------------------------------------------------------
def read_evidence(raw: bytes) -> dict:
    """ERDS evidence XML (EN 319 522-3). Elements are looked up by local name, independent of namespace."""
    _reject_dtd(raw)
    root = ET.fromstring(raw)

    def first(name):
        for element in root.iter():
            if local_name(element) == name and (element.text or "").strip():
                return element.text.strip()
        return ""

    reasons = []
    for reason in root.iter():
        if local_name(reason) == "EventReason":
            reasons.append({
                "code": next((normalize_id(c.text) for c in reason.iter() if local_name(c) == "Code"), ""),
                "details": [(c.text or "").strip() for c in reason.iter() if local_name(c) == "Details"]})
    return {
        "root": local_name(root),
        "namespace": root.tag[1:].split("}")[0] if root.tag.startswith("{") else "",
        "event": first("ERDSEventId"),
        "evidence_id": first("EvidenceIdentifier"),
        "message_id": first("MessageIdentifier"),
        "app_layer_id": first("AppLayerIdentifier"),
        "policy": first("EvidenceIssuerPolicyID"),
        "event_time": first("EventTime"),
        "subject": first("Subject"),
        "reasons": reasons,
        "xmldsig_signed": any(local_name(e) == "Signature" for e in root.iter()),
    }


_schema_cache: dict = {}


def validate_evidence(raw: bytes, xsd_dir):
    """Validate an evidence against the ETSI EN 319 522-3 XSD (Annex A) kept in ``xsd_dir``.

    The schemas are not bundled (ETSI licence); download ``1952203xmlSchema.xsd`` and the schemas it imports
    (xml, xmldsig, saml, xmlenc) into one directory and pass it with ``--xsd-dir``.  Needs ``lxml``.
    Returns ``(ok | None when not runnable, [messages])``.
    """
    if not xsd_dir:
        return None, ["no --xsd-dir given: XSD validation skipped"]
    try:
        from lxml import etree
    except ImportError:
        return None, ["lxml not installed (pip install lxml): XSD validation skipped"]
    try:
        if xsd_dir not in _schema_cache:
            _schema_cache[xsd_dir] = etree.XMLSchema(etree.parse(os.path.join(xsd_dir, XSD_MAIN_FILE)))
        schema = _schema_cache[xsd_dir]
    except (OSError, etree.XMLSchemaParseError) as exc:
        return None, [f"XSD cannot be loaded from {xsd_dir}: {exc}"]
    try:
        document = etree.fromstring(raw, etree.XMLParser(no_network=True, resolve_entities=False))
    except etree.XMLSyntaxError as exc:
        return False, [f"XML not well-formed: {exc}"]
    ok = schema.validate(document)
    return ok, [f"line {e.line}: {e.message}" for e in schema.error_log][:15]


def original_digests(raw_envelope: bytes, algorithm: str) -> set:
    """Candidate values of ``REM-DigestValue``: base64 digest of the original ``message/rfc822`` part
    terminated by CRLF (EN 319 532-4 C.4.5.1 / AgID PP2).  Indicative: the provider's normalisation may differ."""
    message = email.message_from_bytes(raw_envelope)     # compat32 keeps the headers as they are
    for part in message.walk():
        if part.get_content_type() == "message/rfc822":
            inner = part.get_payload(0).as_bytes().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
            candidates = {inner, inner.rstrip(b"\r\n") + b"\r\n", inner.rstrip(b"\r\n")}
            return {base64.b64encode(hashlib.new(algorithm, c).digest()).decode() for c in candidates}
    return set()


# ---------------------------------------------------------------------------------------------
def _text(element, tag_name: str) -> str:
    found = element.find(".//" + tag_name)
    return (found.text or "").strip() if found is not None else ""


def read_daticert(raw: bytes) -> dict:
    """Parse ``daticert.xml`` and check it against the DTD rules of DM 2/11/2005 sec. 7.4."""
    _reject_dtd(raw)
    root = ET.fromstring(raw)
    date_el, receipt_el = root.find(".//data"), root.find(".//ricevuta")
    d = {
        "type": root.get("tipo"), "error": root.get("errore"),
        "sender": _text(root, "mittente"),
        "recipients": [(x.get("tipo"), (x.text or "").strip()) for x in root.iter("destinatari")],
        "subject": _text(root, "oggetto"),
        "provider": _text(root, "gestore-emittente"),
        "date": _text(root, "giorno") + " " + _text(root, "ora"),
        "timezone": date_el.get("zona") if date_el is not None else "",
        "identifier": _text(root, "identificativo"),
        "msgid": _text(root, "msgid"),
        "receipt_type": receipt_el.get("tipo") if receipt_el is not None else "",
        "delivery": _text(root, "consegna"),
        "received": [(x.text or "").strip() for x in root.iter("ricezione")],
        "extended_error": _text(root, "errore-esteso"),
    }
    issues = []
    if d["type"] not in DATICERT_TYPES:
        issues.append(f"unexpected type: {d['type']}")
    if (d["error"] or "nessuno") not in DATICERT_ERRORS:
        issues.append(f"unexpected error value: {d['error']}")
    if root.tag != "postacert":
        issues.append("root element is not 'postacert'")
    for field in ("sender", "provider", "identifier"):
        if not d[field]:
            issues.append(f"mandatory field missing: {field}")
    if not d["recipients"]:
        issues.append("no recipients (destinatari+)")
    if d["error"] and d["error"] != "nessuno":
        issues.append(f"the PEC reports an error: {d['error']} {d['extended_error']}")
    d["_issues"] = issues
    return d
