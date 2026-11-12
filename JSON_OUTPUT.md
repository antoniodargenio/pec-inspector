# JSON output (`--json`)

`pec-inspector --json ...` prints **one JSON document** on stdout, encoded as UTF-8, instead of the text report.
Everything else (download folder, IMAP server, progress, error text) goes to **stderr**, so stdout can be piped
straight into `jq`, a script or an AI agent:

```sh
pec-inspector out/ --search "Prot. 0123456" --ca agid.pem --json | jq '.messages[].envelope_signature.chain'
```

Back to the [README](README.md).

* `schema_version` is `1`. Fields may be **added** in later versions without bumping it; renaming or removing
  a field, or changing its meaning, bumps it.
* Absent information is `null` (or an empty list/object), never a missing key, unless stated otherwise.
* Dates are ISO 8601 strings, except `date` fields copied from the message, which keep the original RFC 5322 text.
* Passwords never appear. The document does contain your mail metadata (addresses, subjects, local file paths),
  so treat it as sensitive.
* Exit status: `0` success, `1` IMAP connection/login failure, `2` usage, credentials or server-discovery error.
  On failure with `--json` stdout still carries a JSON document (see [Error document](#error-document)).

## Top level

| Field | Type | Meaning |
|---|---|---|
| `schema_version` | integer | Version of this schema (`1`). |
| `tool` | string | Always `"pec-inspector"`. |
| `version` | string | Version of the tool. |
| `generated_at` | string | UTC timestamp of the run. |
| `mailbox` | object | Where the messages came from, see below. |
| `options` | object | `{"ca_file": bool, "revocation_checked": bool}`: whether trust roots were given (`--ca`) and whether OCSP/CRL were checked. Read it before interpreting `chain.status` / `revocation`. |
| `download_dir` | string | Absolute path of the folder with every unpacked file. |
| `export_dir` | string \| null | Absolute path of the `--export` folder, if requested. |
| `messages` | array | One entry per processed message, oldest first, see [Message](#message). |
| `summary` | object | `{"messages": int, "messages_with_warnings": int, "invalid_signatures": int}`. `invalid_signatures` counts envelope and attachment signatures whose integrity check failed. |

### `mailbox`

IMAP source:

```json
{ "source": "imap", "address": "user@example-pec.test", "folder": "INBOX",
  "server": { "host": "imaps.example.test", "port": 993, "security": "ssl",
              "found_by": "DNS SRV _imaps._tcp.example-pec.test" } }
```

`security` is `"ssl"` (implicit TLS) or `"starttls"`; `found_by` says how the server was determined.
Offline source (`--eml`): `{ "source": "eml", "file": "/abs/path/message.eml" }`.

With `--discover-only` the document contains just `schema_version`, `tool`, `version` and `mailbox`.

## Message

```json
{
  "id": "155",
  "date": "Wed, 11 Nov 2026 16:09:24 +0100",
  "subject": "POSTA CERTIFICATA: Example subject",
  "from": "\"On behalf of: agency@pec.example.test\" <posta-certificata@provider.example.test>",
  "to": "user@example-pec.test",
  "kind": "pec",
  "headers": { "x_trasporto": "posta-certificata", "x_ricevuta": null },
  "rem": null,
  "rem_checks": {},
  "original_message": { "filename": "postacert.eml", "from": "agency@pec.example.test", "to": "user@example-pec.test",
                         "subject": "Example subject", "date": "Wed, 11 Nov 2026 16:09:23 +0100",
                         "saved_as": "/tmp/pec-inspector-x/155_postacert.eml" },
  "daticert": { "...": "see below" },
  "evidence": [],
  "attachments": [ { "name": "daticert.xml", "size": 971, "saved_as": "/tmp/pec-inspector-x/155_daticert.xml", "role": "pec" } ],
  "attachment_signatures": [],
  "envelope_signature": { "...": "see Signature objects" },
  "files": { "envelope_eml": "/tmp/pec-inspector-x/msg_155.eml" },
  "export": { "folder": "/tmp/pec-inspector-x/export/155_POSTA_CERTIFICATA_Example_subject", "attachments": 0 },
  "warnings": []
}
```

| Field | Type | Meaning |
|---|---|---|
| `id` | string | IMAP sequence number (or `"file"` with `--eml`). It identifies the message only within this run/folder state. |
| `date`, `subject`, `from`, `to` | string | Headers of the outer (envelope) message; empty string if absent. |
| `kind` | string | `"pec"` classic PEC (certified), `"rem"` REM (ETSI EN 319 532), `"anomaly"` anomaly envelope (the message was **not** certified), `"not_certified"` no PEC headers at all. Only `pec` and `rem` carry certification value. |
| `headers` | object | `x_trasporto` (`posta-certificata`, `errore`, ...) and `x_ricevuta` (receipt type, e.g. `accettazione`, `avvenuta-consegna`); `null` when absent. |
| `rem` | object \| null | All `REM-*` headers as `{header: value}`; `null` for non-REM messages. |
| `rem_checks` | object | Empty, or `{"original_digest": {"algorithm": "sha256", "matches": bool}}`. `matches: false` is *not verified*, not proof of tampering: the provider's normalisation may differ. |
| `original_message` | object \| null | The enclosed message (`postacert.eml` in PEC, `AttachedMimeMessage` in REM): `filename`, `from`, `to`, `subject`, `date`, `saved_as`. `null` for receipts. |
| `daticert` | object \| null | Parsed `daticert.xml`, see below. |
| `evidence` | array | REM ERDS evidence documents, see below. |
| `attachments` | array | Every file part found: `name`, `size` (bytes), `saved_as` (absolute path), `role` = `"pec"` (certification parts such as `daticert.xml`, `smime.p7s`) or `"original"` (real attachments of the sent message). |
| `attachment_signatures` | array | Signature checks on the `original` attachments, see [Signature objects](#signature-objects). Empty when there are no original attachments. |
| `envelope_signature` | object \| null | Check of `smime.p7s`; `null` when the envelope is unsigned (a warning is added). |
| `files.envelope_eml` | string | Path of the raw message as downloaded. |
| `export` | object \| null | With `--export`: `{"folder": path, "attachments": count}`. |
| `warnings` | array of strings | Human-readable anomalies detected for this message (the `!!` lines of the text report). Empty means none. |

### `daticert`

Parsed from `daticert.xml` (DM 2/11/2005, sec. 7.4); keys are English, the values are the original ones.

| Field | Type | Meaning |
|---|---|---|
| `type` | string | `posta-certificata`, `accettazione`, `non-accettazione`, `presa-in-carico`, `avvenuta-consegna`, `errore-consegna`, `preavviso-errore-consegna`, `rilevazione-virus`. |
| `error` | string | `nessuno` (none), `no-dest`, `no-dominio`, `virus`, `altro`. |
| `sender` | string | Certified sender address. |
| `recipients` | array of `[kind, address]` | `kind` is `certificato` or `esterno`. |
| `subject`, `provider`, `identifier`, `msgid` | string | Subject, issuing provider, PEC identifier, original `Message-ID`. |
| `date`, `timezone` | string | Provider timestamp (`DD/MM/YYYY HH:MM:SS`) and zone (`+0100`). |
| `receipt_type` | string | `completa`, `breve` or `sintetica` (empty if not applicable). |
| `delivery`, `received`, `extended_error` | string / array / string | Delivery mailbox, list of reception details, extended error text. |
| `issues` | array of strings | Violations of the DTD rules (also copied into `warnings`). |

### `evidence[]` (REM)

`file`, `root`, `namespace`, `event` (e.g. `http://uri.etsi.org/19522/Event/ContentConsignment`), `evidence_id`,
`message_id`, `app_layer_id`, `policy`, `event_time`, `subject`, `reasons` (`[{"code": str, "details": [str]}]`),
`xmldsig_signed` (bool: carries a `ds:Signature`) and
`xsd`: `{"status": "valid" | "invalid" | "skipped", "messages": [str]}` (`skipped` without `--xsd-dir`/`lxml`).

## Signature objects

Used by `envelope_signature` (the PEC provider's S/MIME signature) and by each entry of `attachment_signatures`.

```json
{
  "integrity_ok": true,
  "detail": "Verification successful",
  "signer": "CN=Provider S.p.A.,O=Provider S.p.A.,C=IT",
  "issuer": "CN=Example Issuing CA,O=Example Agency,C=IT",
  "certificate_sha1": "c5f1131515c5494176482b5d0e0ec6104125d888",
  "not_before": "2026-08-03T00:00:00+00:00",
  "not_after": "2028-11-05T00:00:00+00:00",
  "valid_at_message_date": true,
  "chain": { "status": "verified", "error": null },
  "revocation": [ { "...": "see below" } ],
  "provider_index_match": null
}
```

| Field | Type | Meaning |
|---|---|---|
| `integrity_ok` | boolean | The CMS signature verifies over the content (nothing altered). **Says nothing about who signed or whether to trust them**: read `chain` too. |
| `detail` | string | OpenSSL's verdict or error text. |
| `signer`, `issuer` | string \| null | RFC 4514 distinguished names. `signer` is `null` when no certificate could be read; then only `label`, `integrity_ok` and `detail` are present. |
| `certificate_sha1` | string | SHA-1 of the signer certificate (the PEC `providerCertificateHash`). |
| `not_before`, `not_after` | string | Validity period of the signer certificate. |
| `valid_at_message_date` | boolean | The message date falls inside that period. |
| `chain.status` | string | `"verified"` chains to the roots given with `--ca`; `"not_verified"` does not (see `chain.error`); `"not_checked"` no `--ca` was given. |
| `revocation` | array \| null | Revocation results, see below; `null` when `--no-revocation` was used. |
| `provider_index_match` | boolean \| null | Envelope only: the certificate is listed in the provider index passed with `--index`; `null` without `--index`. |

Attachment signature entries add `name` (attachment file) and `label` (readable description) and a `type`:

| `type` | Extra fields |
|---|---|
| `cades_enveloping` (`.p7m`) | `extracted_to`: file name of the unpacked signed content in `download_dir` (`null` if the signature is invalid). |
| `cades_detached` (`.p7s`) | `document`: name of the signed file. If it is not among the attachments the entry has `status: "document_missing"` and no verification fields. |
| `pades` (signed PDF) | `index`, `of`: position among the signatures of the file; `covers_whole_file`: **`false` means data was appended after signing** (incremental update). Entries that could not be checked have `status: "unverifiable"` and a `detail`. |
| `pdf` | `signed: false`: the PDF has no digital signature (it may carry a graphical stamp only). |
| `xmldsig` | `status: "not_verified"`: an XMLDSig/XAdES signature was detected but not verified (unsupported). |

### Revocation results

A flat list, one entry per check, from the signer up to the CA just below the root:

```json
{ "level": "signer", "subject": "CN=Provider S.p.A.,...", "method": "ocsp", "status": "good",
  "url": "http://ocsp.example.test/OCSP", "response_authenticated": true,
  "detail": "This Update: Nov 12 09:07:31 2026 GMT; Next Update: Nov 12 21:07:31 2026 GMT" }
{ "level": "signer", "subject": "CN=Provider S.p.A.,...", "method": "crl", "status": "not_revoked",
  "url": "http://crl.example.test/CRL", "signature_verified": true, "expired": false,
  "next_update": "2026-11-13T09:00:00+00:00", "revoked_on": null, "revoked_relative_to_message": null }
```

| Field | Meaning |
|---|---|
| `level` | `"signer"`, `"ca_1"`, `"ca_2"`, ... or `"root"`. |
| `subject` | Certificate the check refers to. |
| `method` | `"ocsp"`, `"crl"` or `"none"` (nothing to check). |
| `status` | OCSP: `good`, `revoked`, `unknown`, `unavailable`, `refused`. CRL: `not_revoked`, `revoked`, `unavailable`. None: `self_signed_root`, `no_reference` (no OCSP/CRL URL in the certificate), `issuer_not_found`, `chain_too_long`. |
| `url` | Responder or CRL URL (`null` for `method: "none"`). `refused` means the URL was blocked by the safety filter (non-public host or scheme; see `--allow-private-urls`). |
| `response_authenticated` | OCSP only: the response signature was verified (needs the responder to chain to `--ca`). |
| `detail` | OCSP: timestamps from the responder or the error; `none`: explanation. |
| `signature_verified`, `expired`, `next_update` | CRL only: the CRL signature verifies against the issuer, the CRL is past its `nextUpdate`, and that date. |
| `revoked_on`, `revoked_relative_to_message` | CRL only, when `status` is `revoked`: revocation time and `"before"` / `"after"` the message date. A revocation *after* the message does not by itself invalidate a signature made earlier. |

## Error document

```json
{ "schema_version": 1, "tool": "pec-inspector", "version": "0.1.0",
  "error": { "code": "credentials", "message": "no password for user@example-pec.test: ..." } }
```

`error.code`: `credentials` (exit 2), `no_imap_server` (exit 2), `imap` (exit 1). The same text is written to stderr.

## Reading it programmatically

A message can be considered *certified and intact* when all of these hold:

```
kind in ("pec", "rem")
and envelope_signature.integrity_ok
and envelope_signature.valid_at_message_date
and envelope_signature.chain.status == "verified"          # requires --ca
and no revocation entry with status "revoked"
and warnings is empty
```

Always check `options.ca_file` and `options.revocation_checked` first: without `--ca` the chain is `"not_checked"`,
and with `--no-revocation` the `revocation` field is `null`. Verify attachments the same way through
`attachment_signatures`; an attachment without an entry (or with `type: "pdf"`, `signed: false`) is simply unsigned.

```python
import json, subprocess

doc = json.loads(subprocess.run(
    ["pec-inspector", "--json", "--last", "5", "--ca", "agid.pem"], capture_output=True, text=True, check=True).stdout)
for m in doc["messages"]:
    sig = m["envelope_signature"] or {}
    ok = (m["kind"] in ("pec", "rem") and sig.get("integrity_ok") and sig.get("chain", {}).get("status") == "verified"
          and not any(r["status"] == "revoked" for r in sig.get("revocation") or []) and not m["warnings"])
    print(m["id"], m["subject"][:60], "OK" if ok else "CHECK")
```
