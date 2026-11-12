# pec-inspector

Read-only command line tool that downloads **PEC** (Italian certified e-mail) and **REM** (ETSI EN 319 532
registered e-mail) messages over IMAP, unpacks them according to the standard PEC structure and checks them:

* classic PEC envelope headers (`X-Trasporto`, `X-Ricevuta`), anomaly envelopes, `daticert.xml` against the
  DTD rules of DM 2 Nov 2005 sec. 7.4;
* REM headers, ERDS evidence (consistency with the headers, optional XSD validation) and the original-message digest;
* the **S/MIME signature of the envelope** (`smime.p7s`): integrity, signer, validity at the message date,
  trust chain, provider hash;
* **digital signatures on the attachments**: CAdES `.p7m` (the signed content is extracted), detached `.p7s`,
  PAdES signatures inside PDFs (also detects data appended after signing); XAdES/XMLDSig is only detected;
* **revocation** (OCSP and CRL) of every certificate in the chain except the root;
* automatic **IMAP server discovery** from the mailbox address.

Nothing is flagged as read, moved or deleted: the folder is opened read-only and messages are fetched with
`BODY.PEEK`. See [SECURITY.md](SECURITY.md).

> The checks are informative and do not replace the verification required by law (e.g. against the official
> list of trust service providers).

## Install

Requires Python 3.9+ and the `openssl` command line tool (used for CMS/S-MIME/OCSP verification) in `PATH`.

The package is not published on PyPI: install it from a clone of this repository, preferably in a virtual
environment. Run **one** of these from the repository root (they are alternatives, not steps):

```sh
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate

pip install .            # core only (cryptography)
pip install ".[dns]"     # core + dnspython: SRV/MX based IMAP discovery
pip install ".[xsd]"     # core + lxml: XSD validation of REM evidence
pip install ".[all]"     # core + dnspython + lxml
```

This installs the `pec-inspector` command. You can also run it without installing:
`PYTHONPATH=src python -m pec_inspector ...` (on Windows PowerShell: `$env:PYTHONPATH="src"`).

## Quick start

```sh
export PEC_ADDRESS=user@example-pec.test
export PEC_PASSWORD='...'                      # or use a credentials file, see below
pec-inspector out/                             # last 10 messages of INBOX
pec-inspector out/ --search "Prot. 0123456"    # IMAP TEXT search
pec-inspector out/ --from agency@pec.example.test
pec-inspector out/ --eml saved-message.eml     # offline analysis, no IMAP access
```

**Where files go.** `OUT_DIR` is the root of everything that is downloaded: pass it as the first argument or set
`PEC_OUT_DIR`. If you give neither, a new private directory (`pec-inspector-XXXX`, mode 0700 on POSIX) is created in the
system temporary directory (`TMPDIR` / `TEMP` / `TMP`); the path and a `file://` link are printed at the start and at the
end, and the directory is removed again if nothing was downloaded. Temporary directories are not cleaned up
automatically after a successful run: delete them when you are done, since they contain your mail.

Each message is unpacked into the output directory: `msg_<n>.eml` (the envelope), `<n>_postacert.eml`,
`<n>_daticert.xml`, `<n>_smime.p7s` and the real attachments as `<n>_orig_<name>`; the report is printed on stdout.

## Export in the clear

`--export` also saves every processed message as plain, readable files and prints the link of the folder at the end
(`--export-dir DIR` chooses the folder, default `<out_dir>/export`, and implies `--export`):

```
<export>/<n>_<subject>/
    message.txt        headers + decoded body of the original message (HTML converted to text if needed)
    message.html       the HTML body, if any
    attachments/       every attachment of the original message; for .p7m also the signed content, unpacked
    pec/               certification parts: daticert.xml, smime.p7s, the PEC wrapper text, the raw envelope.eml
```

```sh
pec-inspector out/ --search "Prot. 0123456" --export
# ...
# Export folder: /home/me/out/export
# Link: file:///home/me/out/export
```

Receipts (acceptance, delivery) have no enclosed original: `message.txt` then holds the receipt text.
Attachment names are sanitised and duplicates renamed. `message.html` starts with a Content-Security-Policy tag that
blocks remote images and scripts, but attachments are saved untouched: open them with the usual care.

## JSON output for scripts and AI agents

`--json` replaces the text report with a single machine-readable JSON document on stdout (UTF-8; progress and
errors go to stderr, errors are also reported as a JSON document with a non-zero exit status):

```sh
pec-inspector --last 5 --ca agid.pem --json | jq '.messages[] | {id, kind, ok: .envelope_signature.integrity_ok}'
```

It carries, per message: classification (`pec` / `rem` / `anomaly` / `not_certified`), the parsed `daticert.xml`
or REM evidence, the attachments, and structured results for every signature (integrity, signer, validity,
trust chain, OCSP/CRL per certificate), plus the warnings. The complete field reference, enumerations and a
Python example are in [JSON_OUTPUT.md](JSON_OUTPUT.md). The document contains mail metadata and local paths:
treat it as sensitive.

## Credentials

Precedence: command line > environment variables > credentials file > interactive prompt (password only).
**The password is never accepted on the command line.**

| Variable | Meaning |
|---|---|
| `PEC_ADDRESS` | mailbox address |
| `PEC_USERNAME` | login name, if different from the address |
| `PEC_PASSWORD` | password |
| `PEC_CREDENTIALS_FILE` | path of a credentials file |
| `PEC_IMAP_HOST`, `PEC_IMAP_PORT`, `PEC_IMAP_SECURITY` | skip discovery (`ssl` or `starttls`) |
| `PEC_PASSWORD_<ADDRESS>` | password of one specific mailbox (see below) |

### Several mailboxes

* **Credentials file** (recommended): one line per mailbox, TAB-separated
  `address<TAB>password[<TAB>imap_host[<TAB>imap_port]]`, `#` comments allowed
  (see [`credentials.example.tsv`](credentials.example.tsv)). Select the mailbox with `--address`
  (optional when the file has a single line).
  ```sh
  pec-inspector out/ --credentials-file ~/.pec-credentials.tsv --address other@example.test
  ```
  Keep it outside the repository and `chmod 600` it; a warning is printed on POSIX if it is group/world readable.
* **Per-mailbox variables**, handy for secret managers and CI: upper-case the address and replace every
  non-alphanumeric character with `_`, e.g. `PEC_PASSWORD_USER_EXAMPLE_PEC_TEST` for `user@example-pec.test`.
  Precedence: `PEC_PASSWORD_<ADDRESS>` > `PEC_PASSWORD` > credentials file.

[`.env.example`](.env.example) lists everything; the tool does not read `.env` files itself.

## IMAP server discovery

Unless you pass `--imap-host`, the server is found from the address domain, in this order:

1. DNS SRV records `_imaps._tcp` / `_imap._tcp` (RFC 6186) — needs `dnspython`;
2. Mozilla autoconfig published by the domain (`https://autoconfig.<domain>/mail/config-v1.1.xml`,
   `https://<domain>/.well-known/autoconfig/mail/config-v1.1.xml`);
3. the same autoconfig on the domains of the MX hosts (PEC addresses on a custom domain are usually hosted by a
   provider that publishes the configuration) — needs `dnspython`;
4. the Thunderbird ISP database (only the domain is sent; disable with `--no-ispdb`);
5. with `--probe`, common host names (`imap.<domain>`, `imaps.<domain>`, `mail.<domain>`, `pec.<domain>`) on port 993.

Many PEC providers publish neither SRV records nor an autoconfig file; for those, `--probe` (which also tries the
MX provider's domain) or an explicit `--imap-host` is needed.
If nothing is found, pass `--imap-host HOST [--imap-port N] [--imap-security ssl|starttls]`.
`--discover-only` prints the server and exits without logging in, `-v` shows what was tried.
Only TLS connections (implicit or STARTTLS, with certificate verification) are used. Microsoft Autodiscover is not implemented.

## Trust chains and revocation

* `--ca PEM` is a PEM bundle of the roots/intermediates you trust. For the envelope signature of a PEC that is the
  provider chain published by AgID (AgID CA and its root); qualified signatures on attachments chain to the root
  of the signer's trust service provider, which you have to supply. Without `--ca` the integrity and validity period
  are still checked and the chain is reported as *not verified*.
* Revocation (OCSP via `openssl ocsp`, CRL via `cryptography`) is checked by default by contacting the servers named in
  the certificates, from the signer up to the CA below the root. A revocation dated *after* the message is reported as
  such. The OCSP response signature is verified only if the responder chains to `--ca`.
  Disable with `--no-revocation`; URLs on private/loopback addresses are refused unless `--allow-private-urls`.
* `--index FILE`: export of the PEC provider index (base `o=postacert`) to confirm the provider certificate hash.
* `--xsd-dir DIR`: directory with the ETSI EN 319 522-3 XSD (`1952203xmlSchema.xsd` and the imported xml, xmldsig,
  saml, xmlenc schemas), not bundled because of the ETSI licence; needs `lxml`.

## Options

Run `pec-inspector --help`. Search arguments for `--search` / `--from` must be ASCII.

## Development

```sh
pip install -e ".[all]"
python -m unittest discover -s tests -v
```

The signature tests generate throw-away keys and certificates with `openssl`/`cryptography`; they are skipped when
`openssl` is missing. No real mailbox or data is used.

## Limitations

* CRL: base lists only (no delta/partitioned CRLs); OCSP/CRL checks cover the certificate chain, not the timestamp
  of the signature (no long-term validation / PAdES-LTV, no signature-time checks).
* XAdES/XMLDSig signatures are detected but not verified.
* IMAP search is ASCII-only.

## License

Released under the MIT License, see [LICENSE.md](LICENSE.md). Security notes: [SECURITY.md](SECURITY.md).
