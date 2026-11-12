# Security notes

pec-inspector reads other people's e-mail and talks to servers named inside certificates, so it treats
everything it parses as hostile.

* **Read-only.** The IMAP folder is opened with `readonly` and messages are fetched with `BODY.PEEK`:
  nothing is flagged, moved or deleted.
* **TLS always verified.** IMAP uses implicit TLS or STARTTLS with certificate and host-name verification;
  plain-text IMAP is never used, even if a provider configuration offers it.
* **Passwords** are never read from the command line and never printed. Prefer a `chmod 600` credentials
  file, a secret manager exporting environment variables, or the interactive prompt.
* **Discovery decides where the password goes.** DNS SRV and autoconfig data are not authenticated beyond
  HTTPS/DNS. The discovered server is printed before login (`--discover-only` stops there); for sensitive
  accounts pass `--imap-host`.
* **Outbound requests triggered by certificates** (OCSP, CRL, AIA) go through a guard that refuses non-HTTP(S)
  schemes and hosts resolving to private/loopback/link-local addresses, re-checks redirects and caps sizes
  (`--allow-private-urls` relaxes this; `--no-revocation` disables the requests). DNS rebinding is not
  prevented. These requests reveal to the CA that a given certificate is being checked.
* **Untrusted files.** Attachment names are sanitised before being written; XML with DTDs/entities is rejected.
* **Not legal evidence.** The checks are informative. They do not replace the verification required by law,
  e.g. against the official list of trust service providers.

Report vulnerabilities privately through the repository's security advisory feature rather than a public issue.

Back to the [README](README.md) · License: [LICENSE.md](LICENSE.md)
