# VulnX

A local, evidence-based security assessment and remediation workspace. **Version 0.2**, built and tested on Apple Silicon. Runtime findings come from actual scanners; the application never seeds fake results.

## Start

Prerequisites: Node 20+, Python 3.11+, Java 17+ for ZAP, and an installed Nmap executable. Tested here with Node 24 and Python 3.14. Nmap remains separately installed under its own license.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
npm ci
npm run build
.venv/bin/python scripts/install_zap.py
.venv/bin/python backend/server.py
```

Open **http://127.0.0.1:8787**. Frontend and API share one origin. `npm run dev` rebuilds assets on change; refresh the page afterward. The ZAP installer downloads the pinned official 2.17.0 cross-platform release and verifies its SHA-256 digest before extraction (approximately 273 MiB). Tool downloads and runtime data are ignored by Git.

## Daily use and data reset

After installation and building, start the app and lab together with `.venv/bin/python scripts/start_local.py --lab`. Keep the terminal open; Ctrl+C stops the processes. Settings includes an operating guide.

Settings → Clear workspace data permanently removes stored targets, scans, findings, reviews, audit history, cached intelligence and generated validation evidence. Type `DELETE ALL DATA` to enable it. Active/queued scans block reset. Installed tools and lab configuration remain; separately downloaded reports and backups are outside its scope. Export reports first.

See [User guide](docs/USER_GUIDE.md) and [Test report](docs/TEST_REPORT.md).

## Real local lab

In a second terminal:

```sh
.venv/bin/python lab/server.py
```

The deliberately vulnerable fixture binds only to loopback and contains no user data. Add these approved assets:

| Asset | Type | Profile |
|---|---|---|
| `mail.vulnx.test` | Email domain | Email configuration; DKIM selector `test` |
| `http://127.0.0.1:18080/` | Website | Website headers or ZAP active lab |
| `https://127.0.0.1:18443/` | Website | TLS configuration |
| `127.0.0.1` | Network | Network inventory; ports `18080,18443` |

DNS queries under `.vulnx.test` go to the actual DNS fixture at `127.0.0.1:15353`; other domains use the system DNS resolver. Settings → Controlled local lab switches between vulnerable and corrected modes. Run a new assessment to measure the change. The TLS certificate remains intentionally self-signed.

## Implemented

- Responsive React/TypeScript dashboard, readiness checks, assets, background jobs, cancellation and error states.
- DNS evidence and basic SPF, DMARC and supplied-selector DKIM checks.
- Single-endpoint HTTP security-header checks with pinned destination validation and no redirects.
- ZAP automation against the controlled lab: real XSS/SQL injection alerts, passive findings and the bundled Retire.js add-on.
- Nmap bounded IPv4 TCP/service inventory; up to 16 addresses and 32 selected ports. Open ports remain observations.
- SSLyze certificate and TLS 1.0–1.3 checks with pinned IP and hostname indication.
- NVD CVE lookup and version-specific CPE candidate matching. Cached, throttled and source-backed. Candidates never automatically become confirmed findings.
- Deduplicated findings, review states/reasons, comparable configuration retests, verified fixes and reopened findings.
- Historical comparisons, evidence, tool metadata, PDF/JSON exports and local audit records.
- One worker at a time, process-group cancellation, time limits, restart recovery and atomic finding/result persistence.

## Coverage and deployment limits

This is a **single-user, loopback-only application**. Accounts, roles, PostgreSQL and externally isolated workers are not implemented. Do not expose it publicly or reverse proxy it. Per-process sessions, CSRF tokens and host/origin checks protect the local browser workflow but are not multi-user authentication.

Active ZAP scanning is restricted to `127.0.0.1:18080`; external approved websites support HTTP header and TLS profiles. ZAP is time bounded and does not prove every route/rule was exercised. Authenticated and arbitrary external active scans are not enabled.

Nmap is unprivileged: OS fingerprinting, UDP and raw-packet scans are not implemented. DNS checks do not include full recursive SPF evaluation, DKIM signature verification or complete DMARC organizational-domain fallback. Unknown DKIM selectors are not assessed. DNS errors never become missing-record findings.

Fix verification applies only to equivalent successful email and HTTP-configuration checks. Absence in failed, partial, redirected or active ZAP scans does not establish a fix. NVD candidates require validation of installed builds, backports and configuration. AI is deferred; guidance works without an AI service.

## Verification

```sh
.venv/bin/python -m unittest discover -s tests -v
npm run build
```

With app and lab running:

```sh
.venv/bin/python scripts/verify_local.py
```

This exercises actual loopback DNS, HTTP, Nmap, TLS and ZAP through the app API, corrects the lab, verifies configuration fixes, retrieves an actual NVD record and downloads reports. It retains real assessment history locally and does not scan external assets. Unit-test fixtures never populate runtime data.

See PROGRESS.md for observed results. requirements.lock.txt records the complete development environment; requirements.txt contains the smaller runtime set.

## Storage and GitHub

Private repository: https://github.com/Chandan280/vulnx

Source and tests are pushed after verified milestones. `.runtime/` (targets, evidence, database, reports, tools, generated lab keys), `.venv`, credentials and `.env` are excluded. GitHub stores source; it does not host the running app.

## Offline email forensics

Open **Email Analyzer** in the sidebar. Choose or drop one `.eml` / `.txt` file (up to 5 MB), or paste a full raw email; click **Analyze Email**. Inspect unfolded headers, encoded subjects, reported authentication claims, Received headers, decoded text/HTML source, HTTP(S) URLs, attachment metadata and SHA-256 hashes. **Clear** removes input and results. Leaving the page also discards them.

Email contents are processed in browser memory, never sent to the API, stored in browser storage or added to assessment history. HTML is shown as inert text; URLs and attachments are never opened. This is an offline inspection tool, not independent SPF/DKIM/DMARC verification, an antivirus engine or a link-reputation service. Authentication-Results headers may be forged. Parsing supports common nested MIME, base64 and quoted-printable; malformed data and limits are surfaced. UTF-8 file reading may not preserve original unencoded binary parts; their hashes carry a warning. Live DNS configuration analysis remains in Scans → Email configuration.

Run `npm run test:email` (Node 22.6+ with TypeScript stripping support; tested on Node 24) for the parser tests. `tests/fixtures/forensics-demo.eml` is explicitly synthetic test input, not seeded runtime data.
