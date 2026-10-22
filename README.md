# VulnX

A local security assessment workspace. **Version 0.1: initial email DNS assessment milestone.** Real runtime outputs only; no seeded dashboard data.

## Run on your Mac

Node 20+ and Python 3.11+ are required. `dig` is included on macOS. For PDF export, install `python3 -m pip install -r requirements.txt` in a virtual environment when reportlab is not already available. The initial implementation was tested with reportlab 5.0.1.

```sh
npm ci
npm run build
python3 backend/server.py
```

Open http://127.0.0.1:8787. All files in `dist/` are served by the same local Python process as the API. Add an approved domain, choose Scans → New assessment, and optionally supply a DKIM selector from the mail administrator. Outbound DNS must be permitted. The current environment already has installed frontend dependencies and reportlab, so only the build and server commands are needed here.

For frontend development, run `npm run dev` in a second terminal to rebuild assets on changes; refresh the page served on port 8787. This keeps the local API and browser session on one origin.

This milestone is **single-user and loopback-only**. Do not publicly deploy it or reverse proxy it. It does not yet provide multi-user authentication or roles. A per-process session and CSRF token, strict host/origin checks and loopback binding protect the local browser workflow; these are not a replacement for production authentication.

## Implemented

- React/TypeScript dashboard, responsive layouts, empty/error states and keyboard focus styling.
- Approved domain assets, actual background DNS TXT queries, assessment stages and cancellation.
- Basic SPF permissive-policy, DMARC policy, DKIM supplied-selector and record-presence checks.
- Real evidence, severity, confidence, limitations, persisted scan history and finding occurrences.
- PDF/JSON exports, local executable readiness checks, restart recovery and local audit records.
- SQLite persistence in ignored `.runtime/`; one assessment worker.

## Deliberate limits

No full SPF recursive evaluation, full DKIM key validation, organizational-domain DMARC fallback, or actual mail authentication tests. A missing DKIM result applies only to the supplied selector. DNS timeout is an error, never a missing-record finding. No fabricated CVE associations. Occurrences are not yet deduplicated. Repeated scans do not automatically establish that a finding is fixed.

ZAP, network/TLS assessments, CVE enrichment, account roles, isolated workers, deduplication, verified remediation and comparable retests are **not implemented**. The UI identifies these limitations. The planned production architecture remains FastAPI/PostgreSQL with isolated queued scanner workers; the initial offline-capable milestone uses the Python standard library and SQLite because package/network access in this execution session is restricted.

## Verify

```sh
npm run build
python3 -m unittest discover -s tests -v
```

Automated tests use isolated test fixtures and temporary storage. They are not live-domain validation and never populate the real workspace. See PROGRESS.md for executed checks and environment blockers.

## Private GitHub repository

User authorized a private repository `vulnx` in their personal account, with commits and pushes after verified milestones. GitHub authentication was invalid at initial setup; no remote creation is claimed.

```sh
gh auth login -h github.com
gh auth status
```

After confirming the account and checking for an existing repository, create the private repository and push the existing local Git history. Never upload `.runtime`, credentials, reports or target evidence. Repository access and GitHub hosting do not deploy the application.
