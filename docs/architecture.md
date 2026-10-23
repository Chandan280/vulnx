# Architecture and evidence model

The React interface sends same-origin requests to a loopback Python API. The API validates scope, persists the job, then submits it to a single background worker. SQLite stores assets, scans, deduplicated findings, occurrences and audit events. Scanner subprocesses run with structured argument arrays, limits and process-group cancellation. This is a local capstone architecture, not a hardened multi-tenant service.

## Evidence pipeline

1. Validate the approved asset and compatible profile.
2. Run the actual tool and preserve coverage, tool identity, outcomes and evidence.
3. Normalize severity and confidence without promoting fingerprints to confirmed vulnerabilities.
4. Identify findings by asset, profile/options, scanner rule and affected endpoint.
5. Persist the result and finding updates atomically.
6. Verify absence only when an equivalent successful configuration check provides adequate coverage.

Historical scan results are evidence snapshots with derived comparison metadata. Finding review states change independently of those snapshots. Accepted-risk and false-positive decisions require a recorded reason.

## Trust boundaries

- Only loopback Host headers are accepted. Cross-origin browser mutations are rejected, with per-process session and CSRF checks.
- Public HTTP/TLS names must resolve exclusively to global IP addresses; the chosen destination is pinned. HTTP redirects are not followed.
- Local scans are restricted to documented lab ports. Active ZAP scans are restricted to the controlled fixture.
- Nmap accepts bounded numeric IPv4 scopes and port lists, without shell interpolation or arbitrary flags.
- DNS resolves names through the system resolver, with an explicit documented `.vulnx.test` local-fixture route.
- NVD is a fixed endpoint with strict CVE/CPE validation, bounded responses, caching and throttling. Candidate associations remain separate from confirmed findings.
- HTML evidence renders as escaped text in React and escaped paragraphs in PDFs. Runtime data and generated lab keys are excluded from Git.

## Evaluation

Run unit tests for malformed targets, forbidden destinations, DNS failure semantics, scope checks, persistence, retest coverage and CVE candidate classification. Run the actual lab verification for genuine scanner integration. Unit-test fixtures never supply dashboard results.

## Next architecture milestone

Move API routes to FastAPI, storage to SQLAlchemy/Alembic and PostgreSQL, and jobs into isolated workers before considering multi-user or remote deployment. Implement user/project authorization and managed secrets at that boundary. Preserve the current actual scanner adapters and evidence semantics.
