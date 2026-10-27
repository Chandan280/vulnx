# VulnX

Build a real, local-first assessment platform. Never invent runtime findings, scan progress, CVE matches, environment readiness, or verification results. Fixtures belong only in tests.

The user authorizes a private GitHub repository named vulnx in their authenticated personal account and commits/pushes after coherent verified changes. Verify account and repository visibility. Never force push or make public. If authentication/network access is blocked, continue locally and report that pushes are pending. Inspect staged changes and exclude secrets, scan targets/evidence, databases and reports. No paid services.

Visual direction: minimal white surfaces, restrained purple accents, readable typography, generous spacing. Keyboard accessibility and honest empty/error states are required.

Current milestone uses React/TypeScript, a Python standard-library API with SQLite, bcrypt/JWT accounts and ownership checks, and actual DNS/Nmap/SSLyze/ZAP adapters. Default binding is loopback. Public configuration requires explicit HTTPS origin, host/target allowlists, persistent secret and durable storage. One backend/worker replica only. This is a capstone, not a hardened public scanning service. The user authorized deployment only at zero cost; do not activate paid plans. Docker and cloud manifests are not proof of successful deployment. Read README.md and PROGRESS.md for actual verification and blockers.

Checks: npm run build;  .venv/bin/python -m unittest discover -s tests -v. Start: .venv/bin/python backend/server.py. Review real browser behavior where available. Keep README and PROGRESS.md accurate.
