# VulnX

Build a real, local-first assessment platform. Never invent runtime findings, scan progress, CVE matches, environment readiness, or verification results. Fixtures belong only in tests.

The user authorizes a private GitHub repository named vulnx in their authenticated personal account and commits/pushes after coherent verified changes. Verify account and repository visibility. Never force push or make public. If authentication/network access is blocked, continue locally and report that pushes are pending. Inspect staged changes and exclude secrets, scan targets/evidence, databases and reports. No paid services.

Visual direction: charcoal, restrained emerald, readable typography, generous spacing. Keyboard accessibility and honest empty/error states are required.

Current milestone uses React/TypeScript, a Python standard-library local API with SQLite, and actual DNS/Nmap/SSLyze/ZAP adapters. Read README.md and PROGRESS.md for tested capabilities and limits. This is a single-user loopback application, not a production multi-user service. Planned migration: FastAPI/PostgreSQL and isolated job workers before wider deployment. Do not expose this milestone publicly.

Checks: npm run build;  .venv/bin/python -m unittest discover -s tests -v. Start: .venv/bin/python backend/server.py. Review real browser behavior where available. Keep README and PROGRESS.md accurate.
