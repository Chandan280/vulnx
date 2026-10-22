# VulnX

Build a real, local-first assessment platform. Never invent runtime findings, scan progress, CVE matches, environment readiness, or verification results. Fixtures belong only in tests.

The user authorizes a private GitHub repository named vulnx in their authenticated personal account and commits/pushes after coherent verified changes. Verify account and repository visibility. Never force push or make public. If authentication/network access is blocked, continue locally and report that pushes are pending. Inspect staged changes and exclude secrets, scan targets/evidence, databases and reports. No paid services.

Visual direction: charcoal, restrained emerald, readable typography, generous spacing. Keyboard accessibility and honest empty/error states are required.

Current first milestone uses React/TypeScript and an offline-installable Python standard-library local API with SQLite. This is a single-user loopback application, not a production multi-user service. Planned migration: FastAPI/PostgreSQL and isolated job workers before wider deployment. Do not expose this milestone publicly.

Checks: npm run build; python3 -m unittest discover -s tests -v. Start: python3 backend/server.py. Review real browser behavior where available. Keep README and PROGRESS.md accurate.
