# VulnX implementation follow-up — 27 October 2026

## Actual outcome

Implemented bcrypt/JWT authentication and account ownership, a Docker definition and administrator lifecycle controls for the custom lab, deployment configuration, purple PDFs and safer legacy-process handling. The native local scanner and authenticated API workflows passed real integration tests. **No live cloud URL was obtained. Actual Docker execution and browser acceptance remain unverified.** This report supersedes earlier statements that authentication was only planned.

## Initial GitHub gate

Local HEAD was `53b0f278ea8334d86db680c0cc60a3f1d270e4aa`; direct `git ls-remote` showed remote main still at `2968b9be684a87f9861ab87fdeef330869d8a349`. Authentication was valid as Chandan280 and branch tracking was correct. GitHub unexpectedly reported the repository as public (zero forks/stars); restored it to private according to the user's original instruction before uploading. Retried ordinary `git push origin main`, then independently verified local HEAD and remote main both equalled `53b0f278ea8334d86db680c0cc60a3f1d270e4aa`. No force push or branch overwrite was used. Development resumed only after that match.

## Decisions and implementation

### Authentication

- Used requested bcrypt, cost 12, with a 12-character minimum and explicit 72-byte UTF-8 maximum to avoid silent truncation. PyJWT validates HS256 signatures and required subject/session/issuer/audience/issued-at/expiry claims. JWT is stored in an HttpOnly cookie, marked Secure for HTTPS hosted configuration.
- Chose eight-hour sessions without refresh-token complexity. Every protected API request also checks the persisted session/user, so logout immediately revokes copied tokens. Restart preserves the key and sessions. No tokens or credentials go into localStorage or Git.
- Added users, auth_sessions, auth_attempts and schema_migrations tables. Existing assets get the migration admin owner; scans/findings inherit ownership via their asset. Target uniqueness is per owner rather than globally shared.
- Added signup/login/logout/me routes, sign-in/signup UI and sign-out. CSRF, origin/host validation and persisted authentication attempt limits remain active. The client returns to sign-in when authentication expires.
- Protected state/history, scan submission, reports, finding reviews, cancellation and workspace reset. Cross-user identifiers are rejected with 404, avoiding existence disclosure. Clear affects only the signed-in user's assessment records; account/other users/shared cache/backups remain.
- Creates a pre-authentication SQLite backup before upgrading legacy storage. Creates one migration admin with a generated random password in the data directory's `bootstrap-admin.json`, mode 0600. The admin has lab-management authority but no bypass into other users' assessment data. Migration is idempotent and regression tested, including preserved backup contents.
- Original and earlier preview databases were inspected read-only: both currently contained zero assets/scans/findings. The original database was not migrated while unsafe legacy listeners remained; its startup guard blocks that operation. A fresh authenticated preview uses a separate directory, so nothing was erased or silently reassigned in the running old workspace.

### Attack Lab

Selected the existing **custom VulnX fixture**, not OWASP Juice Shop. It already exposes actual HTTP XSS/SQLi examples, TLS and DNS in vulnerable/corrected modes and fits the tested ZAP workflow. Substitution avoids changing targets and losing the reproducible correction/retest path.

Added `lab/Dockerfile`, `compose.lab.yml`, fixed-command lifecycle controller and Settings → Attack Lab controls. Start/stop/reset require an admin. Mutations are blocked while scans run. Reset affects only the project's lab container/volume. Configuration includes a non-root user, read-only root filesystem, dropped capabilities, no-new-privileges, CPU/memory/PID limits, an internal network and localhost-only published ports. Corrected/vulnerable mode changes the real marker inside the running container, with native-fixture compatibility.

Docker command and desktop/runtime are absent on this Mac. Controller regression tests and YAML parsing passed, but no image was built or container started. Runtime isolation, ports and reset therefore remain unverified. Do not present this as a demonstrated Docker lab or as Juice Shop. The real native fixture did pass all scanner profiles.

### Deployment

Selected Vercel frontend plus Railway backend with a persistent `/data` SQLite volume and one replica. This preserves tested storage and avoids a rushed Postgres conversion. No paid plans or billing changes were enabled. Free credits do not establish that sustained ZAP workloads fit a zero budget.

Added backend Dockerfile (actual Nmap, Java, DNS tools and checksum-verified ZAP), Railway healthcheck/configuration, volume validation and privilege-dropping entrypoint. Added Vercel configuration and same-origin API bridge preserving cookies, CSRF/origin headers and PDF downloads. Configured public binding via `VULNX_BIND=0.0.0.0` and provider PORT, exact HTTPS origin/host/target allowlists, persistent JWT secret and no API caching. Public startup fails closed if required security or actual volume configuration is absent. Hosted scan targets are explicitly administrator-approved; arbitrary public signup does not enable arbitrary target selection.

Vercel's CLI reported logged out after its cache/config directory was placed in an allowed temporary directory. Railway CLI installation failed downloading the release binary through the network proxy. No provider tokens or local credentials were present, and `gh secret list` returned an empty list. No live backend could be provisioned or paid resource activated. The manifests and API bridge are preparation, not a deployed service. Cloud lab management is disabled and no Docker socket is exposed; the hosted image does not run the vulnerable lab, so active ZAP remains a local lab workflow.

### Remaining fixes

- PDF title and headings now use purple `#7c3aed`; added understated footer/page numbering. Generated a fresh actual authenticated DNS PDF, verified the color in the PDF, rendered and visually inspected both pages. No clipping observed.
- Added a default-workspace startup check for legacy listeners before binding/migration/recovery. This closes the gap where old code did not acquire the new database lock.
- Added `scripts/stop_local.py`, which validates Python listener ports and project cwd before graceful SIGTERM, never broad pkill/SIGKILL. Running it returned PermissionError for all three old backend PIDs. They are still alive; no privileged workaround was attempted.
- Updated the integration verifier for authentication and added a disposable authenticated/full integration runner. Source, credentials, scan evidence and runtime data remain separated by Git exclusions.

## Verification

| Verification | Result |
|---|---|
| Backend unittest suite | 74 passed, 0 failed |
| Offline email-parser suite | 15 passed, 0 failed |
| Vercel API bridge tests | 3 passed, 0 failed |
| TypeScript + production Vite build | Passed |
| Real email DNS baseline | Completed; 3 findings from intentionally vulnerable fixture |
| Real website headers baseline | Completed; 2 findings |
| Real Nmap inventory | Completed; actual services, 0 vulnerability findings |
| Real TLS/SSLyze | Completed; 1 finding from self-signed fixture certificate |
| Real active ZAP | Completed; 19 alert occurrences, including XSS and SQLi assertions |
| Corrected email and header retests | Passed verification-of-fix assertions |
| NVD lookup | Actual CVE-2021-44228 returned with NVD source |
| PDF/JSON API exports | Passed signatures/scan identity |
| Signup → actual DNS scan → finding → exports | Passed |
| Another user exporting that scan | Rejected with 404 |
| Restart then access same account/history/session | Passed |
| Logout then protected state request | Rejected with 401 |
| Purple PDF | Color verified; both pages rendered and inspected |
| Compose/Railway/Vercel configuration syntax | Parsed successfully |
| Actual Docker build/start/stop/reset | Blocked: no Docker runtime |
| Actual Vercel/Railway deployment | Blocked: no authenticated provider access; Railway CLI download also failed |
| Browser automation | Attempted isolated headless Chrome; process aborted in restricted environment, no browser pass claimed |
| Old backend cleanup | Attempted, PermissionError; startup prevention added |

74 backend tests consist of the previous 57, eight authentication tests, four lab-controller tests, four deployment-configuration tests and one legacy-listener regression. Mocked Docker/proxy tests are distinct from real scanner integration. The integration runner keeps evidence only under ignored `.runtime/acceptance`, never the user database. The local lab's native mode was restored after acceptance. No external website was actively scanned during this work.

## Completion scoring

Same five equally weighted checkpoints; each fulfilled checkpoint earns 20%, with no full credit for scaffolding/unverified runtime behaviour.

| Module | Previous | Current | Remaining |
|---|---:|---:|---|
| Website scanner | 60% | 60% | General authorized-site active flow; separately verified library coverage |
| Email DNS | 60% | 60% | Comprehensive record validation; wider standards/authentication coverage |
| Docker Attack Lab | 0% | 20% | Actual Docker execution; demonstrated isolation; demonstrated container lifecycle; reproducible Docker verification |
| Network | 80% | 80% | OS fingerprinting |
| Dashboard/reports | 80% | 80% | Final consolidated submission acceptance, including browser verification |
| NVD | 60% | 60% | Complete traversal; applicability-validation workflow |
| AI | 0% | 0% | Not implemented |
| JWT auth | 0% | 100% of defined checkpoints | Signup, password/login, tokens, ownership and tests implemented; browser/cloud acceptance and production hardening still outstanding |

The Attack Lab's first checkpoint now credits the working custom fixture explicitly authorized as an alternative in the latest request. It does not credit Juice Shop or unexecuted container settings. With this authorized substitution, 23/40 = 57.5%; excluding optional AI, 23/35 = 65.7%. If the professor insists on literal Juice Shop, that module stays 0% and the strict original aggregate is 22/40 = 55%. Original five core modules remain 17/25 = 68%. Deployment is a separate unmet delivery requirement, not hidden inside these module scores. A 100% auth checkpoint score is not a security certification or a claim of production readiness.

## Before presenting

Use the authenticated local preview at http://127.0.0.1:8790/ while it is running. This is local-only, not a public deployment. Create your own account. To manage the lab, use the generated admin credentials in `.runtime/auth-preview/bootstrap-admin.json`; do not include this file in screenshots or submission. This preview has separate empty account storage; it is not a view of the original workspace.

The complete scanner demonstration uses the actual native local fixture. Represent it as the custom VulnX fixture, not Juice Shop. Docker configuration exists but has not run. No public deployed URL is available. Password reset, email verification, MFA, distributed workers, OS fingerprinting, comprehensive SPF/DMARC evaluation, arbitrary active-site scanning and optional AI remain absent. The Python HTTP server is not hardened for unrestricted public production use. These limits belong in the submission.

For normal startup against the original workspace, run `scripts/stop_local.py` from Mac Terminal, ensure old listeners are gone, then start using `scripts/start_local.py --port 8788`. First startup performs the backed-up migration. Do not delete lock files to bypass ownership. If the native lab already runs, do not add `--lab` or start the Docker lab on its occupied ports.
