# VulnX reliability and correctness follow-up — 27 October 2026

## Outcome and boundaries

Steps 1 and 2 are implemented and verified against isolated fresh backends. Replacing the existing production listeners is blocked by process-control permissions, so this is not a claim that the old browser sessions are repaired. Step 3 is planning only: no JWT authentication, deployment, Docker or Juice Shop implementation was added. Existing user data was preserved.

## Step 1: reliability

The old servers accepted connections on 8787 and 8788 but closed requests without HTTP responses. Their stdout/stderr were pipe-backed. Reproducing the old handler with a closed stderr reader produced the same RemoteDisconnected failure: BaseHTTPRequestHandler logs while sending its response, and the failed diagnostic write prevents delivery. This confirms a matching mechanism, not a directly inspected exception from those pre-existing processes.

Before: request/error handling depended on launcher output pipes. After: request and handler errors use a rotating file logger; closing stdout/stderr no longer breaks HTTP. Accepted sockets have a 15-second timeout. Logs omit target URLs and request contents. Logs rotate at 1 MiB with two backups.

Before: another backend could open the same SQLite database and run startup recovery before discovering a port collision, marking the original owner's queued/running scans failed. After: an OS-held nonblocking flock on the canonical database lock path is acquired before initialization/recovery. Socket binding must also succeed before recovery. Ownership remains held through request/worker shutdown and releases on process exit/crash. Different ports do not bypass ownership. Lock files are never unlinked by normal shutdown.

Before: verify_local.py always called port 8787. After: it reads VULNX_PORT, supports --port, validates the range and prints the endpoint. Default remains 8787. The launcher and verifier must use the same setting; there is no automatic process discovery. VULNX_DATA_DIR isolates database, intelligence cache, logs and validation output for tests; shared lab/tool locations are not relocated.

Five subprocess regressions cover: closed stdout/stderr with continued HTTP responses; second instance on another port refused while running/queued rows remain unchanged; crash releases ownership and next startup recovers stale rows; occupied socket prevents recovery; configured verifier port and port validation. These five and the original 34 tests passed before Step 2 started.

Operational blocker: old listeners observed as PID 1903 (8788) and PID 73779 (8787) could not be terminated from this session. Ordinary termination returned PermissionError; escalation was rejected because sandbox_approval is disabled. These legacy processes never acquired the new lock and must be stopped before starting the repaired backend on the existing database. Do not run a new same-database backend alongside them. Check current listeners before terminating PIDs; identifiers can be reused. After stopping both backend instances, start `.venv/bin/python scripts/start_local.py --port 8788` from the repo. The existing separate lab can remain running; do not add --lab while its ports are already occupied.

## Step 2: correctness

Nmap formerly treated an empty parsed host list as successful inventory. It now requires successful XML tool completion and separately tracks expected addresses, observed hosts, assessed hosts and complete coverage. Zero hosts yields partial/no_hosts_observed; down, timed-out, missing-port or filtered-only observations yield partial/incomplete_or_unreachable. A nonzero tool exit, invalid XML or missing/failed completion record is a failure. Open/closed observations with complete selected-port accounting can complete; all-closed grouped ports do not create fake vulnerabilities. Because -Pn assumes hosts are up, that label alone does not establish reachability. The profile remains bounded, unprivileged TCP scanning without OS fingerprinting.

SPF now checks recognized mechanisms, required arguments, IP family/address/prefix validity, a/mx CIDR bounds and duplicate known modifiers. Unknown modifiers remain permitted. Unvalidated macro domains produce an explicit incomplete result. DKIM checks tag syntax/duplicates/version placement, required p, strict base64, DER RSA public-key type and minimum size, and 32-byte Ed25519 public-key encoding. Empty p remains revocation; unknown algorithms are incomplete. Malformed known records produce findings. A completed assessment containing findings means the assessment ran, not that the domain is secure.

The reproduced `v=spf1 INVALID-MECHANISM` and `v=DKIM1; p=not-a-real-key` now create two malformed-record findings instead of completed/zero findings. Fixtures exist only in regression tests. Full recursive SPF evaluation, lookup limits, macro validation, complete optional DKIM-tag semantics, message-signature verification and organizational-domain DMARC handling remain outside the implementation.

## Verification results

| Check | Passed | Failed | Evidence / limits |
|---|---:|---:|---|
| Existing backend tests | 34 | 0 | Included in full unittest discovery |
| New runtime subprocess regressions | 5 | 0 | Actual subprocesses, sockets, lock contention and recovery |
| New email DNS regressions | 11 | 0 | Valid/invalid record cases, generated keys, incomplete cases |
| New Nmap regressions | 7 | 0 | XML outcomes, coverage and process failure |
| Backend total | 57 | 0 | Final run: 1.498 seconds; no skipped tests |
| Offline email-parser tests | 15 | 0 | Node test runner; no skipped tests |
| Frontend production build | 1 | 0 | TypeScript and Vite succeeded |
| Fresh live scanner API workflows | 2 | 0 | Actual controlled-lab DNS and Nmap; isolated temporary DB |
| Export downloads in those workflows | 4 | 0 | PDF signature and JSON scan identity for each profile |

The live email scan completed with one actual revoked-selector finding in the lab's current mode. Nmap completed with one assessed host and both selected lab ports accounted for, zero vulnerability findings. Results were persisted and retrieved through the API. Temporary integration data was removed on exit; user workspace data was untouched. Export checks were structural/identity checks, not fresh visual PDF inspection.

Full ZAP, TLS, NVD and browser acceptance were not rerun for this follow-up. The comprehensive verify_local.py pipeline was not rerun; its configuration was regression tested. Historical integration evidence must remain labelled historical. Build warnings: npm's inherited http-proxy configuration warning and ignored lucide-react use-client directives; neither caused failure.

## Step 3A: proposed JWT authentication — not implemented

Add versioned schema migrations and a users table with UUID, normalized unique email, password_hash, created_at and disabled state. Add refresh_sessions with user_id, hashed refresh token, session ID, expiry, rotation/revocation information. Use Argon2id through a maintained library with per-password salts and calibrated work factors; never plain SHA-256 for passwords.

Proposed endpoints: POST /api/auth/signup, /login, /refresh, /logout and GET /api/auth/me. Use short-lived signed access JWTs (proposed 15 minutes), enforce a fixed algorithm and required issuer/audience/subject/expiry claims, and validate active user/session on protected requests. Use rotating refresh tokens (proposed seven days) in Secure HttpOnly SameSite cookies behind HTTPS; keep access tokens in browser memory. Retain CSRF/origin protection for cookie-based refresh/logout. Logout must revoke the server session so a copied access token tied to it also stops working, rather than only clearing browser state. Add login/signup rate limits and generic authentication failures. Password recovery/email verification would be a separate scope decision.

Ownership is essential: add user_id to assets and user-scoped unique target constraints; scans and findings inherit validated asset ownership. Scope state/history, exports, cancellation, review, retests, audit access and clear-data operations to the authenticated owner. Occurrences must link compatible same-owner findings and scans. Never trust a client-supplied user ID. Shared tool controls/lab configuration must be unavailable to ordinary users. Migrate existing local records only through explicit owner assignment; no automatic claim by the first public signup.

Acceptance: two users cannot enumerate, read, export, review, cancel, retest or erase one another's records; rejected IDs have no side effects; expired/tampered/wrong-audience tokens fail; refresh replay and logout revocation work; persistence survives restart; frontend login/signup/logout work end-to-end.

Estimate: 28–40 focused engineering hours, including migrations/ownership 8–12, token/password/routes 8–10, frontend 4–6, tests/review 8–12. This is an estimate, not time already spent. Public operational hardening, recovery email and MFA are excluded. At 8 hours/week, authentication alone is roughly 3.5–5 weeks.

## Step 3B: proposed deployment — not implemented

Frontend: build React/Vite on Vercel from the private repo with npm ci / npm run build and dist output. Prefer a same-origin /api rewrite to the HTTPS backend so the existing relative API/download URLs can remain. Disable caching of authenticated API responses and verify cookies/CSRF through the proxy. An alternative separate API origin requires an explicit API-base setting for fetches and report links, credential handling, preflight support and a precise allowed-origin list; do not use wildcard credentialed CORS.

Backend: containerized persistent Linux process with Python, Nmap, Java/ZAP and their pinned dependencies. This is a proposal only; no container was created. Replace loopback-only binding with deployment configuration for 0.0.0.0 and provider PORT, and replace current loopback Host/Origin checks with explicit public host/origin and trusted-proxy configuration. Use a production application server, readiness/liveness endpoints, HTTPS at the platform edge, managed secrets and graceful worker shutdown. Public exposure must follow working auth/ownership. Keep scans asynchronous, bounded and cancellable; do not run a minutes-long scan inside an HTTP request.

Persistence/worker changes: use durable PostgreSQL plus migrations when local disk is ephemeral; store or regenerate reports durably. Replace this host-local file lock with a database-backed job lease/heartbeat and atomic claiming for hosted workers. Do not use startup recovery that indiscriminately fails jobs owned by another live worker. Start with one scanner worker and enforce memory/concurrency limits. Prove restart/redeploy behavior and export/backup restoration. Budget/free-host feasibility must be measured with an actual ZAP run, not inferred from a successful frontend build.

Render's official free-service documentation says services sleep after 15 minutes of no inbound traffic, free services cannot attach persistent disks, and free PostgreSQL expires after 30 days. Current SQLite storage cannot simply be moved there safely. Railway's official trial is $5/up to 30 days, followed by $1 free credit per month; its trial is limited to 1 GB RAM and limited trials have network restrictions. Neither establishes a dependable always-on scanner service at zero cost. Scan permissions, outbound connectivity and actual resource needs remain unverified on either provider. No claim is made that cloud OS fingerprinting will be supported.

Recommended budget approach: keep the complete scanner demonstration on the Mac or an approved college machine. A Vercel frontend can be a separate deployment milestone after the backend architecture is approved; it must display backend unavailability honestly. For a full remote demonstration, seek college-hosted compute or explicitly budgeted credits, then benchmark. Do not expose the current unauthenticated local API through a public tunnel.

Estimate after authentication: 20–32 focused hours for a limited hosted demonstration (configuration/container/API serving 6–10, persistence/worker changes 8–12, deployment/acceptance/docs 6–10). This excludes procuring suitable compute, extensive production hardening and Docker/Juice Shop work. Combined auth plus deployment: 48–72 hours, so both are unlikely to fit a four-week month with only 6–8 available hours/week.

Primary sources checked 27 October 2026:

- https://render.com/docs/free
- https://docs.railway.com/pricing/free-trial
- https://vercel.com/docs/routing/rewrites
- https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- https://www.rfc-editor.org/rfc/rfc8725.html
- https://www.rfc-editor.org/rfc/rfc7208.html
- https://www.rfc-editor.org/rfc/rfc6376.html
- https://www.rfc-editor.org/rfc/rfc8301.html
- https://www.rfc-editor.org/rfc/rfc8463.html

## Updated completion using the original five-checkpoint rubric

Each completed checkpoint earns 20%; partial checkpoints receive no full credit. These are scope-coverage scores, not time estimates. Criteria are unchanged from the original audit's build_audit.py scoring table.

| Module | Before | Now | Credited checkpoints | Remaining checkpoints |
|---|---:|---:|---|---|
| Website scanner | 3/5, 60% | 3/5, 60% | Headers; TLS; bounded ZAP pipeline with historical verification | General authorized-site active flow; separately verified library coverage |
| Email DNS | 3/5, 60% | 3/5, 60% | SPF basics; selector DKIM basics; DMARC basics | Comprehensive record validation; broader authentication/standards coverage |
| Docker/Juice Shop | 0/5, 0% | 0/5, 0% | None for requested implementation | Juice Shop; Docker; isolation; lifecycle; reproducible verification |
| Network scanner | 3/5, 60% | 4/5, 80% | Bounded scope; service/version inventory; persistence; reliable incomplete-coverage handling | OS fingerprinting |
| Dashboard/reports | 4/5, 80% | 4/5, 80% | Real dashboard; severity/history; lifecycle; PDF/JSON | Consolidated submission-quality reporting and broader verification |
| NVD | 3/5, 60% | 3/5, 60% | Live lookup; cache/throttling; scanner enrichment | Complete traversal; applicability-validation workflow |
| AI explanations | 0/5, 0% | 0/5, 0% | None | Provider; endpoint; UI; grounded explanations; validation |
| JWT authentication | 0/5, 0% | 0/5, 0% | None | Signup; login/password handling; tokens; authorization; tests |

Expanded scope: 17/40 = 42.5%, previously 40%. Excluding optional AI: 17/35 = 48.6%, previously 45.7%. Original five core modules: 17/25 = 68%, previously 64%. Email does not gain a full comprehensive-validation checkpoint for these bounded repairs. Offline email forensics remains an unscored extension; a planning document earns no implementation credit.

## Risks, repository status and month plan

Known limits: legacy processes are still running old code; flock is macOS/Linux and local-filesystem ownership, not a distributed lock; force-killing a backend can leave external scanner subprocesses without a supervisor; the verifier changes shared lab mode and retains real history; SPF and DKIM validation remain bounded; ZAP/TLS/browser behavior has no fresh acceptance in this follow-up. No new test failure remains. No cloud deployment was attempted.

The configured private GitHub repository is https://github.com/Chandan280/vulnx and last previously verified pushed commit is 2968b9b. This session's authenticated-account and repository-visibility requests timed out during TLS handshakes. Current changes are not claimed pushed; reverify identity/privacy before publishing this milestone. Runtime data, logs and generated evidence must remain excluded from commits.

Week 1: manually restart the repaired backend, confirm the real browser workflow, get professor's hard requirements, and capture a clean full lab acceptance run including cancellation, exports and reset on disposable data. Budget 6–8 hours.

Week 2: work only on the highest-priority confirmed missing rubric requirement. If JWT is mandatory, begin ownership/migrations/auth tests; if Juice Shop is mandatory, scope and verify isolated local lab lifecycle. Do not silently commit to both plus hosting. Budget 6–8 hours; larger mandatory scope requires more time or professor-agreed reductions.

Week 3: finish that chosen requirement and verify its complete demonstration. If no major module is required, prioritize NVD traversal/applicability wording and consolidated evidence/report presentation. Keep the existing local core runnable throughout. Budget 6–8 hours.

Week 4: freeze features, rerun the acceptance checklist, capture screenshots and demo video, prepare architecture/limitations/testing documentation and viva notes, and reserve recovery buffer. Budget 6–8 hours. Defer optional AI and always-on cloud deployment unless explicitly required. Four weeks at this pace provide only 24–32 hours; the estimates above exceed that if auth and hosting are both required.
