# Remaining work — 27 October 2026

Repository: https://github.com/Chandan280/vulnx — PUBLIC, explicitly requested and verified on 27 October. Earlier reports describing private visibility are historical. Public source visibility does not deploy the application or expose its local database.

## Current delivery status and estimates

Estimates are focused engineering hours after required machine/account access exists. They exclude waiting for access, provider approval, credentials or a suitable zero-cost host. Some validation work overlaps; do not simply add every row.

| Work | Current status | Specific remaining work | Estimate |
|---|---|---|---|
| bcrypt/JWT authentication | Implemented and verified through actual local API | Browser acceptance of signup/login/logout, expired-session UX and mobile form layout; no new backend auth implementation needed for requested scope | 2–4 h |
| Per-user ownership | Implemented; HTTP regression tests passed | Include two-account UI demonstration and final regression run in submission evidence | Included in auth acceptance |
| Existing-data migration | Backup/migration implemented and tested; original workspace upgrade pending | Stop legacy servers, launch original workspace, verify backup/admin ownership and counts; original database was last observed empty | 0.5–1.5 h |
| Custom native attack fixture | Working; full real scanner integration passed | Record a clean demonstration | 0.5–1 h |
| Docker lab | Configuration/controller/UI implemented; actual execution unverified | Start a permitted Docker runtime, build image, verify start/stop/reset and corrected mode through app, check isolation and resource limits, resolve native-port conflicts | 4–8 h |
| Literal OWASP Juice Shop | Not implemented; deliberately chose user-authorized custom fixture | Only if rubric requires it: integrate Juice Shop targets, lifecycle and representative scan workflow; do not promise a drop-in corrected Juice Shop equivalent | 12–24 h additional |
| Vercel frontend | Build/config/API bridge prepared, proxy unit tests passed; not deployed | Connect account, configure backend origin, deploy and verify cookies, CSRF, PDFs and failure states | 2–4 h after backend exists |
| Railway backend/storage | Dockerfile, environment/host/target configuration, volume checks prepared; not provisioned | Verify zero-cost eligibility/resources, connect account, build image, mount volume, configure domains/secrets/targets, test tool execution and restart/redeploy persistence | 6–12 h |
| Hosted active ZAP lab | Not implemented | Current image has ZAP but no vulnerable fixture; active profile only permits local lab. A hosted isolated lab and its scope/worker arrangement need separate design and acceptance | 12–24 h additional; may exceed zero-cost hosting |
| Old orphaned backends | Prevention/cleanup script implemented; processes remain | Run scoped cleanup in a permitted Mac Terminal, verify ports released and one-instance restart works | 0.5–1 h |
| Purple PDF | Done; fresh PDF rendered and visually inspected | Final example report for submission | 0.5 h, within demo preparation |
| Local final verification | Passed backend/parser/proxy suites and full native scanner/API flow | Browser acceptance and final demonstration recording | 2–4 h, overlaps rows above |
| Public deployed end-to-end verification | Not performed because no deployment exists | Signup → approved real scan → finding → PDF, two-user rejection, logout and persistence after redeploy | 2–4 h, include in deployment allowance |
| GitHub | Source and reports committed; initial failed pushes repaired; repository now public | Continue verified pushes after changes | Routine |

For a limited remote capstone demonstration, allow roughly **10–20 hours** for deployment and live acceptance after access/free-host feasibility is resolved. That estimate excludes a hosted vulnerable lab, production hardening and migration to distributed workers. There is no honest promise that the complete scanner stack will run indefinitely at zero cost on the selected host.

## Earlier scope not addressed by this round

These were not silently declared complete; this round prioritized the user's auth/lab/deployment request.

| Gap | Estimate if required | Deadline recommendation |
|---|---|---|
| Nmap OS fingerprinting | 6–12 h with suitable privileges and accuracy/unknown-state tests | Only if explicitly scored |
| NVD complete pagination and applicability-review workflow | 6–10 h | Useful after delivery blockers |
| Separately verified outdated-library coverage | 4–8 h | Good bounded improvement if web scanner is heavily scored |
| General authorized-site active ZAP workflow with stronger target/isolation controls | 16–32 h | Defer unless mandatory |
| Comprehensive email standards coverage: recursive SPF, macro/lookup limits, broader DKIM/DMARC validation | 20–40+ h depending on agreed conformance; message-signature verification is additional scope | Clearly document present bounded coverage |
| Optional AI explanation layer with grounding and failure tests | 8–16 h; free-provider availability remains a separate constraint | Defer |
| Password recovery/email verification/MFA | Not part of the minimum requested JWT implementation; scope separately | Defer for local submission unless required |

## Why delivery stopped short

- Vercel CLI explicitly reported logged out. No provider tokens, normal CLI credentials or GitHub deployment secrets were available. Railway CLI binary download also failed through the proxy. A hosting account cannot be selected or authenticated by inventing credentials.
- A checksum-verified official Lima runtime was installed under the ignored project runtime directory. Its attempted dedicated Docker VM failed on macOS boot-session/sysctl permissions. No Docker engine started, so actual container tests could not run.
- The scoped SIGTERM cleanup returned PermissionError for old backends. The default-workspace startup guard now refuses migration/recovery while those listeners remain. No elevated termination bypass was used.
- Headless Chrome aborted in the restricted environment. API acceptance is verified; browser acceptance is not.

## Prioritized deadline plan

1. **Stabilize one local demonstration (0.5–1.5 h).** Clear legacy listeners in a permitted terminal, upgrade the original workspace with backup, verify account ownership and preserve a working run command. Avoid operating several differently configured previews during presentation.
2. **Finish browser acceptance and submission evidence (2–4 h).** Show signup/login, real scan evidence, finding review, export and logout; include a two-user access-denial example. Prepare architecture, limitations and test-count slides/video.
3. **Verify the existing Docker custom lab (4–8 h after runtime access).** Do this before replacing the fixture with Juice Shop. Explicitly label it custom; seek a rubric decision only if the professor requires the named product.
4. **Deploy only if a live URL is required (10–20 h after access/feasibility).** Complete backend persistence first, then Vercel, then live acceptance. A static frontend with an unavailable backend is not a completed deployment. Do not spend credits beyond a verified zero-cost allowance.
5. **Use remaining time on one scored gap.** Choose verified library coverage or NVD completeness before optional AI or broad new scanning capability.
6. **Reserve a final 2–4 h for regression/demo rehearsal.** Freeze features and keep an offline/local fallback. Never rely exclusively on free-host cold starts or the live NVD API during a viva.

With fewer than about ten focused hours left, prioritize the local demonstration, evidence and accurate limitations. Full cloud deployment, Docker verification and literal Juice Shop should not all be promised within that window.

## Same five-checkpoint completion method

Each fulfilled checkpoint earns 20%; scaffolded/unverified checkpoints do not earn full credit. No implementation changed during this visibility/plan update, so scores are unchanged.

| Module | Score | Why it is not higher |
|---|---:|---|
| Website scanner | 60% | General active-site workflow and separately verified library coverage missing |
| Email DNS | 60% | Comprehensive record/standards validation incomplete |
| Custom Docker Attack Lab | 20% | Working fixture credited; container execution, isolation, lifecycle and reproducible Docker verification not demonstrated |
| Network scanner | 80% | OS fingerprinting absent |
| Dashboard/reports | 80% | Final consolidated browser/submission acceptance outstanding |
| NVD | 60% | Complete traversal and applicability workflow incomplete |
| AI | 0% | Not implemented |
| JWT auth | 100% of original feature checkpoints | Signup, password/login, token handling, ownership and API tests implemented; browser/cloud/production acceptance remains separate |

Authorized custom-fixture substitution: **23/40 = 57.5%**. Excluding optional AI: **23/35 = 65.7%**. If literal Juice Shop is required, its score is 0%, giving **22/40 = 55%** under the strict original scope. Original five core modules remain **17/25 = 68%**. Cloud deployment is a separate unmet deliverable; none of these totals means the full requested delivery is complete.

## New risks and regressions to track

- No unresolved failure was observed in the last automated suites: 74 backend, 15 email-parser and 3 API-bridge tests passed; the production build passed. That does not establish absence of defects in unexecuted Docker/cloud/browser paths.
- The new authentication rate limiter keys on the backend's direct peer. Through Vercel, several users can share a limit (20 authentication attempts per 15 minutes), potentially blocking legitimate sign-ins. Before public testing, implement trusted-proxy-aware identification without trusting arbitrary forwarded headers, then regression test it (2–4 h).
- The backend remains the standard-library threaded HTTP server with one worker and a host-local lock. It is not hardened or designed for multiple replicas. Preserve one-replica constraints; production server/distributed job architecture is additional work.
- The hosted image installs ZAP but does not run the vulnerable lab; localhost-only active ZAP cannot simply work there. Hosted Docker controls are deliberately disabled rather than exposing a privileged Docker socket.
- Account-scoped clear intentionally preserves accounts, shared cache, backups and downloaded reports. Do not describe it as erasing every copy of data.
- Migration-admin credentials reside in a restricted local file. Keep it out of screenshots and backups shared with reviewers. Accounts have no self-service password recovery; a forgotten password requires an administrative recovery workflow that has not been built.
- The full acceptance runner's mode-restoration workflow is documented for the native fixture. Verify mode restoration explicitly when introducing the real Docker runtime.
- The original-workspace guard conservatively blocks if either legacy port has a listener, even if that listener is unrelated. This favors avoiding accidental migration while old code runs; document it during startup troubleshooting.

## URLs

- Public source for reviewers: https://github.com/Chandan280/vulnx
- Local authenticated app: http://127.0.0.1:8790/ (HTTP 200 health verified during this update; only available while running on the Mac).
- Public deployed application: **none**. No Vercel or Railway live URL has been produced or verified.
