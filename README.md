# VulnX

A local, evidence-based security assessment and remediation workspace with bcrypt/JWT accounts, built and tested on Apple Silicon. Runtime findings come from actual scanners; the application never seeds fake results.

Latest status: **authentication is implemented and locally verified; cloud deployment lacks provider access. Docker Desktop is now installed, but this assistant environment cannot access its daemon socket or terminate the legacy processes.** See [Docker acceptance status](docs/DOCKER_ACCEPTANCE_STATUS.md) and [implementation report](docs/IMPLEMENTATION_2026-10-27.md). Older audit documents describe historical states.

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

Create an account in the sign-in screen. Passwords require at least 12 characters and at most 72 UTF-8 bytes. Accounts see only their own assets, scans, findings and reports. Logout revokes the server session immediately; JWT sessions expire after eight hours. Password recovery, email verification and MFA are not implemented.

On first upgrade, the original SQLite file is backed up before migration. Existing assets belong to a generated migration admin (`admin@vulnx.local`); its random password is in `.runtime/bootstrap-admin.json` (mode 0600). Never commit or share that file. With `VULNX_DATA_DIR`, look there instead. No shared default password exists. The admin does not bypass other users' data ownership; its extra permission is managing the shared lab.

If old servers remain on 8787/8788, startup refuses to migrate the original workspace. Run `.venv/bin/python scripts/stop_local.py` from a normal Mac Terminal, then start again. The script checks project cwd and Python listeners before sending SIGTERM; it never uses broad pkill or deletes data.

## Daily use and data reset

After installation and building, start the app and lab together with `.venv/bin/python scripts/start_local.py --lab`. Keep the terminal open; Ctrl+C stops the processes. Settings includes an operating guide.

Settings → Clear workspace data removes only the signed-in account's targets, scans, findings, reviews and audit rows. Type `DELETE ALL DATA` to enable it. That account's active/queued scans block reset. Accounts, other users' data, shared intelligence cache, tools, lab configuration, backups and separately exported files remain. Export reports first.

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

### Docker lab (custom fixture, not OWASP Juice Shop)

With a Docker-compatible runtime and Compose v2 installed, an admin can use Settings → Attack Lab → Start / Stop / Reset. The same configuration can run with `docker compose -f compose.lab.yml -p vulnx-lab up -d --build --wait`. Stop any native fixture first to release its ports. Reset removes only the lab's named volume and container; application accounts/history are separate. The image uses a non-root user, read-only root filesystem, dropped capabilities, resource limits, internal network and loopback-only published ports. These settings were reviewed and controller tests passed, but actual container build/network isolation could not be exercised on the current Mac because Docker is absent. The real native fixture passed all scanner integrations.

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

The app now has bcrypt password hashing, JWT authentication, persistent revocable sessions and per-account ownership. It remains a single-process capstone with one scanner worker. PostgreSQL, distributed workers, email verification, password recovery and MFA are not implemented. Hosted configuration/manifests are prepared, but no live Vercel/Railway deployment has been verified. See [deployment instructions and blockers](docs/DEPLOYMENT.md); do not infer production readiness from passing local tests.

Active ZAP scanning is restricted to `127.0.0.1:18080`; external approved websites support HTTP header and TLS profiles. ZAP is time bounded and does not prove every route/rule was exercised. Authenticated and arbitrary external active scans are not enabled.

Nmap is unprivileged: OS fingerprinting, UDP and raw-packet scans are not implemented. DNS checks do not include full recursive SPF evaluation, DKIM signature verification or complete DMARC organizational-domain fallback. Unknown DKIM selectors are not assessed. DNS errors never become missing-record findings.

Fix verification applies only to equivalent successful email and HTTP-configuration checks. Absence in failed, partial, redirected or active ZAP scans does not establish a fix. NVD candidates require validation of installed builds, backports and configuration. AI is deferred; guidance works without an AI service.

## Verification

```sh
.venv/bin/python -m unittest discover -s tests -v
npm run test:email
node --test tests/api_proxy.test.mjs
npm run build
```

With app and lab running:

```sh
.venv/bin/python scripts/verify_local.py
```

For a different app port, use `.venv/bin/python scripts/verify_local.py --port 8788`, or set `VULNX_PORT=8788` for both startup and verification. The verifier does not discover an unrelated running process automatically.

The backend takes an OS-held lock before startup recovery; a second backend using the same database exits even on a different port. Do not delete the lock file while a server is running. HTTP logging goes to rotating `.runtime/server.log`, so closing a launcher output pipe cannot prevent responses. `VULNX_DATA_DIR` overrides database/cache/log storage for isolated tests; installed tools and the shared local lab still use their documented project paths. Old processes started before this lock was implemented must be stopped before upgrading.

Nmap tool completion does not establish target coverage: empty, timed-out, down, missing-port and filtered-only observations are partial. Valid closed-port observations can establish coverage without vulnerabilities. Email DNS checks validate bounded SPF mechanism syntax and DKIM key encoding/structure; unsupported SPF macros or DKIM algorithms are explicitly incomplete. These checks are not full SPF evaluation or message authentication.

See `docs/RELIABILITY_REVIEW_2026-10-27.md` for the latest verification and deferred authentication/deployment plan.

This exercises actual loopback DNS, HTTP, Nmap, TLS and ZAP through the app API, corrects the lab, verifies configuration fixes, retrieves an actual NVD record and downloads reports. It retains real assessment history locally and does not scan external assets. Unit-test fixtures never populate runtime data.

The verifier authenticates using the admin credential file in the selected data directory. For disposable acceptance, run `.venv/bin/python scripts/verify_auth_live.py --full` with the native lab running. It starts an isolated backend, verifies all scanner profiles and signup/ownership/logout/restart/export behaviour, and stores evidence under ignored `.runtime/acceptance/`. It temporarily changes native lab mode and restores it on exit. Run without `--full` for the focused authenticated DNS workflow.

See PROGRESS.md for observed results. requirements.lock.txt records the complete development environment; requirements.txt contains the smaller runtime set.

## Storage and GitHub

Public source repository for external review (requested 27 October 2026): https://github.com/Chandan280/vulnx

Source and tests are pushed after verified milestones. `.runtime/` (targets, evidence, database, reports, tools, generated lab keys), `.venv`, credentials and `.env` are excluded. GitHub stores source; it does not host the running app.

## Offline email forensics

Open **Email Analyzer** in the sidebar. Choose or drop one `.eml` / `.txt` file (up to 5 MB), or paste a full raw email; click **Analyze Email**. Inspect unfolded headers, encoded subjects, reported authentication claims, Received headers, decoded text/HTML source, HTTP(S) URLs, attachment metadata and SHA-256 hashes. **Clear** removes input and results. Leaving the page also discards them.

Email contents are processed in browser memory, never sent to the API, stored in browser storage or added to assessment history. HTML is shown as inert text; URLs and attachments are never opened. This is an offline inspection tool, not independent SPF/DKIM/DMARC verification, an antivirus engine or a link-reputation service. Authentication-Results headers may be forged. Parsing supports common nested MIME, base64 and quoted-printable; malformed data and limits are surfaced. UTF-8 file reading may not preserve original unencoded binary parts; their hashes carry a warning. Live DNS configuration analysis remains in Scans → Email configuration.

Run `npm run test:email` (Node 22.6+ with TypeScript stripping support; tested on Node 24) for the parser tests. `tests/fixtures/forensics-demo.eml` is explicitly synthetic test input, not seeded runtime data.

Results use compact Overview, Headers, Links, Attachments, Reputation and Raw Email tabs in a white-and-purple interface. Edit email preserves the input; Clear discards it. Keyboard Left/Right and Home/End navigate the tabs. To use another local port: `.venv/bin/python scripts/start_local.py --port 8788`.
