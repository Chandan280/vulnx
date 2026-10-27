# Deployment preparation and actual status

No live cloud deployment exists from this work. Vercel CLI reports logged out. No Vercel/Railway/Render environment tokens, normal local CLI credentials or repository deployment secrets were found. Railway CLI installation also failed downloading its binary through the proxy. Do not describe the manifests as a deployed application.

## Choice and cost boundary

Chosen architecture: Vercel frontend plus same-origin API bridge, Railway single backend process plus SQLite on a dedicated volume mounted at `/data`. This retains the tested SQL implementation and avoids a rushed PostgreSQL rewrite. The host-local database lock remains valid only for one replica with one mounted local volume; do not scale horizontally. A separate durable Postgres/worker-lease migration would be required for multiple workers.

Railway is selected for volume support, not as a promise of unlimited free compute. Its documented trial is $5/up to 30 days, then $1 monthly free credit. Nmap/Java/ZAP memory and sustained compute must fit the actual account's credit/resource limits. No paid plan, card, overage or billing change was enabled. If an actual deployment cannot remain at zero charge, stop before provision rather than silently spending. Render free has no persistent disk, and free Render PostgreSQL expires after 30 days, so it was not selected for retained SQLite history.

## Backend setup once account access exists

1. Deploy this private repository using the root Dockerfile; one replica. It installs actual Nmap, DNS tools, Java, Python dependencies and checksum-verified ZAP 2.17.0. No frontend or fake findings are embedded in the backend image.
2. Attach a persistent Railway volume at `/data`. `VULNX_REQUIRE_PERSISTENT_STORAGE=1` fails startup if Railway's actual volume-mount variable is missing or mismatched. Startup repairs the dedicated data directory's ownership and drops to UID 10001 before serving. Container construction is unverified locally because Docker is absent.
3. Set `VULNX_JWT_SECRET` to a cryptographically random secret of at least 32 characters. Keep it stable across restarts and out of Git. Set `VULNX_PUBLIC_ORIGIN` to the exact frontend HTTPS origin and `VULNX_ALLOWED_HOSTS` to the actual backend hostname. Backend binding is `0.0.0.0`; Railway `PORT` is respected.
4. Set `VULNX_ALLOWED_TARGETS` to exact comma-separated canonical assets approved for this deployment. URL assets include scheme, explicit port and trailing slash as normalized by the app. Public signup is enabled, but an account cannot add or scan arbitrary targets outside this list. Do not add private provider infrastructure or metadata endpoints.
5. Verify `/api/health`, create an account, run an allowed scan, export, then redeploy/restart and verify persistence. Back up the volume separately. The bootstrap admin credential file is generated inside the volume; retrieve it only through authorized provider tooling, without publishing it in logs.

The server is still Python's threaded standard-library HTTP server, behind the provider's HTTPS edge. This is a constrained capstone architecture, not an audited public production service. Authentication rate limits are per direct peer; through the proxy, users may share a limit. Long-running scans remain background jobs. Lab container management is disabled for hosted origins, so no Docker socket is mounted into a public web service. The Railway image does not start the vulnerable fixture; active ZAP's current localhost-only target remains a local demonstration feature, not a claimed hosted capability.

## Frontend setup

Deploy the same private repository to Vercel with Vite, `npm run build`, and output `dist`; set Node 22 or newer. Set `VULNX_API_ORIGIN` to the actual backend HTTPS origin. `api/[...path].js` forwards the same-origin `/api` requests to that configured backend, forwarding cookies and CSRF/origin headers and preserving PDF downloads and multiple Set-Cookie headers. It rejects non-HTTPS configuration and does not follow redirects. API responses are not cached. It contains no scan execution logic. Missing backend configuration returns an honest 503.

Because browser requests remain same-origin, Secure HttpOnly SameSite=Strict JWT cookies work without relying on third-party cookies. The backend also supports only explicitly allowed CORS origins and credentials; no wildcard is used. Public HTTPS binding fails closed unless all required host/origin/secret/target settings are provided. The new proxy has three passing local tests; actual provider proxy/cookie behaviour remains unverified until deployed.

## Required live acceptance before claiming completion

- Account signup/login/logout; expired and copied-revoked JWT rejection.
- Two-user read/write/export/cancel/reset isolation.
- Real permitted scan → stored finding → downloaded purple PDF.
- Persistence of account/session/scan history across service restart and redeployment.
- Cold-start, memory limit, tool availability, provider scanning permission, credit/billing limit checks.
- Verify the real GitHub remote commit after pushing; do not infer deployment from a push.

Primary sources checked 27 October 2026: https://docs.railway.com/volumes/reference ; https://docs.railway.com/pricing/free-trial ; https://render.com/docs/free ; https://vercel.com/docs/cli/deploy .
