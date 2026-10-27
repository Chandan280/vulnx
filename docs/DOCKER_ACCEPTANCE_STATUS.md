# Docker Desktop follow-up — 27 October 2026

Docker Desktop is installed. Docker CLI resolves to `/Users/channaaa/.docker/bin/docker`; Compose reports v5.6.1. However, `docker info` from this assistant environment fails with permission denied connecting to `unix:///Users/channaaa/.docker/run/docker.sock`. No container build/start or Docker-backed scan has been executed in this follow-up. Installing Docker did not grant the assistant permission to signal unrelated existing processes or access the daemon socket.

## Required local cleanup

Retried `scripts/stop_local.py`: permission denied for backends on 8787, 8788, 8789 and 8790. The native fixture was independently verified as a Python process in this project's working directory, listening on 18080 and 18443. It would conflict with the Compose lab. Added explicit `--include-lab` support; default behaviour still targets only backend ports. Each target must match both Python process name and this project's cwd. No broad pkill, forced termination or database modification occurs.

Run in the Mac's ordinary Terminal (not the assistant sandbox):

```sh
cd /Users/channaaa/Documents/Codex/2026-10-22/new-chat/vulnx
sudo .venv/bin/python scripts/stop_local.py --include-lab
lsof -nP -iTCP:8787 -iTCP:8788 -iTCP:8789 -iTCP:8790 -iTCP:18080 -iTCP:18443 -sTCP:LISTEN
```

Enter the Mac password only in Terminal. Confirm these listeners are gone before original-workspace startup/migration. If a listener remains, inspect it; do not blindly force-kill an unrelated process.

Check daemon access separately in that Terminal:

```sh
docker info
```

If Docker works there, the daemon is healthy but still inaccessible to this assistant environment. Do not chmod the Docker socket or expose the Docker API over unauthenticated TCP to work around the boundary. Running the following in that Terminal is an alternative to granting the assistant normal daemon access:

```sh
docker compose -f compose.lab.yml -p vulnx-lab up -d --build --wait
```

This builds/starts the lab, but does not by itself prove app lifecycle controls, reset, isolation or all scans work.

## Acceptance matrix

| Claim | Observed result |
|---|---|
| Docker CLI/Compose installed | PASS |
| Assistant can reach Docker engine | BLOCKED: daemon socket permission denied |
| Legacy backend cleanup | FAIL: termination permission denied |
| Native fixture ports available | FAIL: native fixture still listening |
| Image builds and container runs | NOT RUN: engine access and port conflict |
| App start/stop/reset controls | NOT RUN against actual Docker |
| Corrected/vulnerable toggle inside container | NOT RUN |
| Actual resource limits and network isolation | NOT RUN |
| Full scan against container | NOT RUN; earlier native-lab pass does not count |
| Original-workspace upgrade | NOT RUN: explicitly gated on cleanup |
| Stable original-workspace demo | NOT ESTABLISHED |
| Real, non-headless browser acceptance | NOT RUN: requested sequence is blocked before this step |

Docker Attack Lab remains **20%** under the previously disclosed five-checkpoint method. Only the working custom fixture is credited; actual Docker execution/isolation/lifecycle/reproducible verification remain uncredited. This is not OWASP Juice Shop.

## Intended single demo environment after cleanup

Once old listeners are confirmed gone and the Docker lab is running:

```sh
cd /Users/channaaa/Documents/Codex/2026-10-22/new-chat/vulnx
.venv/bin/python scripts/start_local.py --port 8788
```

URL: http://127.0.0.1:8788/ . Do **not** add `--lab`: that starts the native fixture and would compete with Docker. Do not set VULNX_DATA_DIR for this normal startup; the default is the original `.runtime` workspace. Its first authenticated startup creates the tested pre-migration backup and migration admin. Account ownership/count checks must still be performed before calling it the verified stable demo.

The existing 8790 preview is not a substitute for this original-workspace acceptance. No data was migrated or deleted during this blocked follow-up.
