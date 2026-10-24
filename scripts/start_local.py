"""Start the app and optional loopback lab; Ctrl+C stops both owned processes."""
import argparse
import os
import socket
from pathlib import Path
import signal
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parent.parent


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lab',action='store_true',help='Also start the local training lab')
    parser.add_argument('--port',type=int,default=os.environ.get('VULNX_PORT','8787'),help='Local app port (default: VULNX_PORT or 8787)')
    args=parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.exit(1,'Choose a port between 1024 and 65535.\n')
    try:
        with socket.socket() as probe:
            probe.bind(('127.0.0.1',args.port))
    except OSError:
        parser.exit(1,f'Port {args.port} is unavailable. Use the existing app or select --port 8788.\n')
    env=dict(os.environ,VULNX_PORT=str(args.port))
    if not (ROOT/'dist/index.html').exists():
        parser.exit(1,'Frontend missing. Run npm run build first.\n')
    jobs=[]
    try:
        for script in (['lab/server.py'] if args.lab else [])+['backend/server.py']:
            jobs.append(subprocess.Popen([sys.executable,str(ROOT/script)],cwd=ROOT,start_new_session=True,env=env))
        print(f'Open http://127.0.0.1:{args.port}/ - keep this terminal open; Ctrl+C stops VulnX.',flush=True)
        while all(job.poll() is None for job in jobs):time.sleep(.5)
        return next((job.returncode for job in jobs if job.returncode),0)
    except KeyboardInterrupt:
        return 0
    finally:
        for job in jobs:
            if job.poll() is None:job.send_signal(signal.SIGINT)
        for job in jobs:
            try:job.wait(timeout=10)
            except subprocess.TimeoutExpired:job.kill();job.wait()


if __name__=='__main__':raise SystemExit(main())
