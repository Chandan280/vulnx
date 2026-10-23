"""Start the app and optional loopback lab; Ctrl+C stops both owned processes."""
import argparse
from pathlib import Path
import signal
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parent.parent


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lab',action='store_true',help='Also start the local training lab')
    args=parser.parse_args()
    if not (ROOT/'dist/index.html').exists():
        parser.exit(1,'Frontend missing. Run npm run build first.\n')
    jobs=[]
    try:
        for script in (['lab/server.py'] if args.lab else [])+['backend/server.py']:
            jobs.append(subprocess.Popen([sys.executable,str(ROOT/script)],cwd=ROOT,start_new_session=True))
        print('Open http://127.0.0.1:8787/ - keep this terminal open; Ctrl+C stops VulnX.',flush=True)
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
