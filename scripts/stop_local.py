"""Stop only Python backends whose listening port AND cwd match this project.

Run from a normal Mac terminal if the assistant's sandbox cannot signal them.
No SIGKILL, no broad pkill, no database changes.
"""
from pathlib import Path
import argparse
import os
import signal
import subprocess

ROOT=Path(__file__).resolve().parent.parent


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--include-lab',action='store_true',help='Also stop the native Python fixture on 18080/18443, after the same project-directory check.')
    args=parser.parse_args()
    ports=(8787,8788,8789,8790)+( (18080,18443) if args.include_lab else () )
    pids=set()
    for port in ports:
        proc=subprocess.run(['lsof','-nP',f'-iTCP:{port}','-sTCP:LISTEN','-Fpc'],capture_output=True,text=True)
        current=None
        for line in proc.stdout.splitlines():
            if line.startswith('p'):current=int(line[1:])
            elif line.startswith('c') and current and 'python' in line.lower():pids.add(current)
    failed=False
    for pid in sorted(pids):
        proc=subprocess.run(['lsof','-a','-p',str(pid),'-d','cwd','-Fn'],capture_output=True,text=True)
        if 'n'+str(ROOT) not in proc.stdout.splitlines():
            print(f'Skipped PID {pid}: different or unavailable working directory.');continue
        try:
            os.kill(pid,signal.SIGTERM);print(f'Sent graceful termination to project Python service PID {pid}.')
        except PermissionError:
            print(f'Permission denied for PID {pid}. Run this script from your Mac Terminal.');failed=True
        except ProcessLookupError:pass
    return 1 if failed else 0


if __name__=='__main__':raise SystemExit(main())
