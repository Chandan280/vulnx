"""Fixed-command administrator controls for the custom Docker training fixture."""
import json
from pathlib import Path
import shutil
import subprocess

ROOT=Path(__file__).resolve().parent.parent
CONTAINER='vulnx-training-lab'


def run(args,timeout=15):
    proc=subprocess.run(['docker',*args],cwd=ROOT,capture_output=True,text=True,timeout=timeout)
    if proc.returncode:
        raise RuntimeError('Docker operation failed: '+(proc.stderr or proc.stdout)[-1200:])
    return proc.stdout


def status():
    if not shutil.which('docker'):
        return {'available':False,'running':False,'kind':'custom_fixture','detail':'Docker is not installed. Install a Docker-compatible runtime to use container controls.'}
    try:
        run(['info','--format','{{.ServerVersion}}'])
        names=run(['ps','-a','--filter','name=^/'+CONTAINER+'$','--format','{{.Names}}']).splitlines()
        if CONTAINER not in names:return {'available':True,'running':False,'kind':'custom_fixture','detail':'Container has not been created.'}
        state=json.loads(run(['inspect','--format','{{json .State}}',CONTAINER]))
        return {'available':True,'running':bool(state['Running']),'health':state.get('Health',{}).get('Status','unknown'),'kind':'custom_fixture','detail':'Custom VulnX HTTP/TLS/DNS fixture; not OWASP Juice Shop.'}
    except (OSError,RuntimeError,subprocess.TimeoutExpired,ValueError) as exc:
        return {'available':False,'running':False,'kind':'custom_fixture','detail':str(exc)}


def lifecycle(action):
    if action not in ('start','stop','reset'):raise ValueError('Choose start, stop or reset.')
    current=status()
    if not current['available']:raise RuntimeError(current['detail'])
    compose=['compose','-f',str(ROOT/'compose.lab.yml'),'-p','vulnx-lab']
    if action in ('stop','reset'):
        run(compose+['down']+(['--volumes'] if action=='reset' else []),60)
    if action in ('start','reset'):
        run(compose+['up','-d','--build','--wait','--wait-timeout','60'],240)
    return status()


def set_mode(fixed):
    current=status()
    if current['running']:
        script="from pathlib import Path; p=Path('/app/.runtime/lab/fixed'); "+('p.touch()' if fixed else 'p.unlink(missing_ok=True)')
        run(['exec',CONTAINER,'python','-c',script])
        return 'docker'
    # Compatibility with the existing native fixture, which has the same controls.
    marker=ROOT/'.runtime/lab/fixed';marker.parent.mkdir(parents=True,exist_ok=True)
    if fixed:marker.touch()
    else:marker.unlink(missing_ok=True)
    return 'native'
