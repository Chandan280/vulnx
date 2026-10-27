"""Real local acceptance, with an isolated database. Requires the native/Docker lab.

Run --full to additionally exercise DNS, HTTP, Nmap, TLS, active ZAP and NVD.
Keeps isolated evidence under .runtime/acceptance; never clears the user database.
"""
import argparse
import http.cookiejar
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from uuid import uuid4

ROOT=Path(__file__).resolve().parent.parent


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--full',action='store_true');args=parser.parse_args()
    data=ROOT/'.runtime/acceptance'/str(uuid4());data.mkdir(parents=True,mode=0o700)
    with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
    env=dict(os.environ,VULNX_DATA_DIR=str(data),VULNX_PORT=str(port),VULNX_BIND='127.0.0.1')
    for name in ('VULNX_PUBLIC_ORIGIN','VULNX_REQUIRE_PERSISTENT_STORAGE'):env.pop(name,None)
    base=f'http://127.0.0.1:{port}/api/'
    def launch():
        proc=subprocess.Popen([sys.executable,'backend/server.py'],cwd=ROOT,env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        for _ in range(100):
            try:
                with urllib.request.urlopen(base+'health',timeout=.5):return proc
            except OSError:time.sleep(.1)
        proc.terminate();proc.wait();raise RuntimeError('Backend startup failed; inspect isolated server.log.')
    def client():return {'op':urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())),'csrf':''}
    def call(c,path,body=None):
        req=urllib.request.Request(base+path,data=None if body is None else json.dumps(body).encode(),headers={'Content-Type':'application/json','X-VulnX-CSRF':c['csrf']})
        with c['op'].open(req,timeout=30) as res:
            value=json.load(res)
            if 'csrf' in value:c['csrf']=value['csrf']
            return value
    marker=ROOT/'.runtime/lab/fixed';was_fixed=marker.exists()
    proc=launch()
    try:
        if args.full:
            subprocess.run([sys.executable,'scripts/verify_local.py','--port',str(port)],cwd=ROOT,env=env,check=True,timeout=900)
        c=client();call(c,'session')
        call(c,'auth/signup',{'email':'acceptance@example.test','password':secrets.token_urlsafe(24)})
        call(c,'assets',{'domain':'mail.vulnx.test','kind':'domain','authorized':True})
        asset=call(c,'state')['assets'][0]
        scan_id=call(c,'scans',{'asset_id':asset['id'],'profile':'email','selector':'test'})['id']
        deadline=time.monotonic()+120
        while time.monotonic()<deadline:
            scan=next(s for s in call(c,'state')['scans'] if s['id']==scan_id)
            if scan['status'] not in ('queued','running'):break
            time.sleep(.2)
        assert scan['status']=='completed',scan['status']
        assert scan['result']['findings'],'Expected the real lab revoked-selector finding.'
        for fmt in ('pdf','json'):
            with c['op'].open(base+'reports/'+scan_id+'.'+fmt) as res:raw=res.read()
            assert raw.startswith(b'%PDF-') if fmt=='pdf' else json.loads(raw)['id']==scan_id
            (data/('authenticated-report.'+fmt)).write_bytes(raw)
        other=client();call(other,'session');call(other,'auth/signup',{'email':'other@example.test','password':secrets.token_urlsafe(24)})
        assert not call(other,'state')['scans']
        try:call(other,'reports/'+scan_id+'.json');raise AssertionError('Cross-user export succeeded')
        except urllib.error.HTTPError as exc:assert exc.code==404
        proc.terminate();proc.wait(timeout=20);proc=launch()
        assert len(call(c,'state')['scans'])==1,'Session/data did not survive restart'
        call(c,'auth/logout',{})
        try:call(c,'state');raise AssertionError('Logged-out access succeeded')
        except urllib.error.HTTPError as exc:assert exc.code==401
        print('PASS: real signup -> DNS scan -> finding -> PDF/JSON; cross-user rejection; persistence/session after restart; logout.',flush=True)
        print('Isolated evidence: '+str(data),flush=True)
    finally:
        proc.terminate();proc.wait(timeout=20)
        if was_fixed:marker.touch()
        else:marker.unlink(missing_ok=True)


if __name__=='__main__':main()
