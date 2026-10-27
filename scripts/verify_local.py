"""Exercise actual HTTP APIs and scanner processes against the running local lab.

Starts no external-target scans. Keeps the resulting real assessment history.
Prerequisites: running VulnX API (VULNX_PORT or --port) and local lab.
"""
import argparse
import sys
import http.cookiejar
import json
from pathlib import Path
import time
import urllib.request
import urllib.error

ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT))
from backend.runtime import configured_port, data_directory
BASE=f'http://127.0.0.1:{configured_port()}/api/'
opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
csrf=''


def call(path,body=None):
    request=urllib.request.Request(BASE+path,data=json.dumps(body).encode() if body is not None else None,headers={'Content-Type':'application/json','X-VulnX-CSRF':csrf})
    with opener.open(request,timeout=30) as response:return json.load(response)


def scan(asset,profile,selector='',ports='18080,18443'):
    ident=call('scans',{'asset_id':asset,'profile':profile,'selector':selector,'ports':ports})['id']
    deadline=time.monotonic()+420;stage=''
    while time.monotonic()<deadline:
        item=next(s for s in call('state')['scans'] if s['id']==ident)
        if item['stage']!=stage:
            stage=item['stage'];print(profile,stage,flush=True)
        if item['status'] not in ('queued','running'):
            if item['status']!='completed':raise AssertionError(json.dumps(item['result']))
            return item
        time.sleep(1)
    raise AssertionError('Assessment exceeded verification deadline.')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port',type=int,default=configured_port())
    args=parser.parse_args()
    BASE=f'http://127.0.0.1:{configured_port(args.port)}/api/'
    print('Verifying '+BASE,flush=True)
    csrf=call('session')['csrf']
    credentials=json.loads((data_directory()/'bootstrap-admin.json').read_text())
    csrf=call('auth/login',credentials)['csrf']
    call('lab-mode',{'fixed':False})
    names=[('mail.vulnx.test','domain'),('http://127.0.0.1:18080/','website'),('https://127.0.0.1:18443/','website'),('127.0.0.1','network')]
    existing=call('state')['assets']
    for name,kind in names:
        if not any(a['domain']==name for a in existing):call('assets',{'domain':name,'kind':kind,'label':'Controlled lab · '+kind,'authorized':True})
    assets={a['domain']:a['id'] for a in call('state')['assets']}
    results=[]
    for name,profile in [('mail.vulnx.test','email'),('http://127.0.0.1:18080/','web'),('127.0.0.1','network'),('https://127.0.0.1:18443/','tls'),('http://127.0.0.1:18080/','web_active')]:
        item=scan(assets[name],profile,selector='test' if profile=='email' else '')
        results.append(item)
        print(profile,'completed with',len(item['result']['findings']),'real findings',flush=True)
    assert any(f['title']=='Cross Site Scripting (Reflected)' for f in results[-1]['result']['findings'])
    assert any('SQL Injection' in f['title'] for f in results[-1]['result']['findings'])
    assert results[2]['result']['hosts'][0]['services']
    call('lab-mode',{'fixed':True})
    for name,profile in [('mail.vulnx.test','email'),('http://127.0.0.1:18080/','web')]:
        item=scan(assets[name],profile,selector='test' if profile=='email' else '')
        assert item['result']['comparison']['verified_fixed']>=2
        results.append(item)
    intel=call('cve/CVE-2021-44228')
    assert intel['id']=='CVE-2021-44228' and intel['source'].startswith('https://nvd.nist.gov/')
    output=data_directory()/'validation';output.mkdir(parents=True,exist_ok=True)
    for fmt in ('json','pdf'):
        with opener.open(BASE+'reports/'+results[-1]['id']+'.'+fmt,timeout=30) as response:raw=response.read()
        if fmt=='pdf':assert raw.startswith(b'%PDF-')
        else:assert json.loads(raw)['id']==results[-1]['id']
        (output/('verified-report.'+fmt)).write_bytes(raw)
    summary={'scans':[{'id':s['id'],'profile':s['profile'],'status':s['status'],'finding_count':len(s['result']['findings']),'comparison':s['result'].get('comparison')} for s in results],'nvd_source':intel['source'],'exports':['pdf','json'],'mode':'Real loopback HTTP, DNS, TLS and Nmap/ZAP processes; no mocked runtime data.'}
    (output/'summary.json').write_text(json.dumps(summary,indent=2))
    print('PASS: actual scanner integrations, correction/retest, NVD reference and PDF/JSON exports.',flush=True)
