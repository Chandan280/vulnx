"""NVD records are references; lookup alone never confirms target applicability."""
import json
import re
import threading
import time
import hashlib
import urllib.request
import urllib.parse
import urllib.error
from pathlib import Path
from datetime import datetime, timezone

LOCK=threading.Lock()
LAST_REQUEST=0.0
from backend.runtime import data_directory
CACHE=data_directory()/'nvd'


def request_nvd(parameters):
    global LAST_REQUEST
    with LOCK:
        gap=6.2-(time.monotonic()-LAST_REQUEST)
        if gap>0:time.sleep(gap)
        LAST_REQUEST=time.monotonic()
        request=urllib.request.Request('https://services.nvd.nist.gov/rest/json/cves/2.0?'+urllib.parse.urlencode(parameters),headers={'User-Agent':'VulnX-capstone/0.2','Accept':'application/json'})
        with urllib.request.urlopen(request,timeout=20) as response:return json.loads(response.read(4*1024*1024))


def normalize_cpe(cpe):
    if cpe.startswith('cpe:/'):
        fields=cpe[5:].split(':')
        if len(fields)<4:return None
        fields+=['*']*(11-len(fields))
    elif cpe.startswith('cpe:2.3:'):
        fields=cpe[8:].split(':')
    else:return None
    if len(fields)!=11 or fields[0] not in ('a','o','h') or fields[3] in ('','*','-'):
        return None
    if not all(re.fullmatch(r'[a-zA-Z0-9_.~*+\-]+',f) for f in fields):return None
    return 'cpe:2.3:'+':'.join(fields)


def by_cpe(cpe):
    normalized=normalize_cpe(cpe)
    if not normalized:raise ValueError('CPE requires a supported complete product and version fingerprint.')
    CACHE.mkdir(parents=True,exist_ok=True)
    path=CACHE/('cpe-'+hashlib.sha256(normalized.encode()).hexdigest()+'.json')
    if path.exists() and time.time()-path.stat().st_mtime<86400:
        cached=json.loads(path.read_text());cached['cached']=True;return cached
    payload=request_nvd({'cpeName':normalized,'isVulnerable':'','resultsPerPage':20})
    candidates=[]
    for row in payload.get('vulnerabilities',[]):
        c=row['cve'];metrics=c.get('metrics',{})
        metric=next((metrics[k][0] for k in ('cvssMetricV40','cvssMetricV31','cvssMetricV30','cvssMetricV2') if metrics.get(k)),{})
        candidates.append({'id':c['id'],'description':next((d['value'] for d in c.get('descriptions',[]) if d['lang']=='en'),''),'source':'https://nvd.nist.gov/vuln/detail/'+c['id'],'cvss':metric.get('cvssData')})
    result={'observed_cpe':cpe,'queried_cpe':normalized,'candidates':candidates,'total':payload.get('totalResults',0),'retrieved':datetime.now(timezone.utc).isoformat(),'cached':False,'status':'retrieved','applicability':'NVD vulnerable-product match to an observed version fingerprint. Candidate association only: validate the installed build, backports, configuration and exploit prerequisites before confirming.'}
    path.write_text(json.dumps(result));return result


def lookup(cve):
    global LAST_REQUEST
    if not re.fullmatch(r'CVE-\d{4}-\d{4,}',cve):
        raise ValueError('Enter a valid CVE identifier, such as CVE-2021-44228.')
    CACHE.mkdir(parents=True,exist_ok=True)
    path=CACHE/(cve+'.json')
    if path.exists() and time.time()-path.stat().st_mtime<86400:
        cached=json.loads(path.read_text());cached['cached']=True;return cached
    payload=request_nvd({'cveId':cve})
    entries=payload.get('vulnerabilities',[])
    if not entries:raise ValueError('No NVD record found for this CVE.')
    c=entries[0]['cve']
    metrics=c.get('metrics',{})
    metric=next((metrics[k][0] for k in ('cvssMetricV40','cvssMetricV31','cvssMetricV30','cvssMetricV2') if metrics.get(k)),{})
    result={'id':c['id'],'description':next((d['value'] for d in c.get('descriptions',[]) if d['lang']=='en'),'No English description available.'),'published':c.get('published'),'modified':c.get('lastModified'),'status':c.get('vulnStatus'),'cvss':metric.get('cvssData'),'metric_source':metric.get('source'),'references':[r['url'] for r in c.get('references',[]) if r.get('url','').startswith('https://')][:10],'source':'https://nvd.nist.gov/vuln/detail/'+c['id'],'retrieved':datetime.now(timezone.utc).isoformat(),'cached':False,'applicability':'Reference lookup only. Product/version and configuration applicability have not been established for any target.'}
    path.write_text(json.dumps(result));return result
