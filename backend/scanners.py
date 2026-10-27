"""Real scanner adapters. Each result includes coverage and concrete tool evidence."""
from datetime import datetime, timezone
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from urllib.parse import urlsplit
from backend.checks import Cancelled
from backend.scope import resolved_url, ports, network_target

ROOT=Path(__file__).resolve().parent.parent


def command(args,event,timeout=180,cwd=None):
    proc=subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True,cwd=cwd)
    deadline=time.monotonic()+timeout
    try:
        while True:
            if event.is_set():
                raise Cancelled()
            if time.monotonic()>deadline:
                raise TimeoutError(f'Scanner exceeded its {timeout}-second time limit.')
            try:
                out,err=proc.communicate(timeout=.2)
                if proc.returncode:
                    raise RuntimeError((err or out or 'Scanner failed')[-2000:])
                return out
            except subprocess.TimeoutExpired:
                continue
    finally:
        if proc.poll() is None:
            os.killpg(proc.pid,signal.SIGKILL)
            proc.communicate()


def finding(title,severity,evidence,fix,rule,confidence='High',endpoint='',**extra):
    return {'title':title,'severity':severity,'confidence':confidence,'protocol':rule.split('-')[0].upper(),'evidence':evidence,'remediation':fix,'rule_id':rule,'endpoint':endpoint,'cve':None,**extra}


def result(checks,findings,limitations,**extra):
    attempted=[c for c in checks if c['status']!='skipped']
    errors=sum(c['status']=='error' for c in attempted)
    return {'checks':checks,'findings':findings,'limitations':limitations,'status':'failed' if attempted and errors==len(attempted) else 'partial' if errors else 'completed',**extra}


def parse_nmap(xml):
    root=ET.fromstring(xml)
    hosts=[]
    for host in root.findall('host'):
        address=host.find("address[@addrtype='ipv4']")
        if address is None:address=host.find('address')
        status=host.find('status')
        item={'address':address.get('addr') if address is not None else None,'status':status.get('state') if status is not None else 'unknown','timedout':host.get('timedout')=='true','services':[], 'extraports':[dict(x.attrib) for x in host.findall('ports/extraports')]}
        for port in host.findall('ports/port'):
            service=port.find('service')
            item['services'].append({'port':int(port.get('portid')),'protocol':port.get('protocol'),'state':port.find('state').get('state'),'name':service.get('name','unknown') if service is not None else 'unknown','product':service.get('product','') if service is not None else '', 'version':service.get('version','') if service is not None else '', 'confidence':service.get('conf','') if service is not None else '', 'cpes':[x.text for x in service.findall('cpe')] if service is not None else []})
        hosts.append(item)
    return hosts,root.get('version','unknown')


def network(value,port_list,event,update):
    target=network_target(value)
    selected=ports(port_list)
    if target=='127.0.0.1' and not set(selected).issubset({18080,18443}):
        raise ValueError('Loopback scan is outside the local lab scope.')
    update('Nmap: connecting to selected ports')
    xml=command(['nmap','-sT','-sV','--version-light','-Pn','-T3','--max-retries','1','--host-timeout','60s','-p',','.join(map(str,selected)),'-oX','-',target],event,180)
    hosts,version=parse_nmap(xml)
    root=ET.fromstring(xml)
    finished=root.find('runstats/finished')
    if root.tag!='nmaprun' or finished is None or finished.get('exit')!='success':
        raise RuntimeError('Nmap XML does not confirm successful tool completion.')
    expected=ipaddress.ip_network(target).num_addresses
    complete=[]; incomplete=[]
    for host in hosts:
        grouped=sum(int(x.get('count','0')) for x in host['extraports'])
        covered=len(host['services'])+grouped
        states={p['state'] for p in host['services']}|{p.get('state') for p in host['extraports']}
        # -Pn labels hosts up without proving reachability. Filtered-only is indeterminate.
        assessed=(host['status']=='up' and not host['timedout'] and covered==len(selected) and bool(states & {'open','closed'}))
        (complete if assessed else incomplete).append(host)
    addresses={h['address'] for h in hosts}
    full=bool(hosts) and not incomplete and len(addresses)==expected
    outcome='assessed' if full else 'no_hosts_observed' if not hosts else 'incomplete_or_unreachable'
    assessment='Port and service inventory complete' if full else 'Nmap finished with no hosts observed; coverage not established' if not hosts else 'Incomplete or indeterminate host coverage; review observations'
    checks=[{'protocol':'Nmap','query':value,'status':'ok' if full else 'error','assessment':assessment,'records':[json.dumps(h,indent=2) for h in hosts]}]
    if not full:checks[0]['error']='No complete security conclusion: missing, timed-out, down or filtered-only host observations.'
    report=result(checks,[],['Open ports are observations, not automatically vulnerabilities.','This unprivileged TCP profile does not perform OS fingerprinting, UDP scanning, brute force, or exploitation.','Product and version banners are fingerprints; no CVE applicability is inferred from names alone.','With -Pn, up is assumed. Filtered-only results do not prove host reachability.'],tool={'name':'Nmap','version':version},hosts=hosts,coverage={'ports':selected,'target':target,'outcome':outcome,'expected_addresses':expected,'observed_hosts':len(hosts),'assessed_hosts':len(complete),'complete':full})
    report['status']='completed' if full else 'partial'
    return report



def web(value,event,update):
    parsed,ip=resolved_url(value)
    if event.is_set():raise Cancelled()
    update('HTTP: requesting approved endpoint')
    sock=socket.create_connection((ip,parsed.port),timeout=10)
    try:
        if parsed.scheme=='https':
            sock=ssl.create_default_context().wrap_socket(sock,server_hostname=parsed.hostname)
        path=parsed.path or '/'
        authority=parsed.netloc
        sock.sendall(f'GET {path} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: VulnX/0.2\r\nAccept: text/html\r\nConnection: close\r\n\r\n'.encode('ascii'))
        response=http.client.HTTPResponse(sock);response.begin()
        headers={k.lower():v for k,v in response.getheaders() if k.lower() not in ('set-cookie','authorization','proxy-authorization')}
        body=response.read(1024*1024)
        status=response.status
    finally:sock.close()
    if event.is_set():raise Cancelled()
    checks=[{'protocol':'HTTP','query':value,'status':'ok','assessment':f'HTTP {status}; single endpoint inspected','records':[json.dumps(headers,indent=2)]}]
    findings=[]
    limits=['Single endpoint response only; no crawling or XSS/SQLi testing in this profile. Use the active local lab profile for ZAP.','Redirects are not followed. Session cookies and credentials are not stored. Missing headers do not prove exploitability.']
    if status>=300 and status<400:
        return result(checks,[],limits+['This response redirects; the destination has not been assessed.'],coverage={'endpoint':value,'http_status':status,'rule_set':'http-headers-0.2','content_assessed':False})
    if status>=400:
        checks[0].update(status='error',assessment=f'HTTP {status}; intended application page was not assessed')
        return result(checks,[],limits,coverage={'endpoint':value,'http_status':status,'content_assessed':False})
    is_html='text/html' in headers.get('content-type','')
    required=[('x-content-type-options','Missing X-Content-Type-Options','Low','Set X-Content-Type-Options: nosniff.')]
    if is_html:required.append(('content-security-policy','Missing Content Security Policy','Medium','Deploy a tested Content-Security-Policy suited to the application.'))
    if parsed.scheme=='https':required.append(('strict-transport-security','Missing HTTP Strict Transport Security','Low','After confirming HTTPS coverage, configure an appropriate Strict-Transport-Security policy.'))
    for header,title,severity,fix in required:
        if not headers.get(header,'').strip() or (header=='x-content-type-options' and headers[header].strip().lower()!='nosniff'):
            observed=headers.get(header,'').strip()
            evidence=f'GET {value} returned HTTP {status}; {header}: {observed!r}.' if observed else f'GET {value} returned HTTP {status} without {header}.'
            findings.append(finding(title.replace('Missing','Invalid') if observed else title,severity,evidence,fix,'http-'+header,endpoint=value))
    return result(checks,findings,limits,tool={'name':'VulnX HTTP checks','version':'0.2'},coverage={'endpoint':value,'http_status':status,'rule_set':'http-headers-0.2','content_assessed':True},body_sha256=hashlib.sha256(body).hexdigest())


def tls(value,event,update):
    parsed,ip=resolved_url(value,tls=True)
    update('SSLyze: inspecting TLS configuration')
    with tempfile.TemporaryDirectory(dir=ROOT/'.runtime') as folder:
        output=Path(folder)/'tls.json'
        command([sys.executable,'-m','sslyze','--mozilla_config','disable','--slow_connection','--certinfo','--tlsv1','--tlsv1_1','--tlsv1_2','--tlsv1_3','--sni',parsed.hostname,'--json_out',str(output),f'{parsed.hostname}:{parsed.port}{{{ip}}}'],event,180)
        payload=json.loads(output.read_text())
    checks=[];findings=[]
    for server in payload.get('server_scan_results',[]):
        if server.get('scan_status')!='COMPLETED':
            checks.append({'protocol':'TLS','query':value,'status':'error','assessment':'TLS scan did not complete','records':[],'error':str(server.get('connectivity_error_trace') or server.get('scan_status'))})
            continue
        for name,attempt in (server.get('scan_result') or {}).items():
            if not isinstance(attempt,dict) or attempt.get('status')=='NOT_SCHEDULED':continue
            successful=attempt.get('status')=='COMPLETED'
            details=attempt.get('result') or {}
            if name=='certificate_info':
                deployments=details.get('certificate_deployments',[])
                summaries=[]
                for dep in deployments:
                    trust=dep.get('path_validation_results',[])
                    summaries.append({'hostname_matches':dep.get('leaf_certificate_subject_matches_hostname'),'trust_results':[{'store':v.get('trust_store',{}).get('name'),'verified':v.get('was_validation_successful'),'error':v.get('validation_error')} for v in trust]})
                    if trust and not any(v.get('was_validation_successful') for v in trust):
                        findings.append(finding('TLS certificate chain not trusted','High',json.dumps(summaries[-1],indent=2),'Install a valid certificate and complete chain from a trusted CA; use a deliberately trusted CA for a private lab.','tls-certificate-trust',endpoint=value))
                    if dep.get('leaf_certificate_subject_matches_hostname') is False:
                        findings.append(finding('TLS certificate hostname mismatch','High',f'Certificate does not match {parsed.hostname}.','Install a certificate whose SAN includes the intended hostname.','tls-certificate-hostname',endpoint=value))
                records=[json.dumps(summaries,indent=2)]
            else:
                accepted=details.get('accepted_cipher_suites',[])
                records=[json.dumps({'supported':details.get('is_tls_version_supported'),'accepted_cipher_count':len(accepted)},indent=2)]
                if name in ('tls_1_0_cipher_suites','tls_1_1_cipher_suites') and details.get('is_tls_version_supported'):
                    findings.append(finding('Legacy TLS protocol enabled','Medium',name+' is supported.','Disable TLS 1.0/1.1 after checking client compatibility.','tls-'+name,endpoint=value))
            checks.append({'protocol':name,'query':value,'status':'ok' if successful else 'error','assessment':'Checked' if successful else 'Check failed','records':records,'error':None if successful else str(attempt.get('error_reason'))+' '+str(attempt.get('error_trace') or '')[:2000]})
    if not checks:raise RuntimeError('SSLyze returned no completed or failed checks.')
    return result(checks,findings,['TLS 1.0–1.3 and certificate checks only. Other SSLyze plugins are not included in this profile.','Certificate trust errors in the built-in self-signed lab are expected and remain real findings.'],tool={'name':'SSLyze','version':payload.get('sslyze_version','unknown')},coverage={'endpoint':value,'pinned_ip':ip})


def zap(value,event,update):
    parsed=urlsplit(value)
    if parsed.hostname!='127.0.0.1' or parsed.port!=18080:
        raise ValueError('ZAP active profile is restricted to the built-in local lab.')
    script=ROOT/'.runtime/tools/ZAP_2.17.0/zap.sh'
    if not script.exists():raise RuntimeError('ZAP is not installed. Run scripts/install_zap.py.')
    update('ZAP: starting isolated lab assessment')
    with tempfile.TemporaryDirectory(dir=ROOT/'.runtime') as folder:
        home=Path(folder)
        plan={'env':{'contexts':[{'name':'vulnx-lab','urls':[value],'includePaths':[re.escape(value.rstrip('/'))+'.*']}],'parameters':{'failOnError':True,'failOnWarning':False,'progressToStdout':True}},'jobs':[{'type':'passiveScan-config','parameters':{'scanOnlyInScope':True}},{'type':'spider','parameters':{'context':'vulnx-lab','maxDuration':1,'maxDepth':3}},{'type':'passiveScan-wait','parameters':{'maxDuration':1}},{'type':'activeScan','parameters':{'context':'vulnx-lab','maxScanDurationInMins':2,'maxRuleDurationInMins':1},'policyDefinition':{'defaultStrength':'Low','defaultThreshold':'Medium'}},{'type':'passiveScan-wait','parameters':{'maxDuration':1}},{'type':'report','parameters':{'template':'traditional-json','reportDir':str(home),'reportFile':'report.json','reportTitle':'VulnX local lab assessment'}}]}
        plan_path=home/'plan.yaml';plan_path.write_text(json.dumps(plan))
        output=command(['bash',str(script),'-cmd','-dir',str(home/'zap-home'),'-autorun',str(plan_path)],event,360)
        reports=list(home.glob('report*.json'))
        if not reports:raise RuntimeError('ZAP did not produce its JSON report. '+output[-1000:])
        report=json.loads(reports[0].read_text())
    findings=[]
    for site in report.get('site',[]):
        for alert in site.get('alerts',[]):
            instances=alert.get('instances',[])
            for item in instances[:20] or [{}]:
                endpoint=item.get('uri',value)
                # Preserve endpoint without payload query values in exported findings.
                endpoint=endpoint.split('?',1)[0]
                if not endpoint.startswith('http://127.0.0.1:18080/'):continue
                evidence=str(item.get('evidence'))[:2000] if item.get('evidence') else 'Scanner observation: '+re.sub('<[^>]+>',' ',str(alert.get('desc','')))[:2000]
                curated={'40012':'Encode untrusted output for its HTML, attribute or JavaScript context. Use framework escaping by default, validate inputs, and add a tested Content Security Policy as defense in depth. Retest the affected parameter.','40018':'Replace SQL string concatenation with parameterized queries. Validate input types and use a database account with only the permissions the application needs. Retest the affected endpoint.'}
                guidance=curated.get(str(alert.get('pluginid')),re.sub('<[^>]+>',' ',alert.get('solution','Review ZAP guidance.')))
                findings.append(finding(alert.get('name','ZAP alert'),{'0':'Info','1':'Low','2':'Medium','3':'High'}.get(str(alert.get('riskcode')),'Info'),evidence,guidance,'zap-'+str(alert.get('pluginid','unknown')),confidence={'0':'False positive','1':'Low','2':'Medium','3':'High','4':'Confirmed'}.get(str(alert.get('confidence')),'Unknown'),endpoint=endpoint,cwe=alert.get('cweid'),references=alert.get('reference','')))
    checks=[{'protocol':'ZAP','query':value,'status':'ok','assessment':'Bounded active lab scan complete','records':['ZAP report generated from real spider, passive and active scan jobs.']}]
    return result(checks,findings,['Active scanning is time bounded and may not exercise every route or rule.','This profile is restricted to the built-in loopback lab. It is not a guarantee of detecting all XSS or SQL injection.','Alert evidence is truncated and query payload values are omitted from endpoint identifiers.'],tool={'name':'ZAP','version':report.get('@version','2.17.0')},coverage={'endpoint':value,'rule_set':'zap-lab-active-0.2','content_assessed':True})
