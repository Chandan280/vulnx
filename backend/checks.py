"""Conservative DNS configuration checks. Observations are never delivery tests."""
import ipaddress
import re
import shlex
import subprocess


class Cancelled(Exception):
    pass


def domain_name(value):
    value = value.strip().rstrip('.').lower()
    try:
        value = value.encode('idna').decode('ascii')
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise ValueError('Enter a domain name, not an IP address.')
    if len(value) > 253 or '.' not in value or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', x) for x in value.split('.')):
        raise ValueError('Enter a valid domain, without a URL, path or port.')
    if value.endswith(('.localhost', '.local', '.internal')):
        raise ValueError('This DNS profile uses public DNS names; local lab DNS support is not configured.')
    return value


def selector_name(value):
    if not value:
        return ''
    if len(value) > 63 or not re.fullmatch(r'[A-Za-z0-9_-]+', value):
        raise ValueError('DKIM selector must contain only letters, digits, underscores or hyphens (maximum 63 characters).')
    return value


def parse_dns(stdout, stderr='', returncode=0):
    if returncode:
        return {'status': 'error', 'records': [], 'error': (stderr or stdout or 'DNS process failed')[-1000:]}
    match = re.search(r'status: (\w+)', stdout)
    if not match:
        return {'status': 'error', 'records': [], 'error': 'DNS resolver returned no parseable response.'}
    code = match.group(1)
    if code not in ('NOERROR', 'NXDOMAIN'):
        return {'status': 'error', 'records': [], 'error': 'DNS response: ' + code}
    records = []
    for line in stdout.splitlines():
        if line.startswith(';'):
            continue
        match = re.match(r'^\S+\s+\d+\s+IN\s+TXT\s+(.+)$', line)
        if match:
            try:
                records.append(''.join(shlex.split(match.group(1))))
            except ValueError:
                return {'status': 'error', 'records': [], 'error': 'Malformed TXT response.'}
    return {'status': 'ok' if records else 'absent', 'records': records, 'rcode': code}


def lookup(name, cancelled):
    try:
        proc = subprocess.Popen(['dig', '+time=3', '+tries=1', '+noall', '+comments', '+answer', name, 'TXT'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except OSError as exc:
        return {'status': 'error', 'records': [], 'error': str(exc)}
    import time
    deadline = time.monotonic() + 8
    while True:
        if cancelled.is_set():
            proc.kill()
            proc.communicate()
            raise Cancelled()
        if time.monotonic() > deadline:
            proc.kill()
            proc.communicate()
            return {'status': 'error', 'records': [], 'error': 'DNS lookup timed out.'}
        try:
            out, err = proc.communicate(timeout=0.2)
            return parse_dns(out, err, proc.returncode)
        except subprocess.TimeoutExpired:
            continue


def assess(domain, selector, cancelled, update=lambda stage: None, resolver=lookup):
    checks, findings = [], []
    specifications = [('SPF', domain, 'v=spf1'), ('DMARC', '_dmarc.' + domain, 'v=dmarc1')]
    if selector:
        specifications.append(('DKIM', selector + '._domainkey.' + domain, None))
    def finding(title, severity, protocol, evidence, fix):
        findings.append({'title': title, 'severity': severity, 'confidence': 'High', 'protocol': protocol, 'evidence': evidence, 'remediation': fix, 'rule_id': 'dns-' + title.lower().replace(' ', '-'), 'cve': None})
    for protocol, name, prefix in specifications:
        if cancelled.is_set():
            raise Cancelled()
        update('Querying ' + protocol)
        answer = resolver(name, cancelled)
        relevant = [r for r in answer['records'] if prefix is None or r.lower().startswith(prefix)]
        check = {'protocol': protocol, 'query': name, **answer, 'assessment': 'Not assessed'}
        checks.append(check)
        if answer['status'] == 'error':
            continue
        if not relevant:
            check['assessment'] = 'Record not found'
            finding(protocol + ' record not found', 'Low' if protocol == 'DKIM' else 'Medium', protocol, 'No matching TXT record at ' + name, 'Confirm the intended mail configuration. Publish a valid record if this domain sends mail.' if protocol != 'DKIM' else 'Verify the selector with your mail provider. This result applies only to the supplied selector.')
            continue
        if len(relevant) > 1:
            check['assessment'] = 'Needs attention'
            finding('Multiple ' + protocol + ' records', 'Medium', protocol, '\n'.join(relevant), 'Review and consolidate the records according to your mail provider and the applicable specification.')
            continue
        record = relevant[0]
        check['assessment'] = 'Basic checks complete'
        tags = {}
        for part in record.split(';'):
            if '=' in part:
                key, val = part.split('=', 1)
                tags[key.strip().lower()] = val.strip()
        if protocol == 'SPF' and any(t.lower() in ('all', '+all') for t in record.split()[1:]):
            finding('SPF permits every sender', 'High', protocol, record, 'Replace the permissive all mechanism with an appropriate policy after validating legitimate senders.')
        if protocol == 'DMARC':
            policy = tags.get('p', '').lower()
            if policy not in ('none', 'quarantine', 'reject'):
                finding('DMARC policy missing or invalid', 'Medium', protocol, record, 'Configure a valid p= policy and validate the complete record.')
            elif policy == 'none':
                finding('DMARC policy is monitoring only', 'Low', protocol, record, 'Review authentication reports, then consider quarantine or reject when legitimate mail is aligned. Monitoring can be intentional.')
        if protocol == 'DKIM':
            if 'p' not in tags:
                finding('DKIM public key missing', 'Medium', protocol, record, 'Confirm that this selector publishes a valid DKIM key record.')
            elif not tags['p']:
                finding('DKIM selector key revoked', 'Info', protocol, record, 'An empty p= revokes this selector. Check whether it is intentionally retired and verify the active selector.')
    if not selector:
        checks.append({'protocol': 'DKIM', 'status': 'skipped', 'assessment': 'Selector required', 'records': [], 'query': None})
    errors = sum(c['status'] == 'error' for c in checks)
    attempted = sum(c['status'] != 'skipped' for c in checks)
    return {'checks': checks, 'findings': findings, 'status': 'failed' if errors == attempted else 'partial' if errors else 'completed', 'limitations': ['Basic DNS configuration checks only; not an email delivery or authentication test.', 'SPF recursive lookup limits, full DKIM key cryptography, DMARC organizational-domain fallback and full standards validation are not yet implemented.', 'No CVE enrichment is performed for these configuration findings.']}
