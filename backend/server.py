"""Authenticated single-process assessment API with explicit hosted configuration."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
import io
import logging
import signal
import hashlib
import json
import mimetypes
import re
import os
import secrets
import shutil
import sqlite3
import sys
import threading
from urllib.parse import urlparse
from uuid import uuid4
from xml.sax.saxutils import escape

sys.path.insert(0, str(Path(__file__).parent.parent))
from backend.checks import assess, domain_name, selector_name, Cancelled
from backend import scope, scanners, intelligence, auth, lab_control, deployment
from backend.runtime import data_directory, configured_port, database_lock, configure_logging, refuse_legacy_listeners

ROOT = Path(__file__).resolve().parent.parent
DATA = data_directory()
LOGGER = logging.getLogger('vulnx')
LOGGER.addHandler(logging.NullHandler())
DB = DATA / 'vulnx.sqlite'
TOKEN = secrets.token_urlsafe(32)
POOL = ThreadPoolExecutor(max_workers=1)
EVENTS = {}
LOCK = threading.Lock()
WORKSPACE_LOCK = threading.RLock()


def now():
    return datetime.now(timezone.utc).isoformat()


@contextmanager
def connection():
    db = sqlite3.connect(DB, timeout=10)
    db.row_factory = sqlite3.Row
    try:
        with db:
            yield db
    finally:
        db.close()


def initialize():
    DATA.mkdir(parents=True,exist_ok=True, mode=0o700)
    if DB.exists():
        with sqlite3.connect(DB) as source:
            legacy = source.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='assets'").fetchone() and not source.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='users'").fetchone()
            backup = DATA / (DB.stem+'-before-auth.sqlite')
            if legacy and not backup.exists():
                fd=os.open(backup,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600);os.close(fd)
                with sqlite3.connect(backup) as dest:source.backup(dest)
    with connection() as db:
        db.executescript('''CREATE TABLE IF NOT EXISTS assets(id TEXT PRIMARY KEY, domain TEXT UNIQUE, label TEXT, created TEXT);
        CREATE TABLE IF NOT EXISTS scans(id TEXT PRIMARY KEY, asset_id TEXT, domain TEXT, selector TEXT, status TEXT, stage TEXT, created TEXT, finished TEXT, result TEXT);
        CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, action TEXT, detail TEXT, created TEXT);''')
        for table,columns in {'assets':{'kind':"TEXT DEFAULT 'domain'"},'scans':{'profile':"TEXT DEFAULT 'email'",'ports':"TEXT DEFAULT '80,443'",'retest_of':'TEXT','processed':"INTEGER DEFAULT 0"}}.items():
            existing={r['name'] for r in db.execute('PRAGMA table_info('+table+')')}
            for name,definition in columns.items():
                if name not in existing:db.execute(f'ALTER TABLE {table} ADD COLUMN {name} {definition}')
        db.executescript('''CREATE TABLE IF NOT EXISTS findings(id TEXT PRIMARY KEY,asset_id TEXT,signature TEXT,rule_id TEXT,profile TEXT,title TEXT,severity TEXT,confidence TEXT,evidence TEXT,remediation TEXT,endpoint TEXT,status TEXT,first_seen TEXT,last_seen TEXT,scan_id TEXT,note TEXT);
        CREATE TABLE IF NOT EXISTS occurrences(finding_id TEXT,scan_id TEXT,PRIMARY KEY(finding_id,scan_id));''')
        auth.migrate(db, DATA)
        db.execute("UPDATE scans SET status='failed',stage='Interrupted by server restart',finished=? WHERE status IN ('running','queued')", (now(),))


def audit(db, action, detail, owner_id=auth.ADMIN_ID):
    db.execute('INSERT INTO audit(action,detail,created,owner_id) VALUES (?,?,?,?)', (action, detail, now(), owner_id))


def state(owner_id=None):
    with connection() as db:
        clause = ' WHERE a.owner_id=?' if owner_id else ''
        args = (owner_id,) if owner_id else ()
        assets = [dict(r) for r in db.execute('SELECT a.* FROM assets a'+clause+' ORDER BY a.created DESC',args)]
        scans = [dict(r) for r in db.execute('SELECT s.* FROM scans s JOIN assets a ON a.id=s.asset_id'+clause+' ORDER BY s.created DESC',args)] if owner_id else [dict(r) for r in db.execute('SELECT * FROM scans ORDER BY created DESC')]
        findings=[dict(r) for r in db.execute('SELECT f.*,a.domain FROM findings f JOIN assets a ON a.id=f.asset_id'+clause+' ORDER BY f.last_seen DESC',args)]
    for scan in scans:
        scan['result'] = json.loads(scan['result']) if scan['result'] else None
    return {'assets': assets, 'scans': scans, 'findings':findings}


def clear_workspace(confirmation, owner_id=None):
    """Serialize reset with job submission; never erase a live worker's records."""
    if confirmation != 'DELETE ALL DATA':
        raise ValueError('Type DELETE ALL DATA to confirm permanent removal.')
    with WORKSPACE_LOCK:
        if owner_id:
            with connection() as db:
                owned = 'SELECT id FROM assets WHERE owner_id=?'
                scan_ids = 'SELECT id FROM scans WHERE asset_id IN ('+owned+')'
                if db.execute("SELECT 1 FROM scans WHERE status IN ('queued','running') AND asset_id IN ("+owned+')',(owner_id,)).fetchone():
                    raise ValueError('Cancel or finish your assessments before clearing data.')
                db.execute('DELETE FROM occurrences WHERE scan_id IN ('+scan_ids+')',(owner_id,))
                for table in ('findings','scans'):
                    db.execute('DELETE FROM '+table+' WHERE asset_id IN ('+owned+')',(owner_id,))
                db.execute('DELETE FROM assets WHERE owner_id=?',(owner_id,))
                db.execute('DELETE FROM audit WHERE owner_id=?',(owner_id,))
            return {'ok':True,'note':'Your assessment data was removed. Your account and other users were preserved.'}
        with LOCK:
            if EVENTS:
                raise ValueError('Cancel or finish all assessments before clearing data.')
        with connection() as db:
            if db.execute("SELECT count(*) FROM scans WHERE status IN ('queued','running')").fetchone()[0]:
                raise ValueError('Cancel or finish all assessments before clearing data.')
            db.execute('PRAGMA secure_delete=ON')
            counts={table:db.execute('SELECT count(*) FROM '+table).fetchone()[0] for table in ('assets','scans','findings','occurrences','audit')}
            for table in ('occurrences','findings','scans','assets','audit'):
                db.execute('DELETE FROM '+table)
        # Only application-owned generated evidence; installed tools are preserved.
        for name in ('validation','nvd'):
            path=DATA/name
            if path.is_symlink():path.unlink()
            elif path.exists():shutil.rmtree(path)
        for path in DATA.glob('*-validation.json'):
            path.unlink()
        with connection() as db:
            db.execute('VACUUM')
        return {'ok':True,'deleted':counts,'note':'Workspace cleared. Exported downloads and system backups are outside this app.'}


def reconcile(scan_id,result):
    with connection() as db:
        scan=db.execute('SELECT * FROM scans WHERE id=?',(scan_id,)).fetchone()
        observed_at=scan['finished'] or now()
        signature=hashlib.sha256(json.dumps([scan['asset_id'],scan['profile'],scan['selector'],scan['ports']]).encode()).hexdigest()
        prior={r['id']:dict(r) for r in db.execute('SELECT * FROM findings WHERE signature=?',(signature,))}
        observed=set();new=0;recurring=0;fixed=0
        for f in result['findings']:
            endpoint=f.get('endpoint') or scan['domain']
            key=hashlib.sha256((signature+'|'+f['rule_id']+'|'+endpoint).encode()).hexdigest()[:24]
            f['finding_id']=key
            if key in observed:
                continue
            observed.add(key)
            if key in prior:
                recurring+=1
                status='reopened' if prior[key]['status']=='verified_fixed' else prior[key]['status']
                if status=='pending_retest':status='open'
                db.execute('UPDATE findings SET title=?,severity=?,confidence=?,evidence=?,remediation=?,last_seen=?,scan_id=?,status=? WHERE id=?',(f['title'],f['severity'],f['confidence'],f['evidence'],f['remediation'],observed_at,scan_id,status,key))
            else:
                new+=1
                db.execute('INSERT INTO findings VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',(key,scan['asset_id'],signature,f['rule_id'],scan['profile'],f['title'],f['severity'],f['confidence'],f['evidence'],f['remediation'],endpoint,'open',observed_at,observed_at,scan_id,''))
            db.execute('INSERT OR IGNORE INTO occurrences VALUES (?,?)',(key,scan_id))
        comparable=result['status']=='completed' and (scan['profile']=='email' or (scan['profile']=='web' and result.get('coverage',{}).get('content_assessed') is True))
        for key,f in prior.items():
            if key not in observed and f['status'] in ('open','in_progress','pending_retest','reopened'):
                if comparable:
                    fixed+=1
                    db.execute("UPDATE findings SET status='verified_fixed',scan_id=?,note=? WHERE id=?",(scan_id,'Relevant configuration check no longer flags this issue in a comparable successful assessment.',key))
        result['comparison']={'new':new,'recurring':recurring,'verified_fixed':fixed,'not_observed':len(set(prior)-observed),'fix_verification_supported':comparable,'note':'Verification applies to checked configuration rules only; failed, partial and active ZAP scans cannot establish a fix by absence.'}
        db.execute('UPDATE scans SET result=?,status=?,stage=?,finished=?,processed=1 WHERE id=?',(json.dumps(result),result['status'],'Assessment finished',observed_at,scan_id))


def backfill():
    with connection() as db:
        pending=[dict(r) for r in db.execute('SELECT id,result FROM scans WHERE processed=0 AND result IS NOT NULL ORDER BY created')]
    for scan in pending:
        reconcile(scan['id'],json.loads(scan['result']))


def set_scan(scan_id, **fields):
    with connection() as db:
        db.execute('UPDATE scans SET ' + ','.join(k + '=?' for k in fields) + ' WHERE id=?', (*fields.values(), scan_id))


def execute_scan(scan_id, domain, selector, event, profile='email', port_list='80,443'):
    try:
        if event.is_set():
            raise Cancelled()
        set_scan(scan_id, status='running', stage='Starting '+profile+' assessment')
        update=lambda stage:set_scan(scan_id,stage=stage)
        if profile=='email':result=assess(domain,selector,event,update)
        elif profile=='network':result=scanners.network(domain,port_list,event,update)
        elif profile=='tls':result=scanners.tls(domain,event,update)
        elif profile=='web':result=scanners.web(domain,event,update)
        elif profile=='web_active':result=scanners.zap(domain,event,update)
        else:raise ValueError('Unknown profile')
        # Enrichment never upgrades scanner confidence or manufactures a finding.
        if profile=='network':
            cpes=list(dict.fromkeys(c for h in result.get('hosts',[]) for service in h['services'] for c in service['cpes'] if intelligence.normalize_cpe(c)))[:3]
            matches=[]
            for cpe in cpes:
                if event.is_set():raise Cancelled()
                update('NVD: checking observed product version')
                try:matches.append(intelligence.by_cpe(cpe))
                except Exception:matches.append({'observed_cpe':cpe,'status':'unavailable','candidates':[],'applicability':'NVD enrichment failed; no CVE applicability is inferred.'})
            result['cve_matches']=matches
        if profile=='web_active':
            for f in result['findings']:
                identifiers=re.findall(r'CVE-\d{4}-\d{4,}',f.get('references',''))[:2]
                f['cve_records']=[]
                for identifier in identifiers:
                    if event.is_set():raise Cancelled()
                    try:f['cve_records'].append(intelligence.lookup(identifier))
                    except Exception:f['enrichment_status']='unavailable'
        if event.is_set():
            raise Cancelled()
        reconcile(scan_id,result)
    except Cancelled:
        set_scan(scan_id, status='cancelled', stage='Cancelled by user', finished=now())
    except Exception as exc:
        status='timed_out' if isinstance(exc,TimeoutError) else 'failed'
        failure={'status':status,'checks':[{'protocol':profile,'status':'error','assessment':'Assessment could not finish','query':domain,'records':[],'error':str(exc)[:2000]}],'findings':[],'limitations':['No successful assessment result. No findings may be inferred from this failure.']}
        set_scan(scan_id, status=status, stage='Assessment could not finish', finished=now(),result=json.dumps(failure))
        LOGGER.error('Assessment %s failed (%s)', scan_id, type(exc).__name__)
    finally:
        with LOCK:
            EVENTS.pop(scan_id, None)


def pdf_report(scan):
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, title='VulnX assessment', author='VulnX', leftMargin=45, rightMargin=45)
    styles = getSampleStyleSheet()
    for name in ('Title','Heading2','Heading3'):
        styles[name].textColor = colors.HexColor('#7c3aed')
    story = []
    def p(text, style='BodyText'):
        story.append(Paragraph(escape(str(text)).replace('\n', '<br/>'), styles[style]))
        story.append(Spacer(1, 9))
    p('VulnX | Security assessment', 'Title')
    for key in ('id', 'domain', 'profile', 'selector', 'status', 'created', 'finished'):
        p(key.capitalize() + ': ' + str(scan.get(key) or 'Not supplied'))
    p('Scope and method', 'Heading2')
    p('User-approved target. Profile: '+str(scan.get('profile','email'))+'. Scope and coverage are specific to the selected scanner; review all limitations below.')
    result = scan.get('result') or {}
    if result.get('tool'):p('Scanner: '+json.dumps(result['tool']))
    if result.get('comparison'):p('Comparison: '+json.dumps(result['comparison']))
    for match in result.get('cve_matches',[]):
        p('CVE intelligence: '+match['observed_cpe'],'Heading2')
        p(match['applicability'])
        for candidate in match['candidates']:p(candidate['id']+' | '+candidate['source'])
    for check in result.get('checks', []):
        p(check['protocol'] + ' — ' + check['assessment'], 'Heading2')
        p('Query: ' + str(check.get('query') or 'Not performed'))
        p('Check status: ' + check['status'])
        for record in check['records']:
            p(record)
        if check.get('error'):
            p(check['error'])
    p('Findings', 'Heading2')
    if not result.get('findings'):
        p('No findings recorded. Review failed/skipped checks and limitations before interpreting this result.')
    for finding in result.get('findings', []):
        p(finding['severity'] + ' | ' + finding['title'], 'Heading3')
        p('Evidence: ' + finding['evidence'])
        p('Remediation: ' + finding['remediation'])
    p('Limitations', 'Heading2')
    for limitation in result.get('limitations', ['This assessment did not produce a result.']):
        p(limitation)
    def footer(canvas,document):
        canvas.saveState()
        canvas.setStrokeColor(colors.HexColor('#ede9fe'))
        canvas.line(45,37,document.pagesize[0]-45,37)
        canvas.setFillColor(colors.HexColor('#6b6478'));canvas.setFont('Helvetica',8)
        canvas.drawString(45,25,'VulnX | Evidence-based assessment | Review coverage and limitations')
        canvas.drawRightString(document.pagesize[0]-45,25,str(document.page))
        canvas.restoreState()
    doc.build(story,onFirstPage=footer,onLaterPages=footer)
    return buffer.getvalue()


class LocalHTTPServer(ThreadingHTTPServer):
    daemon_threads = False

    def handle_error(self, request, client_address):
        LOGGER.error('HTTP handler failed (%s)', sys.exc_info()[0].__name__)


class Handler(BaseHTTPRequestHandler):
    def auth_cookie_name(self):
        return 'vulnx_auth_' + str(self.server.server_port)

    def current_user(self):
        token = auth.cookie_value(self.headers, self.auth_cookie_name())
        if not token:
            return None
        with connection() as db:
            return auth.validate(db,token,auth.secret(DATA))

    def require_user(self):
        self.user = self.current_user()
        if self.user:
            return True
        self.reply(401,{'error':'Sign in to access your workspace.','code':'authentication_required'})
        return False

    def setup(self):
        super().setup()
        self.connection.settimeout(15)

    def log_message(self, format, *args):
        # Do not log target paths, queries, credentials, or depend on terminal pipes.
        LOGGER.info('HTTP request handled')

    def reply(self, code, body, content='application/json', cookie=False, download=None):
        raw = json.dumps(body).encode() if content == 'application/json' else body
        self.send_response(code)
        self.send_header('Content-Type', content)
        self.send_header('Content-Length', str(len(raw)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        origin=self.headers.get('Origin')
        if origin and origin in deployment.allowed_origins(self.headers.get('Host','')):
            self.send_header('Access-Control-Allow-Origin',origin)
            self.send_header('Access-Control-Allow-Credentials','true')
            self.send_header('Vary','Origin')
            self.send_header('Access-Control-Allow-Methods','GET, POST, OPTIONS')
            self.send_header('Access-Control-Allow-Headers','Content-Type, X-VulnX-CSRF')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        if cookie:
            self.send_header('Set-Cookie', self.session_cookie_name() + '=' + getattr(self,'csrf_value',TOKEN) + '; HttpOnly; SameSite=Strict; Path=/' + ('; Secure' if deployment.public_origin() else ''))
        if hasattr(self,'auth_cookie'):
            self.send_header('Set-Cookie',self.auth_cookie_name()+'='+self.auth_cookie+'; HttpOnly; SameSite=Strict; Path=/; Max-Age='+str(auth.TTL if self.auth_cookie else 0)+ ('; Secure' if deployment.public_origin() else ''))
        if download:
            self.send_header('Content-Disposition', 'attachment; filename="' + download + '"')
        self.end_headers()
        self.wfile.write(raw)

    def session_cookie_name(self):
        # Cookies are shared across ports; isolate each local server session.
        return 'vulnx_session_' + str(self.server.server_port)

    def allowed(self, mutation=False):
        host = self.headers.get('Host', '')
        if host not in deployment.allowed_hosts(self.server.server_port):
            self.reply(403, {'error': 'Host not allowed.'})
            return False
        origin = self.headers.get('Origin')
        if origin and origin not in deployment.allowed_origins(host):
            self.reply(403, {'error': 'Cross-origin request rejected.'})
            return False
        user = self.current_user()
        self.csrf_value = user['csrf'] if user else TOKEN
        if mutation and (not secrets.compare_digest(self.headers.get('X-VulnX-CSRF',''),self.csrf_value) or auth.cookie_value(self.headers,self.session_cookie_name()) != self.csrf_value):
            self.reply(403, {'error': 'Refresh the local workspace session.', 'code': 'session_expired'})
            return False
        return True

    def do_GET(self):
        if urlparse(self.path).path == '/api/health':
            return self.reply(200,{'status':'ok'})
        if not self.allowed():
            return
        path = urlparse(self.path).path
        if path == '/api/session':
            user = self.current_user()
            return self.reply(200, {'csrf':self.csrf_value,'user':auth.public_user(user) if user else None}, cookie=True)
        if path.startswith('/api/') and not self.require_user():
            return
        if path == '/api/auth/me':
            return self.reply(200,auth.public_user(self.user))
        if path == '/api/lab':
            if self.user['role']!='admin':return self.reply(403,{'error':'Lab controls require an administrator.'})
            return self.reply(200,lab_control.status())
        if path == '/api/state':
            return self.reply(200, state(self.user['id']))
        if path == '/api/readiness':
            util=__import__('importlib.util',fromlist=['find_spec'])
            return self.reply(200, {'dns':bool(shutil.which('dig')),'nmap':bool(shutil.which('nmap')),'tls':util.find_spec('sslyze') is not None,'zap':(ROOT/'.runtime/tools/ZAP_2.17.0/zap.sh').exists(),'pdf':util.find_spec('reportlab') is not None,'mode':'Single-user local workspace','network':'Installed dependencies only; actual outcomes are recorded by each assessment.'})
        if path.startswith('/api/cve/'):
            try:
                with WORKSPACE_LOCK:
                    return self.reply(200,intelligence.lookup(path.rsplit('/',1)[-1].upper()))
            except ValueError as exc:return self.reply(400,{'error':str(exc)})
            except Exception:return self.reply(503,{'error':'NVD is unavailable or rate limited. Try again later; no intelligence was invented.'})
        if path.startswith('/api/reports/'):
            key = path.rsplit('/', 1)[-1]
            scan_id, _, fmt = key.partition('.')
            scan = next((s for s in state(self.user['id'])['scans'] if s['id'] == scan_id), None)
            if not scan:
                return self.reply(404, {'error': 'Assessment not found.'})
            if scan['status'] in ('running', 'queued'):
                return self.reply(409, {'error': 'Wait for the assessment to finish.'})
            if fmt == 'json':
                return self.reply(200, scan, download='vulnx-' + scan_id + '.json')
            if fmt == 'pdf':
                try:
                    return self.reply(200, pdf_report(scan), 'application/pdf', download='vulnx-' + scan_id + '.pdf')
                except ImportError:
                    return self.reply(503, {'error': 'PDF dependency missing: install reportlab.'})
            return self.reply(400, {'error': 'Choose PDF or JSON.'})
        if path.startswith('/api/'):
            return self.reply(404, {'error': 'Unknown endpoint.'})
        file = (ROOT / 'dist' / path.lstrip('/')).resolve()
        if not file.is_relative_to((ROOT / 'dist').resolve()):
            return self.reply(403, {'error': 'Invalid path.'})
        if path == '/' or not file.is_file():
            file = ROOT / 'dist' / 'index.html'
        if not file.exists():
            return self.reply(503, {'error': 'Build the frontend with npm run build.'})
        self.reply(200, file.read_bytes(), mimetypes.guess_type(file)[0] or 'application/octet-stream')

    def do_POST(self):
        with WORKSPACE_LOCK:
            self.handle_post()

    def do_OPTIONS(self):
        if self.allowed():self.reply(204,b'',content='text/plain')

    def handle_post(self):
        if not self.allowed(mutation=True):
            return
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if length <= 0 or length > 8192:
                raise ValueError('Invalid request size.')
            body = json.loads(self.rfile.read(length))
            if not isinstance(body, dict):
                raise ValueError('Expected an object.')
            path = urlparse(self.path).path
            if path in ('/api/auth/signup','/api/auth/login'):
                with connection() as db:
                    if not auth.rate_limit(db,self.client_address[0]):
                        return self.reply(429,{'error':'Too many authentication attempts. Try again in 15 minutes.'})
                with connection() as db:
                    user = auth.register(db,body.get('email'),body.get('password')) if path.endswith('signup') else auth.login(db,body.get('email'),body.get('password'))
                    if not user:
                        return self.reply(401,{'error':'Invalid email or password.'})
                    self.auth_cookie,self.csrf_value = auth.issue(db,user,auth.secret(DATA))
                return self.reply(201 if path.endswith('signup') else 200,{'user':auth.public_user(user),'csrf':self.csrf_value},cookie=True)
            if not self.require_user():
                return
            if path == '/api/auth/logout':
                with connection() as db:
                    db.execute('UPDATE auth_sessions SET revoked=1 WHERE id=?',(self.user['session_id'],))
                self.auth_cookie='';self.csrf_value=TOKEN
                return self.reply(200,{'ok':True,'csrf':TOKEN},cookie=True)
            if path == '/api/workspace/clear':
                return self.reply(200,clear_workspace(body.get('confirmation'),self.user['id']))
            if path == '/api/assets':
                if body.get('authorized') is not True:
                    raise ValueError('Confirm that this target is authorized.')
                kind=str(body.get('kind','domain'))
                domain = scope.target(str(body.get('domain', '')),kind)
                if not deployment.target_allowed(domain):return self.reply(403,{'error':'This target is not enabled by the deployment administrator.'})
                label = str(body.get('label', '')).strip()[:80] or domain
                with connection() as db:
                    db.execute('INSERT INTO assets(id,domain,label,created,kind,owner_id) VALUES (?,?,?,?,?,?)', (str(uuid4()), domain, label, now(),kind,self.user['id']))
                    audit(db, 'asset_added', domain,self.user['id'])
                return self.reply(201, {'ok': True})
            if path == '/api/scans':
                with connection() as db:
                    asset = db.execute('SELECT * FROM assets WHERE id=? AND owner_id=?', (str(body.get('asset_id')),self.user['id'])).fetchone()
                    if not asset:
                        return self.reply(404,{'error':'Asset not found.'})
                    if not deployment.target_allowed(asset['domain']):return self.reply(403,{'error':'This target is not enabled by the deployment administrator.'})
                    if db.execute("SELECT count(*) FROM scans WHERE status IN ('queued','running')").fetchone()[0] >= 10:
                        raise ValueError('Queue is full. Wait for a scan to finish.')
                    profile=str(body.get('profile','email'))
                    port_list=','.join(map(str,scope.ports(str(body.get('ports','80,443')))))
                    scope.validate_profile(asset,profile,port_list)
                    selector = selector_name(str(body.get('selector', '')).strip()) if profile=='email' else ''
                    scan_id = str(uuid4())
                    db.execute('INSERT INTO scans(id,asset_id,domain,selector,status,stage,created,finished,result,profile,ports,retest_of) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)', (scan_id, asset['id'], asset['domain'], selector, 'queued', 'Waiting for local worker', now(), None, None,profile,port_list,None))
                    audit(db, 'scan_queued', scan_id,self.user['id'])
                event = threading.Event()
                with LOCK:
                    EVENTS[scan_id] = event
                POOL.submit(execute_scan, scan_id, asset['domain'], selector, event,profile,port_list)
                return self.reply(202, {'id': scan_id})
            if path.startswith('/api/findings/'):
                key=path.rsplit('/',1)[-1];status=str(body.get('status',''));note=str(body.get('note','')).strip()[:1000]
                if status not in ('open','in_progress','pending_retest','accepted_risk','false_positive'):
                    raise ValueError('Use a supported review state. Verified fixes require a successful comparable retest.')
                if status in ('accepted_risk','false_positive') and not note:raise ValueError('Record the reason for this decision.')
                with connection() as db:
                    if not db.execute('SELECT f.id FROM findings f JOIN assets a ON a.id=f.asset_id WHERE f.id=? AND a.owner_id=?',(key,self.user['id'])).fetchone():return self.reply(404,{'error':'Finding not found.'})
                    db.execute('UPDATE findings SET status=?,note=? WHERE id=?',(status,note,key));audit(db,'finding_status_changed',key+':'+status,self.user['id'])
                return self.reply(200,{'ok':True})
            if path in ('/api/lab','/api/lab-mode'):
                if self.user['role']!='admin':return self.reply(403,{'error':'Lab controls require an administrator.'})
                if deployment.public_origin():return self.reply(403,{'error':'Container controls are local-only; no cloud Docker socket is exposed.'})
                with connection() as db:
                    if db.execute("SELECT 1 FROM scans WHERE status IN ('queued','running')").fetchone():return self.reply(409,{'error':'Finish or cancel scans before changing the shared lab.'})
                if path=='/api/lab':
                    try:return self.reply(200,lab_control.lifecycle(body.get('action')))
                    except (RuntimeError,OSError,__import__('subprocess').TimeoutExpired) as exc:return self.reply(503,{'error':str(exc)})
                fixed=body.get('fixed')
                if not isinstance(fixed,bool):raise ValueError('Choose vulnerable or corrected lab mode.')
                try:engine=lab_control.set_mode(fixed)
                except (RuntimeError,OSError,__import__('subprocess').TimeoutExpired) as exc:return self.reply(503,{'error':str(exc)})
                return self.reply(200,{'fixed':fixed,'engine':engine})
            if path.startswith('/api/cancel/'):
                scan_id = path.rsplit('/', 1)[-1]
                with connection() as db:
                    if not db.execute('SELECT s.id FROM scans s JOIN assets a ON a.id=s.asset_id WHERE s.id=? AND a.owner_id=?',(scan_id,self.user['id'])).fetchone():return self.reply(404,{'error':'Assessment not found.'})
                with LOCK:
                    event = EVENTS.get(scan_id)
                    if not event:
                        return self.reply(409, {'error': 'Assessment is already finished.'})
                    event.set()
                with connection() as db:
                    audit(db, 'scan_cancel_requested', scan_id,self.user['id'])
                return self.reply(200, {'ok': True})
            self.reply(404, {'error': 'Unknown endpoint.'})
        except sqlite3.IntegrityError:
            self.reply(409, {'error': 'That account or asset already exists.'})
        except (ValueError, TypeError, UnicodeError) as exc:
            self.reply(400, {'error': str(exc)})


def main():
    def stop_server(*_):
        raise KeyboardInterrupt

    server = None
    try:
        port = configured_port()
        deployment.validate(DATA)
        with database_lock(DB):
            refuse_legacy_listeners(DATA)
            configure_logging(DATA)
            # Binding must succeed before recovery is allowed to mutate stored jobs.
            server = LocalHTTPServer((deployment.bind_address(), port), Handler)
            try:
                initialize()
                backfill()
                signal.signal(signal.SIGTERM, stop_server)
                LOGGER.info('Local workspace started on port %s', port)
                try:
                    print(f'VulnX local workspace: http://127.0.0.1:{port}', flush=True)
                except (OSError, ValueError):
                    pass
                server.serve_forever()
            except KeyboardInterrupt:
                pass
            finally:
                with LOCK:
                    for event in list(EVENTS.values()):
                        event.set()
                # Keep database ownership until requests and all jobs have stopped.
                server.server_close()
                POOL.shutdown(wait=True)
        return 0
    except (OSError, ValueError, RuntimeError) as exc:
        try:
            print(str(exc), file=sys.stderr, flush=True)
        except (OSError, ValueError):
            pass
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
