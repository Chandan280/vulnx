"""Single-user, loopback-only milestone server. Never expose to a public interface."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
import io
import json
import mimetypes
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

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / '.runtime'
DB = DATA / 'vulnx.sqlite'
TOKEN = secrets.token_urlsafe(32)
POOL = ThreadPoolExecutor(max_workers=1)
EVENTS = {}
LOCK = threading.Lock()


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
    DATA.mkdir(exist_ok=True, mode=0o700)
    with connection() as db:
        db.executescript('''CREATE TABLE IF NOT EXISTS assets(id TEXT PRIMARY KEY, domain TEXT UNIQUE, label TEXT, created TEXT);
        CREATE TABLE IF NOT EXISTS scans(id TEXT PRIMARY KEY, asset_id TEXT, domain TEXT, selector TEXT, status TEXT, stage TEXT, created TEXT, finished TEXT, result TEXT);
        CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, action TEXT, detail TEXT, created TEXT);''')
        db.execute("UPDATE scans SET status='failed',stage='Interrupted by server restart',finished=? WHERE status IN ('running','queued')", (now(),))


def audit(db, action, detail):
    db.execute('INSERT INTO audit(action,detail,created) VALUES (?,?,?)', (action, detail, now()))


def state():
    with connection() as db:
        assets = [dict(r) for r in db.execute('SELECT * FROM assets ORDER BY created DESC')]
        scans = [dict(r) for r in db.execute('SELECT * FROM scans ORDER BY created DESC')]
    for scan in scans:
        scan['result'] = json.loads(scan['result']) if scan['result'] else None
    return {'assets': assets, 'scans': scans}


def set_scan(scan_id, **fields):
    with connection() as db:
        db.execute('UPDATE scans SET ' + ','.join(k + '=?' for k in fields) + ' WHERE id=?', (*fields.values(), scan_id))


def execute_scan(scan_id, domain, selector, event):
    try:
        if event.is_set():
            raise Cancelled()
        set_scan(scan_id, status='running', stage='Starting DNS queries')
        result = assess(domain, selector, event, lambda stage: set_scan(scan_id, stage=stage))
        if event.is_set():
            raise Cancelled()
        set_scan(scan_id, status=result['status'], stage='Assessment finished', finished=now(), result=json.dumps(result))
    except Cancelled:
        set_scan(scan_id, status='cancelled', stage='Cancelled by user', finished=now())
    except Exception:
        set_scan(scan_id, status='failed', stage='Internal assessment error; check server logs', finished=now())
        import traceback
        traceback.print_exc()
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
    styles['Title'].textColor = colors.HexColor('#146b50')
    story = []
    def p(text, style='BodyText'):
        story.append(Paragraph(escape(str(text)).replace('\n', '<br/>'), styles[style]))
        story.append(Spacer(1, 9))
    p('VulnX | Email configuration assessment', 'Title')
    for key in ('id', 'domain', 'selector', 'status', 'created', 'finished'):
        p(key.capitalize() + ': ' + str(scan.get(key) or 'Not supplied'))
    p('Scope and method', 'Heading2')
    p('User-approved domain. DNS TXT queries using the installed dig executable; VulnX basic rule set 0.1. No message delivery or active web testing.')
    result = scan.get('result') or {}
    for check in result.get('checks', []):
        p(check['protocol'] + ' — ' + check['assessment'], 'Heading2')
        p('Query: ' + str(check.get('query') or 'Not performed'))
        p('DNS status: ' + check['status'])
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
    doc.build(story)
    return buffer.getvalue()


class Handler(BaseHTTPRequestHandler):
    def reply(self, code, body, content='application/json', cookie=False, download=None):
        raw = json.dumps(body).encode() if content == 'application/json' else body
        self.send_response(code)
        self.send_header('Content-Type', content)
        self.send_header('Content-Length', str(len(raw)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        if cookie:
            self.send_header('Set-Cookie', 'vulnx_session=' + TOKEN + '; HttpOnly; SameSite=Strict; Path=/')
        if download:
            self.send_header('Content-Disposition', 'attachment; filename="' + download + '"')
        self.end_headers()
        self.wfile.write(raw)

    def allowed(self, mutation=False):
        host = self.headers.get('Host', '')
        expected = '127.0.0.1:' + str(self.server.server_port)
        if host not in (expected, 'localhost:' + str(self.server.server_port)):
            self.reply(403, {'error': 'Loopback host required.'})
            return False
        origin = self.headers.get('Origin')
        if origin and origin != 'http://' + host:
            self.reply(403, {'error': 'Cross-origin request rejected.'})
            return False
        if mutation and (self.headers.get('X-VulnX-CSRF') != TOKEN or ('vulnx_session=' + TOKEN) not in self.headers.get('Cookie', '').split('; ')):
            self.reply(403, {'error': 'Refresh the local workspace session.'})
            return False
        return True

    def do_GET(self):
        if not self.allowed():
            return
        path = urlparse(self.path).path
        if path == '/api/session':
            return self.reply(200, {'csrf': TOKEN}, cookie=True)
        if path.startswith('/api/') and ('vulnx_session=' + TOKEN) not in self.headers.get('Cookie', '').split('; '):
            return self.reply(401, {'error': 'Open the local workspace first.'})
        if path == '/api/state':
            return self.reply(200, state())
        if path == '/api/readiness':
            return self.reply(200, {'dns': bool(shutil.which('dig')), 'nmap': bool(shutil.which('nmap')), 'pdf': __import__('importlib.util', fromlist=['find_spec']).find_spec('reportlab') is not None, 'mode': 'Single-user local milestone', 'network': 'Not checked; each assessment records actual resolver success or failure.'})
        if path.startswith('/api/reports/'):
            key = path.rsplit('/', 1)[-1]
            scan_id, _, fmt = key.partition('.')
            scan = next((s for s in state()['scans'] if s['id'] == scan_id), None)
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
            if path == '/api/assets':
                if body.get('authorized') is not True:
                    raise ValueError('Confirm that this target is authorized.')
                domain = domain_name(str(body.get('domain', '')))
                label = str(body.get('label', '')).strip()[:80] or domain
                with connection() as db:
                    db.execute('INSERT INTO assets VALUES (?,?,?,?)', (str(uuid4()), domain, label, now()))
                    audit(db, 'asset_added', domain)
                return self.reply(201, {'ok': True})
            if path == '/api/scans':
                with connection() as db:
                    asset = db.execute('SELECT * FROM assets WHERE id=?', (str(body.get('asset_id')),)).fetchone()
                    if not asset:
                        raise ValueError('Select an existing approved asset.')
                    if db.execute("SELECT count(*) FROM scans WHERE status IN ('queued','running')").fetchone()[0] >= 10:
                        raise ValueError('Queue is full. Wait for a scan to finish.')
                    selector = selector_name(str(body.get('selector', '')).strip())
                    scan_id = str(uuid4())
                    db.execute('INSERT INTO scans VALUES (?,?,?,?,?,?,?,?,?)', (scan_id, asset['id'], asset['domain'], selector, 'queued', 'Waiting for local worker', now(), None, None))
                    audit(db, 'scan_queued', scan_id)
                event = threading.Event()
                with LOCK:
                    EVENTS[scan_id] = event
                POOL.submit(execute_scan, scan_id, asset['domain'], selector, event)
                return self.reply(202, {'id': scan_id})
            if path.startswith('/api/cancel/'):
                scan_id = path.rsplit('/', 1)[-1]
                with LOCK:
                    event = EVENTS.get(scan_id)
                    if not event:
                        return self.reply(409, {'error': 'Assessment is already finished.'})
                    event.set()
                with connection() as db:
                    audit(db, 'scan_cancel_requested', scan_id)
                return self.reply(200, {'ok': True})
            self.reply(404, {'error': 'Unknown endpoint.'})
        except sqlite3.IntegrityError:
            self.reply(409, {'error': 'That domain is already in your assets.'})
        except (ValueError, TypeError, UnicodeError) as exc:
            self.reply(400, {'error': str(exc)})


if __name__ == '__main__':
    initialize()
    port = int(os.environ.get('VULNX_PORT', '8787'))
    server = ThreadingHTTPServer(('127.0.0.1', port), Handler)
    print(f'VulnX local workspace: http://127.0.0.1:{port}', flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        for event in list(EVENTS.values()):
            event.set()
        server.server_close()
        POOL.shutdown(wait=True)
