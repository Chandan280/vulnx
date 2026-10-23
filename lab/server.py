"""Intentionally vulnerable, loopback-only training fixture. Contains no user data."""
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import html
import json
import socketserver
import sqlite3
import ssl
import threading
from urllib.parse import urlparse, parse_qs

ROOT=Path(__file__).resolve().parent.parent
DATA=ROOT/'.runtime/lab'
DATA.mkdir(parents=True,exist_ok=True)


def fixed():
    return (DATA/'fixed').exists()


class Web(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed=urlparse(self.path)
        query=parse_qs(parsed.query)
        body='<h1>VulnX controlled training lab</h1><p>Local test fixture; no real user data.</p><a href="/search?q=hello">Search</a> <a href="/item?id=1">Item</a><form action="/search"><input name="q"><button>Search</button></form>'
        if parsed.path=='/search':
            text=query.get('q',[''])[0]
            body+='<p>Search: '+(html.escape(text) if fixed() else text)+'</p>'
        if parsed.path=='/item':
            with sqlite3.connect(':memory:') as db:
                db.executescript("CREATE TABLE items(id INTEGER, name TEXT); INSERT INTO items VALUES (1,'Training item'),(2,'Another fixture');")
                try:
                    value=query.get('id',['1'])[0]
                    rows=db.execute('SELECT name FROM items WHERE id=?',(value,)).fetchall() if fixed() else db.execute('SELECT name FROM items WHERE id='+value).fetchall()
                    body+='<pre>'+html.escape(str(rows))+'</pre>'
                except sqlite3.Error as exc:
                    body+='<pre>'+('Invalid item' if fixed() else 'SQLite error: '+html.escape(str(exc)))+'</pre>'
        raw=('<!doctype html><html><head><title>VulnX local lab</title></head><body>'+body+'</body></html>').encode()
        self.send_response(200);self.send_header('Content-Type','text/html; charset=utf-8');self.send_header('Content-Length',str(len(raw)))
        if fixed():
            self.send_header('Content-Security-Policy',"default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
            self.send_header('X-Content-Type-Options','nosniff')
            self.send_header('X-Frame-Options','DENY')
        self.end_headers();self.wfile.write(raw)
    def log_message(self,*args):pass


def certificate():
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes,serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    import ipaddress
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'VulnX local lab')])
    cert=x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(datetime.now(timezone.utc)-timedelta(days=1)).not_valid_after(datetime.now(timezone.utc)+timedelta(days=7)).add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('127.0.0.1')),x509.DNSName('localhost')]),critical=False).sign(key,hashes.SHA256())
    (DATA/'key.pem').write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    (DATA/'key.pem').chmod(0o600)
    (DATA/'cert.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))


class DNS(socketserver.BaseRequestHandler):
    def handle(self):
        import dns.message,dns.rrset,dns.rcode,dns.rdatatype
        raw,sock=self.request
        try:
            query=dns.message.from_wire(raw);response=dns.message.make_response(query)
            question=query.question[0];name=str(question.name).lower()
            records={'mail.vulnx.test.':'v=spf1 -all' if fixed() else 'v=spf1 +all','_dmarc.mail.vulnx.test.':'v=DMARC1; p=reject' if fixed() else 'v=DMARC1; p=none','test._domainkey.mail.vulnx.test.':'v=DKIM1; p='}
            if name in records and question.rdtype==dns.rdatatype.TXT:
                response.answer.append(dns.rrset.from_text(name,60,'IN','TXT','"'+records[name]+'"'))
            else:response.set_rcode(dns.rcode.NXDOMAIN)
            sock.sendto(response.to_wire(),self.client_address)
        except Exception:pass


if __name__=='__main__':
    certificate()
    http=ThreadingHTTPServer(('127.0.0.1',18080),Web)
    https=ThreadingHTTPServer(('127.0.0.1',18443),Web)
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(DATA/'cert.pem',DATA/'key.pem');https.socket=context.wrap_socket(https.socket,server_side=True)
    dns_server=socketserver.ThreadingUDPServer(('127.0.0.1',15353),DNS)
    for server in (http,https,dns_server):threading.Thread(target=server.serve_forever,daemon=True).start()
    print('VulnX lab: HTTP 18080, TLS 18443, DNS 15353, all bound to 127.0.0.1. Ctrl+C stops.',flush=True)
    try:threading.Event().wait()
    except KeyboardInterrupt:
        for server in (http,https,dns_server):server.shutdown();server.server_close()
