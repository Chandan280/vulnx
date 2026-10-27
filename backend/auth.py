"""Password authentication, revocable JWT sessions and lossless ownership migration."""
from http.cookies import SimpleCookie
import hashlib
import json
import os
import re
import secrets
import time
from uuid import uuid4
import bcrypt
import jwt

ADMIN_ID = 'migration-admin'
ISSUER = 'vulnx'
AUDIENCE = 'vulnx-browser'
TTL = 8 * 3600


def password_hash(password):
    if not isinstance(password, str) or len(password) < 12 or len(password.encode()) > 72:
        raise ValueError('Use a password of at least 12 characters and at most 72 UTF-8 bytes.')
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()


def email_address(value):
    email = str(value).strip().lower()
    if len(email) > 254 or not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', email):
        raise ValueError('Enter a valid email address.')
    return email


def private_file(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as handle:
        handle.write(value)


def secret(data):
    supplied = os.environ.get('VULNX_JWT_SECRET')
    if supplied:
        if len(supplied) < 32:
            raise ValueError('VULNX_JWT_SECRET must contain at least 32 characters.')
        return supplied
    path = data / 'jwt-secret'
    if not path.exists():
        try: private_file(path, secrets.token_urlsafe(48))
        except FileExistsError: pass
    return path.read_text().strip()


def migrate(db, data):
    db.executescript('''
        CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,email TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,role TEXT NOT NULL DEFAULT 'user',created INTEGER NOT NULL,disabled INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS auth_sessions(id TEXT PRIMARY KEY,user_id TEXT NOT NULL,csrf TEXT NOT NULL,expires INTEGER NOT NULL,revoked INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS auth_attempts(key TEXT PRIMARY KEY,started INTEGER NOT NULL,count INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY,applied INTEGER NOT NULL);
    ''')
    if not db.execute('SELECT 1 FROM users WHERE id=?', (ADMIN_ID,)).fetchone():
        path = data / 'bootstrap-admin.json'
        if not path.exists():
            private_file(path, json.dumps({'email':'admin@vulnx.local','password':secrets.token_urlsafe(24)}, indent=2))
        credentials = json.loads(path.read_text())
        db.execute('INSERT INTO users(id,email,password_hash,role,created) VALUES (?,?,?,?,?)', (ADMIN_ID,credentials['email'],password_hash(credentials['password']),'admin',int(time.time())))
    columns = {r['name'] for r in db.execute('PRAGMA table_info(assets)')}
    if 'owner_id' not in columns:
        # Rebuild to replace the old global UNIQUE(domain) with per-user uniqueness.
        db.execute('CREATE TABLE assets_owned(id TEXT PRIMARY KEY,domain TEXT NOT NULL,label TEXT,created TEXT,kind TEXT,owner_id TEXT NOT NULL REFERENCES users(id),UNIQUE(owner_id,domain))')
        db.execute('INSERT INTO assets_owned SELECT id,domain,label,created,kind,? FROM assets', (ADMIN_ID,))
        db.execute('DROP TABLE assets')
        db.execute('ALTER TABLE assets_owned RENAME TO assets')
    if 'owner_id' not in {r['name'] for r in db.execute('PRAGMA table_info(audit)')}:
        db.execute('ALTER TABLE audit ADD COLUMN owner_id TEXT')
        db.execute('UPDATE audit SET owner_id=?', (ADMIN_ID,))
    db.execute('INSERT OR IGNORE INTO schema_migrations VALUES (1,?)', (int(time.time()),))
    secret(data)


def public_user(user):
    return {key:user[key] for key in ('id','email','role')}


def issue(db, user, key):
    stamp = int(time.time())
    ident = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(32)
    db.execute('DELETE FROM auth_sessions WHERE expires<?', (stamp,))
    db.execute('INSERT INTO auth_sessions VALUES (?,?,?,?,0)', (ident,user['id'],csrf,stamp+TTL))
    token = jwt.encode({'sub':user['id'],'jti':ident,'iat':stamp,'exp':stamp+TTL,'iss':ISSUER,'aud':AUDIENCE},key,algorithm='HS256')
    return token, csrf


def validate(db, token, key):
    try:
        claims = jwt.decode(token,key,algorithms=['HS256'],issuer=ISSUER,audience=AUDIENCE,options={'require':['sub','jti','iat','exp','iss','aud']})
        row = db.execute('SELECT u.*,s.id AS session_id,s.csrf FROM users u JOIN auth_sessions s ON s.user_id=u.id WHERE u.id=? AND s.id=? AND s.revoked=0 AND s.expires>? AND u.disabled=0', (claims['sub'],claims['jti'],int(time.time()))).fetchone()
        return dict(row) if row else None
    except jwt.InvalidTokenError:
        return None


def cookie_value(headers, name):
    try:
        jar = SimpleCookie(); jar.load(headers.get('Cookie',''))
        return jar[name].value if name in jar else ''
    except Exception:
        return ''


def rate_limit(db, peer):
    stamp = int(time.time())
    key = hashlib.sha256(peer.encode()).hexdigest()
    db.execute('DELETE FROM auth_attempts WHERE started<?', (stamp-900,))
    row = db.execute('SELECT count FROM auth_attempts WHERE key=?',(key,)).fetchone()
    if row and row['count'] >= 20:
        return False
    db.execute('INSERT INTO auth_attempts VALUES (?,?,1) ON CONFLICT(key) DO UPDATE SET count=count+1',(key,stamp))
    return True


def register(db, email, password):
    user = {'id':str(uuid4()),'email':email_address(email),'role':'user'}
    db.execute('INSERT INTO users(id,email,password_hash,created) VALUES (?,?,?,?)',(user['id'],user['email'],password_hash(password),int(time.time())))
    return user


def login(db, email, password):
    row = db.execute('SELECT * FROM users WHERE email=? AND disabled=0',(str(email).strip().lower(),)).fetchone()
    # Perform an expensive check for unknown users too, reducing enumeration by timing.
    hashed = row['password_hash'] if row else '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYzu2CQdSuZ9qH2CC5dTQbG9t5zJQ9wG'
    if not isinstance(password,str) or len(password.encode()) > 72:
        return None
    valid = bcrypt.checkpw(password.encode(),hashed.encode())
    return dict(row) if row and valid else None
