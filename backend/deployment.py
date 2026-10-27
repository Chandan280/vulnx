"""Explicit hosted configuration; local defaults remain loopback-only."""
import os
from urllib.parse import urlsplit


def bind_address():
    return os.environ.get('VULNX_BIND','127.0.0.1')


def public_origin():
    return os.environ.get('VULNX_PUBLIC_ORIGIN','').rstrip('/')


def allowed_hosts(port):
    if not public_origin():return {f'127.0.0.1:{port}',f'localhost:{port}'}
    return {v.strip() for v in os.environ.get('VULNX_ALLOWED_HOSTS','').split(',') if v.strip()}


def allowed_origins(host):
    return {public_origin()} if public_origin() else {'http://'+host}


def validate(data):
    if bind_address() not in ('127.0.0.1','0.0.0.0'):
        raise ValueError('VULNX_BIND must be 127.0.0.1 or 0.0.0.0.')
    if bind_address()=='0.0.0.0':
        parsed=urlsplit(public_origin())
        if parsed.scheme!='https' or not parsed.netloc or parsed.path or parsed.query or parsed.fragment or parsed.username:
            raise ValueError('Public binding requires an explicit HTTPS VULNX_PUBLIC_ORIGIN.')
        if not allowed_hosts(0):raise ValueError('Public binding requires VULNX_ALLOWED_HOSTS.')
        if not os.environ.get('VULNX_ALLOWED_TARGETS'):raise ValueError('Public binding requires an explicit VULNX_ALLOWED_TARGETS scan allowlist.')
        if len(os.environ.get('VULNX_JWT_SECRET',''))<32:raise ValueError('Public binding requires a persistent VULNX_JWT_SECRET of at least 32 characters.')
    if os.environ.get('VULNX_REQUIRE_PERSISTENT_STORAGE')=='1':
        mount=os.environ.get('RAILWAY_VOLUME_MOUNT_PATH')
        if not mount or str(data)!=mount.rstrip('/'):
            raise ValueError('A Railway persistent volume mounted at VULNX_DATA_DIR is required before starting.')


def target_allowed(value):
    if not public_origin():return True
    allowed={v.strip() for v in os.environ.get('VULNX_ALLOWED_TARGETS','').split(',')}
    return value in allowed
