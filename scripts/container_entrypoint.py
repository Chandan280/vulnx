"""Prepare the dedicated Railway data mount, then drop privileges before serving."""
import os
from pathlib import Path

data=Path('/data')
if os.environ.get('RAILWAY_VOLUME_MOUNT_PATH') != str(data):
    raise SystemExit('Attach a persistent Railway volume at /data before deployment.')
data.mkdir(exist_ok=True,mode=0o700)
if os.getuid()==0:
    os.chown(data,10001,10001)
    # Existing database/log/key files also need to survive changes in image UID.
    for path in data.rglob('*'):
        if not path.is_symlink():os.chown(path,10001,10001)
    os.setgroups([]);os.setgid(10001);os.setuid(10001)
os.execvp('python',['python','backend/server.py'])
