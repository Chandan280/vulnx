"""Download the official pinned ZAP distribution and verify its published digest."""
from pathlib import Path
import hashlib
import urllib.request
import zipfile

root=Path(__file__).resolve().parent.parent/'.runtime/tools'
root.mkdir(parents=True,exist_ok=True)
archive=root/'zap.zip'
url='https://github.com/zaproxy/zaproxy/releases/download/v2.17.0/ZAP_2.17.0_Crossplatform.zip'
if not archive.exists():
    urllib.request.urlretrieve(url,archive)
digest=hashlib.sha256(archive.read_bytes()).hexdigest()
if digest!='94c8f767b1c2e94f0db66b3ae56514d5e3f5a728ee1b6c798e0c8fe2d61fbff0':
    raise SystemExit('ZAP checksum mismatch; refusing to extract or run it.')
with zipfile.ZipFile(archive) as bundle:
    bundle.extractall(root)
print('ZAP 2.17.0 verified and installed in',root)
