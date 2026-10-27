"""Local process configuration and OS-held database ownership (macOS/Linux)."""
from contextlib import contextmanager
from pathlib import Path
import fcntl
import logging
from logging.handlers import RotatingFileHandler
import os

ROOT = Path(__file__).resolve().parent.parent


def data_directory():
    return Path(os.environ.get('VULNX_DATA_DIR', str(ROOT / '.runtime'))).expanduser().resolve()


def configured_port(value=None):
    port = int(value if value is not None else os.environ.get('VULNX_PORT', '8787'))
    if not 1024 <= port <= 65535:
        raise ValueError('Choose a port between 1024 and 65535.')
    return port


@contextmanager
def database_lock(database):
    # Resolve aliases; never unlink the lock file: that would permit a second inode/lock.
    path = Path(str(Path(database).resolve()) + '.lock')
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with path.open('a+') as handle:
        os.chmod(path, 0o600)
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('Another VulnX backend owns this database. Stop that instance first.') from None
        try:
            handle.seek(0); handle.truncate(); handle.write(str(os.getpid())); handle.flush()
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def configure_logging(directory):
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    logger = logging.getLogger('vulnx')
    logger.setLevel(logging.INFO)
    logger.propagate = False
    log_path = directory / 'server.log'
    handler = RotatingFileHandler(log_path, maxBytes=1024*1024, backupCount=2)
    os.chmod(log_path, 0o600)
    handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
    logger.addHandler(handler)
    # A failed diagnostic sink must never break an HTTP response.
    logging.raiseExceptions = False
    return logger
