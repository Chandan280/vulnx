"""Real subprocess regressions: ownership/recovery and detached HTTP logging."""
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request
from unittest.mock import patch
from backend.runtime import configured_port

ROOT=Path(__file__).resolve().parent.parent


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0))
        return sock.getsockname()[1]


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.data=Path(self.temp.name)
        self.processes=[]

    def tearDown(self):
        for p in self.processes:
            if p.poll() is None:
                p.terminate()
                try:p.wait(timeout=8)
                except subprocess.TimeoutExpired:p.kill();p.wait()
            for stream in (p.stdout,p.stderr):
                if stream and not stream.closed:stream.close()
        self.temp.cleanup()

    def launch(self,port=None):
        port=port or free_port()
        env=dict(os.environ,VULNX_DATA_DIR=str(self.data),VULNX_PORT=str(port))
        p=subprocess.Popen([sys.executable,'-u','backend/server.py'],cwd=ROOT,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        self.processes.append(p)
        return p,port

    def ready(self,p,port):
        deadline=time.monotonic()+8
        while time.monotonic()<deadline:
            if p.poll() is not None:self.fail('Backend exited: '+p.stderr.read())
            try:
                with urllib.request.urlopen(f'http://127.0.0.1:{port}/api/session',timeout=.5) as response:
                    if response.status==200:return
            except (OSError,ValueError):pass
            time.sleep(.05)
        self.fail('Backend did not become ready')

    def seed(self):
        with sqlite3.connect(self.data/'vulnx.sqlite') as db:
            db.executemany('INSERT INTO scans(id,status) VALUES (?,?)',[('active','running'),('waiting','queued')])

    def states(self):
        with sqlite3.connect(self.data/'vulnx.sqlite') as db:return dict(db.execute('SELECT id,status FROM scans'))

    def test_http_survives_closed_stdout_and_stderr(self):
        p,port=self.launch();self.ready(p,port)
        p.stdout.close();p.stderr.close()
        for _ in range(3):
            with urllib.request.urlopen(f'http://127.0.0.1:{port}/api/session',timeout=2) as response:self.assertEqual(response.status,200)
        self.assertIsNone(p.poll())

    def test_second_port_same_database_cannot_recover_active_jobs(self):
        p,port=self.launch();self.ready(p,port);self.seed()
        other,_=self.launch();out,err=other.communicate(timeout=5)
        self.assertEqual(other.returncode,1);self.assertIn('owns this database',err)
        self.assertEqual(self.states(),{'active':'running','waiting':'queued'})
        self.ready(p,port)

    def test_crashed_owner_releases_lock_and_next_owner_recovers(self):
        p,port=self.launch();self.ready(p,port);self.seed();p.kill();p.wait(timeout=5)
        other,port=self.launch();self.ready(other,port)
        self.assertEqual(self.states(),{'active':'failed','waiting':'failed'})

    def test_occupied_port_does_not_run_recovery(self):
        p,port=self.launch();self.ready(p,port);p.terminate();p.wait(timeout=5);self.seed()
        with socket.socket() as sock:
            sock.bind(('127.0.0.1',0));sock.listen()
            other,_=self.launch(sock.getsockname()[1]);other.communicate(timeout=5)
            self.assertEqual(other.returncode,1)
        self.assertEqual(self.states(),{'active':'running','waiting':'queued'})

    def test_verifier_honors_configured_port(self):
        env=dict(os.environ,VULNX_PORT='9899')
        run=subprocess.run([sys.executable,'-c','from scripts.verify_local import BASE; print(BASE)'],cwd=ROOT,env=env,capture_output=True,text=True,check=True)
        self.assertEqual(run.stdout.strip(),'http://127.0.0.1:9899/api/')
        with patch.dict(os.environ,{'VULNX_PORT':'9899'}):
            self.assertEqual(configured_port(),9899)
            self.assertEqual(configured_port(9799),9799)
            with self.assertRaises(ValueError):configured_port(0)
