import contextlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from pentestlab.cli import main
from pentestlab.reporting import envelope, markdown, validate

ROOT = Path(__file__).resolve().parents[1]


class Handler(BaseHTTPRequestHandler):
    requests = []

    def do_HEAD(self):
        self.server.observed.append(self.path)
        self.send_response(302 if self.path == '/redirect' else 200)
        self.send_header('X-Lab', 'local-only')
        if self.path == '/redirect':
            self.send_header('Location', '/should-not-follow')
        self.end_headers()

    def log_message(self, *args):
        pass


class IntegrationTests(unittest.TestCase):
    def test_real_http_cli_and_markdown_pipeline(self):
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        server.observed = []
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as directory:
                result_path = Path(directory) / 'headers.json'
                report_path = Path(directory) / 'report.md'
                url = f'http://127.0.0.1:{server.server_port}/redirect'
                # Clear proxy environment so this loopback integration never goes through a proxy.
                import os
                environment = {key: value for key, value in os.environ.items() if 'proxy' not in key.lower()}
                environment['NO_PROXY'] = '*'
                result = subprocess.run([sys.executable, '-m', 'pentestlab', 'headers', url, '--output', str(result_path)], cwd=ROOT, env=environment, capture_output=True, text=True, timeout=15)
                self.assertEqual(result.returncode, 0, result.stderr)
                document = validate(json.loads(result_path.read_text()))
                self.assertEqual(document['observations']['status'], 302)
                self.assertEqual(server.observed, ['/redirect'])
                self.assertEqual(main(['report', str(result_path), '--output', str(report_path)]), 0)
                self.assertIn('local-only', report_path.read_text())
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)

    def test_real_tcp_server_greeting(self):
        # Start only our own loopback service on an OS-selected free port.
        process = subprocess.Popen([sys.executable, '-u', 'server.py', '--port', '0', '--timeout', '5'], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        lines = []
        ready = threading.Event()
        def read_startup():
            lines.append(process.stdout.readline())
            ready.set()
        reader = threading.Thread(target=read_startup, daemon=True)
        reader.start()
        try:
            self.assertTrue(ready.wait(8), 'server did not become ready')
            self.assertTrue(lines[0].startswith('Listening on 127.0.0.1:'), lines)
            port = int(lines[0].strip().rsplit(':', 1)[1])
            with socket.create_connection(('127.0.0.1', port), timeout=3) as client:
                self.assertIn(b'Thank you for connecting 127.0.0.1', client.recv(1024))
            self.assertEqual(process.wait(timeout=8), 0)
        finally:
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=5)
            reader.join(timeout=1)

    def test_offline_scan_envelope(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(main(['scan', '--xml', str(ROOT/'examples/nmap.xml')]), 0)
        document = validate(json.loads(output.getvalue()))
        self.assertEqual(document['options']['mode'], 'offline-xml')
        self.assertNotIn('ports', document['options'])
        self.assertEqual(len(document['observations']['hosts']), 2)

    def test_operational_failure_is_structured(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(main(['scan', '--xml', 'nonexistent.xml']), 2)
        result = validate(json.loads(output.getvalue()))
        self.assertEqual(result['status'], 'error')
        self.assertTrue(result['errors'])

    def test_no_overwrite_and_no_request_when_output_exists(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'result.json'
            path.write_text('keep')
            with patch('inforecon.inspect_headers') as request, contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                main(['headers', 'http://127.0.0.1', '--output', str(path)])
            request.assert_not_called()
            self.assertEqual(path.read_text(), 'keep')

    def test_report_rejects_legacy_or_unknown_schema(self):
        for document in ({'hosts': []}, {'schema_version': 2}, [], {'schema_version': True}):
            with self.assertRaises(ValueError):
                markdown([document])

    def test_report_fences_untrusted_strings(self):
        document = envelope('headers', '<script>alert(1)</script>```', {}, {'headers': [['X-Test', '````']]})
        output = markdown([document])
        self.assertIn('`````json', output)
        self.assertEqual(output.count('`````'), 2)

    def test_report_validates_before_writing(self):
        with tempfile.TemporaryDirectory() as directory:
            bad = Path(directory)/'bad.json'
            target = Path(directory)/'out.md'
            bad.write_text('{}')
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(['report', str(bad), '--output', str(target)]), 2)
            self.assertFalse(target.exists())
