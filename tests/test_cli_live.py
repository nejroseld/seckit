"""Opt-in real-scanner CLI proposal/apply check in a disposable project."""
import _isolate  # noqa: F401
import json
import os
import select
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


@unittest.skipUnless(os.environ.get('GUARDKIT_LIVE_SCANNERS') == '1',
                     'set GUARDKIT_LIVE_SCANNERS=1 with scanners installed for the real CLI workflow')
class LiveCLIApprovalTests(unittest.TestCase):
    def test_dockerfile_proposal_then_apply_is_verified_and_preserves_local_edits(self):
        with tempfile.TemporaryDirectory(prefix='guardkit-cli-live-') as temp:
            root = Path(temp)
            docker = root / 'Dockerfile'
            docker.write_text('FROM alpine:3.20\nUSER root\nHEALTHCHECK CMD ["true"]\nCMD ["true"]\n')
            note = root / 'uncommitted.txt'
            note.write_bytes(b'local work\n')
            command = [sys.executable, '-m', 'guardkit', 'fix', '--root', temp]
            cwd = Path(__file__).resolve().parents[1]
            proposal = subprocess.run(command, cwd=cwd, capture_output=True, text=True, timeout=120)
            self.assertEqual(proposal.returncode, 0, proposal.stderr)
            data = json.loads(proposal.stdout)
            self.assertTrue(data['review_id'])
            self.assertTrue(any('USER 65532:65532' in plan['diff'] for plan in data['plans']))
            self.assertEqual(docker.read_text().splitlines()[1], 'USER root')

            applied = subprocess.run([*command, '--apply', data['review_id']], cwd=cwd,
                                     capture_output=True, text=True, timeout=180)
            self.assertIn(applied.returncode, (0, 1), applied.stderr)
            report = json.loads(applied.stdout)
            self.assertEqual(report['project_tests']['status'], 'not_run')
            self.assertEqual(docker.read_text().splitlines()[1], 'USER 65532:65532')
            self.assertEqual(note.read_bytes(), b'local work\n')

    def test_mcp_proposal_apply_rescans_and_rejects_replay(self):
        with tempfile.TemporaryDirectory(prefix='guardkit-mcp-live-') as temp:
            root = Path(temp)
            docker = root / 'Dockerfile'
            docker.write_bytes(b'FROM alpine:3.20\r\nUSER root\r\nCMD ["true"]\r\n')
            note = root / 'uncommitted.txt'
            note.write_bytes(b'local work\r\n')
            process = subprocess.Popen([sys.executable, '-m', 'guardkit', 'mcp', '--root', temp],
                                       cwd=Path(__file__).resolve().parents[1], stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)

            def call(message_id, name, arguments=None):
                request = {'jsonrpc': '2.0', 'id': message_id, 'method': 'tools/call',
                           'params': {'name': name, 'arguments': arguments or {}}}
                process.stdin.write(json.dumps(request) + '\n')
                process.stdin.flush()
                self.assertTrue(select.select([process.stdout], [], [], 180)[0], 'MCP server response timed out')
                response = json.loads(process.stdout.readline())
                self.assertEqual(response.get('id'), message_id)
                return response['result']

            try:
                proposed = call(1, 'propose_safe_fixes')['structuredContent']
                self.assertTrue(proposed.get('review_id'))
                self.assertTrue(any('USER 65532:65532' in plan['diff'] for plan in proposed['plans']))
                expected_ids = sorted({fid for plan in proposed['plans'] for fid in plan['finding_ids']})
                self.assertEqual(docker.read_bytes(), b'FROM alpine:3.20\r\nUSER root\r\nCMD ["true"]\r\n')

                applied = call(2, 'apply_safe_fixes', {'review_id': proposed['review_id']})
                report = applied['structuredContent']
                self.assertFalse(applied.get('isError'))
                self.assertTrue(report['complete'])
                self.assertEqual(report['resolved_ids'], expected_ids)
                self.assertEqual(docker.read_bytes(), b'FROM alpine:3.20\r\nUSER 65532:65532\r\nCMD ["true"]\r\n')
                self.assertEqual(note.read_bytes(), b'local work\r\n')

                replay = call(3, 'apply_safe_fixes', {'review_id': proposed['review_id']})
                self.assertTrue(replay.get('isError'))
                self.assertIn('already consumed', replay['structuredContent']['error'])
            finally:
                process.stdin.close()
                try:
                    process.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                errors = process.stderr.read() if process.returncode != 0 else ''
                process.stdout.close()
                process.stderr.close()
                if process.returncode != 0:
                    self.fail(errors[-2000:])
