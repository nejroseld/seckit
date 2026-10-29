"""Opt-in real-scanner CLI approval/remediation check in a disposable project."""
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import time
import unittest


@unittest.skipUnless(os.name == 'posix' and os.environ.get('GUARDKIT_LIVE_SCANNERS') == '1',
                     'set GUARDKIT_LIVE_SCANNERS=1 with scanners installed for the real PTY workflow')
class LiveCLIApprovalTests(unittest.TestCase):
    def test_approved_dockerfile_fix_is_verified_and_preserves_local_edits(self):
        import pty
        with tempfile.TemporaryDirectory(prefix='guardkit-cli-live-') as temp:
            root = Path(temp)
            docker = root / 'Dockerfile'
            docker.write_text('FROM alpine:3.20\nUSER root\nHEALTHCHECK CMD ["true"]\nCMD ["true"]\n')
            (root / 'trivy.yaml').write_text('severity: [UNKNOWN]\n')
            (root / '.trivyignore').write_text('DS-0002\n')
            note = root / 'uncommitted.txt'
            note.write_bytes(b'local work\n')
            master, slave = pty.openpty()
            process = subprocess.Popen([sys.executable, '-m', 'guardkit', 'fix', '--root', temp, '--skip-tests'],
                                       cwd=Path(__file__).resolve().parents[1], stdin=slave, stdout=slave, stderr=slave,
                                       start_new_session=True)
            os.close(slave)
            transcript = b''
            approved = False
            deadline = time.monotonic() + 90
            try:
                while time.monotonic() < deadline:
                    if select.select([master], [], [], 0.2)[0]:
                        try:
                            chunk = os.read(master, 8192)
                        except OSError:
                            break
                        if not chunk:
                            break
                        transcript += chunk
                        if b'[y/N]' in transcript and not approved:
                            self.assertIn(b'-USER root', transcript)
                            self.assertIn(b'+USER 65532:65532', transcript)
                            self.assertEqual(docker.read_text().splitlines()[1], 'USER root')
                            os.write(master, b'y\n')
                            approved = True
                    elif process.poll() is not None:
                        break
                process.wait(timeout=5)
                self.assertTrue(approved, 'CLI did not request approval')
                self.assertIn(process.returncode, (0, 1), transcript.decode(errors='replace')[-1500:])
                self.assertIn(b'1 finding(s) no longer reported', transcript)
                self.assertEqual(docker.read_text().splitlines()[1], 'USER 65532:65532')
                self.assertEqual(note.read_bytes(), b'local work\n')
            finally:
                os.close(master)
                if process.poll() is None:
                    process.kill()
                process.wait()
