import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from guardkit import cli, provision

class ProvisionTests(unittest.TestCase):
    def test_download_corruption_fails_before_execute(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(provision, 'fetch', return_value=b'corrupted'), patch.object(provision, 'compatible') as execute:
                with self.assertRaises(provision.ProvisionError):
                    provision._trivy(Path(tmp))
                execute.assert_not_called()
            self.assertFalse(list(Path(tmp).rglob('trivy')))

    @unittest.skipIf(os.name == "nt", "Synthetic POSIX archive fixture")
    def test_archive_extracts_only_verified_binary_and_reuses_cache(self):
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode='w:gz') as archive:
            for name, content in [('trivy', b'verified-binary'), ('../../escape', b'bad')]:
                member = tarfile.TarInfo(name); member.size = len(content)
                archive.addfile(member, io.BytesIO(content))
        binary = data.getvalue()
        manifest = (hashlib.sha256(binary).hexdigest() + f'  trivy_{provision.TRIVY}_Linux-64bit.tar.gz\n').encode()
        with tempfile.TemporaryDirectory() as tmp, patch.object(provision.platform, 'system', return_value='Linux'), patch.object(provision.platform, 'machine', return_value='x86_64'), patch.object(provision, 'CHECKSUM_SHA256', hashlib.sha256(manifest).hexdigest()), patch.object(provision, 'fetch', side_effect=[manifest, binary]) as fetch, patch.object(provision, 'compatible', return_value=True):
            result = Path(provision._trivy(Path(tmp)))
            self.assertEqual(result.read_bytes(), b'verified-binary')
            self.assertEqual(fetch.call_count, 2)
            self.assertEqual(provision._trivy(Path(tmp)), str(result))
            self.assertEqual(fetch.call_count, 2)
            self.assertFalse((Path(tmp) / 'escape').exists())

    def test_reuses_exact_installed_versions(self):
        with patch.object(provision.shutil, 'which', side_effect=lambda name: '/trusted/' + name), patch.object(provision, 'compatible', return_value=True), patch.object(provision, '_trivy') as install:
            self.assertEqual(set(provision.tools()), {'trivy', 'semgrep'})
            install.assert_not_called()

    def test_http_download_rejected(self):
        with self.assertRaises(provision.ProvisionError): provision.fetch('http://example.test/tool')

class CLITests(unittest.TestCase):
    def run_cli(self, args):
        output, errors = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            code = cli.main(args)
        return code, output.getvalue(), errors.getvalue()

    def test_init_standard_project_and_idempotence(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(provision, 'tools', return_value={'trivy':'trivy','semgrep':'semgrep'}):
            root = Path(tmp); (root/'package.json').write_text('{"dependencies":{"next":"15","react":"19"}}')
            code, out, err = self.run_cli(['init','--root',tmp,'--json'])
            self.assertEqual(code,0)
            self.assertIn('Next.js',json.loads(out)['stack'])
            self.assertEqual(len(json.loads(out)['agent_files_created']),3)
            code, out, err = self.run_cli(['init','--root',tmp,'--json'])
            self.assertEqual(json.loads(out)['agent_files_created'],[])

    def test_scan_errors_never_look_clean(self):
        with patch.object(cli, '_scan', return_value={'findings':[], 'errors':['scanner offline']}):
            code,out,err = self.run_cli(['scan','--json'])
            self.assertEqual(code,2)
            self.assertEqual(json.loads(out)['errors'],['scanner offline'])

    def test_scan_exit_status_findings(self):
        with patch.object(cli, '_scan', return_value={'findings':[{'id':'a'}], 'errors':[]}):
            code,out,err = self.run_cli(['scan','--json'])
            self.assertEqual(code,1)

    def test_fix_refuses_noninteractive_approval(self):
        with tempfile.TemporaryDirectory() as tmp:
            finding={'id':'secret','title':'Secret','file':'.env'}
            with patch.object(cli, '_scan', return_value={'findings':[finding], 'errors':[]}), patch.object(sys.stdin,'isatty',return_value=False):
                code,out,err=self.run_cli(['fix','--root',tmp])
                self.assertEqual(code,2)
                self.assertFalse((Path(tmp)/'.gitignore').exists())

    def test_mcp_cli_callback_through_protocol(self):
        request='\n'.join(json.dumps(x) for x in [
            {'jsonrpc':'2.0','id':1,'method':'initialize'},
            {'jsonrpc':'2.0','id':2,'method':'tools/call','params':{'name':'scan','arguments':{}}}])
        with patch.object(sys,'stdin',io.StringIO(request)), patch.object(cli, '_scan', return_value={'findings':[],'errors':[]}) as scanner:
            code,out,err=self.run_cli(['mcp'])
            self.assertEqual(code,0)
            responses=[json.loads(x) for x in out.splitlines()]
            self.assertFalse(responses[1]['result'].get('isError'))
            scanner.assert_called_once()

    def test_real_module_help_and_doctor(self):
        proc=subprocess.run([sys.executable,'-m','guardkit','--help'],capture_output=True,text=True)
        self.assertEqual(proc.returncode,0)
        for command in ['init','scan','fix','doctor','mcp']: self.assertIn(command,proc.stdout)

if __name__=='__main__': unittest.main()

class ApprovalVerificationTests(unittest.TestCase):
    def test_approved_fix_rescans_and_preserves_unrelated_edits(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            (root/'Dockerfile').write_bytes(b'FROM alpine:3.20\r\nUSER root\r\nCMD ["app"]\r\n')
            (root/'local.txt').write_bytes(b'pre-existing uncommitted work\n')
            finding={'id':'root-user','rule_id':'DS002','title':'Last USER should not be root',
                     'file':'Dockerfile','line':2,'severity':'HIGH'}
            with patch.object(cli,'_scan',side_effect=[{'findings':[finding],'errors':[]},{'findings':[],'errors':[]}]) as scanner, patch.object(sys.stdin,'isatty',return_value=True), patch('builtins.input',return_value='y'), contextlib.redirect_stdout(io.StringIO()) as output:
                code=cli.main(['fix','--root',tmp])
            self.assertEqual(code,0)
            self.assertEqual(scanner.call_count,2)
            self.assertIn('1 finding(s) no longer reported',output.getvalue())
            self.assertEqual((root/'Dockerfile').read_bytes(), b'FROM alpine:3.20\r\nUSER 65532:65532\r\nCMD ["app"]\r\n')
            self.assertEqual((root/'local.txt').read_bytes(),b'pre-existing uncommitted work\n')

    def test_rejected_fix_never_writes(self):
        with tempfile.TemporaryDirectory() as tmp:
            source=b'FROM alpine\nUSER root\n'
            root=Path(tmp); (root/'Dockerfile').write_bytes(source)
            finding={'id':'root-user','rule_id':'DS002','file':'Dockerfile','line':2}
            with patch.object(cli,'_scan',return_value={'findings':[finding],'errors':[]}), patch.object(sys.stdin,'isatty',return_value=True), patch('builtins.input',return_value='n'), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(cli.main(['fix','--root',tmp]),0)
            self.assertEqual((root/'Dockerfile').read_bytes(),source)

    @unittest.skipUnless(hasattr(os, 'link'), 'Hard links unavailable')
    def test_hardlinked_target_cannot_modify_external_file(self):
        from guardkit import fixes
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); outside=root/'original'; outside.write_text('USER root\n')
            os.link(outside,root/'Dockerfile')
            plans=fixes.propose(root,[{'id':'a','rule_id':'DS002','file':'Dockerfile','line':1}])
            with self.assertRaises(ValueError): fixes.apply(root,plans)
            self.assertEqual(outside.read_text(),'USER root\n')

class WheelTrustTests(unittest.TestCase):
    def test_semgrep_pip_commands_ignore_repo_local_module(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / 'repo'; repo.mkdir()
            marker = root / 'pip-shadowed'
            (repo / 'pip.py').write_text(
                "from pathlib import Path\nPath(%r).write_text('executed')\n" % str(marker)
            )
            wheel_bytes = b'harmless synthetic wheel'
            wheel_name = 'dependency-1.0-py3-none-any.whl'
            metadata = {'urls': [{'filename': wheel_name, 'digests': {
                'sha256': hashlib.sha256(wheel_bytes).hexdigest()}}]}
            commands = []

            def checked(command):
                commands.append(command)
                # Exercise the actual interpreter/module prefix emitted by _semgrep,
                # with the same untrusted cwd inherited by _checked, but replace
                # pip's network/download/install work with local synthetic data.
                proc = subprocess.run(
                    [*command[:4], '--version'], cwd=repo,
                    capture_output=True, text=True, timeout=30,
                )
                if proc.returncode:
                    raise AssertionError(proc.stderr)
                self.assertIn('pip ', proc.stdout)
                if 'download' in command:
                    destination = Path(command[command.index('--dest') + 1])
                    (destination / wheel_name).write_bytes(wheel_bytes)

            with patch.object(provision, '_checked', side_effect=checked), \
                 patch.object(provision, 'fetch', return_value=json.dumps(metadata).encode()), \
                 patch.object(provision, 'compatible', return_value=True):
                provision._semgrep(root)

            self.assertEqual(len(commands), 2)
            self.assertTrue(all(command[1] == '-I' for command in commands))
            self.assertFalse(marker.exists())

    def test_unverified_transitive_wheel_is_never_installed(self):
        calls=[]
        def command(args):
            calls.append(args)
            if 'download' in args:
                destination=Path(args[args.index('--dest')+1])
                (destination/'dependency-1.0-py3-none-any.whl').write_bytes(b'corrupted-wheel')
        metadata={'urls':[{'filename':'dependency-1.0-py3-none-any.whl','digests':{'sha256':'0'*64}}]}
        with tempfile.TemporaryDirectory() as tmp, patch.object(provision.venv,'EnvBuilder') as builder, patch.object(provision,'_checked',side_effect=command), patch.object(provision,'fetch',return_value=json.dumps(metadata).encode()):
            with self.assertRaises(provision.ProvisionError): provision._semgrep(Path(tmp))
        self.assertEqual(len(calls),1)
        self.assertIn('-I',calls[0])
        self.assertIn('--only-binary=:all:',calls[0])
        self.assertNotIn('install',calls[0])
