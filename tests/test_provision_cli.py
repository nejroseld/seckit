import _isolate  # noqa: F401
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

from bluekit import cli, provision, reviews

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
            code, out, err = self.run_cli(['init','--root',tmp])
            self.assertEqual(code,0)
            self.assertIn('Next.js',json.loads(out)['stack'])
            self.assertEqual(set(json.loads(out)['agent_files_created']), {'AGENTS.md', 'CLAUDE.md', '.cursor/rules/bluekit.mdc', '.agents/skills/bluekit/SKILL.md', '.claude/skills/bluekit/SKILL.md', '.agents/skills/bluekit-audit/SKILL.md', '.claude/skills/bluekit-audit/SKILL.md'})
            code, out, err = self.run_cli(['init','--root',tmp])
            self.assertEqual(json.loads(out)['agent_files_created'],[])

    def test_scan_errors_never_look_clean(self):
        with patch.object(cli, '_scan', return_value={'findings':[], 'errors':['scanner offline']}):
            code,out,err = self.run_cli(['scan'])
            self.assertEqual(code,2)
            self.assertEqual(json.loads(out)['errors'],['scanner offline'])

    def test_scan_exit_status_findings(self):
        with patch.object(cli, '_scan', return_value={'findings':[{'id':'a'}], 'errors':[]}):
            code,out,err = self.run_cli(['scan'])
            self.assertEqual(code,1)

    def test_human_output_is_opt_in(self):
        with patch.object(cli, '_scan', return_value={'findings':[], 'errors':[], 'stack':[]}):
            code,out,_=self.run_cli(['scan','--human'])
            self.assertEqual(code,0)
            self.assertIn('Bluekit',out)

    def test_doctor_defaults_to_json_and_supports_human(self):
        with patch.object(provision, 'tools', return_value={'trivy':'/bin/trivy','semgrep':'/bin/semgrep'}):
            code,out,_=self.run_cli(['doctor'])
            self.assertEqual(code,0)
            self.assertIn('tools',json.loads(out))
            code,out,_=self.run_cli(['doctor','--human'])
            self.assertEqual(code,0)
            self.assertIn('Bluekit',out)

    def test_fix_defaults_to_json_proposal_without_prompt_or_project_execution(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as cache:
            root=Path(tmp)
            (root/'package.json').write_text('{"scripts":{"test":"touch SHOULD_NOT_RUN"}}')
            finding={'id':'secret','title':'Secret file','file':'.env','severity':'HIGH'}
            with patch.object(reviews, '_directory', return_value=Path(cache)), \
                 patch.object(cli, '_scan', return_value={'findings':[finding], 'errors':[]}), \
                 patch('builtins.input', side_effect=AssertionError('must not prompt')), \
                 patch.object(cli.subprocess, 'run') as project_run:
                code,out,err=self.run_cli(['fix','--root',tmp])
            proposal=json.loads(out)
            self.assertEqual(code,0)
            self.assertRegex(proposal['review_id'], r'^[0-9a-f]{64}$')
            self.assertEqual(proposal['plans'][0]['finding_ids'], ['secret'])
            self.assertFalse((root/'.gitignore').exists())
            project_run.assert_not_called()
            self.assertFalse((root/'SHOULD_NOT_RUN').exists())

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
        proc=subprocess.run([sys.executable,'-m','bluekit','--help'],capture_output=True,text=True)
        self.assertEqual(proc.returncode,0)
        for command in ['init','scan','fix','doctor','mcp']: self.assertIn(command,proc.stdout)

if __name__=='__main__': unittest.main()

class ApprovalVerificationTests(unittest.TestCase):
    def test_apply_consumes_proposal_preserves_crlf_and_local_edits_then_rescans(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as cache:
            root=Path(tmp)
            (root/'Dockerfile').write_bytes(b'FROM alpine:3.20\r\nUSER root\r\nCMD ["app"]\r\n')
            (root/'local.txt').write_bytes(b'pre-existing uncommitted work\n')
            finding={'id':'root-user','rule_id':'DS002','title':'Last USER should not be root',
                     'file':'Dockerfile','line':2,'severity':'HIGH'}
            with patch.object(reviews, '_directory', return_value=Path(cache)), \
                 patch.object(cli,'_scan',side_effect=[{'findings':[finding],'errors':[]},{'findings':[],'errors':[]}]) as scanner:
                code, out, _=CLITests().run_cli(['fix','--root',tmp])
                review_id=json.loads(out)['review_id']
                code, out, _=CLITests().run_cli(['fix','--root',tmp,'--apply',review_id])
            self.assertEqual(code,0)
            self.assertEqual(scanner.call_count,2)
            self.assertEqual((root/'Dockerfile').read_bytes(), b'FROM alpine:3.20\r\nUSER 65532:65532\r\nCMD ["app"]\r\n')
            self.assertEqual((root/'local.txt').read_bytes(),b'pre-existing uncommitted work\n')
            self.assertEqual(json.loads(out)['fix_verification']['resolved_ids'], ['root-user'])
            self.assertEqual(json.loads(out)['project_tests']['status'], 'not_run')

    def test_postapply_incomplete_scan_does_not_claim_resolved_ids(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as cache:
            root=Path(tmp)
            docker=root/'Dockerfile'; docker.write_bytes(b'FROM alpine\nUSER root\n')
            finding={'id':'root-user','rule_id':'DS002','file':'Dockerfile','line':2}
            with patch.object(reviews, '_directory', return_value=Path(cache)), patch.object(cli,'_scan',side_effect=[
                {'findings':[finding],'errors':[]}, {'findings':[],'errors':['scanner offline']}]) as scanner:
                _, proposal, _=CLITests().run_cli(['fix','--root',tmp])
                review_id=json.loads(proposal)['review_id']
                code, output, _=CLITests().run_cli(['fix','--root',tmp,'--apply',review_id])
            report=json.loads(output)
            self.assertEqual(code,2)
            self.assertEqual(report['fix_verification']['status'],'incomplete')
            self.assertEqual(report['fix_verification']['resolved_ids'],[])
            self.assertEqual(scanner.call_count,2)

    def test_review_is_root_bound_single_use_and_stale_content_is_preserved(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as other, tempfile.TemporaryDirectory() as cache:
            root=Path(tmp); docker=root/'Dockerfile'; original=b'FROM alpine\nUSER root\n'; docker.write_bytes(original)
            finding={'id':'root-user','rule_id':'DS002','file':'Dockerfile','line':2}
            with patch.object(reviews, '_directory', return_value=Path(cache)), patch.object(cli,'_scan',return_value={'findings':[finding],'errors':[]}):
                _, proposal, _=CLITests().run_cli(['fix','--root',tmp])
                review_id=json.loads(proposal)['review_id']
                code, _, _=CLITests().run_cli(['fix','--root',other,'--apply',review_id])
                self.assertEqual(code,2)
                _, proposal, _=CLITests().run_cli(['fix','--root',tmp])
                review_id=json.loads(proposal)['review_id']
                docker.write_bytes(original+b'# local edit\n')
                code, _, _=CLITests().run_cli(['fix','--root',tmp,'--apply',review_id])
                self.assertEqual(code,2)
                self.assertEqual(docker.read_bytes(),original+b'# local edit\n')
                code, _, _=CLITests().run_cli(['fix','--root',tmp,'--apply',review_id])
                self.assertEqual(code,2)

    def test_explicit_run_tests_only_after_apply_and_check_alias(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as cache:
            root=Path(tmp).resolve(); docker=root/'Dockerfile'; docker.write_text('FROM alpine\nUSER root\n')
            finding={'id':'root-user','rule_id':'DS002','file':'Dockerfile','line':2}
            with patch.object(reviews,'_directory',return_value=Path(cache)), patch.object(cli,'_scan',side_effect=[
                {'findings':[finding],'errors':[]}, {'findings':[],'errors':[]}]), patch.object(cli,'_project_tests',return_value=['fake-test']) as test_command, \
                 patch.object(cli.subprocess,'run',return_value=type('Process',(),{'returncode':0})()):
                code, proposal, _=CLITests().run_cli(['fix','--root',tmp,'--check'])
                review_id=json.loads(proposal)['review_id']
                test_command.assert_not_called()
                code, output, _=CLITests().run_cli(['fix','--root',tmp,'--apply',review_id,'--run-tests'])
                self.assertEqual(code,0)
                test_command.assert_called_once_with(root)
                self.assertEqual(json.loads(output)['project_tests']['command'],['fake-test'])

    def test_fix_skip_tests_hidden_noop_and_run_tests_requires_apply(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(cli,'_scan',return_value={'findings':[],'errors':[]}):
            code, _, _=CLITests().run_cli(['fix','--root',tmp,'--skip-tests'])
            self.assertEqual(code,0)
            code, out, _=CLITests().run_cli(['fix','--root',tmp,'--run-tests'])
            self.assertEqual(code,2)
            self.assertIn('errors',json.loads(out))

    @unittest.skipUnless(hasattr(os, 'link'), 'Hard links unavailable')
    def test_hardlinked_target_cannot_modify_external_file(self):
        from bluekit import fixes
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
            pip_bytes = b'harmless synthetic pip wheel'
            pip_name = f'pip-{provision.PIP}-py3-none-any.whl'
            pip_url = 'https://files.pythonhosted.org/packages/pip.whl'
            pip_metadata = {'info': {'name': 'pip', 'version': provision.PIP}, 'urls': [{
                'filename': pip_name, 'packagetype': 'bdist_wheel', 'url': pip_url,
                'digests': {'sha256': hashlib.sha256(pip_bytes).hexdigest()}}]}
            dependency_bytes = b'harmless synthetic dependency wheel'
            dependency_name = 'dependency-1.0-py3-none-any.whl'
            dependency_metadata = {'urls': [{'filename': dependency_name, 'digests': {
                'sha256': hashlib.sha256(dependency_bytes).hexdigest()}}]}
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
                    (destination / dependency_name).write_bytes(dependency_bytes)

            def metadata_for(url):
                if url == 'https://pypi.org/pypi/pip/26.2.2/json':
                    return json.dumps(pip_metadata).encode()
                if url == pip_url:
                    return pip_bytes
                return json.dumps(dependency_metadata).encode()

            with patch.object(provision, '_checked', side_effect=checked), \
                 patch.object(provision, '_pip_version', side_effect=['26.0.1', provision.PIP]), \
                 patch.object(provision, 'fetch', side_effect=metadata_for), \
                 patch.object(provision, 'compatible', return_value=True):
                provision._semgrep(root)

            self.assertEqual(len(commands), 3)
            self.assertTrue(all(command[1] == '-I' for command in commands))
            self.assertIn('verified-pip.txt', commands[0][-1])
            self.assertIn('download', commands[1])
            self.assertIn('verified.txt', commands[2][-1])
            self.assertFalse(marker.exists())

    def test_tampered_pinned_pip_wheel_is_rejected_before_install(self):
        wheel_name = f'pip-{provision.PIP}-py3-none-any.whl'
        url = 'https://files.pythonhosted.org/packages/pip.whl'
        metadata = {'info': {'name': 'pip', 'version': provision.PIP}, 'urls': [{
            'filename': wheel_name, 'packagetype': 'bdist_wheel', 'url': url,
            'digests': {'sha256': '0' * 64}}]}
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(provision, '_pip_version', return_value='26.0.1'), \
             patch.object(provision, 'fetch', side_effect=[json.dumps(metadata).encode(), b'tampered wheel']), \
             patch.object(provision, '_checked') as execute:
            with self.assertRaisesRegex(provision.ProvisionError, 'checksum mismatch'):
                provision._ensure_pip('/tmp/venv/bin/python', Path(tmp))
        execute.assert_not_called()

    def test_cached_semgrep_refreshes_pip_without_rebuilding_venv(self):
        pip_bytes=b'verified pip wheel'
        pip_name=f'pip-{provision.PIP}-py3-none-any.whl'
        pip_url='https://files.pythonhosted.org/packages/pip.whl'
        metadata={'info':{'name':'pip','version':provision.PIP},'urls':[{'filename':pip_name,'packagetype':'bdist_wheel','url':pip_url,'digests':{'sha256':hashlib.sha256(pip_bytes).hexdigest()}}]}
        def metadata_for(url):
            if url=='https://pypi.org/pypi/pip/26.2.2/json': return json.dumps(metadata).encode()
            if url==pip_url: return pip_bytes
            self.fail(f'unexpected metadata request: {url}')
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp)
            bindir=base/f'semgrep-{provision.SEMGREP}'/('Scripts' if os.name=='nt' else 'bin')
            bindir.mkdir(parents=True)
            executable=bindir/('semgrep.exe' if os.name=='nt' else 'semgrep')
            executable.write_text('existing compatible scanner')
            with patch.object(provision,'compatible',return_value=True), \
                 patch.object(provision,'_pip_version',side_effect=['26.0.1',provision.PIP]), \
                 patch.object(provision,'fetch',side_effect=metadata_for), \
                 patch.object(provision,'_checked') as install, \
                 patch.object(provision.venv,'EnvBuilder') as rebuild:
                self.assertEqual(provision._semgrep(base),str(executable))
            rebuild.assert_not_called()
            install.assert_called_once()
            command=install.call_args.args[0]
            self.assertIn('verified-pip.txt',command[-1])
            self.assertIn('-I',command)
            self.assertIn('--no-index',command)
            self.assertIn('--no-deps',command)
            self.assertIn('--require-hashes',command)

    def test_unverified_transitive_wheel_is_never_installed(self):
        calls=[]
        def command(args):
            calls.append(args)
            if 'download' in args:
                destination=Path(args[args.index('--dest')+1])
                (destination/'dependency-1.0-py3-none-any.whl').write_bytes(b'corrupted-wheel')
        pip_bytes=b'verified pip wheel'
        pip_name=f'pip-{provision.PIP}-py3-none-any.whl'
        pip_url='https://files.pythonhosted.org/packages/pip.whl'
        pip_metadata={'info':{'name':'pip','version':provision.PIP},'urls':[{'filename':pip_name,'packagetype':'bdist_wheel','url':pip_url,'digests':{'sha256':hashlib.sha256(pip_bytes).hexdigest()}}]}
        dependency_metadata={'urls':[{'filename':'dependency-1.0-py3-none-any.whl','digests':{'sha256':'0'*64}}]}
        def metadata_for(url):
            if url=='https://pypi.org/pypi/pip/26.2.2/json': return json.dumps(pip_metadata).encode()
            if url==pip_url: return pip_bytes
            return json.dumps(dependency_metadata).encode()
        with tempfile.TemporaryDirectory() as tmp, patch.object(provision.venv,'EnvBuilder') as builder, patch.object(provision,'_pip_version',side_effect=['26.0.1',provision.PIP]), patch.object(provision,'_checked',side_effect=command), patch.object(provision,'fetch',side_effect=metadata_for):
            with self.assertRaises(provision.ProvisionError): provision._semgrep(Path(tmp))
        self.assertEqual(len(calls),2)
        self.assertIn('-I',calls[0])
        self.assertIn('verified-pip.txt',calls[0][-1])
        self.assertIn('--only-binary=:all:',calls[1])
        self.assertFalse(any('verified.txt' in call[-1] for call in calls))
