# Validation status

For the subsequent security review, fixes, and their verification, see the
[security audit](security-audit.md). The results below describe the earlier run.

Verified on Linux x64, Python 3.14.6, on 2026-10-29. The package is built locally;
it has not been published to PyPI/npm. macOS and Windows are implementation
and CI targets, not locally verified platforms.

## Observed results

The final full run passed all 54 tests, including live Codex, real scanner CLI,
and HTTPS tests, in 40.477 seconds with no skips.

- Real Trivy 0.76.1 and Semgrep CE 1.182.0 were downloaded, verified, installed
  without administrator access, and executed. Semgrep validates the bundled rules.
- Initial sequential installation took 185.837 seconds. After parallelizing the
  independent installations and wheel verification, a fresh scanner/pip cache
  installation took 102.004 seconds. This is one machine with available network
  caches, not a guaranteed setup time or a population success rate. Cached init
  took 2.735 seconds. No manual project configuration was needed.
- The real acceptance harness passes: all four scanner categories are present,
  one Dockerfile root-user fix disappears on rescan, and an unrelated local edit
  remains byte-for-byte intact. See [recorded acceptance](../benchmarks/acceptance-latest.json).
- A real terminal test displays the Dockerfile diff, waits for approval, applies
  it, and verifies remediation with both scanners. Repository Trivy configuration
  and ignore files cannot suppress the tested finding.
- Codex CLI 0.160.0 successfully called scan, findings, and propose_safe_fixes
  through MCP in an ephemeral, read-only session. The fixture was unchanged.
  Some combined runs exited with Codex process errors; an isolated repeat and
  the final complete suite passed.
  External model availability is not required for standalone Guardkit scanning.
- Live HTTPS tests use a synthetic token and a disposable certificate. They
  verify authenticated requests, reflected body/header exclusion, blocked
  redirects, expiry, and revocation. They use a fake store, not a live keychain.
- A wheel installs in a clean virtual environment and includes both rule files.
  No account, API key, Docker, sudo, or permanent service is needed for scanning.

## Benchmark interpretation

[Recorded metrics](../benchmarks/latest.json) include seven labeled application
findings with exact rule/file/line matches. All seven are detected. The ordinary
clean fixture has no findings. A separate hard-negative fixture preserves a safe
Set-allowlisted redirect that Semgrep CE still flags: it counts as a false
positive rather than being hidden. Application precision is consequently 87.5%
and recall 100% on this tiny set. These are not general accuracy estimates.

P0 precision/recall are 100% for **one** labeled normalized credential exposure,
with zero P0 findings in clean/hard-negative fixtures. The Docker ENV warning
and token detector are consolidated with both rule IDs retained. Such a small
sample cannot establish a population-level 90% precision target. Credential,
dependency, and misconfiguration category recall is 100% on this smoke fixture;
category recall is not exhaustive vulnerability recall.

Fresh transitive Python dependencies and changing CVE databases limit exact
reproducibility. This run used a Trivy database updated at
2026-10-29T07:17:11.934066875Z. Engine versions, bundled rules, fixtures, and the
installed environment's verified wheel hashes are pinned/recorded. A rigorous
comparison also needs an identical database/environment snapshot.

## Reproduce

```sh
python3 -m unittest discover -s tests -v
GUARDKIT_LIVE_SCANNERS=1 python3 -m unittest discover -s tests -p 'test_cli_live.py' -v
GUARDKIT_LIVE_CODEX=1 python3 -m unittest discover -s tests -p 'test_agents_live.py' -v
python3 benchmarks/acceptance.py
python3 benchmarks/run.py --trivy "$HOME/.cache/guardkit/trivy-0.76.1/trivy" --semgrep "$HOME/.cache/guardkit/semgrep-1.182.0/bin/semgrep"
```

Codex's optional test requires an existing authenticated Codex session. HTTPS
tests need OpenSSL and loopback access. The acceptance harness never executes
fixture application code; fixes run only inside disposable copies. Deliberately
vulnerable fixtures and synthetic credentials must never be deployed.

## Remaining boundaries

Live native-keychain enrollment was not tested: this headless environment has
`secret-tool` but no desktop Secret Service. Claude Code/Cursor integration files
and MCP protocol are tested, while those applications were not launched here.
The GitHub workflow covers package tests on three operating systems and Linux
real-engine acceptance; those hosted jobs have not run in this workspace.

The broker does **not** isolate credentials from arbitrary code running as the
same OS user. That code can invoke the store or inspect the process. Supported
broker responses contain only HTTP status, not token/body/headers. A strong
hostile-agent boundary needs a separate OS identity/host and authenticated
policy-limited transport; Guardkit does not claim to provide that deployment.
See [secrets](secrets.md).
