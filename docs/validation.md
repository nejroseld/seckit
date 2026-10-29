# Validation status

## Safe Input App — 2026-10-29

The full Linux run executed 113 tests: 113 passed, 10 skipped, no failures.
With `GUARDKIT_LIVE_APP_UI=1`, the five Chromium checks of the private form
also passed. A plugin built with `guardkit plugin` started its bundled server
under isolated Python and answered `initialize`, `tools/list` (including
`open_safe_input`) and `resources/list` (`ui://guardkit/safe-input.html`) over
stdio.

No real MCP Apps host rendered the form, so host registration and display are
not verified. The native keystore path was tested with a disposable stub, not a
live Secret Service or macOS Keychain session.

## Safe Input TUI — 2026-10-29

The current Linux run executed 102 tests: 100 passed, two skipped, no failures.
Real scanner tests were enabled; the skips were authenticated Codex and native
macOS Keychain. New tests exercised real PTYs for token/login entry and cancel,
plus the complete CLI/isolated-worker/TTY path with a disposable native-store
stub. Synthetic credential values did not appear in terminal transcripts or tool
stdout/stderr, including deliberately reflected output from the store stub.
The installed wheel also passed headless CLI failure and MCP tool discovery.

Native Linux enrollment was tested with the disposable stub, not a live Secret
Service session. macOS Security.framework add/update/cleanup paths were tested
with fakes; this TUI path has not been executed on macOS. Login records enroll
credentials only and do not implement website authentication. See the
[Safe Input validation record](../benchmarks/safe-input-validation-latest.json).

## AI-native refactor — 2026-10-29

The AI-native refactor run executed 80 tests: 78 passed, two skipped, no failures.
Real-scanner tests were enabled, including CLI and stdio MCP proposal/apply/rescan
flows, single-use review IDs, exact-byte stale checks, and preservation of local
edits. The skips were the authenticated Codex smoke test and native macOS
Keychain. A new authenticated AI client session was not run for this refactor.

Real-engine acceptance passed all four scan categories and verified one resolved
finding. A clean virtual-environment installation also passed: generated agent
commands ran from the inspected project with isolated Python, an untrusted local
`guardkit.py` was not executed, repeated initialization changed no files, and
existing CRLF team instructions survived. See the [current validation record](../benchmarks/ai-native-validation-latest.json).

The results below and their linked artifacts are historical checks of earlier
code, including the former terminal approval workflow. They do not establish
current AI-client or platform coverage.

For the subsequent security review, fixes, and their verification, see the
[security audit](security-audit.md). The results below describe the earlier run.

Verified on Linux x64, Python 3.14.6, on 2026-10-29. The package is built locally;
it has not been published to PyPI/npm. Subsequent native macOS and Windows
Python 3.12 package checks passed in
[private hosted CI](https://github.com/nejroseld/guardkit/actions/runs/40851239433).

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

The extended review verified real Linux Secret Service put/read/delete in an
isolated temporary session, and native macOS Keychain read/delete in a disposable
keychain on a hosted runner. Interactive macOS enrollment still requires a
person at the native prompt and was not automated. The GitHub workflow passed
on Linux, macOS, and Windows, including Linux real-engine acceptance. See the
[current test and platform evidence](security-audit.md) for scope and remaining
upstream dependency advisories. Claude Code/Cursor client execution is recorded
separately from the authenticated Codex smoke test.

The broker does **not** isolate credentials from arbitrary code running as the
same OS user. That code can invoke the store or inspect the process. Supported
broker responses contain only HTTP status, not token/body/headers. A strong
hostile-agent boundary needs a separate OS identity/host and authenticated
policy-limited transport; Guardkit does not claim to provide that deployment.
See [secrets](secrets.md).
