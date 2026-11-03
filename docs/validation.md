# Validation status

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
- A wheel installs in a clean virtual environment and includes both rule files.
  No account, API key, Docker, sudo, or permanent service is needed for scanning.

## Benchmark interpretation

[Recorded metrics](../benchmarks/latest.json) include seven labeled application
findings with exact rule/file/line matches. All seven are detected. The ordinary
clean fixture has no findings. A separate hard-negative fixture preserves a safe
Set-allowlisted redirect. The redirect rule was first reported on it (87.5%
precision); a sanitizer for `allowed.has(x) ? x : default` removed the false
positive without touching the positive fixture, so precision and recall are
now 100% on this tiny set. Any new report on that fixture still counts as a
false positive rather than being hidden. These are not general accuracy estimates.

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
