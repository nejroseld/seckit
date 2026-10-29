# Security audit — 2026-10-29

The review covered the Python CLI, scanner provisioning and invocation,
credential broker, fix application, agent integration, packaging, and CI.
Three issues were reproduced with synthetic inputs and fixed. No real
credentials were used. Deliberately vulnerable benchmark fixtures were excluded
from the findings below.

## Findings and fixes

| Severity | Finding | Fix |
| --- | --- | --- |
| High | Semgrep provisioning executed a repository-local `pip.py` through `python -m pip`, before wheel verification. | Both pip download and install now use Python isolated mode: `python -I -m pip`. |
| Medium | Repository-controlled Semgrep suppressions silently removed findings, weakening audits of untrusted repositories. | Ignore `.semgrepignore`, `.gitignore`, and inline `nosemgrep`; supply Guardkit's generated/dependency directory exclusions explicitly. |
| Low | Finding paths containing terminal control characters were printed verbatim. | Escape nonprintable characters at the terminal sink, preserving original paths in JSON. |

The High issue requires invoking a command that provisions Semgrep while the
current working directory is an attacker-controlled repository. A harmless
`pip.py` wrote a marker when the real `_semgrep` installer was invoked before
the fix. This executes with the user's privileges; package hashes do not protect
the earlier Python module lookup. The regression exercises both command prefixes
emitted by the installer in a real temporary virtual environment, substituting
`--version` and synthetic wheel metadata to avoid network access.

The Medium issue concerns scanner completeness, rather than a vulnerability in
Semgrep itself. Before the fix, real Semgrep reported one finding for
`eval(userInput)`, then zero findings and zero errors with either `.semgrepignore`
or an inline `nosemgrep`. The fixed wrapper detects suppressed files in a
temporary Git repository, including a nested ignore file; `vendor` stays excluded.
`--x-ignore-semgrepignore-files` is an internal flag of the pinned Semgrep
version. Engine upgrades must preserve this behavior and pass the live test.

The Low issue was reproduced with a filename containing ESC, erase-line, and
carriage-return characters, through real Semgrep, normalization, and CLI output.
The impact is terminal output manipulation; command execution was not demonstrated.
The regression also covers bidirectional formatting controls and JSON round trips.

## Verification

- `python3 -m unittest discover -s tests -v`: 54 tests, no failures, four skips.
  Skips cover opt-in Codex/scanner tests and unavailable loopback HTTPS binding.
- `GUARDKIT_LIVE_SCANNERS=1 python3 -m unittest discover -s tests -p 'test_scanning_live.py' -v`:
  the real Semgrep regression passed, including suppression resistance, generated
  directory exclusions, and terminal escaping. Trivy is stubbed in this test.
- The local wheel was rebuilt offline from the corrected source and its SHA-256
  checksum regenerated. No package was published.

## Extended verification after sandbox restrictions were lifted

- The full opt-in Linux run completed **57 tests with no failures or skips**
  in 63.283 seconds, including the authenticated Codex MCP session, real scanner
  PTY approval, and all loopback HTTPS checks. See
  [test evidence](../benchmarks/security-tests-latest.json).
- Real-engine acceptance passed: all four finding categories were present,
  one approved finding disappeared on rescan, and unrelated edits were preserved.
  See [acceptance evidence](../benchmarks/security-acceptance-latest.json).
- Trivy and Semgrep reported zero findings/errors in the staged production
  sources and CI configuration. The Trivy DB was updated 2026-10-29 at 07:17 UTC;
  [scope and DB metadata](../benchmarks/security-production-scan-latest.json)
  record intentional fixture/test/generated-artifact exclusions.
- The labeled benchmark reproduced 7/7 code matches and one known hard-negative
  false positive: 87.5% precision and 100% recall on this small sample.
  See [benchmark evidence](../benchmarks/security-benchmark-latest.json).
- The installed Semgrep environment has **nine dependency advisory findings**:
  four in `mcp==1.29.0`, one in `opentelemetry-api==1.37.0`, and four in
  `pip==26.0.1`. These are dependency inventory findings, not nine demonstrated
  exploits in Guardkit. Semgrep 1.182.1 still pins the same MCP/OpenTelemetry
  versions, so an engine patch upgrade alone cannot remove them. Guardkit invokes
  local scans, not the Semgrep MCP HTTP service. See the
  [exact inventory, advisory URLs, and applicability limits](../benchmarks/security-dependencies-latest.json).
- The build requirement now excludes known affected old setuptools versions:
  `setuptools>=84.1.0`. This does not remove the Semgrep environment warnings.

### Remaining limits

This is a source review with targeted reproductions, not an exhaustive proof of
security. Hosted CI, native macOS/Windows execution, and live native-keychain
access are recorded separately as the extended verification continues. The
standalone Trivy binary was not audited through a complete upstream SBOM.

The broker's repeated requests during a TTL grant are documented behavior and
were not counted as a vulnerability. Its documented lack of isolation from
hostile processes running as the same OS user remains. No additional confirmed
credential-exfiltration or fix-path-traversal issue was established.
