# Local scanners and bundled rules

Repository `.semgrepignore` and `.gitignore` files and inline `nosemgrep`
comments cannot suppress the Guardkit audit. Semgrep exclusions are supplied by
Guardkit for the same generated/dependency directories excluded from Trivy.
This uses `--x-ignore-semgrepignore-files` from the pinned Semgrep version;
engine upgrades must pass the live suppression regression before changing the
pin. Terminal output escapes nonprintable characters in finding paths; JSON
retains the original paths for tools.

Guardkit invokes Trivy with explicit vulnerability, misconfiguration, and secret scanners, then invokes Semgrep with the local `guardkit/rules` directory. It does not use the Semgrep Registry or download rule packs. Both scanners skip common generated/dependency trees. Semgrep version checks and metrics are disabled. JSON output is normalized to stable finding IDs, priority, severity, confidence, location, explanation, impact, remediation, conservative fix availability, classification, and verification status. Source snippets and secret matches are intentionally omitted; scanner diagnostics are reduced to counts to avoid leaking arbitrary scanner output.

Trivy's filesystem scanner supports local project scanning and JSON output. It can report dependency vulnerabilities, configuration findings, and secrets; Guardkit maps those result types into its common schema. Its machine-readable output and filesystem command are documented in the [Trivy filesystem CLI reference](https://www.trivy.dev/docs/latest/guide/references/configuration/cli/trivy_filesystem/) and [filesystem scanning guide](https://trivy.dev/docs/latest/target/filesystem/).

Semgrep runs in local configuration mode against rules maintained in this repository. The rules are original Guardkit rules, authored here and licensed MIT, and do not copy Semgrep-maintained rule content. This matters because Semgrep's maintained community rules have their own [Semgrep Rules License](https://semgrep.dev/legal/rules-license/) with restrictions on redistribution and use; the engine and rules have separate licensing. Semgrep's documentation supports locally written rules, JSON output, and configuration-file scanning; see [rule syntax examples](https://semgrep.dev/docs/writing-rules/rule-ideas) and [Community Edition output overview](https://semgrep.dev/products/community-edition/).

The bundled checks cover Python shell execution, pickle/YAML deserialization, Flask debug mode, disabled TLS verification, SQL injection, SSRF, path traversal, and disabled JWT signature checks. JavaScript and TypeScript rules cover dynamic evaluation, child-process shell calls constrained to imported child-process bindings, raw React HTML, weak hashes, SQL injection, SSRF, open redirects, unverified JWT decoding, and arbitrary-origin reflection with credentialed CORS. Taint rules explicitly define sources and sinks, following Semgrep's documented [taint rule structure](https://semgrep.dev/docs/writing-rules/glossary) and [pattern composition](https://semgrep.dev/blog/2024/structure-mode-never-write-an-invalid-semgrep-rule/). The YAML deserialization rule exempts explicit safe loaders; Semgrep's [pattern-not syntax](https://semgrep.dev/blog/2020/writing-semgrep-rules-a-methodology/) is used to narrow that rule. Findings require human review; a pattern or intrafile dataflow match is not proof of exploitability. Trivy CVE findings are classified as confirmed scanner reports, while rule matches and secrets are heuristic pending review. Priorities put credential-like findings first. The CLI marks only coordinator-supported fixes as available; dependency upgrades remain advisory. Run both tools with current databases and versions in the host environment. Trivy may need network access to refresh its vulnerability database; Semgrep local rules themselves require no network fetch.

## Small controlled benchmark

Run `python benchmarks/run.py --trivy trivy --semgrep semgrep` to scan the paired hand-labeled fixtures. They include vulnerable and clean code patterns, a vulnerable/fixed Lodash lockfile pair, a root/modern Dockerfile pair, and placeholder credentials. Output separates exact static-rule precision/recall from category-level Trivy recall for credentials, dependencies, and misconfiguration; elapsed time includes both scans. This is a smoke benchmark only and cannot support general accuracy claims. Installation/setup time and vulnerability database provisioning are external to Guardkit and are reported as unmeasured. Trivy and Semgrep are not bundled with the source; they were provisioned and the real benchmark executed locally.

The real-engine benchmark now runs successfully; results are in [latest.json](../benchmarks/latest.json). It includes a separate safe allowlist flow that CE flags as a heuristic warning. This counts against application precision. P0 labels and exact code locations are evaluated independently, and Docker ENV/token reports are consolidated with supporting rule provenance retained. See [validation](validation.md) for the measured sample and limits.

## Accepted findings: `.guardkit/ignore.json`

Scanner ignore files stay disabled, because a repository must not hide its own
findings. Guardkit has one explicit mechanism instead:

```json
{"ignore": [
  {"path": "tests/fixtures/**", "reason": "Deliberately vulnerable fixtures"},
  {"rule_id": "guardkit.python.pickle-load", "path": "tools/*.py", "reason": "Trusted local cache"}
]}
```

Each entry needs a non-empty `reason` and at least one of `path` (glob; `dir/**`
for a subtree), `id` or `rule_id`; all given keys must match. Matching findings
leave `findings` (so they do not affect the exit code) and appear in
`suppressed` with `suppressed_reason`. Invalid entries are skipped and listed
in `warnings`. Agents must not add entries unless the user asks.

Dependency findings include `package`, `installed_version` and `fixed_version`
(null when no patched release is known), so an agent can bump the version
without extra lookups. The Express open-redirect rule treats
`allowed.has(x) ? x : default` as a sanitizer.
