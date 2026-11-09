# Code audit tools

Seckit gives a coding agent the tools for a full blue-team code audit, not
just a scanner run. They follow the workflow of public audit skill sets such as
[Trail of Bits skills](https://github.com/trailofbits/skills)
(audit-context-building, differential-review, variant-analysis, fp-check,
insecure-defaults, supply-chain-risk-auditor, agentic-actions-auditor, SARIF)
and the tools of the [Semgrep MCP server](https://github.com/semgrep/mcp)
(custom-rule scans). The implementation is original, offline and stdlib-only;
nothing executes project code.

`seckit init` installs a second skill, `seckit-audit`, into
`.claude/skills/` and `.agents/skills/`. It contains the audit methodology and
the exact commands for this machine. The same methodology is served as MCP
prompts.

## Commands and MCP tools

| CLI | MCP tool | What it returns |
|---|---|---|
| `surface [--kind K] [--path P]` | `attack_surface` | Entry points (routes, CLI, handlers), sinks (exec, eval, SQL, files, SSRF, HTML, deserialization, weak crypto), auth/CSRF/validation controls, insecure defaults, and `review_order`: files ranked for manual reading, with `unguarded_entry` for routes without visible auth |
| `supply-chain` | `supply_chain` | Install scripts, git/URL dependencies, floating versions, missing lockfiles, packages without integrity, `--extra-index-url` (dependency confusion), unpinned or HTTP indexes, unpinned actions, `write-all`, missing `permissions`, workflow script injection, pwn requests, untrusted issue/PR text reaching AI agent actions, `curl \| sh`, untagged base images, `ADD <url>` |
| `diff --base REF [--no-scan]` | `diff_review` | Changed files with security-sensitive paths, new risky lines, removed controls (for example a deleted `@login_required`), and scan findings mapped to changed lines |
| `rule --pattern P --lang L` or `rule --config FILE` | `rule_scan` | Findings from one agent-written Semgrep rule (variant analysis), with rule syntax errors |
| | `search_code` | Regex matches with masked snippets; the pattern runs on masked text and credential files are skipped |
| | `read_code` | Numbered file lines, max 500 per call, credential-shaped values masked; credential files and `.git/` refused |
| `triage ID --verdict V --reason R` | `triage` | Stores `true_positive`, `false_positive`, `needs_info` or `fixed` with a reason in `.seckit/triage.json` |
| `trust` | | Shows `.seckit/ignore.json` and `.seckit/triage.json` and, after confirmation in a terminal, applies them on this machine |
| `report --format markdown\|sarif\|json [--output F]` | `audit_report` | Scan + supply-chain findings with triage verdicts; Markdown adds an attack-surface summary, SARIF 2.1.0 suits GitHub code scanning |

MCP prompts: `security_audit`, `differential_review`, `variant_analysis`,
`triage_findings`.

Exit codes match `scan`: 0 nothing found, 1 findings (for `diff`: new risky
lines, removed controls or findings in changed files), 2 incomplete or usage
error. `surface` and `triage` return 0.

## Safety notes

- Signals from `surface` and `diff` are heuristics: places to read, not
  findings. The agent confirms or refutes them by reading the code.
- `diff` never runs `git diff` against the working tree. Repository-defined
  clean/smudge filters, textconv drivers, external diff tools and fsmonitor
  hooks could execute code. Seckit reads trees and blobs with git plumbing
  and compares working files in Python. Base refs that look like options are
  rejected.
- `read_code` and `search_code` resolve paths inside the root and never follow
  symlinks. Everything they return goes to the agent's model provider, so files
  that are credentials by name (`.env*` except `*.example`/`*.sample`/`*.template`,
  `*.pem`, `*.key`, `id_rsa*`, `.npmrc`, `.netrc`, `.pypirc`, `credentials*.json`,
  service-account JSON, `*.tfstate`, and anything under `.git/`) are refused or
  skipped. In other files, masking catches `key = value` assignments (also quoted
  JSON keys), bearer tokens, credentials in URLs, private-key blocks and common
  token formats (AWS, GitHub, Slack, OpenAI/Anthropic, Google, npm, PyPI, JWT).
  Masking is a fallback, not a guarantee: a secret in an unrecognized form can
  still be returned. `search_code` matches against the masked text, so a pattern
  cannot probe a secret character by character.
- `rule_scan` uses the pinned local Semgrep, writes the rule to a temporary
  directory outside the project and keeps the same exclusions and anti
  suppression flags as `scan`.
- Triage annotates findings and never hides them. A `false_positive` becomes a
  SARIF suppression with the reason so dashboards show it as reviewed.
  Suppression in Seckit's own reports remains `.seckit/ignore.json`.
- Both files are part of the project, so their author controls them. Verdicts
  and suppressions apply only when this machine wrote the file (`seckit triage`
  on an accepted or absent file) or the user accepted its exact bytes with
  `seckit trust`. A `triage.json` shipped with a cloned repository is therefore
  ignored, with a warning, until the user reviews it: otherwise its verdicts
  would become SARIF suppressions and text the agent reads. Recording a verdict
  in such a file keeps its existing entries and leaves it unaccepted.
- Supply-chain findings honour `.seckit/ignore.json` like scan findings.
