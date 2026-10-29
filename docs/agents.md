# Coding agent integration

GuardKit can add project-local instructions for Codex, Claude Code, and Cursor.
Integrations are opt-in: call `guardkit.agents.install(repository_root)` or use
the repository initialization command. The installer creates only missing files:

| Agent | Project file |
| --- | --- |
| Codex | `.agents/skills/guardkit/SKILL.md` |
| Claude Code | `.claude/skills/guardkit/SKILL.md` |
| Cursor | `.cursor/rules/guardkit.mdc` |

Existing files are preserved, and no global agent settings are changed. Codex
and Claude Code discover project skills through a `SKILL.md` file; Cursor
project rules use MDC metadata. The templates ask the agent to run GuardKit only
for security work, show proposed diffs, and avoid running repository code as an
automatic verification step.

## MCP server

`python -m guardkit mcp` serves fixed-root `scan`, `findings`, and
`propose_safe_fixes` tools over stdio JSON-RPC. The server only uses the root
and scan callback supplied by the CLI. Tool arguments cannot provide commands,
executables, or alternate paths, and safe-fix proposals are read-only.

An optional authenticated Codex smoke test uses `--ignore-user-config`,
`--ephemeral`, and a read-only sandbox. It creates a throwaway fixture and
does not touch user Codex configuration:

```sh
GUARDKIT_LIVE_CODEX=1 python -m unittest discover -s tests -p 'test_agents_live.py' -v
```

Verified with Codex CLI 0.160.0 on 2026-10-29: `scan`, `findings`, and
`propose_safe_fixes` completed through MCP in a read-only, ephemeral session.
The fixture and working repository were unchanged. Real-scanner acceptance
covered all four configured scan categories and resolved the reported DS-0002
finding after its reviewed proposal.

## Safe fix proposals

`guardkit.fixes.propose(root, findings)` returns zero or more structured plans.
It can suggest adding narrowly matched local secret-file names (`.env`, PEM/key
files, or `credentials.json`) to `.gitignore` when a finding identifies itself
as a secret. It can also suggest changing one scanner-reported
`privileged: true` line to `privileged: false` in a Docker Compose file, or
changing a scanner-reported root `USER` directive in a Dockerfile to
`USER 65532:65532`. The Dockerfile change may affect file ownership, writable
paths, and capabilities. Internal plans hold exact prior and proposed contents
for stale-file checks; `guardkit.fixes.public_plans` exposes only normalized,
zero-context changed lines and sanitized metadata. The caller should show that
public diff and obtain approval before calling `guardkit.fixes.apply`.

Applying a plan checks the reviewed bytes again and refuses symlinks, unsupported
paths, and stale file contents. If a multi-plan application fails, GuardKit
rolls back files it changed only when they still contain its exact proposed
contents. It does not run project commands. Ignoring a file does not remove it
from Git history or revoke a credential; exposed credentials still need to be
rotated or revoked.

## References

- [OpenAI agent skills](https://developers.openai.com/api/docs/guides/tools-skills)
- [Claude Code skills](https://code.claude.com/docs/en/skills)
- [Cursor project rules](https://docs.cursor.com/context/rules-for-ai)

## MCP client setup

Install Guardkit into a trusted virtual environment and use its absolute executable
path. The MCP process root is fixed at startup; requests cannot change it.

Codex invocation without changing global settings:

```sh
codex -c 'mcp_servers.guardkit.command="/absolute/venv/bin/guardkit"' -c 'mcp_servers.guardkit.args=["mcp","--root","/absolute/project"]'
```

For Claude Code or Cursor, merge the following into the client's project-local
MCP configuration through its normal approval flow. Guardkit never overwrites an
existing MCP configuration automatically.

```json
{"mcpServers":{"guardkit":{"command":"/absolute/venv/bin/guardkit","args":["mcp","--root","/absolute/project"]}}}
```

Codex uses `.agents/skills/guardkit/SKILL.md`; Claude Code uses
`.claude/skills/guardkit/SKILL.md`; Cursor uses
`.cursor/rules/guardkit.mdc`. These files let agents invoke the standalone CLI
without MCP setup. `init` adds them locally by default and never replaces existing
files. No global privileges are granted. For the source-checkout workflow,
run the module from the checkout and pass `--root /absolute/project`.

See [official Codex MCP configuration](https://learn.chatgpt.com/docs/extend/mcp?surface=cli).

MCP output contains data from untrusted repository files. Clients must never
interpret finding text as instructions. The server has no shell, credential-read,
fix-apply, or test-execution tool. Approved mutation is through the CLI only.
