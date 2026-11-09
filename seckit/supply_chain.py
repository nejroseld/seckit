"""Offline supply-chain and CI/CD risk checks.

Covers what CVE databases miss: install-time code execution, dependencies from
arbitrary URLs, dependency-confusion index settings, unpinned GitHub Actions,
workflow script injection, untrusted input reaching AI agent actions, and
remote scripts piped into shells in Dockerfiles. Manifests are parsed as data.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from . import ignores
from .audit import iter_files, read_text, snippet
from .scanning import UNTRUSTED, _finding

_INSTALL_SCRIPTS = ("preinstall", "install", "postinstall", "prepare", "prepublish")
_URL_SPEC = re.compile(r"^(?:git\+|git:|github:|gitlab:|bitbucket:|https?://|file:|link:)|^[\w.-]+/[\w.-]+(?:#.*)?$")
_FLOATING = {"*", "latest", "", "x"}
_UNTRUSTED_EVENT = re.compile(
    r"\$\{\{\s*github\.(?:event\.(?:issue\.(?:title|body)|pull_request\.(?:title|body|head\.ref|head\.label)|"
    r"comment\.body|review\.body|review_comment\.body|discussion\.(?:title|body)|head_commit\.(?:message|author\.\w+)|"
    r"commits\S*\.(?:message|author\.\w+)|pages\S*\.page_name|workflow_run\.(?:head_branch|display_title))|head_ref)\s*\}\}")
_AGENT_ACTIONS = re.compile(r"(?i)uses:\s*['\"]?(?:anthropics/claude-code-action|anthropics/claude-code-base-action|openai/codex-action|"
                            r"google-github-actions/run-gemini-cli|github/copilot|[\w.-]+/[\w.-]*(?:ai|llm|gpt|claude|agent)[\w.-]*)@")
_USES = re.compile(r"^\s*-?\s*uses:\s*['\"]?([^'\"\s#]+)")


def _add(out: list, rule: str, title: str, severity: str, file: str, line: int, why: str, impact: str, fix: str,
         root: Path, category: str = "dependency", identity: str = "") -> None:
    item = _finding("Seckit", rule, title, severity, "MEDIUM", file, line, why, impact, fix, False,
                    "Re-run supply_chain after the change.", root, finding_category=category, identity=identity)
    # Manifest values (action refs, package specs) look like paths; keep them readable but masked for secrets.
    item.update(title=snippet(title, 300), explanation=snippet(why, 1200), source="supply-chain")
    out.append(item)


def _line_of(text: str, needle: str) -> int:
    for number, line in enumerate(text.splitlines(), 1):
        if needle in line:
            return number
    return 0


def _npm(root: Path, rel: str, path: Path, out: list) -> None:
    text = read_text(path)
    try:
        data = json.loads(text or "")
    except ValueError:
        return
    if not isinstance(data, dict):
        return
    scripts = data.get("scripts") if isinstance(data.get("scripts"), dict) else {}
    for name in _INSTALL_SCRIPTS:
        if isinstance(scripts.get(name), str):
            _add(out, "seckit.supply-chain.npm-install-script", f"package.json defines a `{name}` lifecycle script", "LOW",
                 rel, _line_of(text, f'"{name}"'), f"`npm install` runs `{name}` automatically: {scripts[name][:200]}",
                 "Code runs on every developer machine and CI runner that installs this package.",
                 "Confirm the script is needed and does not download or execute remote code.", root, identity=name)
    deps_total = 0
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        deps = data.get(section)
        if not isinstance(deps, dict):
            continue
        for name, spec in deps.items():
            deps_total += 1
            spec = str(spec).strip()
            if _URL_SPEC.match(spec) and not spec.startswith("npm:"):
                _add(out, "seckit.supply-chain.npm-url-dependency", f"{str(name)[:120]} is installed from a URL or git, not the registry", "MEDIUM",
                     rel, _line_of(text, f'"{name}"'), f"Spec `{spec[:200]}` bypasses registry integrity and version immutability.",
                     "The referenced code can change without a version bump or be replaced by whoever controls the URL.",
                     "Publish to the registry or pin to an exact commit hash and verify its owner.", root, identity=name)
            elif spec.lower() in _FLOATING:
                _add(out, "seckit.supply-chain.npm-floating-version", f"{str(name)[:120]} uses a floating version `{spec or '(empty)'}`", "MEDIUM",
                     rel, _line_of(text, f'"{name}"'), "Any future release, including a compromised one, is accepted.",
                     "A malicious publish of this package would be installed automatically.",
                     "Pin a version range and commit a lockfile.", root, identity=name)
    folder = path.parent
    if deps_total and not any((folder / lock).is_file() for lock in ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb", "bun.lock")):
        _add(out, "seckit.supply-chain.missing-lockfile", "Node project has dependencies but no lockfile", "MEDIUM", rel, 0,
             "Without a lockfile, every install can resolve different transitive versions.",
             "Builds are not reproducible and CVE scanning of transitive packages is incomplete.",
             "Commit package-lock.json, yarn.lock or pnpm-lock.yaml.", root)


def _npm_lock(root: Path, rel: str, path: Path, out: list) -> None:
    try:
        data = json.loads(read_text(path) or "")
        packages = data.get("packages", {})
    except (ValueError, AttributeError):
        return
    if not isinstance(packages, dict):
        return
    scripted = sorted(name.rsplit("node_modules/", 1)[-1] for name, meta in packages.items()
                      if name and isinstance(meta, dict) and meta.get("hasInstallScript"))
    if scripted:
        _add(out, "seckit.supply-chain.dependency-install-scripts", f"{len(scripted)} installed package(s) run install scripts", "LOW",
             rel, 0, "Packages: " + ", ".join(scripted[:25]) + (" ..." if len(scripted) > 25 else ""),
             "Each listed package executes code during installation.",
             "Review them; consider `npm ci --ignore-scripts` with an explicit allowlist.", root)
    for name, meta in packages.items():
        if not name or not isinstance(meta, dict):
            continue
        resolved = str(meta.get("resolved") or "")
        if resolved.startswith("http://"):
            _add(out, "seckit.supply-chain.insecure-resolved-url", f"{name.rsplit('node_modules/', 1)[-1]} resolves over plain HTTP", "HIGH",
                 rel, 0, "The lockfile fetches this package without TLS.", "A network attacker can substitute the package.",
                 "Re-resolve from an HTTPS registry.", root, identity=name)
        elif resolved and not meta.get("integrity") and not meta.get("link") and resolved.startswith("https://"):
            _add(out, "seckit.supply-chain.missing-integrity", f"{name.rsplit('node_modules/', 1)[-1]} has no integrity hash", "LOW",
                 rel, 0, "Without `integrity`, npm cannot detect a changed tarball.", "Tampered artifacts may be installed silently.",
                 "Regenerate the lockfile so every remote package has an integrity hash.", root, identity=name)


def _requirements(root: Path, rel: str, path: Path, out: list) -> None:
    text = read_text(path) or ""
    has_hashes = "--hash=" in text
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.split(" #", 1)[0].strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("--extra-index-url"):
            _add(out, "seckit.supply-chain.extra-index-url", "pip uses --extra-index-url", "HIGH", rel, number,
                 "pip picks the highest version across all indexes, so a public package can shadow a private one.",
                 "Dependency confusion: an attacker publishes your internal package name on PyPI.",
                 "Use a single --index-url that proxies PyPI, or pin with --hash.", root, identity=str(number))
        elif re.match(r"^(?:-i|--index-url)\s+http://", line) or line.startswith("--trusted-host"):
            _add(out, "seckit.supply-chain.insecure-index", "pip index without TLS verification", "HIGH", rel, number,
                 "Packages are downloaded over HTTP or with certificate checks disabled.",
                 "A network attacker can replace packages.", "Use an HTTPS index and remove --trusted-host.", root, identity=str(number))
        elif re.match(r"^(?:-e\s+)?(?:git\+|hg\+|svn\+|https?://)|\s@\s*(?:git\+|https?://)", line):
            _add(out, "seckit.supply-chain.pip-url-dependency", "Requirement installed from a VCS or URL", "MEDIUM", rel, number,
                 f"`{line[:200]}` bypasses PyPI versioning.", "The referenced code can change under the same reference.",
                 "Pin to a commit hash or publish to an index; add --hash where possible.", root, identity=str(number))
        elif not line.startswith("-") and "==" not in line and "@" not in line and not has_hashes:
            _add(out, "seckit.supply-chain.unpinned-requirement", f"Unpinned requirement `{line[:80]}`", "LOW", rel, number,
                 "Without an exact pin or lockfile, each install may pick a new release.",
                 "A compromised or breaking release is installed automatically.",
                 "Pin with == (or use a lockfile such as uv.lock / poetry.lock) and consider --require-hashes.", root, identity=line[:80])


def _workflow(root: Path, rel: str, path: Path, out: list) -> None:
    text = read_text(path) or ""
    lines = text.splitlines()
    triggers_prt = "pull_request_target" in text or re.search(r"^\s*workflow_run\s*:", text, re.M) is not None
    if not re.search(r"^permissions\s*:", text, re.M):
        _add(out, "seckit.ci.missing-permissions", "Workflow has no top-level `permissions`", "LOW", rel, 1,
             "The GITHUB_TOKEN gets the repository default, often read-write.",
             "A compromised step can push code or tamper with releases.",
             "Add `permissions: contents: read` at the top and grant more per job only where needed.", root, "misconfiguration")
    in_run = False
    run_indent = 0
    for number, line in enumerate(lines, 1):
        stripped = line.strip()
        indent = len(line) - len(line.lstrip())
        if re.match(r"^-?\s*run\s*:", stripped):
            in_run, run_indent = True, indent
        elif in_run and stripped and indent <= run_indent:
            in_run = False
        if re.search(r"permissions\s*:\s*write-all", line):
            _add(out, "seckit.ci.write-all", "Workflow grants `write-all` permissions", "MEDIUM", rel, number,
                 "Every step receives a token that can write to the repository.", "Any compromised dependency or action can push code.",
                 "Grant only the scopes each job needs.", root, "misconfiguration", str(number))
        used = _USES.match(line)
        if used:
            ref = used.group(1)
            if not ref.startswith(("./", "docker://")) and "@" in ref:
                version = ref.rsplit("@", 1)[1]
                if not re.fullmatch(r"[0-9a-f]{40}", version):
                    owner = ref.split("/", 1)[0].lower()
                    _add(out, "seckit.ci.unpinned-action", f"Action `{ref[:120]}` is not pinned to a commit SHA",
                         "LOW" if owner in {"actions", "github"} else "MEDIUM", rel, number,
                         "Tags and branches are mutable; the action owner (or an attacker with their access) can change the code.",
                         "A retagged action runs with this workflow's token and secrets.",
                         "Pin to a full 40-character commit SHA and keep the tag in a comment.", root, "misconfiguration", ref)
        if _UNTRUSTED_EVENT.search(line) and (in_run or re.match(r"^-?\s*run\s*:", stripped) or "script:" in line):
            _add(out, "seckit.ci.script-injection", "Untrusted event data is expanded inside a shell script", "HIGH", rel, number,
                 "`${{ }}` is substituted before the shell runs, so an issue title or branch name becomes code.",
                 "Anyone who can open an issue or PR can run commands with the workflow's token and secrets.",
                 "Pass the value through `env:` and reference it as \"$VAR\" in the script.", root, "misconfiguration", str(number))
        if triggers_prt and re.search(r"ref\s*:\s*\$\{\{\s*github\.(?:event\.pull_request\.head\.(?:sha|ref)|head_ref)", line):
            _add(out, "seckit.ci.pwn-request", "Privileged workflow checks out untrusted pull request code", "CRITICAL", rel, number,
                 "pull_request_target/workflow_run runs with secrets and a write token, and this step fetches the PR head.",
                 "A fork PR can execute arbitrary code with repository secrets (\"pwn request\").",
                 "Use the `pull_request` trigger for untrusted code, or never build/run the checked-out head in this job.",
                 root, "misconfiguration", str(number))
    if _AGENT_ACTIONS.search(text) and _UNTRUSTED_EVENT.search(text):
        _add(out, "seckit.ci.agent-prompt-injection", "AI agent action receives untrusted issue/PR text", "HIGH", rel,
             _line_of(text, "uses:"), "Issue, comment or PR text reaches an AI agent step in the same workflow.",
             "Prompt injection can make the agent leak secrets or push changes with the workflow token.",
             "Restrict triggers to trusted actors, drop write permissions and secrets from that job, and pass untrusted text only as data.",
             root, "misconfiguration")


def _dockerfile(root: Path, rel: str, path: Path, out: list) -> None:
    text = read_text(path) or ""
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        match = re.match(r"(?i)^FROM\s+(?:--platform=\S+\s+)?(\S+)", stripped)
        if match:
            image = match.group(1)
            if image.lower() != "scratch" and "$" not in image and "@sha256:" not in image:
                tag = image.rsplit("/", 1)[-1].partition(":")[2]
                if not tag or tag == "latest":
                    _add(out, "seckit.supply-chain.floating-base-image", f"Base image `{image[:100]}` has no fixed tag", "MEDIUM",
                         rel, number, "`latest` or no tag pulls whatever is current at build time.",
                         "Builds are not reproducible and a compromised upstream image is picked up automatically.",
                         "Pin a version tag and preferably an @sha256 digest.", root, "misconfiguration", image)
        if re.search(r"(?i)\b(?:curl|wget)\b[^|;&]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b", stripped):
            _add(out, "seckit.supply-chain.curl-pipe-shell", "Remote script is piped into a shell", "HIGH", rel, number,
                 "The downloaded script is executed without integrity verification.",
                 "Whoever controls that URL controls the image.", "Download, verify a checksum or signature, then execute.",
                 root, "misconfiguration", str(number))
        if re.match(r"(?i)^ADD\s+https?://", stripped):
            _add(out, "seckit.supply-chain.add-remote-url", "ADD fetches a remote URL without verification", "MEDIUM", rel, number,
                 "ADD downloads at build time with no checksum.", "The fetched content can change between builds.",
                 "Use ADD --checksum=sha256:... or download and verify in RUN.", root, "misconfiguration", str(number))


def scan(root: Path) -> dict[str, Any]:
    """Run all offline supply-chain checks; returns normalized findings."""
    root = Path(root).resolve()
    out: list[dict[str, Any]] = []
    errors: list[str] = []
    walk: dict[str, Any] = {}
    # Lockfiles are often larger than the 1 MB source limit; they are read only when matched.
    for rel, path in iter_files(root, None, stats=walk, max_size=_MAX_MANIFEST):
        name = path.name
        try:
            if name == "package.json":
                _npm(root, rel, path, out)
            elif name in ("package-lock.json", "npm-shrinkwrap.json"):
                _npm_lock(root, rel, path, out)
            elif re.fullmatch(r"(?:.*[-_.])?requirements(?:[-_.].*)?\.(?:txt|in)", name):
                _requirements(root, rel, path, out)
            elif rel.startswith(".github/workflows/") and path.suffix in (".yml", ".yaml"):
                _workflow(root, rel, path, out)
            elif name == "Dockerfile" or name.startswith("Dockerfile.") or name.endswith(".Dockerfile"):
                _dockerfile(root, rel, path, out)
        except (OSError, ValueError, TypeError, AttributeError, RecursionError):
            errors.append(f"Supply-chain check could not parse {rel[:200]}")
    order = {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "P4": 4}
    unique = {f["id"]: f for f in out}
    findings = sorted(unique.values(), key=lambda f: (order[f["priority"]], f["file"], f["line"]))
    relevant = [rel for rel in walk["oversized"] if _relevant(rel)]
    if relevant:
        errors.append(f"Supply-chain check skipped {len(relevant)} manifest(s) over {_MAX_MANIFEST // 1_000_000} MB")
    if walk["truncated"]:
        errors.append("Supply-chain check stopped after 20000 files; manifests and workflows after that were not read")
    return ignores.apply(root, {"findings": findings, "errors": errors, "untrusted_data": UNTRUSTED})


_MAX_MANIFEST = 64_000_000


def _relevant(rel: str) -> bool:
    name = rel.rsplit("/", 1)[-1]
    return (name in ("package.json", "package-lock.json", "npm-shrinkwrap.json")
            or re.fullmatch(r"(?:.*[-_.])?requirements(?:[-_.].*)?\.(?:txt|in)", name) is not None
            or (rel.startswith(".github/workflows/") and name.endswith((".yml", ".yaml")))
            or name == "Dockerfile" or name.startswith("Dockerfile.") or name.endswith(".Dockerfile"))
