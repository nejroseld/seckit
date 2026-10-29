# Guardkit secret storage and request broker

Guardkit uses the operating system's existing password store; it does not create
an encrypted file or implement cryptography. `SecretStore` supports the macOS
login Keychain through the `security` utility and Linux Secret Service through
`secret-tool` (typically provided by GNOME Keyring or KWallet). Linux needs a
running Secret Service session. Windows is unsupported. The ordinary `put`
command prompts on a foreground terminal. Linux's hidden terminal input is
piped to `secret-tool`; macOS uses the native `security` prompt because Apple's
CLI has no safe stdin password option.

## Safe Input for agent requests

An agent can ask the user to enroll a credential without receiving its value:

```sh
guardkit secrets input service-api --kind token --service github.com
```

`kind` is `token` (the default) or `login`; the service defaults to the
credential name. The matching MCP tool is `open_safe_input` with `{name, kind,
service}` and the same defaults. In a client that advertises MCP Apps support,
it opens the encrypted in-chat form described below. Other clients open a local
curses form on the controlling `/dev/tty`; it does not use MCP/CLI tool stdin or stdout for the form. All fields,
including username, are masked. Tab or Enter moves between fields, Ctrl+U
clears the focused field, Ctrl+S saves or replaces the credential, and Esc or
Ctrl+C cancels. Input is bounded to five minutes. The tool result contains only
status, `credential_ref`, and `kind`; an unavailable terminal may also include
the fixed `terminal_unavailable` error code. It never contains entered values.

## Claude Code panel

`guardkit init` also writes a Claude Code mod to `.claude/skills/guardkit-input/`
(source: `guardkit/claude_mod/`, bound to the Python and Guardkit paths of the
installation that ran `init`). Claude Code loads it from the project's skills
folder and asks once before enabling mods. It adds the `/safe-input NAME
[token|login] [SERVICE]` command and the tools `open_safe_input` and
`safe_input_status`: the user types into a masked pane, the value goes through
stdin to `store_main` and then to the native store or the file vault, and the
agent only sees a status and the credential reference. Re-running `init`
refreshes these files; do not edit them by hand. Remove the folder to uninstall.

If the OS secret store is unavailable or rejects the write (no Secret Service
running, a headless SSH session, an unsupported platform), Guardkit falls back to
an encrypted file vault: `~/.config/guardkit/vault.json` (AES-256-GCM, each entry
bound to its name) with a random key in `vault.key`, both mode 0600
(`GUARDKIT_HOME` or `XDG_CONFIG_HOME` relocate them). No password or setup is
needed. This protects against accidental leaks through git, backups and logs, not
against other code running as the same user, the same trust level as an SSH key
file. A later successful native write replaces the vault entry.
`guardkit secrets status` shows which backend is available and the vault's names.

The form stores directly in the OS secret store: Linux Secret Service via
`secret-tool`, and macOS Keychain via Security.framework, without placing the
value in command arguments. A login is stored as one opaque JSON record with
`username` and `password`; it is enrollment only and does not sign into a site
or work with the Bearer-token request broker. Enrolled tokens can be used with
that broker. If no controlling terminal is available (including headless MCP or
remote sessions), the MCP tool returns unavailable. The CLI command instead runs
the form on a private pty and prints an `attach` command; the user runs it in their own
terminal to join the form. The relay is a same-user, owner-only unix socket, so keystrokes
never pass through tool output or chat. The user can also run the CLI command
in their own terminal. Windows is unsupported. No browser, web server, GUI, or
additional dependency is involved.

Safe Input is a trusted local enrollment UI. The agent must not read the native
store, capture terminal keystrokes, or transmit credential values through tools
or chat. It does not grant the agent secret-reading or approval access. A
same-user process with unrestricted access is not isolated from the terminal,
process memory, or native store; see [Limits and operational notes](#limits-and-operational-notes).

The native stores are established platform facilities: Apple's Keychain Services
stores small secret items in an encrypted database and supports access controls
([Apple Keychain Services](https://developer.apple.com/documentation/security/keychain-services));
Linux Secret Service defines the desktop secret-store API
([freedesktop.org Secret Service specification](https://specifications.freedesktop.org/secret-service/latest/)).
Guardkit delegates protection at rest to those services.

## Private in-chat form

MCP Apps clients can render an embedded credential form with `open_safe_input`.
The server negotiates the host capability rather than assuming terminal access.
The user enters a token or username/password into masked fields, reviews the
service and credential reference, then explicitly saves or cancels. The form
never sends plaintext through the tool bridge: Web Crypto encrypts with a fresh
AES-256-GCM key and wraps that key with the request's RSA-OAEP/SHA-256 public key.
The local Guardkit server decrypts directly into the native-store adapter.

`submit_safe_input` and `cancel_safe_input` are app-only tools, hidden from the
model by compliant hosts. Submission requires a five-minute, single-use
capability delivered only through the tool result's private `_meta`; model-visible
results and `safe_input_status` contain metadata only. Invalid, expired, replayed,
or tampered submissions are rejected without returning secret-bearing errors.
The app clears fields after saving, cancel, expiry, and host teardown. It uses no
network endpoints, external assets, browser storage, or model-context updates.

This requires a local server on a machine with a working native secret store
and a host that renders MCP Apps. Register the generated local plugin in that
host; returning HTML or starting a PTY inside an unrelated chat does not attach
an app to that chat. See [local plugin setup](safe-input-app.md). The host, its
iframe runtime, and the local OS account remain trusted; encryption prevents
plaintext submission payloads entering the tool bridge, not a malicious host
from inspecting its own form. No cloud vault or website-login automation is
provided.

## Broker boundary

`RequestBroker` is an in-process building block, not an MCP server. Guardkit's
coding-agent MCP interface does not expose secret-reading or broker operations;
`open_safe_input` is the limited exception for user-driven enrollment and
returns metadata only.
An integration may expose `send()` only when the endpoint policy is fixed in
trusted application code and approval remains in the trusted foreground
terminal. Do not register `approve_interactive`, `_grant_after_confirmation`,
`SecretStore._read`, or `SecretStore` itself as an MCP/tool interface. The broker
accepts one exact HTTPS
URL and method per endpoint policy, uses the credential only as an HTTP header,
ignores proxy environment variables, blocks redirects, and returns only the
numeric HTTP status. It drains and discards response bodies and ignores response
headers because an upstream can echo credentials or request content in either.
The in-memory approval lasts at most one hour and can be revoked immediately.

The CLI supports one-shot requests and a narrow JSON-lines foreground service:

```sh
guardkit secrets request service-api https://api.example.test/v1/status --method GET --ttl 60
```

`request` prompts on `/dev/tty`, sends one bodyless request, and writes only the
numeric HTTP status to stdout. `serve` prompts once on `/dev/tty`, then accepts
only `{"op":"request"}` and `{"op":"revoke"}` lines on stdin. It does not
accept URLs, methods, bodies, shell commands, or secret values through that
protocol. `serve` is limited to macOS and Linux because it requires `/dev/tty`.
Never expose terminal approval, secret retrieval, or broker operations to the
agent as tools. The agent's security workflow does not need to read stored
credentials. `open_safe_input` only asks the user to enroll a value in a local
masked form; it does not reveal or approve use of that value.

The implementation borrows a narrow idea from keygrant: put values in an OS
keystore and mediate their use with human approval. keygrant's documentation
describes name-only agent metadata and exact-command grants; Guardkit does not
execute arbitrary shell commands or pass values to child processes. Its optional
broker is narrower: one configured HTTPS request with metadata-only output
([keygrant overview](https://keygrant.app/docs/),
[keygrant approvals](https://keygrant.app/docs/approvals/)).

Infisical Agent is designed to fetch secrets and keep local files or templates in
sync. For agent credential brokering, Infisical's current Agent Vault project
acts as a separate HTTP proxy that injects credentials while forwarding upstream
requests. Its own guidance recommends deploying it on a separate host from
agents, which makes the trust boundary meaningful
([Infisical Agent Vault](https://github.com/Infisical/agent-vault),
[Agent Vault protocol](https://github.com/Infisical/agent-vault/blob/main/docs/agents/protocol.mdx)).
Vault Agent is a general-purpose client daemon for auto-authentication, caching,
templating, and process supervision; those features do not by themselves isolate
an agent running under the same user
([HashiCorp Vault Agent](https://developer.hashicorp.com/vault/docs/agent-and-proxy/agent)).

## Limits and operational notes

This is useful against accidental disclosure through the broker's response,
logs, or source changes. It is **not** a security boundary against hostile code
running with the same OS user. Such code can inspect process memory, invoke the
native store directly, instrument Python, or use any already approved request.
The TTY prompt is only meaningful when a person can inspect and control that
terminal. Do not claim the agent is isolated from secrets on a shared unrestricted
user account.
For a strong boundary, place the broker and native credential store under a
separate OS identity or host and expose only a separately authenticated,
policy-limited network API.

The HTTP body can contain non-secret request data and is limited to 1 MiB. The
response is consumed and discarded up to 1 MiB; no response content is returned.
The module does not provide response-body parsing, output redaction, a persistent
approval database, remote vault sync, key rotation, or audit storage. Credential
rotation and deletion happen in the OS store or upstream service. Python cannot
guarantee zeroization of immutable strings in memory.

## API sketch

```python
from guardkit.secrets import Endpoint, RequestBroker, SecretStore

endpoint = Endpoint(
    name="issue",
    url="https://api.example.test/v1/issue",
    method="POST",
    credential_name="service-api",
)
broker = RequestBroker(SecretStore(), {endpoint.name: endpoint})
broker.approve_interactive("issue", ttl=300)  # requires foreground TTY
metadata = broker.send("issue", "POST", endpoint.url, b'{"action":"status"}')
broker.revoke("issue")
```

Secret enrollment from a terminal:

```text
guardkit secrets put service-api
```

The prompt is hidden. Do not pipe secrets into the command or place them in shell
history, process arguments, environment variables, logs, chat, or repository
files. For an agent-requested masked form, use `guardkit secrets input NAME`
(see above). The corresponding `delete NAME` operation removes the named item.

## Validation

`tests/test_secrets_live.py` starts two temporary loopback HTTPS servers and
creates a short-lived self-signed certificate with OpenSSL. Its test-only client
trusts that certificate directly; it does not change system trust or weaken the
broker's production TLS defaults. A synthetic token is held only by an in-memory
fake store. The live checks send it over TLS, confirm that reflected response
bodies and headers do not appear in results, verify redirects are not followed,
and check that expiry and revocation prevent later network requests. The fixture
does not write to a native keychain or secret service, and shuts down the servers
and removes its temporary certificate and key at teardown.

Run it with `python -m unittest tests.test_secrets_live -v`.
