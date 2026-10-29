# Guardkit Safe Input local plugin

The local plugin packages Guardkit's MCP server and private credential entry UI
for a compatible desktop MCP Apps host. It runs the packaged Guardkit runtime
with a fixed project root. The host must support and render MCP Apps for the
private UI; an ordinary chat session, terminal tool call, or plain HTML page
cannot attach or render this view. Register the generated local plugin with a
supported desktop client and start a new session after registration.

## Build

Install Guardkit with its encryption dependency, then generate a
package for the project you want the server to inspect:

```sh
pip install .
guardkit plugin --root /path/to/project --output /path/to/guardkit-safe-input
```

The output directory must not already exist. The command creates a self-contained
directory with `plugin.json`, `mcp.json`, a bundled Guardkit runtime, server
launcher, and the `guardkit-safe-input` skill. It does not install the plugin,
upload it, or send project data to a service. The MCP server uses the absolute
Python executable from the build environment and the fixed absolute project
path supplied to `--root`.

## Credential entry

Use the `open_safe_input` tool. The credential is entered through the private
UI and the app sends only an encrypted envelope to the local server. The app
generates a random AES-256-GCM key for the submission and wraps that key with
the request's RSA-OAEP/SHA-256 public key. The server decrypts the envelope
locally and stores the credential through the native OS keystore adapter. The
credential value is not returned in the chat/tool result. This encryption flow
is specific to the MCP App; terminal safe input remains a separate local
fallback. The encrypted app flow uses the `cryptography`
dependency installed with Guardkit.

App metadata carries the request identifier, a short-lived capability, the
public key, and expiry needed by the private UI. Tool results expose status and
credential reference, not submitted values. The UI sends credential fields
only in the encrypted submission envelope, then clears its input fields.

Clients without MCP Apps support use Guardkit's terminal-based safe-input
fallback. The user starts that flow in their own terminal; agents should never
ask for a credential in chat or substitute a plain HTML prompt. Native keystore
availability and desktop host support vary by system and client. The package
does not claim that a host has been verified or registered.

This package is for local use. It is not a public plugin submission, account
upload, hosted service, or cloud deployment.
