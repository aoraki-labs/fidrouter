# fidrouter — agent & developer surfaces

Everything is scriptable; the web UI is optional. Three ways in:

## 1. One-line partner enable
```bash
curl -fsSL https://app.fidcore.xyz/enable.sh | bash        # interactive
# non-interactive (agents): NEWAPI_BASE=… ENCLAVE_URL=… EXPECTED_MEASUREMENT=… bash
```
Bundles cp-adapter beside your gateway, generates a CP keypair if needed, prints the next steps.

## 2. CLI (`pip install fidrouter`) — JSON out, exit-code semantics
```bash
pip install https://github.com/aoraki-labs/fidrouter/releases/download/cli-v0.1.1/fidrouter-0.1.1-py3-none-any.whl
# (or, with modern pip:  pip install "git+https://github.com/aoraki-labs/fidrouter@main#subdirectory=cli")   # or a release wheel
```
```bash
fidrouter verify http://enclave.fidcore.xyz:9090      # independently attest an endpoint
fidrouter endpoints                                   # list registered endpoints
fidrouter receipt <X-Fid-Receipt>                     # verify a signed receipt
fidrouter call --endpoint 3 --key sk-… --model claude-opus-5 --message "hi"
fidrouter enable                                      # print the installer one-liner
```
Env: `FIDROUTER_PLATFORM` (default `https://app.fidcore.xyz`). Needs `cryptography`.

## 3. MCP server (`mcp/server.py`) — for agents (Claude Code, etc.)
```bash
pip install "mcp[cli]"
claude mcp add fidrouter -- python3 /path/to/mcp/server.py
```
Tools: `list_endpoints`, `verify_endpoint`, `verify_receipt_tool`, `call` (exchange → attest →
run, fail-closed), `enable_command`. An agent can discover, verify, and use the relay with no UI.

## 4. Drop-in SDK
`from fid import OpenAI` — a drop-in OpenAI client that verifies + E2EEs under the hood
(`sdk/python`, `sdk/ts`).
