# Source provenance

This repository combines the existing personal Messenger MCP and its Go backend in one checkout.

- Node MCP history: `https://github.com/O-chr/messenger-personal-mcp`, commit `7e2269d` (full hash retained in this repository's Git history).
- Go backend snapshot under `backend/`: `https://github.com/O-chr/messenger-cli`, commit `e513ae2`.
- The Go backend is based on `https://github.com/mautrix/meta`. Existing source headers, `LICENSE`, `LICENSE.exceptions`, and upstream README are preserved under `backend/`.

Only Git-tracked source files were imported. Local cookies, device and history keys, OAuth credentials/tokens, message databases, node_modules, compiled binaries, and review screenshots were not imported.

The currently running service still uses the original checkouts. Creating this consolidated repository does not restart the receiver, change its credentials, or run a second process against the live profile. To switch deployments later, build this checkout, update the service executable path, and stop the old receiver before starting the new one.
