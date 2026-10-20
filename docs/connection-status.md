# Connection status (2026-10-20)

Implemented and running on the owner's Mac:

- HTTPS MCP: https://messenger-mcp.the-true-works.com/mcp
- Private GitHub: O-chr/messenger-personal-mcp; Go backend: O-chr/messenger-cli
- Separate Messenger launchd service, Cloudflare tunnel, OAuth token store and permission policy.
- Owner requested read/write on all currently known chats. Explicit rules exist for 23 chats; future chats remain denied. Fifteen currently mapped DMs support E2EE; eight legacy groups lack a supported send route.
- Live E2EE text cache only; no secure-storage history import. No additional real test message has been sent for the MCP work.
- Seven TypeScript tests pass, covering MCP calls and OAuth/HTTP boundaries. Go tests with race detector and go vet pass. npm audit reports zero vulnerabilities.
- Public health returns 200. The MCP endpoint returns 401 without authentication. Configuration and cache permissions verified 0600.

Remaining account connection steps:

1. Owner confirmation to save an added Google OAuth redirect URI:
   https://messenger-mcp.the-true-works.com/oauth/google/callback
   The Google Cloud form is prepared with the original LINE and iCloud redirects preserved.
2. Owner confirmation to create/connect the prepared ChatGPT custom MCP integration and authenticate Codex. ChatGPT successfully discovered OAuth DCR, endpoints, resource and messenger:tools scope.
3. Finish Google authentication in both clients, then verify actual tool discovery and read-only status/list calls. Do not send another real message merely to test connection.
4. Use the verified ChatGPT App identity for any bundled skill/App binding. A portable MCP package alone is not proof of a working ChatGPT connection. The prepared plugin source is not yet account-installed.

Do not claim that either consumer has completed authentication until a real authenticated call succeeds. If an old Codex login flow expires, use `codex mcp login messenger_mcp` to start a fresh flow. The global MCP registration already exists.
