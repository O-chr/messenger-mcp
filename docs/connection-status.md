# Connection status (2026-10-20)

Implemented and running on the owner's Mac:

- HTTPS MCP: https://messenger-mcp.the-true-works.com/mcp
- Private GitHub: O-chr/messenger-personal-mcp; Go backend: O-chr/messenger-cli
- Separate Messenger launchd service, Cloudflare tunnel, OAuth token store and permission policy.
- Owner requested read/write on all currently known chats. Explicit rules exist for 23 chats; future chats remain denied. Fifteen currently mapped DMs support E2EE; eight legacy groups lack a supported send route.
- Live E2EE text cache only; no secure-storage history import. No additional real test message has been sent for the MCP work.
- Twelve TypeScript tests pass, covering MCP calls and OAuth/HTTP boundaries. Go tests with race detector and go vet pass. npm audit reports zero vulnerabilities.
- Public health returns 200. The MCP endpoint returns 401 without authentication. Configuration and cache permissions verified 0600.

Account connection progress:

- Google OAuth redirect saved; original LINE and iCloud redirects preserved. The initial Google propagation delay resolved without changing authentication checks.
- Codex OAuth login completed. Actual exposed tools returned 23 allowed chats with read/write=true, connected=true and confirmation_supported=true. A read-only message-cache call succeeded with an empty result and the explicit live-cache history limitation.
- ChatGPT Google OAuth callback completed. Actual list/status calls succeeded in normal Chat, returning 23 read/write-allowed chats and connected=true. The host does not support native MCP forms; the server now provides a separate Google owner-authenticated confirmation page. A hosted App tool call verified confirmation_supported=true and confirmation_method=google_owner_web_page.
- Canonical hosted private plugin: https://chatgpt.com/plugins/plugin_asdk_app_6ad76a3077648191860ed3c56ada7ac1
- Plugin version 1.0.2, release pluginrel_6ad76e7d66288191b4ff2a7c78ec7f89. The same App binding and presentation were preserved; added personal-messenger skill verified by source read-back. Source under plugin/hosted retains the App-generated compatibility manifest.
- The portable plugin/messenger-personal folder is a source template; no duplicate account plugin was created from it.

Confirmation paths:

- Codex: native MCP elicitation form, verified supported by the real client.
- ChatGPT: the send tool returns a pending confirmation link without sending. The owner signs in with Google and approves the exact recipient/body on a CSRF-protected page. GETs and link previews never send; duplicate POSTs cannot send twice; revocation/target changes/expiry prevent approval. The AI must not approve on the user's behalf.
- The browser confirmation, isolated Google login, no-cookie/wrong-origin/wrong-CSRF rejection, single-send behavior, and unknown-outcome handling were tested with a fake backend. The page was visually checked with clearly fictitious data. No additional real Messenger message was sent for MCP verification.
- Normal Chat verification: https://chatgpt.com/c/6ad76c4f-ec38-83ec-a1d8-776c5843d1ac
