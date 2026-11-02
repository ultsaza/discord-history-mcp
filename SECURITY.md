# Security model

This repository provides an authenticated, read-only MCP interface to Discord text history. It is not an independently audited security product. Operators must configure and maintain their own bot, host, public proxy, callback allowlist and client connections.

## Protections

- Dedicated bot with no Administrator: startup and every history-read permission snapshot reject it. Give only View Channels / Read Message History initially. Add private-thread membership (preferred) or Manage Threads if needed. Discord interactions register the app’s `/mcp` command and send ephemeral consent replies; MCP tools cannot post, edit or delete messages.
- Per-member authority: Discord supplies the approving member and guild. Both caller and bot must currently have View Channel and Read Message History. Private threads also require membership or Manage Threads. Unknown channel types, cross-guild IDs, pending members and inconsistent role snapshots are rejected.
- OAuth authorization-code flow with PKCE S256, exact callback allowlist, client binding, one-use two-minute codes, resource validation and RFC 9207 issuer identification. No downstream Discord user token is accepted or passed through.
- Access tokens last one hour; rotating refresh tokens and grants expire after 30 days. Revoking through `/mcp action:revoke` invalidates the member’s guild grants and outstanding approved requests/codes. Revocation is rechecked at tool execution.
- Access/refresh tokens and OAuth codes are stored only as hashes. Client registration secrets and temporary approval codes are sensitive data in the private SQLite store. State is not message history.
- No client-controlled upstream URLs: history reads target Discord REST only, without redirects. Returned attachments are metadata/URLs; the service does not fetch their contents. Client metadata URLs are not fetched.
- CSP nonce, no framing, no-referrer and no-store approval pages. Client labels are escaped in HTML and sanitized for Discord. Consent is required for every new connection.

## Availability limits

The single worker admits 1,200 HTTP requests/minute overall, with additional global limits: registration 30/minute, authorization 60/minute, token/revocation 120/minute each, and approval-page traffic 600/minute. OPTIONS requests are excluded. Global limits intentionally do not trust source IP headers behind a proxy.

Each member/guild gets 30 tool-work units per minute; search costs five units and other tools cost one. Request bodies are capped at 128 KiB with a ten-second receive timeout; HTTP concurrency is capped at 32. Discord REST has a bounded connection pool and bounded 429 retries. State is capped at 1,000 registrations and 500 temporary authorization requests. Idle unused registrations expire or can be evicted without deleting registrations used by active flows/grants.

These bounds reduce accidental overload and state exhaustion. They are **not DDoS protection**. Attackers can still consume shared quotas or network capacity, and legitimate users can receive 429 responses. Put internet traffic controls and monitoring in front of a deployment that requires stronger availability. HTTP access logs are disabled by default to avoid logging codes; add sanitized operational/audit events at the proxy if needed, without message bodies, tokens or authorization query strings.

## Remaining risks

- A process compromise can expose the bot credential and OAuth registration secrets. Read-only MCP tools do not make a stolen Discord bot token read-only. Run under a dedicated identity/container; keep bot permissions minimal and protect Docker/host access.
- Allowed callbacks reduce arbitrary-client phishing but do not cryptographically attest the client vendor. Check the exact callback with vendor documentation and approve only a connection you initiated. Never forward another person’s approval code as an authorization shortcut.
- A stolen bearer token can be replayed until expiry or revocation. Refresh tokens rotate, but reuse does not currently revoke an entire token family automatically. Revoke the member’s grants if compromise is suspected.
- Discord permission checks and the subsequent read are separate API requests; a permission change can race an in-flight read. The next call refreshes permissions.
- Authorized members can export history they can read. It is sent to the connected AI service; this server cannot retract or control that service’s retention. Agree on the server’s use policy and limit the bot to appropriate channels.
- Messages, embeds, links and attachment names may contain prompt injection. They are untrusted source data. The consuming client must enforce its own tool and disclosure boundaries.
- Public Funnel URLs reveal the service hostname and allow internet traffic to reach the app. Funnel does not authenticate MCP users or harden application dependencies. It does not expose the entire tailnet through this HTTP proxy.
- Keep dependencies and pinned container/action revisions updated. Automated dependency checks detect known advisories, not unknown vulnerabilities or all application bugs.

## Reporting

Report vulnerabilities privately using [GitHub private vulnerability reporting](https://github.com/ultsaza/discord-history-mcp/security/advisories/new). Include a minimal synthetic reproduction and affected version. Do not include live bot tokens, OAuth tokens, private Discord messages or another user’s identifiers in public issues.
