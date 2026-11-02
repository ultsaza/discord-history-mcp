# discord-history-mcp

Share a Discord server’s text history with MCP clients. Each member approves the connection in Discord; every read checks that member’s current permissions and the bot’s permissions.

No Discord user tokens or Discord OAuth client secret. No voice recording, message mirroring, or message-writing MCP tools.

## Quick start

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/).

1. Create a dedicated Discord application and bot in the [Developer Portal](https://discord.com/developers/applications). Enable **Message Content Intent** as permitted for your app. Install it in your server with `bot` and `applications.commands` scopes, and only **View Channels** / **Read Message History** permissions (`66560`). Do not grant Administrator. Private threads also require the bot to be a member, or have Manage Threads.
2. Copy `config.example.json` to `config.json`. Set your public HTTPS origin and server IDs. Add only exact OAuth callbacks you trust. Put the bot token in `secrets/bot-token`, outside Git; protect it with permissions `600`.
3. Run:

```sh
uv sync --locked
uv run discord-history-mcp --config config.json check
uv run discord-history-mcp --config config.json serve
```

4. Publish `127.0.0.1:19230` through an HTTPS reverse proxy. [Tailscale Funnel and container deployment](docs/deployment.md) are documented. Members do not need Tailscale when Funnel is used.
5. Add `https://YOUR-PUBLIC-HOST/mcp` to ChatGPT or Claude using OAuth and dynamic client registration (DCR). Run the displayed `/mcp code:CODE` in Discord and approve the private bot response. Keep the browser page open until it redirects back.

Each member repeats step 5 using their own Discord account. `/mcp action:revoke` revokes all their grants for that server.

The example callbacks follow current [ChatGPT authentication documentation](https://developers.openai.com/plugins/build/auth) and [Claude connector documentation](https://claude.com/docs/connectors/building/authentication). Check your client’s actual callback before enabling it. CIMD / private-key JWT client registration is not supported; choose DCR where offered. Client availability depends on the product plan and workspace policy.

## Tools

| Tool | Result |
| --- | --- |
| `whoami` | Connected member and approved server |
| `list_channels` | Readable text, announcement, forum and media channels |
| `list_threads` | Readable active threads under one channel |
| `get_messages` | 1–100 messages with authors, timestamps and Discord links |
| `search_messages` | Bounded text search through at most 500 messages in one channel |

Messages are returned oldest first. Use `next_before` / `next_after` for pagination. Search reports its coverage; it is not a complete server-wide index. Archived threads can be fetched by ID, but thread discovery covers active threads only. DMs and voice/stage text are excluded.

## Security and operation

- OAuth authorization code + PKCE S256; exact callback allowlist and resource audience validation.
- Explicit Discord consent bound to the interacting member and guild. Grants last 30 days; access tokens last one hour; refresh tokens rotate. Member revocation takes effect on the next request.
- Current membership, roles and channel overrides are fetched for every read. Private threads require membership or Manage Threads. Administrator on the bot is rejected at startup and during reads.
- HTTP defaults to loopback. Request size, body timeout, concurrency, endpoint rates and per-member work are bounded. Idle registrations expire and unused registrations can be evicted; active grants are preserved.
- Tokens and authorization codes are hashed in a private SQLite database. Messages are not stored. Returned Discord content remains untrusted input to the AI client.

Read the [security model and remaining risks](SECURITY.md) before public deployment. In particular, granted history is sent to the connected AI service, and revocation cannot retract data already delivered. Use a dedicated bot and isolated service account/container.

## Development

```sh
uv sync --locked --group dev
uv run ruff check src tests
uv run ruff format --check src tests
uv run pytest -q
uv build
```

Tests use synthetic Discord data and local ASGI transport. A live Discord bot and real ChatGPT/Claude account are still needed to verify a deployment’s first connection.

[日本語の導入手順](docs/README.ja.md) · [Architecture](docs/architecture.md) · [Deployment](docs/deployment.md) · [MIT License](LICENSE)
