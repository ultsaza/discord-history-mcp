# Deployment

Use a **dedicated Discord application**, a protected state directory, and a dedicated service account or isolated container. Keep the public origin stable: changing it invalidates resource-bound tokens and requires new client connections. Configure only exact callback URIs that you have verified with the client vendor; wildcards and inferred client names are not accepted.

## Native service

Follow the root README. Relative token/state paths are resolved relative to the configuration file. The `check` command reads bot/guild metadata and verifies that the bot lacks Administrator; it does not read members’ message history. Use `uv run discord-history-mcp --config config.json invite-url` to print a minimal-permission installation URL before joining the server. `check` requires the bot to already belong to the configured guilds. The Developer Portal URL generator also works with permissions `66560` and `bot applications.commands` scopes.

```sh
uv run discord-history-mcp --config config.json check
uv run discord-history-mcp --config config.json serve
```

Keep one instance running using your operating system’s service manager. `serve` binds loopback by default. Only use `--host 0.0.0.0` inside an isolated environment with restricted ingress. `/healthz` returns 200 when the HTTP service and Discord Gateway are ready, otherwise 503. Startup fails if the bot cannot connect or has Administrator. Investigate a persistent unhealthy state and restart after fixing its cause.

The bot must have access to Message Content data. Enable the corresponding privileged intent in the Developer Portal and obtain review when Discord requires it. Gateway Guild Members / Presence intents are not requested. Private thread history requires bot membership or Manage Threads, plus parent-channel history permissions.

## Docker Compose

The image runs as UID/GID 1000. Compose uses a read-only root filesystem, no Linux capabilities, `no-new-privileges`, bounded resources, and a host-loopback published port. Only OAuth state is writable by the service. A separate setup command provisions the bot token into a named volume; the running service mounts that volume read-only.

```sh
cp config.docker.example.json config.docker.json
mkdir -p secrets
chmod 700 secrets
# Save your token to secrets/bot-token using your editor or password manager.
chmod 600 secrets/bot-token
# Edit config.docker.json: public HTTPS origin, server IDs, exact callbacks.
docker compose build mcp
docker compose run --rm -T provision-token < secrets/bot-token
docker compose run --rm mcp --config /config/config.json check
docker compose up -d mcp
docker compose ps
docker compose logs --tail=50 mcp
```

The setup command receives the token on stdin; do not put it in shell arguments, Dockerfile, Git, or environment examples. Protect the Docker daemon and volumes. A container reduces host file exposure; it does not guarantee containment against a kernel or container-runtime exploit. Use a dedicated host/VM for stronger separation.

Rotate the bot credential in the Developer Portal, update `secrets/bot-token`, run the setup command again, and recreate the service with `docker compose up -d --force-recreate mcp`. OAuth grants remain in the state volume. Remove that volume only if you intend to revoke all connections. Do not use `docker compose down --volumes` for routine maintenance.

## Tailscale Funnel

On the host running the service (or its host-loopback container port):

```sh
tailscale funnel --bg --https=443 http://127.0.0.1:19230
tailscale funnel status
```

Set `base_url` to the exact `https://HOST.TAILNET.ts.net` origin that Funnel reports, then restart the service. The MCP URL is that origin plus `/mcp`. Funnel users do **not** need to join your tailnet or install Tailscale. HTTPS protects transport; OAuth and Discord permissions protect the history. Enabling Funnel makes the HTTP endpoints internet-accessible. Review [Funnel’s requirements](https://tailscale.com/docs/features/tailscale-funnel) and any existing Serve/Funnel listeners before changing them. Do not reset unrelated proxy configuration.

A DNS resolver inside your tailnet may route the hostname privately. Verify public reachability from an external network as well. An unauthenticated MCP request must receive 401; a successful `/healthz` response alone does not prove permission enforcement.

## Other HTTPS proxies and client setup

Any reverse proxy that preserves Host/Authorization headers and does not log credentials or authorization query strings can front the loopback service. Proxy only to this application; do not expose a filesystem or Docker API. Forwarding headers are ignored by the application, and cannot be used to bypass shared rate limits.

Public endpoints include OAuth discovery, DCR, authorization, token exchange and temporary approval pages. `/mcp` requires a valid resource-bound bearer token. Do not put a generic interactive login wall in front of discovery/token endpoints; it can prevent cloud MCP clients from completing OAuth.

The example contains the current stable ChatGPT callback and Claude’s documented callback. ChatGPT uses its stable callback only when issuer identification is supported; this server advertises and returns that issuer. Always compare the exact production URI shown by your client. Do not loosen the allowlist to fix an unexplained mismatch. Client names are descriptive, not identity proof. CIMD/private-key JWT are not implemented; select dynamic client registration (DCR).

Product plans and workspace policy can prevent custom connectors. After deployment, link a real client account, run `whoami`, read a permitted channel, confirm a forbidden channel is denied using a second member with different permissions, and revoke the connection in Discord. Automated tests do not replace this deployment-specific check.
