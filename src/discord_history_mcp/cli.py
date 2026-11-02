import argparse
import asyncio
import json
import logging
import os
import sys
from pathlib import Path

from .config import Config
from .keys import Store, snowflake


async def check(config: Config, *, check_guilds=True):
    from .discord import Discord

    client = Discord(config.token_file.read_text().strip())
    try:
        identity = await client.get("/users/@me")
        guilds = sorted(config.allowed_guilds) if check_guilds else []
        for guild in guilds:
            await client.check_bot(guild)
        if check_guilds:
            Store(config.database).prune()
        return {"bot_id": identity["id"], "guilds_checked": len(guilds)}
    finally:
        await client.client.aclose()


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description="Discord history MCP with per-member OAuth")
    parser.add_argument("--config", type=Path)
    actions = parser.add_subparsers(dest="action", required=True)
    serve = actions.add_parser("serve")
    serve.add_argument("--host", choices=["127.0.0.1", "0.0.0.0"], default="127.0.0.1")
    actions.add_parser(
        "check", help="Check bot access and reject Administrator; do not read messages"
    )
    actions.add_parser("invite-url", help="Print a bot installation URL with minimal permissions")
    revoke = actions.add_parser("revoke", help="Locally revoke a member's grants in one guild")
    revoke.add_argument("--user", required=True)
    revoke.add_argument("--guild", required=True)
    args = parser.parse_args()
    try:
        config = Config.load(args.config)
        if args.action == "serve":
            import uvicorn

            from .server import create_app

            logging.basicConfig(level=logging.INFO)
            logging.getLogger("httpx").setLevel(logging.WARNING)
            uvicorn.run(
                create_app(config, enable_gateway=True),
                host=args.host,
                port=config.port,
                access_log=False,
                proxy_headers=False,
                limit_concurrency=32,
                timeout_keep_alive=15,
                timeout_graceful_shutdown=30,
            )
        elif args.action in {"check", "invite-url"}:
            result = asyncio.run(check(config, check_guilds=args.action == "check"))
            if args.action == "check":
                print(json.dumps(result))
            else:
                print(
                    "https://discord.com/oauth2/authorize?client_id="
                    + result["bot_id"]
                    + "&permissions=66560&scope=bot%20applications.commands"
                )
        else:
            user, guild = snowflake(args.user), snowflake(args.guild)
            if guild not in config.allowed_guilds:
                raise ValueError("Guild is not enabled")
            Store(config.database).revoke(user, guild)
            print(json.dumps({"revoked": True}))
    except (ValueError, OSError, KeyError, RuntimeError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
