"""Bot REST access, intersected with fresh permissions of the authenticated member."""

import asyncio
import datetime
from typing import Any

import httpx

from .keys import Principal, snowflake

VIEW = 1 << 10
HISTORY = 1 << 16
ADMIN = 1 << 3
MANAGE_THREADS = 1 << 34
TEXT = {0, 5}
THREADS = {10, 11, 12}
CONTAINERS = {0, 5, 15, 16}
ALL = (1 << 64) - 1


class AccessDenied(Exception):
    def __init__(self):
        super().__init__("You do not have permission to read this server or channel history.")


def reject_admin_bot(guild: dict, bot: dict) -> None:
    roles = {role["id"]: int(role["permissions"]) for role in guild["roles"]}
    if guild["id"] not in roles or any(role not in roles for role in bot["roles"]):
        raise AccessDenied()
    assigned = roles[guild["id"]]
    for role in bot["roles"]:
        assigned |= roles[role]
    if assigned & ADMIN or bot["user"]["id"] == guild["owner_id"]:
        raise ValueError("Remove the bot's Administrator permission before using this service")


def permissions(guild: dict, member: dict, channel: dict) -> int:
    user_id = member["user"]["id"]
    if user_id == guild["owner_id"]:
        return ALL
    roles = {role["id"]: int(role["permissions"]) for role in guild["roles"]}
    if guild["id"] not in roles or any(role not in roles for role in member["roles"]):
        raise AccessDenied()  # A role change raced the snapshot: don't guess.
    result = roles[guild["id"]]
    for role in member["roles"]:
        result |= roles[role]
    if result & ADMIN:
        return ALL
    if "permission_overwrites" not in channel:
        raise AccessDenied()
    overwrites = channel["permission_overwrites"]
    if any(overwrite["type"] not in {0, 1} for overwrite in overwrites):
        raise AccessDenied()
    for overwrite in overwrites:
        if overwrite["type"] == 0 and overwrite["id"] == guild["id"]:
            result = (result & ~int(overwrite["deny"])) | int(overwrite["allow"])
    deny = allow = 0
    for overwrite in overwrites:
        if overwrite["type"] == 0 and overwrite["id"] in member["roles"]:
            deny |= int(overwrite["deny"])
            allow |= int(overwrite["allow"])
    result = (result & ~deny) | allow
    for overwrite in overwrites:
        if overwrite["type"] == 1 and overwrite["id"] == user_id:
            result = (result & ~int(overwrite["deny"])) | int(overwrite["allow"])
    # Discord removes Manage Threads (among other permissions) during a timeout.
    # Owners and administrators returned above are exempt from this restriction.
    timeout = member.get("communication_disabled_until")
    if timeout is not None:
        try:
            deadline = datetime.datetime.fromisoformat(timeout)
            if deadline.tzinfo is None:
                raise ValueError("Missing timezone")
        except (TypeError, ValueError):
            raise AccessDenied() from None
        if deadline > datetime.datetime.now(datetime.UTC):
            result &= VIEW | HISTORY
    return result


class Discord:
    def __init__(self, token: str, *, client: httpx.AsyncClient | None = None):
        self.client = client or httpx.AsyncClient(
            base_url="https://discord.com/api/v10",
            headers={"Authorization": f"Bot {token}", "User-Agent": "DiscordHistoryMCP/0.1"},
            timeout=15,
            follow_redirects=False,
            limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
        )
        self._bot_id: str | None = None

    async def check_bot(self, guild_id: str):
        if self._bot_id is None:
            self._bot_id = (await self.get("/users/@me"))["id"]
        guild, bot = await asyncio.gather(
            self.get(f"/guilds/{guild_id}"),
            self.get(f"/guilds/{guild_id}/members/{self._bot_id}"),
        )
        reject_admin_bot(guild, bot)

    async def get(self, path: str, params=None) -> Any:
        for attempt in range(3):
            response = await self.client.get(path, params=params)
            if response.status_code in {403, 404}:
                raise AccessDenied()
            if response.status_code == 429:
                retry = float(response.json().get("retry_after", 1))
                if retry > 5 or attempt == 2:
                    raise RuntimeError("Discord rate limit reached. Please retry later.")
                await asyncio.sleep(max(retry, 0.1))
                continue
            if response.status_code != 200:
                raise RuntimeError(f"Discord API request failed (HTTP {response.status_code}).")
            return response.json()
        raise RuntimeError("Discord API retry limit reached")

    async def snapshot(self, principal: Principal):
        guild_id = principal.guild_id
        if self._bot_id is None:
            self._bot_id = (await self.get("/users/@me"))["id"]
        guild, member, bot = await asyncio.gather(
            self.get(f"/guilds/{guild_id}"),
            self.get(f"/guilds/{guild_id}/members/{principal.user_id}"),
            self.get(f"/guilds/{guild_id}/members/{self._bot_id}"),
        )
        if guild["id"] != guild_id or member["user"]["id"] != principal.user_id:
            raise AccessDenied()
        if member.get("pending"):
            raise AccessDenied()
        reject_admin_bot(guild, bot)
        return guild, member, bot

    async def readable(self, channel: dict, snapshot, *, parent: dict | None = None) -> None:
        guild, member, bot = snapshot
        if channel.get("guild_id") != guild["id"]:
            raise AccessDenied()
        if channel["type"] not in TEXT | THREADS | CONTAINERS:
            raise AccessDenied()  # No DMs, voice/stage chats, categories, or unknown channel types.
        target = channel
        if channel["type"] in THREADS:
            parent = parent or await self.get(f"/channels/{snowflake(channel['parent_id'])}")
            if parent.get("guild_id") != guild["id"] or parent["type"] not in CONTAINERS:
                raise AccessDenied()
            target = parent
        for actor in (member, bot):
            actor_permissions = permissions(guild, actor, target)
            if actor_permissions & (VIEW | HISTORY) != VIEW | HISTORY:
                raise AccessDenied()
            if channel["type"] == 12 and not actor_permissions & MANAGE_THREADS:
                await self.get(f"/channels/{channel['id']}/thread-members/{actor['user']['id']}")

    async def list_channels(self, principal: Principal) -> dict:
        snapshot = await self.snapshot(principal)
        channels = await self.get(f"/guilds/{principal.guild_id}/channels")
        result = []
        for channel in channels:
            if channel["type"] not in CONTAINERS:
                continue
            try:
                await self.readable(channel, snapshot)
            except AccessDenied:
                continue
            result.append(self.channel_info(channel))
        return {
            "guild_id": principal.guild_id,
            "channels": result,
            "threads": "Threads are returned separately by list_threads.",
        }

    async def list_threads(self, principal: Principal, parent_channel_id: str) -> dict:
        parent_id = snowflake(parent_channel_id)
        snapshot = await self.snapshot(principal)
        parent = await self.get(f"/channels/{parent_id}")
        await self.readable(parent, snapshot)
        if parent["type"] not in CONTAINERS:
            raise AccessDenied()
        active = await self.get(f"/guilds/{principal.guild_id}/threads/active")
        result = []
        for thread in active["threads"]:
            if thread.get("parent_id") != parent_id:
                continue
            try:
                await self.readable(thread, snapshot, parent=parent)
            except AccessDenied:
                continue
            result.append(self.channel_info(thread))
        return {
            "threads": result,
            "coverage": "active threads only",
            "archived_threads": "Archived threads can be read by their ID with get_messages.",
        }

    @staticmethod
    def channel_info(channel: dict) -> dict:
        return {key: channel.get(key) for key in ("id", "name", "type", "parent_id")}

    async def get_messages(
        self,
        principal: Principal,
        channel_id: str,
        limit: int = 50,
        before: str | None = None,
        after: str | None = None,
    ) -> dict:
        channel_id = snowflake(channel_id)
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("limit must be between 1 and 100")
        if before and after:
            raise ValueError("Use before OR after, not both")
        params = {"limit": limit}
        if before:
            params["before"] = snowflake(before)
        if after:
            params["after"] = snowflake(after)
        snapshot = await self.snapshot(principal)
        channel = await self.get(f"/channels/{channel_id}")
        await self.readable(channel, snapshot)
        if channel["type"] not in TEXT | THREADS:
            raise ValueError("Forum/media parents contain threads; call list_threads first")
        messages = await self.get(f"/channels/{channel_id}/messages", params=params)
        messages.sort(key=lambda item: int(item["id"]))
        records = [self.message_info(item, principal.guild_id, channel_id) for item in messages]
        return {
            "guild_id": principal.guild_id,
            "channel": self.channel_info(channel),
            "messages": records,
            "order": "oldest_first",
            "next_before": messages[0]["id"] if messages else None,
            "next_after": messages[-1]["id"] if messages else None,
            "page_full": len(messages) == limit,
            "permission_checked_at": datetime.datetime.now(datetime.UTC).isoformat(),
        }

    @staticmethod
    def message_info(item: dict, guild_id: str, channel_id: str) -> dict:
        author = item.get("author", {})
        return {
            "id": item["id"],
            "timestamp": item["timestamp"],
            "edited_timestamp": item.get("edited_timestamp"),
            "author": {key: author.get(key) for key in ("id", "username", "global_name", "bot")},
            "content": item.get("content", ""),
            "type": item.get("type"),
            "attachments": [
                {
                    key: attachment.get(key)
                    for key in ("id", "filename", "content_type", "size", "url")
                }
                for attachment in item.get("attachments", [])
            ],
            "embeds": item.get("embeds", []),
            "referenced_message_id": (item.get("message_reference") or {}).get("message_id"),
            "url": f"https://discord.com/channels/{guild_id}/{channel_id}/{item['id']}",
        }

    async def search_messages(
        self,
        principal: Principal,
        channel_id: str,
        query: str,
        max_messages: int = 300,
        before: str | None = None,
    ) -> dict:
        if not query.strip() or len(query) > 200:
            raise ValueError("query must contain 1 to 200 characters")
        if type(max_messages) is not int or not 1 <= max_messages <= 500:
            raise ValueError("max_messages must be between 1 and 500")
        scanned, found, last_page = 0, [], None
        cursor = before
        while scanned < max_messages:
            page_size = min(100, max_messages - scanned)
            page = await self.get_messages(principal, channel_id, page_size, before=cursor)
            records = page["messages"]
            scanned += len(records)
            found.extend(
                record for record in records if query.casefold() in record["content"].casefold()
            )
            last_page = page
            if not page["page_full"]:
                break
            cursor = page["next_before"]
        found.sort(key=lambda item: int(item["id"]))
        return {
            "messages": found,
            "scanned_messages": scanned,
            "scope": "bounded recent-history scan",
            "older_history_not_scanned": bool(last_page and last_page["page_full"]),
            "next_before": last_page["next_before"] if last_page else None,
        }
