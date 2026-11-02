import datetime
import time

import httpx
import pytest

from discord_history_mcp.discord import (
    ADMIN,
    HISTORY,
    MANAGE_THREADS,
    VIEW,
    AccessDenied,
    Discord,
    permissions,
)
from discord_history_mcp.keys import Principal


class World:
    def __init__(self):
        self.guild = {
            "id": "1",
            "name": "Test guild",
            "owner_id": "99",
            "roles": [
                {"id": "1", "permissions": str(VIEW | HISTORY)},
                {"id": "10", "permissions": "0"},
                {"id": "11", "permissions": str(MANAGE_THREADS)},
                {"id": "12", "permissions": str(ADMIN)},
            ],
        }
        self.members = {
            "2": {"user": {"id": "2", "username": "alice"}, "roles": ["10"]},
            "3": {"user": {"id": "3", "username": "bob"}, "roles": []},
            "9": {"user": {"id": "9", "username": "bot"}, "roles": ["11"]},
        }
        self.channels = {
            "100": {
                "id": "100",
                "name": "general",
                "guild_id": "1",
                "type": 0,
                "permission_overwrites": [],
            },
            "101": {
                "id": "101",
                "name": "secret-name",
                "guild_id": "1",
                "type": 0,
                "permission_overwrites": [
                    {"id": "1", "type": 0, "deny": str(VIEW), "allow": "0"},
                    {"id": "10", "type": 0, "deny": "0", "allow": str(VIEW)},
                    {"id": "11", "type": 0, "deny": "0", "allow": str(VIEW)},
                ],
            },
            "102": {
                "id": "102",
                "name": "no-history",
                "guild_id": "1",
                "type": 0,
                "permission_overwrites": [
                    {"id": "1", "type": 0, "deny": str(HISTORY), "allow": "0"}
                ],
            },
            "103": {
                "id": "103",
                "name": "other-guild",
                "guild_id": "55",
                "type": 0,
                "permission_overwrites": [],
            },
            "104": {
                "id": "104",
                "name": "voice",
                "guild_id": "1",
                "type": 2,
                "permission_overwrites": [],
            },
            "110": {
                "id": "110",
                "name": "public-thread",
                "guild_id": "1",
                "type": 11,
                "parent_id": "100",
            },
            "111": {
                "id": "111",
                "name": "private-thread",
                "guild_id": "1",
                "type": 12,
                "parent_id": "100",
            },
            "112": {
                "id": "112",
                "name": "hidden-parent",
                "guild_id": "1",
                "type": 11,
                "parent_id": "101",
            },
        }
        self.calls = []

    def response(self, request):
        assert request.method == "GET"
        path = request.url.path.removeprefix("/api/v10")
        self.calls.append(path)
        if path == "/users/@me":
            data = {"id": "9"}
        elif path == "/guilds/1":
            data = self.guild
        elif path.startswith("/guilds/1/members/"):
            user = path.rsplit("/", 1)[1]
            if user not in self.members:
                return httpx.Response(404)
            data = self.members[user]
        elif path == "/guilds/1/channels":
            data = [
                v
                for v in self.channels.values()
                if v["type"] not in {11, 12} and v["guild_id"] == "1"
            ]
        elif path == "/guilds/1/threads/active":
            data = {"threads": [self.channels[key] for key in ["110", "111", "112"]]}
        elif "/thread-members/" in path:
            user = path.rsplit("/", 1)[1]
            if user != "2":
                return httpx.Response(404)
            data = {"user_id": user}
        elif path.endswith("/messages"):
            data = [
                {
                    "id": "200",
                    "timestamp": "2026-11-02T00:00:00Z",
                    "content": "hello history",
                    "author": {"id": "2", "username": "alice"},
                }
            ]
        elif path.startswith("/channels/"):
            data = self.channels[path.rsplit("/", 1)[1]]
        else:
            raise AssertionError(path)
        return httpx.Response(200, json=data)

    def discord(self):
        return Discord(
            "unused",
            client=httpx.AsyncClient(
                base_url="https://discord.test/api/v10",
                transport=httpx.MockTransport(self.response),
            ),
        )


def principal(user="2"):
    return Principal(user, "1", int(time.time()) + 3600)


@pytest.mark.asyncio
async def test_live_roles_and_membership_change_apply_to_next_fetch():
    world = World()
    discord = world.discord()
    assert (await discord.get_messages(principal(), "101"))["messages"][0][
        "content"
    ] == "hello history"
    world.members["2"]["roles"] = []
    world.calls.clear()
    with pytest.raises(AccessDenied):
        await discord.get_messages(principal(), "101")
    assert "/channels/101/messages" not in world.calls
    del world.members["2"]
    with pytest.raises(AccessDenied):
        await discord.get_messages(principal(), "100")
    await discord.client.aclose()


@pytest.mark.asyncio
async def test_list_and_read_do_not_leak_hidden_channels_or_cross_guild_data():
    world = World()
    discord = world.discord()
    channels = await discord.list_channels(principal("3"))
    assert [channel["id"] for channel in channels["channels"]] == ["100"]
    assert "secret-name" not in str(channels)
    for channel in ("101", "102", "103", "104"):
        with pytest.raises(AccessDenied):
            await discord.get_messages(principal("3"), channel)
        assert f"/channels/{channel}/messages" not in world.calls
    await discord.client.aclose()


@pytest.mark.asyncio
async def test_private_threads_require_membership_and_parent_permissions():
    world = World()
    discord = world.discord()
    assert (await discord.get_messages(principal(), "111"))["messages"]
    with pytest.raises(AccessDenied):
        await discord.get_messages(principal("3"), "111")
    with pytest.raises(AccessDenied):
        await discord.get_messages(principal("3"), "112")
    visible = await discord.list_threads(principal("3"), "100")
    assert [thread["id"] for thread in visible["threads"]] == ["110"]
    await discord.client.aclose()


def test_overwrite_precedence_owner_admin_and_unknown_roles():
    world = World()
    channel = world.channels["101"]
    alice = world.members["2"]
    assert permissions(world.guild, alice, channel) & VIEW
    channel["permission_overwrites"].append({"id": "2", "type": 1, "deny": str(VIEW), "allow": "0"})
    assert not permissions(world.guild, alice, channel) & VIEW
    assert permissions(world.guild, world.members["9"], channel) & MANAGE_THREADS
    assert permissions(world.guild, {"user": {"id": "99"}, "roles": []}, channel) & ADMIN
    assert permissions(world.guild, {"user": {"id": "77"}, "roles": ["12"]}, channel) & ADMIN
    alice["roles"] = ["unknown"]
    with pytest.raises(AccessDenied):
        permissions(world.guild, alice, channel)


@pytest.mark.asyncio
async def test_bounded_search_reports_incomplete_coverage():
    world = World()
    discord = world.discord()
    result = await discord.search_messages(principal(), "100", "hello", max_messages=1)
    assert result["scanned_messages"] == 1
    assert result["older_history_not_scanned"] is True
    assert result["scope"] == "bounded recent-history scan"
    with pytest.raises(ValueError):
        await discord.get_messages(principal(), "../../users/@me")
    with pytest.raises(ValueError):
        await discord.get_messages(principal(), "100", limit=101)
    await discord.client.aclose()


@pytest.mark.asyncio
async def test_bot_permission_is_also_required():
    world = World()
    world.members["9"]["roles"] = []
    discord = world.discord()
    with pytest.raises(AccessDenied):
        await discord.get_messages(principal(), "101")
    assert "/channels/101/messages" not in world.calls
    await discord.client.aclose()


@pytest.mark.asyncio
async def test_timeout_removes_manage_threads_without_removing_readable_public_history():
    world = World()
    world.members["3"]["roles"] = ["11"]
    discord = world.discord()
    try:
        assert (await discord.get_messages(principal("3"), "111"))["messages"]
        world.members["3"]["communication_disabled_until"] = (
            datetime.datetime.now(datetime.UTC) + datetime.timedelta(hours=1)
        ).isoformat()
        with pytest.raises(AccessDenied):
            await discord.get_messages(principal("3"), "111")
        assert (await discord.get_messages(principal("3"), "100"))["messages"]
        world.members["3"]["communication_disabled_until"] = (
            datetime.datetime.now(datetime.UTC) - datetime.timedelta(hours=1)
        ).isoformat()
        assert (await discord.get_messages(principal("3"), "111"))["messages"]
    finally:
        await discord.client.aclose()
