import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from test_access import World, principal
from test_oauth import begin, exchange, rpc
from test_oauth import running as running

from discord_history_mcp.cli import check
from discord_history_mcp.config import Config
from discord_history_mcp.gateway import Gateway, clean_label
from discord_history_mcp.server import create_app


def interaction(user=2, guild=1):
    return SimpleNamespace(
        user=SimpleNamespace(id=user),
        guild_id=guild,
        response=SimpleNamespace(defer=AsyncMock(), send_message=AsyncMock()),
        edit_original_response=AsyncMock(),
    )


async def test_only_the_approving_member_can_complete_the_oauth_connection(running):
    app, client, _world = running
    registration, verifier, response = await begin(client)
    location = response.headers["location"]
    flow = app.state.provider.flow(location.rsplit("/", 1)[1])
    config = Config(
        "https://mcp.test",
        {"1"},
        app.state.provider.store.path.parent,
        app.state.provider.store.path,
        frozenset({"https://client.test/callback"}),
    )
    gateway = Gateway(config, app.state.provider.store)
    try:
        owner = interaction()
        await gateway.handle(owner, flow["approval_code"])
        owner.response.defer.assert_awaited_once_with(ephemeral=True, thinking=True)
        view = owner.edit_original_response.await_args.kwargs["view"]
        assert not gateway.intents.members and not gateway.intents.guild_messages
        assert gateway.intents.message_content
        stranger = interaction(user=3)
        await view.decide(stranger, True)
        assert (await client.get(location + "/status")).json()["status"] == "pending"
        stranger.response.send_message.assert_awaited_once()
        assert stranger.response.send_message.await_args.kwargs["ephemeral"] is True
        await view.decide(interaction(user=2, guild=55), True)
        assert (await client.get(location + "/status")).json()["status"] == "pending"
        await view.decide(owner, True)
        result = (await client.get(location + "/status")).json()
        code = parse_qs(urlsplit(result["redirect_url"]).query)["code"][0]
        token = (await exchange(client, registration, verifier, code)).json()["access_token"]
        response = await rpc(client, token, "tools/call", {"name": "whoami"})
        result = response.json()["result"]
        assert not result.get("isError"), result
        assert json.loads(result["content"][0]["text"])["user_id"] == "2"
        await gateway.handle(owner, action="revoke")
        assert (await rpc(client, token, "tools/list")).status_code == 401
    finally:
        await gateway.close()


async def test_admin_bot_is_rejected_at_preflight_and_after_role_change():
    world = World()
    client = world.discord()
    await client.check_bot("1")
    world.members["9"]["roles"] = ["12"]
    try:
        with pytest.raises(ValueError, match="Administrator"):
            await client.check_bot("1")
        with pytest.raises(ValueError, match="Administrator"):
            await client.get_messages(principal(), "100")
        assert "/channels/100/messages" not in world.calls
    finally:
        await client.client.aclose()


async def test_gateway_lifecycle_health_and_cleanup(monkeypatch, tmp_path):
    instances = []

    class FakeGateway:
        def __init__(self, _config, _store):
            self.connected, self.stop = asyncio.Event(), asyncio.Event()
            self.ready = False
            instances.append(self)

        async def start(self, _token):
            self.ready = True
            self.connected.set()
            await self.stop.wait()

        def is_ready(self):
            return self.ready

        async def close(self):
            self.ready = False
            self.stop.set()

    monkeypatch.setattr("discord_history_mcp.server.Gateway", FakeGateway)
    token_file = tmp_path / "secret"
    token_file.write_text("synthetic-token")
    config = Config(
        "https://mcp.test",
        {"1"},
        tmp_path / "state",
        token_file,
        frozenset({"https://client.test/callback"}),
    )
    discord = World().discord()
    app = create_app(config, discord=discord, enable_gateway=True)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app), base_url=config.base_url
        ) as client:
            assert (await client.get("/healthz")).status_code == 200
            instances[0].ready = False
            assert (await client.get("/healthz")).status_code == 503
    assert instances[0].stop.is_set()
    assert discord.client.is_closed
    assert app.state.gateway_task.done()


def test_client_labels_cannot_add_mentions_or_markdown_blocks():
    assert clean_label("evil\n```@everyone<>\x00") == "evil'''＠everyone‹›"


async def test_installation_url_identity_check_does_not_require_guild_membership(
    monkeypatch, tmp_path
):
    world = World()
    monkeypatch.setattr("discord_history_mcp.discord.Discord", lambda _token: world.discord())
    token_file = tmp_path / "secret"
    token_file.write_text("synthetic-token")
    config = Config(
        "https://mcp.test",
        {"1"},
        tmp_path / "state",
        token_file,
        frozenset({"https://client.test/callback"}),
    )
    assert await check(config, check_guilds=False) == {"bot_id": "9", "guilds_checked": 0}
    assert world.calls == ["/users/@me"]
