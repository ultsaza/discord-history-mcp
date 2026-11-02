import json
import time
from urllib.parse import parse_qs, urlsplit

import pytest
from test_oauth import authorize, begin, exchange, rpc
from test_oauth import running as running

from discord_history_mcp.config import Config
from discord_history_mcp.keys import Store
from discord_history_mcp.limits import SlidingLimits


async def register(client, redirect="https://client.test/callback"):
    return await client.post(
        "/register",
        json={
            "client_name": "ChatGPT",
            "redirect_uris": [redirect],
            "token_endpoint_auth_method": "none",
        },
    )


async def test_callback_allowlist_does_not_trust_the_client_name(running):
    _app, client, _world = running
    for redirect in [
        "https://attacker.test/callback",
        "https://client.test/callback/extra",
        "https://client.test/callback?attacker=1",
        "http://client.test/callback",
        "https://client.test.attacker.test/callback",
    ]:
        response = await register(client, redirect)
        assert response.status_code == 400
    assert (await register(client)).status_code == 201


async def test_issuer_is_identical_in_success_denial_and_authorization_error(running):
    app, client, _world = running
    issuer = (await client.get("/.well-known/oauth-authorization-server")).json()["issuer"]
    _registration, _verifier, response = await begin(client)
    location = response.headers["location"]
    code = app.state.provider.flow(location.rsplit("/", 1)[1])["approval_code"]
    app.state.provider.store.decide(code, "2", "1", True)
    result = (await client.get(location + "/status")).json()
    assert parse_qs(urlsplit(result["redirect_url"]).query)["iss"] == [issuer]
    _, _, response = await begin(client)
    location = response.headers["location"]
    code = app.state.provider.flow(location.rsplit("/", 1)[1])["approval_code"]
    app.state.provider.store.decide(code, "2", "1", False)
    result = (await client.get(location + "/status")).json()
    assert parse_qs(urlsplit(result["redirect_url"]).query)["iss"] == [issuer]
    _, _, response = await begin(client, resource="https://wrong.test/mcp")
    assert parse_qs(urlsplit(response.headers["location"]).query)["iss"] == [issuer]


async def test_unused_registrations_are_evicted_without_invalidating_active_grants(running):
    app, client, _world = running
    provider = app.state.provider
    provider.max_clients = 2
    active, verifier, code = await authorize(app, client)
    tokens = (await exchange(client, active, verifier, code)).json()
    unused = (await register(client)).json()
    replacement = await register(client)
    assert replacement.status_code == 201
    assert await provider.get_client(unused["client_id"]) is None
    assert await provider.get_client(active["client_id"]) is not None
    with provider.store.connect() as db:
        db.execute("UPDATE clients SET expires_at=1")
        db.execute("UPDATE requests SET expires_at=1")
    provider.store.prune()
    assert await provider.get_client(replacement.json()["client_id"]) is None
    refreshed = await client.post(
        "/token",
        data={
            "grant_type": "refresh_token",
            "client_id": active["client_id"],
            "refresh_token": tokens["refresh_token"],
        },
    )
    assert refreshed.status_code == 200


async def test_member_limits_do_not_share_one_members_authority_or_quota(running):
    app, client, _world = running
    tokens = {}
    for member in ["2", "3"]:
        registration, verifier, code = await authorize(app, client, member)
        tokens[member] = (await exchange(client, registration, verifier, code)).json()[
            "access_token"
        ]
    for _ in range(6):
        response = await rpc(
            client,
            tokens["2"],
            "tools/call",
            {
                "name": "search_messages",
                "arguments": {
                    "channel_id": "100",
                    "query": "hello",
                    "max_messages": 1,
                },
            },
        )
        assert not response.json()["result"].get("isError")
    limited = await rpc(client, tokens["2"], "tools/call", {"name": "whoami"})
    assert limited.json()["result"]["isError"] is True
    assert "Member request limit" in str(limited.json())
    allowed = await rpc(client, tokens["3"], "tools/call", {"name": "whoami"})
    assert not allowed.json()["result"].get("isError")


async def test_anonymous_registration_limit_and_blank_token_resource(running):
    app, client, _world = running
    registration, verifier, code = await authorize(app, client)
    assert (await exchange(client, registration, verifier, code, resource="")).status_code == 400
    assert (await exchange(client, registration, verifier, code)).status_code == 200
    for _ in range(29):
        assert (await register(client)).status_code == 201
    denied = await register(client)
    assert denied.status_code == 429
    assert denied.headers["retry-after"] == "60"


def test_rate_window_expires_and_bounds_untrusted_keys():
    now = [0]
    limits = SlidingLimits(clock=lambda: now[0], max_keys=2)
    assert limits.allow("one", 2, 2)
    assert not limits.allow("one", 2)
    assert limits.allow("two", 2)
    assert not limits.allow("three", 2)
    now[0] = 61
    assert limits.allow("three", 2)
    assert limits.allow("one", 2)


def test_configuration_requires_exact_callbacks_and_relative_paths_use_config_directory(tmp_path):
    config_file = tmp_path / "settings/config.json"
    config_file.parent.mkdir()
    data = {
        "base_url": "https://mcp.test",
        "allowed_guild_ids": ["1"],
        "allowed_redirect_uris": ["https://client.test/callback"],
        "bot_token_file": "secret",
        "state_dir": "state",
    }
    config_file.write_text(json.dumps(data))
    config = Config.load(config_file)
    assert config.token_file == config_file.parent / "secret"
    assert config.state_dir == config_file.parent / "state"
    for redirects in [[], ["https://:password@client.test/callback"], ["http://public.test/cb"]]:
        config_file.write_text(json.dumps(data | {"allowed_redirect_uris": redirects}))
        with pytest.raises(ValueError):
            Config.load(config_file)


def test_oauth_state_files_are_private_and_expired_flows_are_removed(tmp_path):
    store = Store(tmp_path / "private/state.sqlite3")
    with store.connect() as db:
        db.execute(
            "INSERT INTO requests VALUES (?,?,?,?, 'pending',NULL,NULL)",
            ("flow", "CODE", "{}", int(time.time()) - 1),
        )
    store.prune()
    with store.connect() as db:
        assert db.execute("SELECT COUNT(*) FROM requests").fetchone()[0] == 0
    assert store.path.stat().st_mode & 0o777 == 0o600
    assert store.path.parent.stat().st_mode & 0o777 == 0o700
