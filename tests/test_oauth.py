import asyncio
import base64
import hashlib
import re
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from test_access import World

from discord_history_mcp.config import Config
from discord_history_mcp.server import create_app


async def begin(
    client, *, resource="https://mcp.test/mcp", redirect="https://client.test/callback"
):
    response = await client.post(
        "/register",
        json={
            "client_name": "Test chat client",
            "redirect_uris": [redirect],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
        },
    )
    assert response.status_code == 201, response.text
    registration = response.json()
    verifier = "valid-verifier-" * 5
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    )
    response = await client.get(
        "/authorize",
        params={
            "client_id": registration["client_id"],
            "response_type": "code",
            "redirect_uri": redirect,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": "original-state",
            "scope": "discord.history.read offline_access",
            "resource": resource,
        },
    )
    return registration, verifier, response


async def authorize(app, client, user="2"):
    registration, verifier, response = await begin(client)
    assert response.status_code in {302, 303, 307}, response.text
    location = urlsplit(response.headers["location"]).path
    page = await client.get(location)
    assert page.status_code == 200
    assert "frame-ancestors 'none'" in page.headers["content-security-policy"]
    approval_code = re.search(r"/mcp code:([A-F0-9]{12})", page.text).group(1)
    pending = await client.get(location + "/status")
    assert pending.json() == {"status": "pending"}
    app.state.provider.store.decide(approval_code, user, "1", True)
    redirect = (await client.get(location + "/status")).json()["redirect_url"]
    parameters = parse_qs(urlsplit(redirect).query)
    assert parameters["state"] == ["original-state"]
    return registration, verifier, parameters["code"][0]


async def exchange(client, registration, verifier, code, **overrides):
    data = {
        "grant_type": "authorization_code",
        "client_id": registration["client_id"],
        "code": code,
        "code_verifier": verifier,
        "redirect_uri": "https://client.test/callback",
        "resource": "https://mcp.test/mcp",
    } | overrides
    return await client.post("/token", data=data)


async def rpc(client, token, method, params=None):
    headers = {
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": "2025-11-25",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return await client.post(
        "/mcp",
        headers=headers,
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params or {},
        },
    )


@pytest.fixture
async def running(tmp_path):
    world = World()
    config = Config(
        "https://mcp.test",
        {"1"},
        tmp_path,
        tmp_path / "unused",
        frozenset({"https://client.test/callback"}),
    )
    app = create_app(config, discord=world.discord())
    started, stop = asyncio.Event(), asyncio.Event()

    async def life():
        async with app.router.lifespan_context(app):
            started.set()
            await stop.wait()

    task = asyncio.create_task(life())
    await asyncio.wait_for(started.wait(), 5)
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app), base_url="https://mcp.test"
        ) as client:
            yield app, client, world
    finally:
        stop.set()
        await task


async def test_discovery_challenge_and_no_anonymous_history(running):
    _app, client, _ = running
    metadata = (await client.get("/.well-known/oauth-authorization-server")).json()
    assert "S256" in metadata["code_challenge_methods_supported"]
    assert metadata["registration_endpoint"].endswith("/register")
    assert "none" in metadata["token_endpoint_auth_methods_supported"]
    assert metadata["authorization_response_iss_parameter_supported"] is True
    assert (await client.options("/.well-known/oauth-authorization-server")).status_code == 200
    denied = await rpc(client, None, "tools/list")
    assert denied.status_code == 401
    assert "resource_metadata=" in denied.headers["www-authenticate"]
    assert "hello history" not in denied.text
    resource = (await client.get("/.well-known/oauth-protected-resource/mcp")).json()
    assert resource["resource"] == "https://mcp.test/mcp"
    assert resource["authorization_servers"] == [metadata["issuer"]]
    assert (await client.post("/connect/fake/approve", json={"user_id": "2"})).status_code != 200


async def test_pkce_code_replay_redirect_binding_and_resource(running):
    app, client, _ = running
    registration, verifier, code = await authorize(app, client)
    assert (await exchange(client, registration, "incorrect", code)).status_code == 400
    assert (
        await exchange(client, registration, verifier, code, resource="https://attacker.test/mcp")
    ).status_code == 400
    assert (
        await exchange(
            client, registration, verifier, code, redirect_uri="https://attacker.test/callback"
        )
    ).status_code == 400
    accepted = await exchange(client, registration, verifier, code)
    assert accepted.status_code == 200, accepted.text
    assert (await exchange(client, registration, verifier, code)).status_code == 400
    _, _, wrong = await begin(client, resource="https://attacker.test/mcp")
    assert "/connect/" not in wrong.headers.get("location", "")
    assert "invalid_request" in (wrong.text + wrong.headers.get("location", ""))


async def test_tools_are_read_only_and_two_members_cannot_share_authority(running):
    app, client, world = running
    credentials = {}
    for user in ["2", "3"]:
        registration, verifier, code = await authorize(app, client, user)
        tokens = (await exchange(client, registration, verifier, code)).json()
        credentials[user] = tokens["access_token"]
    listing = await rpc(client, credentials["2"], "tools/list")
    assert listing.status_code == 200, listing.text
    tools = listing.json()["result"]["tools"]
    assert len(tools) == 5
    assert all(tool["annotations"]["readOnlyHint"] for tool in tools)
    assert all(tool["_meta"]["securitySchemes"][0]["type"] == "oauth2" for tool in tools)

    async def read(user):
        response = await rpc(
            client,
            credentials[user],
            "tools/call",
            {"name": "get_messages", "arguments": {"channel_id": "101"}},
        )
        return user, response.json()

    results = await asyncio.gather(*(read(user) for user in ["2", "3"] * 4))
    for user, body in results:
        if user == "2":
            assert "hello history" in str(body), body
        else:
            assert body["result"]["isError"] is True, body
            assert "hello history" not in str(body)
            assert "secret-name" not in str(body)
    world.members["2"]["roles"] = []
    _, denied = await read("2")
    assert denied["result"]["isError"]


async def test_refresh_rotation_and_member_revoke(running):
    app, client, _ = running
    registration, verifier, code = await authorize(app, client)
    tokens = (await exchange(client, registration, verifier, code)).json()
    refreshed = await client.post(
        "/token",
        data={
            "grant_type": "refresh_token",
            "client_id": registration["client_id"],
            "refresh_token": tokens["refresh_token"],
            "resource": "https://mcp.test/mcp",
        },
    )
    assert refreshed.status_code == 200, refreshed.text
    replacement = refreshed.json()
    assert replacement["refresh_token"] != tokens["refresh_token"]
    reused = await client.post(
        "/token",
        data={
            "grant_type": "refresh_token",
            "client_id": registration["client_id"],
            "refresh_token": tokens["refresh_token"],
        },
    )
    assert reused.status_code == 400
    app.state.provider.store.revoke("2", "1")
    denied = await rpc(client, replacement["access_token"], "tools/list")
    assert denied.status_code == 401
    with app.state.provider.store.connect() as db:
        serialized = str([tuple(row) for row in db.execute("SELECT * FROM tokens")])
    assert tokens["access_token"] not in serialized


async def test_origin_host_and_expired_tokens_are_rejected(running):
    app, client, _ = running
    registration, verifier, code = await authorize(app, client)
    tokens = (await exchange(client, registration, verifier, code)).json()
    headers = {
        "Authorization": "Bearer " + tokens["access_token"],
        "Accept": "application/json, text/event-stream",
        "Origin": "https://attacker.test",
    }
    response = await client.post(
        "/mcp", headers=headers, json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
    )
    assert response.status_code == 403
    assert (await client.get("/healthz", headers={"Host": "attacker.test"})).status_code == 400
    with app.state.provider.store.connect() as db:
        db.execute("UPDATE tokens SET expires_at=1 WHERE kind='access'")
    assert (await rpc(client, tokens["access_token"], "tools/list")).status_code == 401


async def test_deny_and_unapproved_requests_never_issue_credentials(running):
    app, client, _ = running
    _, _, response = await begin(client)
    location = response.headers["location"]
    page = await client.get(location)
    code = re.search(r"/mcp code:([A-F0-9]{12})", page.text).group(1)
    app.state.provider.store.decide(code, "2", "1", False)
    result = (await client.get(location + "/status")).json()
    assert result["status"] == "denied"
    assert parse_qs(urlsplit(result["redirect_url"]).query)["error"] == ["access_denied"]
    with app.state.provider.store.connect() as db:
        assert db.execute("SELECT COUNT(*) FROM tokens").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM codes").fetchone()[0] == 0


async def test_oversized_registration_is_rejected(running):
    _app, client, _world = running
    response = await client.post(
        "/register", content=b"x" * (128 * 1024 + 1), headers={"Content-Type": "application/json"}
    )
    assert response.status_code == 413
