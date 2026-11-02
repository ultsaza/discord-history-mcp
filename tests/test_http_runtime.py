import asyncio
import socket

import httpx
import uvicorn
from test_access import World
from test_oauth import authorize, exchange, rpc

from discord_history_mcp.config import Config
from discord_history_mcp.server import create_app


async def test_real_tcp_oauth_and_permission_checked_read(tmp_path):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    listener.listen(128)
    config = Config(
        "https://mcp.test",
        {"1"},
        tmp_path,
        tmp_path / "unused",
        frozenset({"https://client.test/callback"}),
    )
    app = create_app(config, discord=World().discord())
    server = uvicorn.Server(uvicorn.Config(app, log_level="critical", access_log=False))
    task = asyncio.create_task(server.serve(sockets=[listener]))
    try:
        async with asyncio.timeout(5):
            while not server.started:
                if task.done():
                    await task
                    raise RuntimeError("HTTP server did not start")
                await asyncio.sleep(0.01)
        async with httpx.AsyncClient(base_url=f"http://127.0.0.1:{port}", timeout=5) as client:
            assert (await client.get("/healthz")).status_code == 200
            assert (await rpc(client, None, "tools/list")).status_code == 401
            registration, verifier, code = await authorize(app, client)
            tokens = (await exchange(client, registration, verifier, code)).json()
            response = await rpc(
                client,
                tokens["access_token"],
                "tools/call",
                {
                    "name": "get_messages",
                    "arguments": {"channel_id": "101"},
                },
            )
            assert "hello history" in str(response.json())
    finally:
        server.should_exit = True
        await asyncio.wait_for(task, 5)
        listener.close()
