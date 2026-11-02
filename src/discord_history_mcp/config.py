import json
import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from .keys import snowflake


def validate_redirect(uri: str) -> str:
    parsed = urlsplit(uri)
    loopback = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
    if (
        not parsed.hostname
        or (parsed.scheme != "https" and not (parsed.scheme == "http" and loopback))
        or parsed.fragment
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise ValueError(
            "Redirect URIs require HTTPS (or HTTP loopback), without credentials/fragments"
        )
    return uri


@dataclass(frozen=True)
class Config:
    base_url: str
    allowed_guilds: set[str]
    state_dir: Path
    token_file: Path
    allowed_redirect_uris: frozenset[str]
    port: int = 19230

    @classmethod
    def load(cls, path: Path | None = None):
        path = (path or Path(os.environ.get("DISCORD_MCP_CONFIG", "config.json"))).expanduser()
        data = json.loads(path.read_text())
        base = data["base_url"].rstrip("/")
        parsed = urlsplit(base)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.path
            or parsed.query
            or parsed.fragment
            or parsed.username is not None
            or parsed.password is not None
        ):
            raise ValueError("base_url must be an HTTPS origin without a path")
        guilds = {snowflake(value) for value in data["allowed_guild_ids"]}
        if not guilds:
            raise ValueError("At least one allowed guild is required")
        redirects = frozenset(validate_redirect(uri) for uri in data["allowed_redirect_uris"])
        if not redirects:
            raise ValueError("At least one exact allowed_redirect_uris entry is required")
        port = data.get("port", 19230)
        if type(port) is not int or not 1024 <= port <= 65535:
            raise ValueError("Invalid listen port")

        def local_path(value):
            result = Path(value).expanduser()
            return result if result.is_absolute() else path.resolve().parent / result

        return cls(
            base,
            guilds,
            local_path(data.get("state_dir", "state")),
            local_path(data.get("bot_token_file", "secrets/bot-token")),
            redirects,
            port,
        )

    @property
    def database(self):
        return self.state_dir / "oauth.sqlite3"
