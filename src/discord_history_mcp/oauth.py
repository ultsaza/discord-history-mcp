import json
import secrets
import time
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    RefreshToken,
    RegistrationError,
    TokenError,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from pydantic import AnyHttpUrl

from .config import validate_redirect
from .keys import Store

SCOPE = "discord.history.read"
SCOPES = [SCOPE, "offline_access"]


class Code(AuthorizationCode):
    user_id: str
    guild_id: str


class Refresh(RefreshToken):
    grant_id: str


class Provider:
    def __init__(
        self,
        store: Store,
        base_url: str,
        allowed_guilds: set[str],
        allowed_redirect_uris: frozenset[str],
        *,
        max_clients: int = 1000,
    ):
        self.store = store
        self.base_url = base_url.rstrip("/")
        self.issuer = str(AnyHttpUrl(self.base_url))
        self.resource = self.base_url + "/mcp"
        self.allowed_guilds = allowed_guilds
        self.allowed_redirect_uris = allowed_redirect_uris
        self.max_clients = max_clients

    async def get_client(self, client_id: str):
        self.store.prune()
        with self.store.connect() as db:
            row = db.execute("SELECT data FROM clients WHERE id=?", (client_id,)).fetchone()
        if not row:
            return None
        client = OAuthClientInformationFull.model_validate_json(row[0])
        if not all(str(uri) in self.allowed_redirect_uris for uri in client.redirect_uris or []):
            return None
        return client

    async def register_client(self, client_info: OAuthClientInformationFull):
        for uri in client_info.redirect_uris or []:
            try:
                validate_redirect(str(uri))
            except ValueError as error:
                raise RegistrationError("invalid_redirect_uri", str(error)) from None
            if str(uri) not in self.allowed_redirect_uris:
                raise RegistrationError("invalid_redirect_uri", "Callback is not allowlisted")
        if client_info.token_endpoint_auth_method not in {
            None,
            "none",
            "client_secret_post",
            "client_secret_basic",
        }:
            raise RegistrationError("invalid_client_metadata", "Unsupported client authentication")
        data = client_info.model_dump_json()
        if len(data) > 8192:
            raise RegistrationError("invalid_client_metadata", "Client metadata is too large")
        self.store.prune()
        with self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT COUNT(*) FROM clients").fetchone()[0] >= self.max_clients:
                evicted = db.execute(
                    "DELETE FROM clients WHERE id=(SELECT id FROM clients WHERE "
                    + self.store.unused_client_sql()
                    + " ORDER BY expires_at LIMIT 1)"
                ).rowcount
                if evicted != 1:
                    raise RegistrationError(
                        "invalid_client_metadata", "Active client registration limit reached"
                    )
            db.execute(
                "INSERT INTO clients VALUES (?,?,?)",
                (client_info.client_id, data, int(time.time()) + 86400),
            )

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams):
        if str(params.redirect_uri) not in self.allowed_redirect_uris:
            raise AuthorizeError("invalid_request", "Callback is not allowlisted")
        if params.resource not in {None, self.resource}:
            raise AuthorizeError("invalid_request", "Incorrect resource")
        scopes = params.scopes or SCOPES
        if SCOPE not in scopes or any(scope not in SCOPES for scope in scopes):
            raise AuthorizeError("invalid_scope", "Only Discord history read access is supported")
        self.store.prune()
        flow_id = secrets.token_urlsafe(32)
        code = secrets.token_hex(6).upper()
        data = params.model_dump(mode="json") | {
            "client_id": client.client_id,
            "client_name": (client.client_name or "MCP client")[:100],
            "scopes": scopes,
            "resource": self.resource,
        }
        with self.store.connect() as db:
            if db.execute("SELECT COUNT(*) FROM requests").fetchone()[0] >= 500:
                raise AuthorizeError("temporarily_unavailable", "Too many pending connections")
            db.execute(
                "INSERT INTO requests VALUES (?,?,?,?, 'pending', NULL,NULL)",
                (flow_id, code, json.dumps(data), int(time.time()) + 600),
            )
        return self.base_url + "/connect/" + flow_id

    def flow(self, flow_id: str):
        with self.store.connect() as db:
            row = db.execute(
                "SELECT * FROM requests WHERE flow_id=? AND expires_at>?",
                (flow_id, int(time.time())),
            ).fetchone()
        return dict(row) if row else None

    def poll(self, flow_id: str):
        with self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT * FROM requests WHERE flow_id=? AND expires_at>?",
                (flow_id, int(time.time())),
            ).fetchone()
            if not row:
                return {"status": "expired"}
            if row["status"] == "denied":
                data = json.loads(row["data"])
                redirect = urlsplit(data["redirect_uri"])
                query = parse_qsl(redirect.query, keep_blank_values=True) + [
                    ("error", "access_denied"),
                    ("iss", self.issuer),
                ]
                if data.get("state") is not None:
                    query.append(("state", data["state"]))
                return {
                    "status": "denied",
                    "redirect_url": urlunsplit(redirect._replace(query=urlencode(query))),
                }
            if row["status"] != "approved":
                return {"status": row["status"]}
            if row["guild_id"] not in self.allowed_guilds:
                return {"status": "denied"}
            data = json.loads(row["data"])
            raw_code = "dchc_" + secrets.token_urlsafe(32)
            expires = int(time.time()) + 120
            code = {
                key: data[key]
                for key in (
                    "scopes",
                    "client_id",
                    "code_challenge",
                    "redirect_uri",
                    "redirect_uri_provided_explicitly",
                    "resource",
                )
            }
            code |= {
                "user_id": row["user_id"],
                "guild_id": row["guild_id"],
                "expires_at": expires,
                "subject": row["user_id"],
            }
            db.execute(
                "INSERT INTO codes VALUES (?,?,?,?,?)",
                (
                    self.store.digest(raw_code),
                    json.dumps(code),
                    expires,
                    row["user_id"],
                    row["guild_id"],
                ),
            )
            db.execute("UPDATE requests SET status='consumed' WHERE flow_id=?", (flow_id,))
        redirect = urlsplit(data["redirect_uri"])
        query = parse_qsl(redirect.query, keep_blank_values=True) + [
            ("code", raw_code),
            ("iss", self.issuer),
        ]
        if data.get("state") is not None:
            query.append(("state", data["state"]))
        return {
            "status": "approved",
            "redirect_url": urlunsplit(redirect._replace(query=urlencode(query))),
        }

    async def load_authorization_code(self, client, authorization_code):
        with self.store.connect() as db:
            row = db.execute(
                "SELECT data FROM codes WHERE digest=? AND expires_at>?",
                (self.store.digest(authorization_code), int(time.time())),
            ).fetchone()
        if not row:
            return None
        code = Code(code=authorization_code, **json.loads(row[0]))
        return code if code.client_id == client.client_id else None

    def _mint(self, db, grant_id, expires, scopes):
        now = int(time.time())
        access = "dcha_" + secrets.token_urlsafe(32)
        refresh = "dchr_" + secrets.token_urlsafe(32)
        access_end = min(expires, now + 3600)
        db.executemany(
            "INSERT INTO tokens VALUES (?,?,?,?,?)",
            [
                (self.store.digest(access), "access", grant_id, access_end, json.dumps(scopes)),
                (self.store.digest(refresh), "refresh", grant_id, expires, json.dumps(scopes)),
            ],
        )
        return OAuthToken(
            access_token=access,
            refresh_token=refresh,
            expires_in=access_end - now,
            scope=" ".join(scopes),
        )

    async def exchange_authorization_code(self, client, authorization_code):
        with self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            deleted = db.execute(
                "DELETE FROM codes WHERE digest=? AND expires_at>?",
                (self.store.digest(authorization_code.code), int(time.time())),
            ).rowcount
            if deleted != 1 or authorization_code.client_id != client.client_id:
                raise TokenError("invalid_grant", "Authorization code is invalid or already used")
            if authorization_code.guild_id not in self.allowed_guilds:
                raise TokenError("invalid_grant", "Guild is not enabled")
            grant_id = secrets.token_urlsafe(24)
            expires = int(time.time()) + 30 * 86400
            db.execute(
                "INSERT INTO grants VALUES (?,?,?,?,?,?)",
                (
                    grant_id,
                    authorization_code.user_id,
                    authorization_code.guild_id,
                    client.client_id,
                    expires,
                    self.resource,
                ),
            )
            return self._mint(db, grant_id, expires, authorization_code.scopes)

    def _token(self, token, kind):
        if not isinstance(token, str) or len(token) != 48:
            return None
        with self.store.connect() as db:
            row = db.execute(
                "SELECT t.expires_at, t.scopes, g.* FROM tokens t JOIN grants g "
                "ON t.grant_id=g.id WHERE t.digest=? AND t.kind=? "
                "AND t.expires_at>? AND g.expires_at>?",
                (self.store.digest(token), kind, int(time.time()), int(time.time())),
            ).fetchone()
        if (
            not row
            or row["guild_id"] not in self.allowed_guilds
            or row["resource"] != self.resource
        ):
            return None
        return dict(row)

    async def load_access_token(self, token):
        row = self._token(token, "access")
        if not row:
            return None
        return AccessToken(
            token=token,
            client_id=row["client_id"],
            scopes=json.loads(row["scopes"]),
            expires_at=row["expires_at"],
            resource=row["resource"],
            subject=row["user_id"],
            claims={"user_id": row["user_id"], "guild_id": row["guild_id"], "grant_id": row["id"]},
        )

    async def load_refresh_token(self, client, refresh_token):
        row = self._token(refresh_token, "refresh")
        if not row or row["client_id"] != client.client_id:
            return None
        return Refresh(
            token=refresh_token,
            client_id=client.client_id,
            scopes=json.loads(row["scopes"]),
            expires_at=row["expires_at"],
            resource=row["resource"],
            subject=row["user_id"],
            grant_id=row["id"],
        )

    async def exchange_refresh_token(self, client, refresh_token, scopes):
        with self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT * FROM grants WHERE id=? AND client_id=? AND expires_at>?",
                (refresh_token.grant_id, client.client_id, int(time.time())),
            ).fetchone()
            if not row or not set(scopes).issubset(refresh_token.scopes):
                raise TokenError("invalid_grant", "Refresh grant is invalid")
            deleted = db.execute(
                "DELETE FROM tokens WHERE digest=? AND kind='refresh' AND expires_at>?",
                (self.store.digest(refresh_token.token), int(time.time())),
            ).rowcount
            if deleted != 1:
                raise TokenError("invalid_grant", "Refresh token is invalid or already used")
            return self._mint(db, row["id"], row["expires_at"], scopes)

    async def revoke_token(self, token):
        row = self._token(token.token, "refresh" if isinstance(token, RefreshToken) else "access")
        if row:
            with self.store.connect() as db:
                db.execute("DELETE FROM grants WHERE id=?", (row["id"],))
