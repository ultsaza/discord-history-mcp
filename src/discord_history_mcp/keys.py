import hashlib
import json
import os
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path


def snowflake(value: str) -> str:
    if not isinstance(value, str) or not value.isascii() or not value.isdecimal():
        raise ValueError("Discord IDs must be decimal strings")
    if not 0 < int(value) < 2**64 or str(int(value)) != value:
        raise ValueError("Invalid Discord ID")
    return value


@dataclass(frozen=True)
class Principal:
    user_id: str
    guild_id: str
    expires_at: int


class Store:
    """Local OAuth state. Access/refresh tokens and authorization codes are hashed."""

    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(path.parent, 0o700)
        with self.connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS clients (
                    id TEXT PRIMARY KEY, data TEXT NOT NULL, expires_at INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS requests (
                    flow_id TEXT PRIMARY KEY, approval_code TEXT UNIQUE NOT NULL,
                    data TEXT NOT NULL, expires_at INTEGER NOT NULL, status TEXT NOT NULL,
                    user_id TEXT, guild_id TEXT);
                CREATE TABLE IF NOT EXISTS codes (
                    digest TEXT PRIMARY KEY, data TEXT NOT NULL, expires_at INTEGER NOT NULL,
                    user_id TEXT NOT NULL, guild_id TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS grants (
                    id TEXT PRIMARY KEY, user_id TEXT NOT NULL, guild_id TEXT NOT NULL,
                    client_id TEXT NOT NULL, expires_at INTEGER NOT NULL,
                    resource TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS tokens (
                    digest TEXT PRIMARY KEY, kind TEXT NOT NULL,
                    grant_id TEXT NOT NULL REFERENCES grants(id) ON DELETE CASCADE,
                    expires_at INTEGER NOT NULL, scopes TEXT NOT NULL);
            """)
        os.chmod(path, 0o600)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=5)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        try:
            with db:
                yield db
        finally:
            db.close()

    @staticmethod
    def digest(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()

    def approval_details(self, code: str) -> dict:
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM requests WHERE approval_code=? AND expires_at>? "
                "AND status='pending'",
                (code.upper(), int(time.time())),
            ).fetchone()
        if not row:
            raise ValueError("Invalid or expired code. Start again in your browser.")
        data = json.loads(row["data"])
        return {
            "client_name": data["client_name"],
            "redirect_uri": data["redirect_uri"],
            "expires_at": row["expires_at"],
        }

    def decide(self, code: str, user_id: str, guild_id: str, allow: bool) -> None:
        with self.connect() as db:
            changed = db.execute(
                "UPDATE requests SET status=?, user_id=?, guild_id=? "
                "WHERE approval_code=? AND status='pending' AND expires_at>?",
                (
                    "approved" if allow else "denied",
                    snowflake(user_id),
                    snowflake(guild_id),
                    code.upper(),
                    int(time.time()),
                ),
            ).rowcount
        if changed != 1:
            raise ValueError("Invalid, expired or already handled code.")

    def revoke(self, user_id: str, guild_id: str) -> None:
        with self.connect() as db:
            values = (snowflake(user_id), snowflake(guild_id))
            db.execute("DELETE FROM grants WHERE user_id=? AND guild_id=?", values)
            db.execute("DELETE FROM codes WHERE user_id=? AND guild_id=?", values)
            db.execute("DELETE FROM requests WHERE user_id=? AND guild_id=?", values)

    def prune(self) -> None:
        with self.connect() as db:
            now = int(time.time())
            for table in ("tokens", "grants", "codes", "requests"):
                db.execute(f"DELETE FROM {table} WHERE expires_at<=?", (now,))
            db.execute(
                "DELETE FROM clients WHERE expires_at<=? AND " + self.unused_client_sql(),
                (now,),
            )

    @staticmethod
    def unused_client_sql():
        # Never evict a registration while an authorization flow or grant uses it.
        return (
            "NOT EXISTS (SELECT 1 FROM grants WHERE client_id=clients.id) AND "
            "NOT EXISTS (SELECT 1 FROM requests WHERE json_extract(data,'$.client_id')=clients.id) "
            "AND NOT EXISTS (SELECT 1 FROM codes WHERE json_extract(data,'$.client_id')=clients.id)"
        )
