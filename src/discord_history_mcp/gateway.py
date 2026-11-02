"""Discord interactions authenticate the approving member; no user token is accepted."""

import asyncio
import re
import time
from typing import Literal

import discord
from discord import app_commands

from .config import Config
from .keys import Store


def clean_label(value: str) -> str:
    return "".join(c for c in value if c.isprintable()).translate(
        str.maketrans({"`": "'", "@": "＠", "<": "‹", ">": "›"})
    )[:500]


class Consent(discord.ui.View):
    def __init__(self, store: Store, code: str, user: int, guild: int, expires: int):
        super().__init__(timeout=max(1, min(600, expires - int(time.time()))))
        self.store, self.code, self.user, self.guild = store, code, user, guild

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id == self.user and interaction.guild_id == self.guild:
            return True
        await interaction.response.send_message(
            "Only the member who requested this connection can approve it.", ephemeral=True
        )
        return False

    async def decide(self, interaction: discord.Interaction, allow: bool):
        # Also guard direct invocation; do not rely solely on discord.py's dispatcher.
        if interaction.user.id != self.user or interaction.guild_id != self.guild:
            await self.interaction_check(interaction)
            return
        await interaction.response.defer()
        try:
            self.store.decide(self.code, str(self.user), str(self.guild), allow)
            message = (
                "Approved. Return to your browser to finish connecting."
                if allow
                else "This connection was denied."
            )
        except ValueError:
            message = (
                "This request expired or has already been handled. Start again in your client."
            )
        await interaction.edit_original_response(content=message, view=None)
        self.stop()

    @discord.ui.button(label="Allow history access", style=discord.ButtonStyle.primary)
    async def allow(self, interaction: discord.Interaction, _button: discord.ui.Button):
        await self.decide(interaction, True)

    @discord.ui.button(label="Deny", style=discord.ButtonStyle.secondary)
    async def deny(self, interaction: discord.Interaction, _button: discord.ui.Button):
        await self.decide(interaction, False)


class Gateway(discord.Client):
    def __init__(self, config: Config, store: Store):
        intents = discord.Intents.none()
        intents.guilds = True
        intents.message_content = True
        super().__init__(intents=intents, allowed_mentions=discord.AllowedMentions.none())
        self.config, self.store = config, store
        self.connected = asyncio.Event()
        self.tree = app_commands.CommandTree(self)

        @app_commands.command(
            name="mcp", description="Connect your Discord history to an MCP client"
        )
        @app_commands.guild_only()
        @app_commands.describe(
            code="12-character code shown in your browser", action="Connect or revoke your grants"
        )
        async def command(
            interaction: discord.Interaction,
            code: str | None = None,
            action: Literal["connect", "revoke"] = "connect",
        ):
            await self.handle(interaction, code, action)

        for guild in sorted(config.allowed_guilds):
            self.tree.add_command(command, guild=discord.Object(id=int(guild)))

    async def setup_hook(self):
        for guild in sorted(self.config.allowed_guilds):
            await self.tree.sync(guild=discord.Object(id=int(guild)))

    async def on_ready(self):
        self.connected.set()

    async def handle(self, interaction: discord.Interaction, code=None, action="connect"):
        await interaction.response.defer(ephemeral=True, thinking=True)
        guild, user = str(interaction.guild_id), str(interaction.user.id)
        if guild not in self.config.allowed_guilds:
            await interaction.edit_original_response(content="This server is not enabled.")
            return
        if action == "revoke":
            self.store.revoke(user, guild)
            await interaction.edit_original_response(
                content="All your MCP connections for this server have been revoked."
            )
            return
        if code is None:
            await interaction.edit_original_response(
                content=f"Add `{self.config.base_url}/mcp` to your MCP client using OAuth. "
                "Run `/mcp code:CODE` with the code displayed in the browser, then approve here. "
                "Only history readable by both you and this bot is accessible. "
                "Use `/mcp action:revoke` to disconnect."
            )
            return
        if not re.fullmatch(r"[a-fA-F0-9]{12}", code):
            await interaction.edit_original_response(
                content="Enter the 12-character code from your browser."
            )
            return
        try:
            review = self.store.approval_details(code)
        except ValueError:
            await interaction.edit_original_response(
                content="Invalid or expired code. Start again in your client."
            )
            return
        await interaction.edit_original_response(
            content=(
                f"Allow this connection?\n\nClient: `{clean_label(review['client_name'])}`\n"
                f"Callback: `{clean_label(review['redirect_uri'])}`\n\n"
                "The client can read text history that both you and this bot can currently read "
                "in this Discord server. It cannot send, edit or delete messages through MCP. "
                "Permission lasts 30 days. Use `/mcp action:revoke` to revoke it. "
                "Approve only a connection you started and recognize."
            ),
            view=Consent(self.store, code.upper(), int(user), int(guild), review["expires_at"]),
        )
