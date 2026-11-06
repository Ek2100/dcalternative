"""Drive the privacy panel with a fake interaction, to catch discord.py API misuse."""
import asyncio
from types import SimpleNamespace

import discord

from bot import main as botmain


class FakeFollowup:
    def __init__(self):
        self.sent = []

    async def send(self, *args, view=discord.utils.MISSING, **kwargs):
        # Same rule as discord.py: view must be a View if given at all.
        if view is not discord.utils.MISSING and not isinstance(view, discord.ui.View):
            raise TypeError("expected view parameter to be of type View")
        self.sent.append((kwargs, view))


class FakeResponse:
    async def defer(self, **kwargs):
        pass


def make_interaction(rows):
    async def overview(user_id):
        return rows

    client = SimpleNamespace(service=SimpleNamespace(user_overview=overview), get_guild=lambda gid: None)
    return SimpleNamespace(client=client, user=SimpleNamespace(id=1), response=FakeResponse(),
                           followup=FakeFollowup())


def test_privacy_panel_with_no_data():
    it = make_interaction([])
    asyncio.run(botmain.show_privacy(it))
    (kwargs, view), = it.followup.sent
    assert view is discord.utils.MISSING and kwargs["ephemeral"]


def test_privacy_panel_with_data_has_delete_button():
    it = make_interaction([{"guild_id": 5, "status": "verified", "expires_at": None}])

    async def run():
        await botmain.show_privacy(it)

    asyncio.run(run())
    (_, view), = it.followup.sent
    assert isinstance(view, botmain.PrivacyView)
