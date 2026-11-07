"""Stand up a WPA-Enterprise evil twin for a chosen SSID with no real target in range: collect the
SSID, channel and BSSID to impersonate. Dismisses with ``(ssid, channel, bssid)`` or None."""
from __future__ import annotations

import os
import re
from typing import Optional

from textual import on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label

_MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")


def _random_bssid() -> str:
    return "02:" + ":".join(f"{b:02x}" for b in os.urandom(5))


class RogueEnterpriseModal(ModalScreen[Optional[tuple[str, int, str]]]):
    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    CSS = """
    #rogue-confirm { min-width: 0; width: auto; }
    #rogue-cancel { min-width: 0; width: auto; }
    """

    DEFAULT_CSS = """
    RogueEnterpriseModal { align: center middle; background: rgba(0, 0, 0, 0.5); }
    #rogue-dialog {
        width: 60; max-width: 100%; height: auto; max-height: 100%;
        padding: 0 1; background: $surface; border: solid $primary;
    }
    #rogue-body { height: auto; max-height: 1fr; }
    #rogue-title { width: 1fr; text-align: center; text-style: bold; color: $accent; }
    #rogue-dialog Horizontal { height: auto; }
    #rogue-buttons { align: right middle; margin-top: 1; }
    """

    def compose(self) -> ComposeResult:
        with Vertical(id="rogue-dialog"):
            with VerticalScroll(id="rogue-body"):
                yield Label("Rogue WPA-Enterprise AP", id="rogue-title")
                yield Label("[dim]Impersonate an 802.1X network with no real target in range.[/dim]")
                yield Label("SSID (network name to impersonate):")
                yield Input("", placeholder="CorpWiFi", id="rogue-ssid")
                yield Label("Channel:")
                yield Input("1", id="rogue-channel")
                yield Label("BSSID:")
                yield Input(_random_bssid(), id="rogue-bssid")
                with Horizontal(id="rogue-buttons"):
                    yield Button("Cancel", variant="error", id="rogue-cancel")
                    yield Button("Create", variant="success", id="rogue-confirm")

    def action_cancel(self) -> None:
        self.dismiss(None)

    @on(Button.Pressed, "#rogue-cancel")
    def _cancel(self, event: Button.Pressed) -> None:
        event.stop()
        self.dismiss(None)

    @on(Button.Pressed, "#rogue-confirm")
    def _confirm(self, event: Button.Pressed) -> None:
        event.stop()
        ssid = self.query_one("#rogue-ssid", Input).value.strip()
        if not ssid:
            self.notify("Enter an SSID to impersonate", severity="error")
            return
        if len(ssid.encode("utf-8")) > 32:
            self.notify("SSID must be at most 32 bytes", severity="error")
            return
        try:
            channel = int(self.query_one("#rogue-channel", Input).value.strip())
        except ValueError:
            self.notify("Channel must be a number", severity="error")
            return
        bssid = self.query_one("#rogue-bssid", Input).value.strip().lower()
        if not _MAC_RE.match(bssid):
            self.notify("BSSID must look like aa:bb:cc:dd:ee:ff", severity="error")
            return
        self.dismiss((ssid, channel, bssid))
