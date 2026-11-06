"""Modal to configure and launch the wifite2-style Auto-Attack: aggression and the SSID
exclusion list. Dismisses with ``(aggressive, excluded_ssids)`` or None when cancelled."""
from __future__ import annotations

from typing import Optional

from textual import on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Checkbox, Label, TextArea

from wifit3.persist.config import Config

_AGGRESSIVE_HINT = ("[dim]Passive sends only PMKID association requests. Aggressive also deauths "
                    "clients, replays WEP and brute-forces WPS PINs.[/dim]")
_EXCLUDE_HINT = "[dim]One SSID per line. These networks are never attacked (case-insensitive).[/dim]"


class AutoAttackModal(ModalScreen[Optional[tuple[bool, list[str]]]]):
    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    CSS = """
    #auto-attack-confirm { min-width: 0; width: auto; }
    #auto-attack-cancel { min-width: 0; width: auto; }
    """

    DEFAULT_CSS = """
    AutoAttackModal {
        align: center middle;
        background: rgba(0, 0, 0, 0.5);
    }
    #auto-attack-dialog {
        width: 68;
        max-width: 100%;
        height: auto;
        max-height: 100%;
        padding: 0 1;
        background: $surface;
        border: solid $primary;
    }
    #auto-attack-body { height: auto; max-height: 1fr; }
    #auto-attack-title { width: 1fr; text-align: center; text-style: bold; color: $accent; }
    #auto-attack-dialog Horizontal { height: auto; }
    #auto-attack-excluded { height: 8; }
    #auto-attack-buttons { align: right middle; margin-top: 1; }
    """

    def compose(self) -> ComposeResult:
        with Vertical(id="auto-attack-dialog"):
            with VerticalScroll(id="auto-attack-body"):
                yield Label("Auto-Attack", id="auto-attack-title")
                yield Checkbox("Aggressive (deauth / WEP replay / WPS PIN)",
                               value=Config.auto_attack_aggressive, id="auto-attack-aggressive")
                yield Label(_AGGRESSIVE_HINT)
                yield Label("Excluded SSIDs:")
                yield Label(_EXCLUDE_HINT)
                yield TextArea("\n".join(Config.auto_attack_excluded_ssids),
                               id="auto-attack-excluded")
                with Horizontal(id="auto-attack-buttons"):
                    yield Button("Cancel", variant="error", id="auto-attack-cancel")
                    yield Button("Start", variant="success", id="auto-attack-confirm")

    def action_cancel(self) -> None:
        self.dismiss(None)

    @on(Button.Pressed, "#auto-attack-cancel")
    def _cancel(self, event: Button.Pressed) -> None:
        event.stop()
        self.action_cancel()

    @on(Button.Pressed, "#auto-attack-confirm")
    def _confirm(self, event: Button.Pressed) -> None:
        event.stop()
        aggressive = self.query_one("#auto-attack-aggressive", Checkbox).value
        raw = self.query_one("#auto-attack-excluded", TextArea).text
        excluded = [line.strip() for line in raw.splitlines() if line.strip()]
        self.dismiss((aggressive, excluded))
