from collections.abc import Sequence
from typing import Optional

from rich.markup import escape
from textual import on, work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label

from wifit3.persist.ap_state import DatedHashline
from wifit3.persist.config import Config, ConfigError
from wifit3.vault.tools.wpa_sec_api import WpaSecClient, WpaSecError

_KEY_HINT = "[dim]Get a key at wpa-sec.stanev.org → Get key (needed to see your results)[/dim]"
_PCAP_HINT = "[dim]wpa-sec cracks the handshake pcap: keep 'Save pcap' on when capturing[/dim]"


class WpaSecConfigModal(ModalScreen[dict]):
    """Server URL and API key for wpa-sec jobs; dismisses with the job's (empty) ``config``,
    or None when cancelled."""

    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    CSS = """
    #wpa-sec-reveal { min-width: 0; width: auto; }
    #wpa-sec-test { min-width: 0; width: auto; }
    """

    DEFAULT_CSS = """
    WpaSecConfigModal {
        align: center middle;
        background: rgba(0, 0, 0, 0.5);
    }
    #wpa-sec-dialog {
        width: 64;
        max-width: 100%;
        height: auto;
        max-height: 100%;
        padding: 0 1;
        background: $surface;
        border: solid $primary;
    }
    #wpa-sec-body { height: auto; max-height: 1fr; }
    #wpa-sec-title {
        width: 1fr;
        text-align: center;
        text-style: bold;
        color: $accent;
    }
    #wpa-sec-dialog Horizontal { height: auto; }
    #wpa-sec-key-label { width: 1fr; }
    #wpa-sec-test-row { margin-top: 1; }
    #wpa-sec-test-result { width: 1fr; margin-left: 1; }
    #wpa-sec-buttons { align: right middle; }
    """

    def __init__(self, confirm_label: str = "Launch", bssid: Optional[str] = None,
                 probed_ssids: Sequence[str] = (), hashlines: Sequence[DatedHashline] = ()) -> None:
        super().__init__()
        self._confirm_label = confirm_label

    def compose(self) -> ComposeResult:
        settings = Config.wpa_sec
        with Vertical(id="wpa-sec-dialog"):
            with VerticalScroll(id="wpa-sec-body"):
                yield Label("wpa-sec", id="wpa-sec-title")
                yield Label("Server URL:")
                yield Input(settings.url, placeholder="https://wpa-sec.stanev.org",
                            id="wpa-sec-url")
                with Horizontal():
                    yield Label("API key:", id="wpa-sec-key-label")
                    yield Button("reveal", compact=True, id="wpa-sec-reveal")
                yield Input(settings.key or "", password=True, id="wpa-sec-key")
                yield Label(_KEY_HINT)
                yield Label(_PCAP_HINT)
                with Horizontal(id="wpa-sec-test-row"):
                    yield Button("Test key", "primary", compact=True, id="wpa-sec-test")
                    yield Label("", id="wpa-sec-test-result")
                with Horizontal(id="wpa-sec-buttons"):
                    yield Button("Cancel", variant="error", id="wpa-sec-cancel")
                    yield Button(self._confirm_label, variant="success", id="wpa-sec-confirm")

    @on(Button.Pressed, "#wpa-sec-reveal")
    def _toggle_reveal(self, event: Button.Pressed) -> None:
        event.stop()
        key = self.query_one("#wpa-sec-key", Input)
        key.password = not key.password
        event.button.label = "reveal" if key.password else "hide"

    @on(Button.Pressed, "#wpa-sec-test")
    def _test_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        self.query_one("#wpa-sec-test-result", Label).update("[dim]Connecting…[/dim]")
        self._test(self.query_one("#wpa-sec-url", Input).value.strip(),
                   self.query_one("#wpa-sec-key", Input).value.strip())

    @work(thread=True, exclusive=True, group="wpa-sec-test")
    def _test(self, url: str, key: str) -> None:
        if not (url and key):
            self.app.call_from_thread(self._show_test, "[$error]Enter the URL and key first[/]")
            return
        try:
            results = WpaSecClient(url, key).results()
        except WpaSecError as e:
            self.app.call_from_thread(self._show_test, f"[$error]{escape(str(e))}[/]")
            return
        self.app.call_from_thread(
            self._show_test, f"[$success]Key works · {len(results)} cracked so far[/]")

    def _show_test(self, markup: str) -> None:
        if self.is_attached:
            self.query_one("#wpa-sec-test-result", Label).update(markup)

    def action_cancel(self) -> None:
        self.dismiss(None)

    @on(Button.Pressed, "#wpa-sec-cancel")
    def _cancel(self, event: Button.Pressed) -> None:
        event.stop()
        self.action_cancel()

    @on(Button.Pressed, "#wpa-sec-confirm")
    def _confirm(self, event: Button.Pressed) -> None:
        event.stop()
        url = self.query_one("#wpa-sec-url", Input).value.strip()
        key = self.query_one("#wpa-sec-key", Input).value.strip()
        if not (url and key):
            self.notify("Please provide the server URL and API key", severity="error")
            return
        Config.wpa_sec.url = url
        Config.wpa_sec.key = key
        try:
            Config.save()
        except ConfigError as e:
            self.notify(str(e), title="Config Error", severity="warning")
        self.dismiss({})
