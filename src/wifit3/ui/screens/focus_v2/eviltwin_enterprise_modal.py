"""Configure the WPA-Enterprise evil twin before it starts: host interface, BSSID, EAP method,
optional GTC downgrade, and optional deauth eviction. Dismisses with an EnterpriseEvilTwinInput."""
import re
from typing import Optional

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Checkbox, Input, Label, Select

from wifit3.campaigns.eviltwin import PuntMode
from wifit3.campaigns.eviltwin_enterprise.campaign import EnterpriseEvilTwinInput
from wifit3.campaigns.eviltwin_enterprise.eap_server import Method
from wifit3.dot11.pmf import PmfPosture
from wifit3.ui.screens.focus_v2.art import display_name
from wifit3.ui.screens.focus_v2.eviltwin_modal import _can_host
from wifit3.wlan.array import fake_mac_rank

_MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")


class EnterpriseEvilTwinModal(ModalScreen[Optional[EnterpriseEvilTwinInput]]):
    """Host interface, BSSID, EAP method and GTC/deauth options for the enterprise twin."""

    BINDINGS = [Binding("escape", "cancel", "Cancel", show=True)]

    CSS = """
    #ent-confirm { min-width: 0; width: auto; }
    #ent-cancel { min-width: 0; width: auto; }
    """

    DEFAULT_CSS = """
    EnterpriseEvilTwinModal { align: center middle; background: rgba(0, 0, 0, 0.5); }
    #ent-dialog {
        width: 66; max-width: 100%; height: auto; max-height: 100%;
        padding: 0 1; background: $surface; border: solid $primary;
    }
    #ent-body { height: auto; max-height: 1fr; }
    #ent-title { width: 1fr; text-align: center; text-style: bold; color: $accent; }
    #ent-dialog Horizontal { height: auto; }
    #ent-buttons { align: right middle; margin-top: 1; }
    """

    def __init__(self, target, members) -> None:
        super().__init__()
        self.target = target
        self._hosts = sorted((m for m in members if _can_host(m)), key=fake_mac_rank)

    def compose(self) -> ComposeResult:
        with Vertical(id="ent-dialog"):
            with VerticalScroll(id="ent-body"):
                yield Label("WPA-Enterprise Evil Twin", id="ent-title")
                yield Label(f"Target: [b]{self.target.ssid or self.target.bssid}[/b] "
                            f"(CH {self.target.channel})")
                yield Label("Host interface:")
                yield Select([(display_name(m), i) for i, m in enumerate(self._hosts)],
                             value=0 if self._hosts else Select.BLANK, id="ent-iface")
                yield Label("Twin BSSID:")
                yield Input(self.target.bssid.lower(), id="ent-bssid")
                yield Label("EAP method:")
                yield Select([("PEAP (MSCHAPv2)", Method.PEAP.value),
                              ("EAP-TTLS (PAP/MSCHAPv2)", Method.TTLS.value)],
                             value=Method.PEAP.value, id="ent-method")
                yield Checkbox("GTC downgrade (capture plaintext passwords)", value=False,
                               id="ent-gtc")
                yield Checkbox("Evict clients from the real AP (deauth)",
                               value=self.target.pmf_posture not in (PmfPosture.REQUIRED,
                                                                     PmfPosture.INVALID),
                               id="ent-deauth")
                with Horizontal(id="ent-buttons"):
                    yield Button("Cancel", variant="error", id="ent-cancel")
                    yield Button("Start", variant="success", id="ent-confirm")

    def action_cancel(self) -> None:
        self.dismiss(None)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        if event.button.id == "ent-cancel":
            self.dismiss(None)
            return
        twin_iface = self._selected_host()
        if twin_iface is None:
            self.notify("No interface can host the twin (needs a MAC-spoofing card)",
                        severity="error")
            return
        bssid = self.query_one("#ent-bssid", Input).value.strip().lower()
        if not _MAC_RE.match(bssid):
            self.notify("BSSID must look like aa:bb:cc:dd:ee:ff", severity="error")
            return
        method = Method(self.query_one("#ent-method", Select).value)
        gtc = self.query_one("#ent-gtc", Checkbox).value
        deauth = self.query_one("#ent-deauth", Checkbox).value
        punt_modes: tuple[PuntMode, ...] = (PuntMode.DEAUTH,) if deauth else ()
        self.dismiss(EnterpriseEvilTwinInput(
            twin_iface=twin_iface, punt_iface=twin_iface, twin_channel=self.target.channel,
            twin_bssid=bssid, method=method, gtc_downgrade=gtc, punt_modes=punt_modes,
            punt_period_sec=20.0 if deauth else None))

    def _selected_host(self):
        value = self.query_one("#ent-iface", Select).value
        if value is Select.BLANK or not self._hosts:
            return None
        return self._hosts[int(value)]
