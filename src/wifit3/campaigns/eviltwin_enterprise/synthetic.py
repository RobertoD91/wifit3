"""Build a synthetic WPA-Enterprise AccessPoint target, so the enterprise evil twin can be stood up
for a chosen SSID even when the real network is not in range (nothing to clone)."""
from __future__ import annotations

from wifit3.dot11.ap import build_enterprise_beacon
from wifit3.dot11.mac import str_to_mac
from wifit3.dot11.rsn import AKM_802_1X
from wifit3.models import AccessPoint


def synthetic_enterprise_ap(ssid: str, channel: int, bssid: str) -> AccessPoint:
    """An AccessPoint that looks like a WPA2-Enterprise network to the Focus screen and the twin:
    802.1X AKM, a synthesized beacon to clone, so ``eap_only`` holds and the Enterprise Twin button
    is offered."""
    beacon = build_enterprise_beacon(ssid, channel, str_to_mac(bssid))
    return AccessPoint(
        bssid=bssid.lower(), ssid=ssid, channel=channel, encryption="WPA2-EAP",
        akms=["EAP"], akm_suites=[AKM_802_1X], rsn_valid=True, pairwise_cipher="CCMP",
        last_beacon_frame=beacon,
    )
