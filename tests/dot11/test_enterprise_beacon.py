"""The enterprise twin beacon advertises an 802.1X RSN AKM, not PSK."""
from wifit3.dot11.ap import beacon_clone, beacon_clone_enterprise
from wifit3.dot11.ie import GENERIC_RSN_IE, force_psk_akm, ssid_ie
from wifit3.dot11.rsn import AKM_802_1X

_AKM_8021X = b"\x00\x0f\xac\x01"
_AKM_PSK = b"\x00\x0f\xac\x02"


def test_force_akm_rewrites_to_8021x():
    ie = force_psk_akm(GENERIC_RSN_IE, akm=AKM_802_1X)
    assert _AKM_8021X in ie and _AKM_PSK not in ie


def _beacon() -> bytes:
    head = b"\x80\x00" + b"\x00" * 34                 # 36-byte beacon head
    return head + ssid_ie("CorpNet") + GENERIC_RSN_IE


def test_enterprise_clone_advertises_8021x():
    twin = beacon_clone_enterprise(_beacon(), 6)
    assert _AKM_8021X in twin and _AKM_PSK not in twin


def test_psk_clone_still_advertises_psk():
    twin = beacon_clone(_beacon(), 6)
    assert _AKM_PSK in twin and _AKM_8021X not in twin
