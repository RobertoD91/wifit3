"""Standalone (no target in range) enterprise twin: synthesized beacon + synthetic AccessPoint."""
from wifit3.campaigns.eviltwin_enterprise.campaign import EnterpriseEvilTwinCampaign
from wifit3.campaigns.eviltwin_enterprise.synthetic import synthetic_enterprise_ap
from wifit3.dot11.ap import beacon_clone_enterprise, build_enterprise_beacon
from wifit3.dot11.mac import str_to_mac
from wifit3.dot11.parser import WlanFrameParser
from wifit3.dot11.rsn import AKM_802_1X
from wifit3.models.access_point import eap_only

_BSSID = "02:11:22:33:44:55"


def test_built_beacon_parses_as_enterprise():
    beacon = build_enterprise_beacon("CorpWiFi", 6, str_to_mac(_BSSID))
    pkt = WlanFrameParser.parse_80211_frame(beacon, 0)
    assert pkt.type == "beacon"
    assert pkt.ssid == "CorpWiFi"
    assert AKM_802_1X in pkt.akm_suites


def test_built_beacon_is_cloneable_by_the_twin():
    beacon = build_enterprise_beacon("CorpWiFi", 6, str_to_mac(_BSSID))
    twin = beacon_clone_enterprise(beacon, 6, str_to_mac(_BSSID))
    assert b"\x00\x0f\xac\x01" in twin                     # still an 802.1X RSN
    assert WlanFrameParser.parse_80211_frame(twin, 0).ssid == "CorpWiFi"


def test_synthetic_ap_is_eap_only_and_offers_the_twin():
    ap = synthetic_enterprise_ap("CorpWiFi", 11, _BSSID)
    assert ap.ssid == "CorpWiFi" and ap.channel == 11 and ap.bssid == _BSSID
    assert eap_only(ap)
    assert EnterpriseEvilTwinCampaign.visible(ap)
    assert EnterpriseEvilTwinCampaign.ineligible_reason(ap) is None
