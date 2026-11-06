"""AutoAttack driver: campaign selection, exclusion, and a stubbed run loop (no radio)."""
import asyncio
from types import SimpleNamespace

from wifit3.campaigns import auto_attack
from wifit3.campaigns.auto_attack import AutoAttack, already_won, select_campaigns
from wifit3.campaigns.deauth import DeauthCampaign
from wifit3.campaigns.pin import WpsCampaign
from wifit3.campaigns.pmkid import PmkidHarvestAttack
from wifit3.campaigns.wep import WepCampaign
from wifit3.dot11.pmf import PmfPosture
from wifit3.dot11.rsn import AKM_802_1X, AKM_PSK


def fake_ap(**overrides):
    base = dict(bssid="aa:bb:cc:dd:ee:ff", ssid="Net", channel=6, encryption="OPEN",
                akm_suites=[], rsn_valid=False, is_hidden=False, pmf_posture=PmfPosture.DISABLED,
                last_beacon_frame=b"\x80" + b"\x00" * 40, wep_key=None, wps=False,
                wps_locked=False, vendor_akm_offered=False, handshakes={})
    base.update(overrides)
    return SimpleNamespace(**base)


def test_select_wpa_psk_passive_is_pmkid_only():
    ap = fake_ap(encryption="WPA2", akm_suites=[AKM_PSK], rsn_valid=True)
    assert select_campaigns(ap, aggressive=False) == [PmkidHarvestAttack]


def test_select_wpa_psk_aggressive_adds_deauth():
    ap = fake_ap(encryption="WPA2", akm_suites=[AKM_PSK], rsn_valid=True)
    assert select_campaigns(ap, aggressive=True) == [PmkidHarvestAttack, DeauthCampaign]


def test_select_wep_only_when_aggressive():
    ap = fake_ap(encryption="WEP")
    assert select_campaigns(ap, aggressive=False) == []
    assert select_campaigns(ap, aggressive=True) == [WepCampaign]


def test_select_wps_when_aggressive():
    ap = fake_ap(encryption="WPA2", akm_suites=[AKM_PSK], rsn_valid=True, wps=True)
    chosen = select_campaigns(ap, aggressive=True)
    assert chosen[0] is WpsCampaign and PmkidHarvestAttack in chosen and DeauthCampaign in chosen


def test_enterprise_is_never_auto_attacked():
    ap = fake_ap(encryption="WPA2", akm_suites=[AKM_802_1X], rsn_valid=True)
    assert select_campaigns(ap, aggressive=False) == []
    assert select_campaigns(ap, aggressive=True) == []


def test_open_network_has_nothing_to_attack():
    assert select_campaigns(fake_ap(), aggressive=True) == []


def test_already_won():
    assert already_won(fake_ap(encryption="WEP", wep_key=b"\x01\x02\x03\x04\x05"))
    assert not already_won(fake_ap(encryption="WEP", wep_key=None))
    assert not already_won(fake_ap(encryption="WPA2", akm_suites=[AKM_PSK], handshakes={}))


def test_is_excluded_is_case_insensitive():
    aa = AutoAttack(_FakeArray([]), aggressive=False, excluded_ssids=["HomeNet", "Guest"])
    assert aa.is_excluded("homenet")
    assert aa.is_excluded("GUEST")
    assert not aa.is_excluded("Office")
    assert not aa.is_excluded(None)


class _FakeArray:
    def __init__(self, aps):
        self._aps = aps
        self.stop_calls = 0
        self.hop_calls = []

    def get_access_points(self, include_eviltwin=True):
        return list(self._aps)

    async def stop_hopping(self):
        self.stop_calls += 1

    async def start_hopping(self, channels=None, interval=0.25, include_dfs_channels=False):
        self.hop_calls.append(channels)


class _StubCampaign:
    key = "pmkid"
    idle_label = "Stub"

    def __init__(self):
        self.ran = False

    def run(self):
        self.ran = True
        return True

    @property
    def done(self):
        return True

    async def stop(self):
        pass


async def test_run_loop_attacks_and_records_capture(monkeypatch):
    ap = fake_ap(ssid="Net", encryption="WPA2", akm_suites=[AKM_PSK], rsn_valid=True)
    stub = _StubCampaign()
    captured: list = []
    monkeypatch.setattr(auto_attack, "select_campaigns", lambda ap, aggressive: [_StubCampaign])
    monkeypatch.setattr(auto_attack, "_construct", lambda cls, array, ap, log: stub)
    # Won only once the stub has run, so the target is picked first, then counted as captured.
    monkeypatch.setattr(auto_attack, "already_won", lambda ap: stub.ran)

    array = _FakeArray([ap])
    aa = AutoAttack(array, aggressive=False, excluded_ssids=[], channels=[1, 6, 11],
                    scan_window_sec=0.05, on_capture=captured.append)
    task = asyncio.create_task(aa.run())
    for _ in range(100):
        await asyncio.sleep(0.02)
        if stub.ran:
            break
    aa.request_stop()
    await asyncio.wait_for(task, timeout=2)

    assert stub.ran
    assert aa.attacked == 1 and aa.captured == 1
    assert captured == [ap]
    assert array.stop_calls >= 1 and array.hop_calls           # hopping stopped then resumed
    assert array.hop_calls[-1] == [1, 6, 11]
