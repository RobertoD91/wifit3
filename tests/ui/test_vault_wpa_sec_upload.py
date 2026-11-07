"""VaultDrawer bulk 'Upload to wpa-sec' action: queues one job per uncracked WPA/PMKID handshake
that has a pcap, skips those without one, and never double-queues."""
from types import SimpleNamespace

from wifit3.models import CaptureType, PersistedCapture
from wifit3.models.jobs import ToolName, ToolStatus
from wifit3.ui.screens.vault_drawer import VaultDrawer
from wifit3.vault.tools import wpa_sec as wpa_sec_tool


def _line(kind="02"):
    return SimpleNamespace(line=SimpleNamespace(kind=kind), raw=f"WPA*{kind}*deadbeef")


def _capture(bssid):
    return PersistedCapture(type=CaptureType.HS, timestamp=1, path=f"/caps/{bssid}.hc22000",
                            bssid=bssid, ssid="CorpNet")


class _FakeManager:
    def __init__(self):
        self.submitted = []
        self.active = []

    def get_active_jobs(self):
        return self.active

    def submit_job(self, tool_name, capture, config, hashlines):
        self.submitted.append((tool_name, capture.bssid, tuple(hashlines)))
        return f"{tool_name}_{capture.bssid}"


class _FakeVault:
    def __init__(self, states):
        self._states = states
        self.manager = _FakeManager()

    def all_captures(self):
        return [_capture(b) for b in self._states]

    def ap_state(self, bssid):
        return self._states[bssid]


def _drawer(vault, monkeypatch):
    drawer = object.__new__(VaultDrawer)
    drawer._fake_app = SimpleNamespace(vault=vault)
    monkeypatch.setattr(VaultDrawer, "app", property(lambda self: self._fake_app))
    drawer._notes = []
    drawer.notify = lambda msg, severity="information": drawer._notes.append((msg, severity))
    return drawer


def test_uploads_only_handshakes_with_a_pcap(monkeypatch):
    # aa has a pcap -> queued; bb has none -> skipped.
    monkeypatch.setattr(wpa_sec_tool.WpaSecTool, "_handshake_pcap",
                        staticmethod(lambda bssid: "/caps/x.pcap" if bssid == "aa" else None))
    states = {
        "aa": SimpleNamespace(hashline_capture=_capture("aa"), uncracked=(_line("02"),)),
        "bb": SimpleNamespace(hashline_capture=_capture("bb"), uncracked=(_line("01"),)),
    }
    vault = _FakeVault(states)
    drawer = _drawer(vault, monkeypatch)

    drawer._do_wpa_sec_upload()

    assert [s[1] for s in vault.manager.submitted] == ["aa"]
    assert vault.manager.submitted[0][0] == ToolName.WPA_SEC
    assert any("Queued 1" in m and "1 skipped" in m for m, _ in drawer._notes)


def test_skips_captures_with_an_active_job(monkeypatch):
    monkeypatch.setattr(wpa_sec_tool.WpaSecTool, "_handshake_pcap",
                        staticmethod(lambda bssid: "/caps/x.pcap"))
    states = {"aa": SimpleNamespace(hashline_capture=_capture("aa"), uncracked=(_line("02"),))}
    vault = _FakeVault(states)
    vault.manager.active = [SimpleNamespace(capture_path="/caps/aa.hc22000",
                                            tool_name=ToolName.WPA_SEC, status=ToolStatus.RUNNING)]
    drawer = _drawer(vault, monkeypatch)

    drawer._do_wpa_sec_upload()

    assert vault.manager.submitted == []
    assert any("No uncracked" in m for m, _ in drawer._notes)


def test_non_wpa_lines_are_not_uploaded(monkeypatch):
    monkeypatch.setattr(wpa_sec_tool.WpaSecTool, "_handshake_pcap",
                        staticmethod(lambda bssid: "/caps/x.pcap"))
    # kind 99 is not WPA/PMKID -> nothing to upload.
    states = {"aa": SimpleNamespace(hashline_capture=_capture("aa"), uncracked=(_line("99"),))}
    vault = _FakeVault(states)
    drawer = _drawer(vault, monkeypatch)

    drawer._do_wpa_sec_upload()

    assert vault.manager.submitted == []
