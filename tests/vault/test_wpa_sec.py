"""wpa-sec client + vault tool, no network: urlopen and the HTTP client are stubbed."""
import io
import time
from types import SimpleNamespace

import pytest

from wifit3.models import CaptureType, PersistedCapture, ToolStatus
from wifit3.models.jobs import JobState
from wifit3.persist.config import Config
from wifit3.vault.tools import wpa_sec as wpa_sec_tool
from wifit3.vault.tools import wpa_sec_api
from wifit3.vault.tools.wpa_sec import WpaSecTool
from wifit3.vault.tools.wpa_sec_api import SubmitResult, WpaSecClient, WpaSecResult


class _FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def _capture_urlopen(monkeypatch, body: bytes):
    """Stub urlopen; record the Request it is handed so the wire format can be asserted."""
    seen = {}

    def fake_urlopen(request, timeout=None):
        seen["request"] = request
        return _FakeResponse(body)

    monkeypatch.setattr(wpa_sec_api.urllib.request, "urlopen", fake_urlopen)
    return seen


def test_submit_sends_multipart_with_key_cookie(monkeypatch, tmp_path):
    pcap = tmp_path / "cap.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1PCAPBYTES")
    seen = _capture_urlopen(monkeypatch, b"OK, 1 new handshake(s)")

    result = WpaSecClient("https://wpa-sec.stanev.org/", "DEADBEEF").submit(pcap)

    request = seen["request"]
    assert request.method == "POST"
    assert request.get_header("Cookie") == "key=DEADBEEF"
    assert request.get_header("Content-type").startswith("multipart/form-data; boundary=")
    assert b'name="file"; filename="cap.pcap"' in request.data
    assert b"PCAPBYTES" in request.data
    assert result.accepted and not result.already


def test_submit_recognizes_already_submitted(monkeypatch, tmp_path):
    pcap = tmp_path / "cap.pcap"
    pcap.write_bytes(b"x")
    _capture_urlopen(monkeypatch, b"File already submitted")

    result = WpaSecClient("https://wpa-sec.stanev.org", "K").submit(pcap)

    assert result.already and not result.accepted


def test_results_parses_potfile(monkeypatch):
    body = (b"aabbccddeeff:1122334455ff:HomeNet:hunter2\n"
            b"001122334455:aabbccddee00:Caf\xc3\xa9\x3a2:p:a:ss\n"   # colons in essid and psk
            b"\n"
            b"garbage-line\n")
    _capture_urlopen(monkeypatch, body)

    results = WpaSecClient("https://wpa-sec.stanev.org", "K").results()

    assert results[0] == WpaSecResult("aabbccddeeff", "1122334455ff", "HomeNet", "hunter2")
    # bssid/station split off the front, psk off the back; the essid keeps its interior colon
    assert results[1].bssid == "001122334455"
    assert results[1].essid == "Café:2:p:a"
    assert results[1].psk == "ss"
    assert len(results) == 2


class _FakeClient:
    """Stands in for WpaSecClient: records submits, returns a canned potfile."""
    instances: list["_FakeClient"] = []

    def __init__(self, url, key):
        self.url, self.key = url, key
        self.submitted: list = []
        _FakeClient.instances.append(self)

    def submit(self, pcap_path):
        self.submitted.append(pcap_path)
        return SubmitResult(accepted=True, already=False, message="OK")

    def results(self):
        return [WpaSecResult("aabbccddeeff", "112233445566", "HomeNet", "s3cret!")]


def _hashlines(path, bssid="aa:bb:cc:dd:ee:ff"):
    # WPA*02 (EAPOL) line; only .kind/.bssid are read by the tool.
    return [("WPA*02*...", SimpleNamespace(kind="02", bssid=bssid, ssid="HomeNet"))]


def _drive_to_done(tool, job, timeout=3.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        result = tool.poll_status(job)
        if result.status != ToolStatus.RUNNING:
            return result
        time.sleep(0.02)
    raise AssertionError(f"job never left RUNNING: {tool.poll_status(job)}")


def test_tool_launch_uploads_pcap_and_reports_crack(monkeypatch, tmp_path):
    monkeypatch.setattr(Config, "captures_dir", str(tmp_path))
    monkeypatch.setattr(Config, "wpa_sec", SimpleNamespace(
        key="K", url="https://wpa-sec.stanev.org", auto_upload=False))
    monkeypatch.setattr(wpa_sec_tool, "WpaSecClient", _FakeClient)
    monkeypatch.setattr(wpa_sec_tool, "require_hashlines",
                        lambda path: _hashlines(path))
    _FakeClient.instances.clear()
    pcap = tmp_path / "HomeNet_aa-bb-cc-dd-ee-ff_100_handshake.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1handshake")

    tool = WpaSecTool()
    capture = PersistedCapture(type=CaptureType.HS, timestamp=0, path=str(tmp_path / "x.hc22000"),
                               bssid="aa:bb:cc:dd:ee:ff", ssid="HomeNet")
    job = JobState(job_id="wpa_sec_x_1", tool_name="wpa_sec", capture_path=capture.path,
                   hashlines_path=str(tmp_path / "x.hc22000"), status=ToolStatus.QUEUED,
                   progress_msg="")

    tool.launch(job, capture)
    result = _drive_to_done(tool, job)

    assert result.status == ToolStatus.SUCCESS
    assert result.keys == ("s3cret!",)
    assert _FakeClient.instances[-1].submitted == [pcap]
    assert job.api_id == "wpa-sec"                 # marked adoptable across restarts


def test_tool_launch_without_pcap_errors(monkeypatch, tmp_path):
    monkeypatch.setattr(Config, "captures_dir", str(tmp_path))
    monkeypatch.setattr(Config, "wpa_sec", SimpleNamespace(key="K", url="u", auto_upload=False))
    tool = WpaSecTool()
    capture = PersistedCapture(type=CaptureType.PMKID, timestamp=0, path="x", bssid="aa:bb:cc:dd:ee:ff")
    job = JobState(job_id="j", tool_name="wpa_sec", capture_path="x", hashlines_path="x",
                   status=ToolStatus.QUEUED, progress_msg="")

    with pytest.raises(ValueError, match="handshake pcap"):
        tool.launch(job, capture)


def test_can_crack_only_wpa_and_pmkid():
    tool = WpaSecTool()
    assert tool.can_crack([SimpleNamespace(kind="02")])
    assert tool.can_crack([SimpleNamespace(kind="01")])
    assert not tool.can_crack([SimpleNamespace(kind="99")])


def test_config_round_trip(monkeypatch, tmp_path):
    from wifit3.persist import config as config_mod
    monkeypatch.setattr(config_mod, "_PATH", tmp_path / "config.toml")
    Config.wpa_sec = config_mod.WpaSecSettings(key="MYKEY", url="https://example.test",
                                               auto_upload=True)
    Config.save()
    Config.wpa_sec = config_mod.WpaSecSettings()
    Config.load()
    assert Config.wpa_sec.key == "MYKEY"
    assert Config.wpa_sec.url == "https://example.test"
    assert Config.wpa_sec.auto_upload is True
