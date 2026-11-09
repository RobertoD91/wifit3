"""EnterpriseFakeAP responder wiring: assoc triggers an EAP identity request; an identity response
is captured. No TLS (the tunnel only starts once an identity arrives)."""
import asyncio
import struct
import time

from wifit3.campaigns.eviltwin_enterprise.fake_ap import EnterpriseFakeAP
from wifit3.dot11.auth_assoc import assoc_req, auth_req
from wifit3.dot11.eap import EAP_RESPONSE
from wifit3.dot11.eap_build import EAP_TYPE_IDENTITY, eap_from_frame, eap_packet
from wifit3.dot11.eapol import LLC_SNAP_EAPOL, data_header
from wifit3.dot11.parser import WlanFrameParser

_BSSID = bytes.fromhex("9483c48c3f78")
_CLIENT = bytes.fromhex("02aabbccddee")
_SSID = "CorpNet"


class FakeIface:
    FAKE_MAC = None

    def __init__(self, channel=1):
        self.sent: list[bytes] = []
        self.current_channel = channel

    async def send_no_wait(self, frame):
        self.sent.append(frame)
        return True

    async def set_channel(self, channel, scan=False):
        self.current_channel = channel
        return True

    async def set_fake_mac(self, mac=None, bssid=None):
        return ":".join(f"{b:02x}" for b in bssid)

    async def clear_fake_mac(self):
        pass


def _parse(frame):
    return WlanFrameParser.parse_80211_frame(frame, 0)


def _client_eap(eap: bytes) -> bytes:
    eapol = bytes([2, 0]) + struct.pack(">H", len(eap)) + eap
    return data_header(to_ds=True, bssid=_BSSID, client=_CLIENT) + LLC_SNAP_EAPOL + eapol


def _fakeap(captures):
    return EnterpriseFakeAP(FakeIface(), _BSSID, _SSID, 1, twin_beacon=bytes(60),
                            on_capture=captures.append)


async def _flush():
    await asyncio.sleep(0.01)


def _seq_of(frame: bytes) -> int:
    return struct.unpack_from("<H", frame, 22)[0] >> 4


async def test_assoc_triggers_identity_request():
    fap = _fakeap([])
    fap.on_rx(_parse(auth_req(_BSSID, _CLIENT)))
    await _flush()
    fap.on_rx(_parse(assoc_req(_BSSID, _CLIENT, _SSID)))
    await _flush()
    assert fap.stats.auth == 1 and fap.stats.assoc == 1
    eaps = [eap_from_frame(f) for f in fap.iface.sent]
    identity_reqs = [m for m in eaps if m and m.method_type == EAP_TYPE_IDENTITY]
    assert identity_reqs, "expected an EAP-Request/Identity after association"


async def test_identity_response_is_captured():
    captures = []
    fap = _fakeap(captures)
    fap.on_rx(_parse(assoc_req(_BSSID, _CLIENT, _SSID)))
    await _flush()
    fap.on_rx(_parse(_client_eap(eap_packet(EAP_RESPONSE, 1, EAP_TYPE_IDENTITY, b"anon@corp"))))
    await _flush()
    assert any(c.inner_method == "Identity" and c.username == "anon@corp" for c in captures)
    assert fap.stats.identities == 1


def test_reauth_is_silent_after_a_credential_capture():
    events: list[str] = []
    fap = EnterpriseFakeAP(FakeIface(), _BSSID, _SSID, 1, twin_beacon=bytes(60),
                           on_event=events.append)
    cs = "02:aa:bb:cc:dd:ee"
    fap._new_server(cs).on_event("hello")
    assert events, "a fresh client's EAP steps should be logged"
    events.clear()
    fap._credentialed.add(cs)                     # already captured this client's credential
    fap._new_server(cs).on_event("again")
    assert events == [], "a captured client's re-auth must not spam the log"


async def test_tx_frames_carry_incrementing_sequence_numbers():
    fap = _fakeap([])
    fap.on_rx(_parse(auth_req(_BSSID, _CLIENT)))
    await _flush()
    fap.on_rx(_parse(assoc_req(_BSSID, _CLIENT, _SSID)))
    await _flush()
    seqs = [_seq_of(f) for f in fap.iface.sent]
    assert len(seqs) >= 2
    assert seqs == sorted(seqs) and len(set(seqs)) == len(seqs), f"non-incrementing seqs: {seqs}"


async def test_eap_from_unseen_client_is_ignored():
    fap = _fakeap([])
    # an EAP response with no prior auth / assoc / EAPOL-Start: nothing should answer it
    fap.on_rx(_parse(_client_eap(eap_packet(EAP_RESPONSE, 1, EAP_TYPE_IDENTITY, b"anon@corp"))))
    await _flush()
    assert fap._servers == {}
    assert fap.iface.sent == []


def test_idle_sessions_are_reaped():
    fap = _fakeap([])
    cs = "02:aa:bb:cc:dd:ee"
    fap._last_seen[cs] = time.monotonic() - 120
    fap._servers[cs] = object()
    fap._credentialed.add(cs)
    fap._last_reap = time.monotonic() - 60          # force the reap window open
    fap._reap_idle_sessions()
    assert cs not in fap._last_seen and cs not in fap._servers and cs not in fap._credentialed


async def test_eapol_start_also_begins_eap():
    fap = _fakeap([])
    start = data_header(to_ds=True, bssid=_BSSID, client=_CLIENT) + LLC_SNAP_EAPOL + b"\x02\x01\x00\x00"
    fap.on_rx(_parse(start))
    await _flush()
    assert fap.stats.eapol_starts == 1
    assert any(eap_from_frame(f) and eap_from_frame(f).method_type == EAP_TYPE_IDENTITY
               for f in fap.iface.sent)
