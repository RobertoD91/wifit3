"""End-to-end enterprise-twin EAP test driven by a REAL supplicant.

wpa_supplicant's ``eapol_test`` (a genuine EAP peer: PEAPv0/v1, EAP-TTLS, MSCHAPv2, GTC) runs the EAP
conversation over RADIUS against a tiny in-process RADIUS shim that bridges the EAP to wifit3's rogue
``EapServer``. This catches real-client wire quirks (e.g. PEAPv0 headerless inner EAP) that a
hand-written test client would miss.

Skipped unless ``eapol_test`` is available: set ``WIFIT3_EAPOL_TEST=/path/to/eapol_test`` or put it on
PATH. Build it from the wpa_supplicant source with ``CONFIG_EAPOL_TEST=y`` (``make eapol_test``).
"""
import hashlib
import hmac
import os
import shutil
import socket
import struct
import subprocess
import threading

import pytest

from wifit3.campaigns.eviltwin_enterprise.eap_server import EapServer, Method
from wifit3.dot11.eap_build import parse_eap

_EAPOL_TEST = os.environ.get("WIFIT3_EAPOL_TEST") or shutil.which("eapol_test")
pytestmark = pytest.mark.skipif(not _EAPOL_TEST, reason="eapol_test (wpa_supplicant) not available")

_SECRET = b"testing123"
_ACCESS_CHALLENGE, _ACCESS_ACCEPT = 11, 2
_EAP_MESSAGE, _MSG_AUTH, _STATE = 79, 80, 24


def _attrs(blob):
    out, i = [], 0
    while i + 2 <= len(blob):
        ln = blob[i + 1]
        if ln < 2 or i + ln > len(blob):
            break
        out.append((blob[i], blob[i + 2:i + ln]))
        i += ln
    return out


def _eap_message_attrs(eap):
    chunks = [eap[i:i + 253] for i in range(0, len(eap), 253)] or [b""]
    return b"".join(bytes([_EAP_MESSAGE, len(c) + 2]) + c for c in chunks)


def _response(code, ident, req_auth, attrs):
    attrs += bytes([_MSG_AUTH, 18]) + b"\x00" * 16
    header = struct.pack(">BBH", code, ident, 20 + len(attrs))
    msg_auth = hmac.new(_SECRET, header + req_auth + attrs, hashlib.md5).digest()
    attrs = attrs[:-16] + msg_auth
    resp_auth = hashlib.md5(header + req_auth + attrs + _SECRET).digest()
    return header + resp_auth + attrs


def _bridge(sock, server, result, stop):
    started = False
    while not stop.is_set():
        try:
            data, addr = sock.recvfrom(4096)
        except socket.timeout:
            continue
        ident, length = data[1], struct.unpack(">H", data[2:4])[0]
        req_auth = data[4:20]
        eap_in = b"".join(v for t, v in _attrs(data[20:length]) if t == _EAP_MESSAGE)
        if not started:
            server.start()                       # the peer already answered identity locally
            started = True
        msg = parse_eap(eap_in)
        out = server.receive(msg) if msg is not None else []
        eap_out = out[0] if out else b""
        if server.captured is not None and server.done:
            result["cap"] = server.captured
            sock.sendto(_response(_ACCESS_ACCEPT, ident, req_auth, _eap_message_attrs(eap_out)), addr)
            return
        state = bytes([_STATE, 18]) + b"wifit3-bridge-01"
        sock.sendto(_response(_ACCESS_CHALLENGE, ident, req_auth,
                              _eap_message_attrs(eap_out) + state), addr)


def _drive(tmp_path, *, method, gtc_downgrade, eap, phase1, phase2, identity, password):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.settimeout(0.5)
    port = sock.getsockname()[1]
    server = EapServer("CorpNet", method=method, gtc_downgrade=gtc_downgrade)
    result, stop = {}, threading.Event()
    thread = threading.Thread(target=_bridge, args=(sock, server, result, stop), daemon=True)
    thread.start()
    conf = tmp_path / "peer.conf"
    phase1_line = f'\tphase1="{phase1}"\n' if phase1 else ""
    conf.write_text(
        "network={\n\tkey_mgmt=IEEE8021X\n"
        f'\teap={eap}\n\tidentity="{identity}"\n\tanonymous_identity="anonymous"\n'
        f'\tpassword="{password}"\n{phase1_line}\tphase2="{phase2}"\n}}\n')
    try:
        subprocess.run([_EAPOL_TEST, "-c", str(conf), "-a", "127.0.0.1", "-p", str(port),
                        "-s", _SECRET.decode()], timeout=30, capture_output=True)
    finally:
        stop.set()
        thread.join(5)
        sock.close()
    return result.get("cap")


def test_peapv0_mschapv2(tmp_path):
    cap = _drive(tmp_path, method=Method.PEAP, gtc_downgrade=False, eap="PEAP",
                 phase1="peapver=0 crypto_binding=0", phase2="auth=MSCHAPV2",
                 identity="alice", password="Secret123!")
    assert cap is not None and cap.inner_method == "MSCHAPv2" and cap.username == "alice"
    assert cap.hashline and cap.hashline.startswith("alice::::")


def test_peapv1_mschapv2(tmp_path):
    cap = _drive(tmp_path, method=Method.PEAP, gtc_downgrade=False, eap="PEAP",
                 phase1="peapver=1 crypto_binding=0", phase2="auth=MSCHAPV2",
                 identity="dave", password="Secret123!")
    assert cap is not None and cap.inner_method == "MSCHAPv2" and cap.username == "dave"


def test_peap_gtc_downgrade_plaintext(tmp_path):
    cap = _drive(tmp_path, method=Method.PEAP, gtc_downgrade=True, eap="PEAP",
                 phase1="peapver=0 crypto_binding=0", phase2="auth=GTC",
                 identity="carol", password="GtcPass9!")
    assert cap is not None and cap.inner_method == "GTC"
    assert cap.username == "carol" and cap.password == "GtcPass9!"


def test_peap_gtc_downgrade_nak_falls_back_to_mschapv2(tmp_path):
    # Server offers GTC, the MSCHAPv2-only client NAKs, server switches and still captures.
    cap = _drive(tmp_path, method=Method.PEAP, gtc_downgrade=True, eap="PEAP",
                 phase1="peapver=0 crypto_binding=0", phase2="auth=MSCHAPV2",
                 identity="alice", password="Secret123!")
    assert cap is not None and cap.inner_method == "MSCHAPv2"


def test_ttls_pap_plaintext(tmp_path):
    cap = _drive(tmp_path, method=Method.TTLS, gtc_downgrade=False, eap="TTLS",
                 phase1="", phase2="auth=PAP", identity="bob", password="Secret123!")
    assert cap is not None and cap.inner_method == "PAP"
    assert cap.username == "bob" and cap.password == "Secret123!"
