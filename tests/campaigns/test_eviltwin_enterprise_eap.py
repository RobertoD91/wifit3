"""End-to-end EAP server test: a simulated non-validating PEAP supplicant (built from the same
primitives, using Python's ssl as the client side of the tunnel over memory BIOs) drives the rogue
EapServer through a full PEAP handshake and inner MSCHAPv2 / GTC exchange, and we assert the
credential captured matches what the client sent. No hardware, no sockets.
"""
import struct


from wifit3.campaigns.eviltwin_enterprise.eap_server import EapServer, Method
from wifit3.campaigns.eviltwin_enterprise.tls import TlsTunnel, client_context
from wifit3.crack.netntlm_format import mschapv2_hashline
from wifit3.dot11.eap import EAP_FAILURE, EAP_REQUEST, EAP_RESPONSE, EAP_SUCCESS
from wifit3.dot11.eap_build import (
    EAP_TYPE_GTC, EAP_TYPE_IDENTITY, EAP_TYPE_MSCHAPV2, EAP_TYPE_PEAP,
    eap_frame, eap_packet, eap_tls_body, parse_eap, parse_eap_tls_body,
)


class _PeapClient:
    """A misconfigured PEAP supplicant: accepts any certificate and answers the inner challenge with
    a fixed PeerChallenge + NT-Response (the values a real client would compute from its password)."""

    def __init__(self, inner_username="corp\\alice", gtc_password="s3cr3t", junk_first=False):
        self.inner_username = inner_username
        self.gtc_password = gtc_password
        self.junk_first = junk_first
        self.peer_challenge = bytes(range(16))
        self.nt_response = bytes(range(100, 124))
        self.auth_challenge = b""
        self.tunnel = TlsTunnel(client_context(), server_side=False, server_hostname="radius.local")
        self._in = bytearray()
        self._sent_junk = False
        self.done = False

    def respond(self, pkt: bytes):
        """Return the client's EAP reply to one server EAP packet, or None once the run ends."""
        msg = parse_eap(pkt)
        assert msg is not None, pkt.hex()
        if msg.code in (EAP_SUCCESS, EAP_FAILURE):
            self.done = True
            return None
        if msg.method_type == EAP_TYPE_IDENTITY:
            return eap_packet(EAP_RESPONSE, msg.identifier, EAP_TYPE_IDENTITY, b"anonymous")
        body = parse_eap_tls_body(msg.data)
        assert body is not None
        if body.start:
            return self._tls_reply(msg.identifier, self.tunnel.pump_handshake())
        self._in += body.tls_data
        if body.more:
            return self._tls_reply(msg.identifier, b"")         # ACK, more fragments to come
        tls_in, self._in = bytes(self._in), bytearray()
        self.tunnel.feed(tls_in)
        if not self.tunnel.handshake_done:
            out = self.tunnel.pump_handshake()
            if self.tunnel.handshake_done and not out and self.junk_first and not self._sent_junk:
                self._sent_junk = True                          # a non-EAP first phase-2 packet
                return self._tls_reply(msg.identifier, self.tunnel.write_app(b"\x00\x00\x00junk"))
            return self._tls_reply(msg.identifier, out)         # our flight, or empty ACK when done
        return self._phase2(msg.identifier)

    def _phase2(self, outer_id: int):
        inner = parse_eap(self.tunnel.read_app())
        assert inner is not None and inner.code == EAP_REQUEST
        if inner.method_type == EAP_TYPE_IDENTITY:
            reply = eap_packet(EAP_RESPONSE, inner.identifier, EAP_TYPE_IDENTITY,
                               self.inner_username.encode())
        elif inner.method_type == EAP_TYPE_MSCHAPV2:
            self.auth_challenge = inner.data[5:21]
            name = self.inner_username.encode()
            value = self.peer_challenge + b"\x00" * 8 + self.nt_response + b"\x00"
            data = struct.pack(">BBH", 2, inner.data[1], 4 + 1 + 49 + len(name)) + bytes([49]) + value + name
            reply = eap_packet(EAP_RESPONSE, inner.identifier, EAP_TYPE_MSCHAPV2, data)
        elif inner.method_type == EAP_TYPE_GTC:
            reply = eap_packet(EAP_RESPONSE, inner.identifier, EAP_TYPE_GTC, self.gtc_password.encode())
        else:
            raise AssertionError(f"unexpected inner type {inner.method_type}")
        return self._tls_reply(outer_id, self.tunnel.write_app(reply))

    def _tls_reply(self, outer_id: int, out: bytes) -> bytes:
        total = len(out) if out else None
        return eap_frame(EAP_RESPONSE, outer_id, eap_tls_body(EAP_TYPE_PEAP, out, total_length=total))


def _run(server: EapServer, client: _PeapClient) -> None:
    pkt = server.start()[0]
    for _ in range(200):
        reply = client.respond(pkt)
        if reply is None:
            return
        out = server.receive(parse_eap(reply))
        if not out:
            return
        pkt = out[0]
    raise AssertionError("EAP exchange did not terminate")


def test_peap_mschapv2_capture_matches_client():
    events: list[str] = []
    server = EapServer("CorpNet", method=Method.PEAP, on_event=events.append)
    client = _PeapClient(inner_username="corp\\alice")
    _run(server, client)

    cap = server.captured
    assert cap is not None and cap.inner_method == "MSCHAPv2"
    joined = " | ".join(events)
    assert "TLS tunnel established" in joined         # progress milestones are emitted for the demo
    assert "offering inner MSCHAPv2" in joined
    assert cap.username == "corp\\alice"
    expected = mschapv2_hashline("corp\\alice", client.auth_challenge,
                                 client.peer_challenge, client.nt_response)
    assert cap.hashline == expected
    assert server.done


def test_peap_recovers_from_a_non_eap_first_phase2_packet():
    # Some supplicants send a non-EAP packet first after the tunnel; the server must re-request the
    # inner identity rather than give up (the macOS 'could not parse the inner EAP packet' case).
    events: list[str] = []
    server = EapServer("CorpNet", method=Method.PEAP, on_event=events.append)
    client = _PeapClient(inner_username="corp\\alice", junk_first=True)
    _run(server, client)

    cap = server.captured
    assert cap is not None and cap.inner_method == "MSCHAPv2" and cap.username == "corp\\alice"
    assert any("re-requesting inner identity" in e for e in events)


def test_peap_gtc_downgrade_captures_plaintext():
    server = EapServer("CorpNet", method=Method.PEAP, gtc_downgrade=True)
    client = _PeapClient(inner_username="bob", gtc_password="hunter2")
    _run(server, client)

    cap = server.captured
    assert cap is not None and cap.inner_method == "GTC"
    assert cap.username == "bob" and cap.password == "hunter2"
    assert server.plaintext_credential == "bob:hunter2"


def test_identity_is_captured_before_tunnel():
    server = EapServer("CorpNet")
    first = server.start()
    assert parse_eap(first[0]).method_type == EAP_TYPE_IDENTITY
    server.receive(parse_eap(eap_packet(EAP_RESPONSE, 1, EAP_TYPE_IDENTITY, b"outer@corp")))
    assert server.captured is not None
    assert server.captured.username == "outer@corp"
