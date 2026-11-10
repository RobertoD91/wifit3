"""EAP / 802.1X-over-802.11 builders and parsers for the rogue authenticator (RFC 3748, 5216).

Build and parse bare EAP packets, wrap them in an EAPOL-EAP data frame, and read/write the EAP-TLS
(also PEAP / EAP-TTLS) flags-and-fragment header. Spec only: no device, no asyncio, no credential
interpretation.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional

from wifit3.dot11.eap import EAP_FAILURE, EAP_REQUEST, EAP_SUCCESS
from wifit3.dot11.eapol import LLC_SNAP_EAPOL, data_header

# EAP method Type numbers (RFC 3748 + IANA).
EAP_TYPE_IDENTITY = 1
EAP_TYPE_NAK = 3
EAP_TYPE_MD5 = 4
EAP_TYPE_GTC = 6
EAP_TYPE_TLS = 13
EAP_TYPE_TTLS = 21
EAP_TYPE_PEAP = 25
EAP_TYPE_MSCHAPV2 = 26

EAPOL_VERSION = 2
EAPOL_TYPE_EAP = 0
EAPOL_TYPE_START = 1

# EAP-TLS / PEAP / TTLS flag bits in the first payload byte (RFC 5216 section 3.1).
TLS_FLAG_LENGTH = 0x80          # L: a 4-byte TLS Message Length follows
TLS_FLAG_MORE = 0x40           # M: more fragments to come
TLS_FLAG_START = 0x20          # S: start of a new TLS conversation


@dataclass(frozen=True)
class EapMessage:
    """A decoded EAP packet. ``method_type`` is None for Success/Failure (which carry no type)."""
    code: int
    identifier: int
    method_type: Optional[int]
    data: bytes                 # everything after the type byte (empty for Success/Failure)


def eap_frame(code: int, identifier: int, body: bytes = b"") -> bytes:
    """Wrap an already-built EAP body (type byte onward) in the EAP header: code, id, length."""
    return struct.pack(">BBH", code, identifier, 4 + len(body)) + body


def eap_packet(code: int, identifier: int, method_type: Optional[int] = None,
               data: bytes = b"") -> bytes:
    """A bare EAP packet (RFC 3748 section 4): code, id, length, optional type + data."""
    body = (bytes([method_type]) + data) if method_type is not None else b""
    return eap_frame(code, identifier, body)


def eap_request_identity(identifier: int, prompt: bytes = b"") -> bytes:
    return eap_packet(EAP_REQUEST, identifier, EAP_TYPE_IDENTITY, prompt)


def eap_success(identifier: int) -> bytes:
    return eap_packet(EAP_SUCCESS, identifier)


def eap_failure(identifier: int) -> bytes:
    return eap_packet(EAP_FAILURE, identifier)


def parse_eap(payload: bytes) -> Optional[EapMessage]:
    """Decode an EAP packet from its own bytes (code..). None when truncated or length-inconsistent."""
    if len(payload) < 4:
        return None
    code, identifier, length = struct.unpack_from(">BBH", payload, 0)
    if length < 4 or length > len(payload):
        return None
    has_type = code in (EAP_REQUEST, 2) and length > 4      # 2 == EAP_RESPONSE
    method_type = payload[4] if has_type else None
    data = payload[5:length] if has_type else payload[4:length]
    return EapMessage(code=code, identifier=identifier, method_type=method_type, data=data)


def eap_tls_body(method_type: int, tls_data: bytes = b"", *, start: bool = False,
                 more: bool = False, total_length: Optional[int] = None, version: int = 0) -> bytes:
    """The EAP data body for a TLS-based method (PEAP/TTLS/TLS): flags byte (+ 4-byte total length
    when given) + the TLS fragment. ``version`` rides the low bits for PEAP."""
    flags = version & 0x07
    if start:
        flags |= TLS_FLAG_START
    if more:
        flags |= TLS_FLAG_MORE
    if total_length is not None:
        flags |= TLS_FLAG_LENGTH
        return bytes([method_type, flags]) + struct.pack(">I", total_length) + tls_data
    return bytes([method_type, flags]) + tls_data


@dataclass(frozen=True)
class EapTlsBody:
    flags: int
    total_length: Optional[int]
    tls_data: bytes

    @property
    def start(self) -> bool:
        return bool(self.flags & TLS_FLAG_START)

    @property
    def more(self) -> bool:
        return bool(self.flags & TLS_FLAG_MORE)


def parse_eap_tls_body(data: bytes) -> Optional[EapTlsBody]:
    """Decode a TLS-method EAP body (the bytes after the EAP type). None when truncated."""
    if len(data) < 1:
        return None
    flags = data[0]
    rest = data[1:]
    total_length = None
    if flags & TLS_FLAG_LENGTH:
        if len(rest) < 4:
            return None
        total_length = struct.unpack_from(">I", rest, 0)[0]
        rest = rest[4:]
    return EapTlsBody(flags=flags, total_length=total_length, tls_data=rest)


def eapol_eap_frame(bssid: bytes, client: bytes, eap_bytes: bytes) -> bytes:
    """An AP->STA 802.11 data frame carrying one EAP packet (EAPOL type 0)."""
    eapol = bytes([EAPOL_VERSION, EAPOL_TYPE_EAP]) + struct.pack(">H", len(eap_bytes)) + eap_bytes
    return data_header(to_ds=False, bssid=bssid, client=client) + LLC_SNAP_EAPOL + eapol


def _eapol_payload(raw: bytes) -> Optional[tuple[int, bytes]]:
    """``(eapol_type, eapol_body)`` for a frame carrying EAPOL, located by its LLC/SNAP header
    (tolerating a variable 802.11 header length / DMA padding), or None."""
    start = raw.find(LLC_SNAP_EAPOL)
    if start < 0:
        return None
    header = start + len(LLC_SNAP_EAPOL)
    if header + 4 > len(raw):
        return None
    eapol_type = raw[header + 1]
    length = struct.unpack_from(">H", raw, header + 2)[0]
    body = raw[header + 4:header + 4 + length]
    return eapol_type, body


def eap_from_frame(raw: bytes) -> Optional[EapMessage]:
    """The EAP packet carried by an EAPOL-EAP data frame, or None when it isn't one."""
    payload = _eapol_payload(raw)
    if payload is None or payload[0] != EAPOL_TYPE_EAP:
        return None
    return parse_eap(payload[1])


def is_eapol_start(raw: bytes) -> bool:
    payload = _eapol_payload(raw)
    return payload is not None and payload[0] == EAPOL_TYPE_START
