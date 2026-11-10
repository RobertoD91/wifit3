"""Format credentials captured by the WPA-Enterprise evil twin into crackable lines.

MSCHAPv2 (PEAP / EAP-TTLS inner) lands as a hashcat ``-m 5500`` (NetNTLMv1) line, also readable by
asleap. GTC / PAP yield a plaintext ``username:password``. Spec only (RFC 2759): no network, no I/O.
"""
from __future__ import annotations

import hashlib

NT_RESPONSE_LEN = 24
CHALLENGE_LEN = 16


def mschapv2_challenge_hash(peer_challenge: bytes, auth_challenge: bytes, username: str) -> bytes:
    """The 8-byte ChallengeHash (RFC 2759 section 8.2): SHA1(PeerChallenge | AuthChallenge |
    UserName)[:8]. This is the server challenge hashcat ``-m 5500`` and asleap expect."""
    if len(peer_challenge) != CHALLENGE_LEN or len(auth_challenge) != CHALLENGE_LEN:
        raise ValueError("MSCHAPv2 challenges must be 16 bytes")
    digest = hashlib.sha1(peer_challenge + auth_challenge + username.encode("utf-8")).digest()
    return digest[:8]


def mschapv2_hashline(username: str, auth_challenge: bytes, peer_challenge: bytes,
                      nt_response: bytes) -> str:
    """A hashcat ``-m 5500`` line for a captured MSCHAPv2 exchange:
    ``username::::<NT-response>:<ChallengeHash>`` (empty domain and LM fields, as asleap writes)."""
    if len(nt_response) != NT_RESPONSE_LEN:
        raise ValueError(f"NT response must be {NT_RESPONSE_LEN} bytes, got {len(nt_response)}")
    challenge = mschapv2_challenge_hash(peer_challenge, auth_challenge, username)
    return f"{username}::::{nt_response.hex()}:{challenge.hex()}"


def strip_domain(username: str) -> str:
    """The bare user from a qualified name: ``DOMAIN\\user`` or ``user@realm`` both yield ``user``."""
    return username.split("\\")[-1].split("@")[0]


def mschapv2_hashlines(username: str, auth_challenge: bytes, peer_challenge: bytes,
                       nt_response: bytes) -> list[str]:
    """Crackable ``-m 5500`` lines for one MSCHAPv2 response: the given name, plus a stripped-user
    line when it is domain-qualified (some supplicants hash the bare user, and only that line cracks)."""
    lines = [mschapv2_hashline(username, auth_challenge, peer_challenge, nt_response)]
    bare = strip_domain(username)
    if bare and bare != username:
        lines.append(mschapv2_hashline(bare, auth_challenge, peer_challenge, nt_response))
    return lines


def plaintext_line(username: str, password: str) -> str:
    """A ``username:password`` line for a GTC / PAP capture (already plaintext, nothing to crack)."""
    return f"{username}:{password}"
