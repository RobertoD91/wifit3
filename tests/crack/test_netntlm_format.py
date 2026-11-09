"""MSCHAPv2 -> hashcat -m 5500 line + plaintext formatting."""
import hashlib

import pytest

from wifit3.crack.netntlm_format import (
    mschapv2_challenge_hash, mschapv2_hashline, mschapv2_hashlines, plaintext_line, strip_domain,
)


def test_challenge_hash_matches_rfc_2759():
    peer = bytes(range(16))
    auth = bytes(range(16, 32))
    expected = hashlib.sha1(peer + auth + b"alice").digest()[:8]
    assert mschapv2_challenge_hash(peer, auth, "alice") == expected


def test_hashline_shape_is_mode_5500():
    auth = bytes(16)
    peer = bytes(range(16))
    nt = bytes(range(24))
    line = mschapv2_hashline("alice", auth, peer, nt)
    fields = line.split(":")
    assert fields[0] == "alice"
    assert fields[1] == "" and fields[2] == "" and fields[3] == ""     # empty domain + LM
    assert fields[4] == nt.hex() and len(fields[4]) == 48
    assert len(fields[5]) == 16                                        # 8-byte challenge hash


def test_hashline_rejects_bad_nt_length():
    with pytest.raises(ValueError):
        mschapv2_hashline("x", bytes(16), bytes(16), b"short")


def test_each_hashline_challenge_is_keyed_to_its_own_username():
    # The property a -m 5500 cracker relies on: the challenge field must be SHA1(peer|auth|name)[:8]
    # for the SAME name that labels the line, or the NT-response never matches and the hash is
    # uncrackable. A domain-qualified name emits a qualified and a stripped line; each must hold the
    # challenge for its own name.
    peer, auth, nt = bytes(range(16)), bytes(range(16, 32)), bytes(range(100, 124))
    lines = mschapv2_hashlines("CORP\\alice", auth, peer, nt)
    assert {line.split(":")[0] for line in lines} == {"CORP\\alice", "alice"}
    for line in lines:
        name, _lm_user, _dom, _lm, nt_hex, chal_hex = line.split(":")
        assert nt_hex == nt.hex()
        assert bytes.fromhex(chal_hex) == mschapv2_challenge_hash(peer, auth, name)


def test_plain_username_emits_a_single_line():
    assert len(mschapv2_hashlines("alice", bytes(16), bytes(range(16)), bytes(range(24)))) == 1


def test_strip_domain():
    assert strip_domain("CORP\\alice") == "alice"
    assert strip_domain("alice@corp.example") == "alice"
    assert strip_domain("alice") == "alice"


def test_plaintext_line():
    assert plaintext_line("bob", "hunter2") == "bob:hunter2"
