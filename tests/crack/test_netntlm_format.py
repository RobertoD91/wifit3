"""MSCHAPv2 -> hashcat -m 5500 line + plaintext formatting."""
import hashlib

import pytest

from wifit3.crack.netntlm_format import (
    mschapv2_challenge_hash, mschapv2_hashline, plaintext_line,
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


def test_plaintext_line():
    assert plaintext_line("bob", "hunter2") == "bob:hunter2"
