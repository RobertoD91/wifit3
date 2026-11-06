"""EAP-MSCHAPv2 challenge build + response parse."""
import struct

from wifit3.dot11.mschapv2 import OPCODE_CHALLENGE, challenge_request_data, parse_response


def test_challenge_request_layout():
    auth = bytes(range(16))
    data = challenge_request_data(5, auth, name=b"srv")
    assert data[0] == OPCODE_CHALLENGE and data[1] == 5
    assert data[4] == 16 and data[5:21] == auth and data[21:] == b"srv"


def _response(ms_id, peer, nt, name):
    value = peer + b"\x00" * 8 + nt + b"\x00"
    return struct.pack(">BBH", 2, ms_id, 4 + 1 + 49 + len(name)) + bytes([49]) + value + name


def test_parse_response_extracts_peer_challenge_nt_and_name():
    peer = bytes(range(16))
    nt = bytes(range(50, 74))
    resp = parse_response(_response(9, peer, nt, b"corp\\bob"))
    assert resp.ms_id == 9 and resp.peer_challenge == peer
    assert resp.nt_response == nt and resp.name == "corp\\bob"


def test_parse_response_rejects_wrong_opcode_or_size():
    assert parse_response(b"\x01\x01\x00\x05\x10") is None    # opcode 1 (challenge, not response)
    assert parse_response(struct.pack(">BBH", 2, 1, 6) + bytes([48])) is None   # value-size != 49
