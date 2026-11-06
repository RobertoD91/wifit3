"""EAP / EAPOL-EAP builders and parsers."""
from wifit3.dot11.eap import EAP_REQUEST, EAP_RESPONSE, EAP_SUCCESS
from wifit3.dot11.eap_build import (
    EAP_TYPE_IDENTITY, EAP_TYPE_PEAP, TLS_FLAG_LENGTH, TLS_FLAG_MORE, TLS_FLAG_START,
    eap_from_frame, eap_packet, eap_request_identity, eap_success, eap_tls_body,
    eapol_eap_frame, is_eapol_start, parse_eap, parse_eap_tls_body,
)


def test_eap_packet_round_trip():
    pkt = eap_packet(EAP_RESPONSE, 7, EAP_TYPE_IDENTITY, b"alice")
    msg = parse_eap(pkt)
    assert msg.code == EAP_RESPONSE and msg.identifier == 7
    assert msg.method_type == EAP_TYPE_IDENTITY and msg.data == b"alice"


def test_eap_success_has_no_type():
    msg = parse_eap(eap_success(3))
    assert msg.code == EAP_SUCCESS and msg.method_type is None and msg.data == b""


def test_parse_eap_rejects_truncated_and_overlong():
    assert parse_eap(b"\x01\x01") is None
    assert parse_eap(b"\x01\x01\x00\xff") is None            # length 255 > payload


def test_eap_tls_body_round_trip_with_length_and_more():
    body = eap_tls_body(EAP_TYPE_PEAP, b"\xaa\xbb", start=True, more=True, total_length=2)
    assert body[0] == EAP_TYPE_PEAP
    parsed = parse_eap_tls_body(body[1:])
    assert parsed.flags & TLS_FLAG_START and parsed.flags & TLS_FLAG_MORE
    assert parsed.flags & TLS_FLAG_LENGTH and parsed.total_length == 2
    assert parsed.tls_data == b"\xaa\xbb"
    assert parsed.start and parsed.more


def test_eap_tls_body_without_length():
    parsed = parse_eap_tls_body(eap_tls_body(EAP_TYPE_PEAP, b"\x01")[1:])
    assert parsed.total_length is None and parsed.tls_data == b"\x01"


def test_eapol_eap_frame_round_trip():
    bssid = bytes.fromhex("9483c48c3f78")
    client = bytes.fromhex("02aabbccddee")
    eap = eap_request_identity(1)
    frame = eapol_eap_frame(bssid, client, eap)
    # AP->STA: addr1 = client, addr2/3 = bssid
    assert frame[4:10] == client and frame[10:16] == bssid
    msg = eap_from_frame(frame)
    assert msg.code == EAP_REQUEST and msg.method_type == EAP_TYPE_IDENTITY
    assert not is_eapol_start(frame)


def test_is_eapol_start_detects_type_1():
    from wifit3.dot11.eapol import LLC_SNAP_EAPOL, data_header
    frame = data_header(to_ds=True, bssid=bytes(6), client=bytes(6)) + LLC_SNAP_EAPOL + b"\x02\x01\x00\x00"
    assert is_eapol_start(frame)
    assert eap_from_frame(frame) is None                     # not an EAP (type 0) frame
