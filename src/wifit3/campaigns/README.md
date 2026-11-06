# campaigns/

Attack implementations. Each takes a `WlanInterface` and a target from `models/`
(`AccessPoint` / `Client`) and runs natively on the interface primitives (no
`aircrack-ng` / `reaver` / `hcxdumptool` subprocess).

What lives here:
- `campaign.py`: the radio-owning `Campaign` base every attack subclasses.
- `pmkid.py`: PMKID capture (passive and active).
- `auto_attack.py`: the wifite2-style driver that walks every AP and runs the fitting campaign,
  skipping an SSID exclusion list and every WPA-Enterprise network (not a `Campaign`: it serialises
  real campaigns on the `Campaign.active` mutex).
- `eviltwin/`: WPA2 twin that punts clients off a WPA3-transition AP to capture a crackable 4-way.
- `eviltwin_enterprise/`: rogue 802.1X authenticator (PEAP / EAP-TTLS, MSCHAPv2 + GTC downgrade)
  that harvests EAP identities and credentials from WPA-Enterprise clients.
- `decloak.py`: hidden-SSID reveal.
- `pin.py` / `pbc.py`: WPS PIN brute-force (Registrar) and PBC capture (Enrollee).
- `wep/`: the WEP campaign (fake-auth, ARP replay, ChopChop). See [`wep/README.md`](wep/README.md).
- `wps/`: the WSC machinery the PIN/PBC campaigns drive. See [`wps/README.md`](wps/README.md).

The attacks build on `WlanInterface` primitives: `send_no_wait` / `send_until_ack`
inject a raw 802.11 frame, `deauth_broadcast` / `deauth_client` send a no-ACK deauth
burst, and `register_rx_callback(cb)` gives a low-latency RX feed that bypasses the
UI-polled AP registry (how the WEP/WPS state machines run).

Active TX is passive by default, behind explicit Focus actions.
