# eviltwin_enterprise/

A rogue 802.1X authenticator (PEAP / EAP-TTLS) that harvests EAP identities and MSCHAPv2 / GTC / PAP
credentials from WPA-Enterprise clients — the eaphammer / hostapd-wpe idea, native to wifit3 (no
hostapd, no RADIUS, no subprocess). Authorized assessments and teaching only.

## The point of the demo: a *valid* certificate is not safety

During PEAP / EAP-TTLS the server presents a TLS certificate. Whether a supplicant is safe depends
entirely on **how** it validates that certificate:

| Supplicant configuration | Outcome against this twin |
|---|---|
| Pins the exact enterprise CA **and** the server name | Refuses every twin — the only real defence |
| Trusts any publicly-valid CA, or matches the name loosely (suffix/wildcard, or no name check) | **Accepts a valid certificate the attacker legitimately holds for a look-alike domain** |
| Validates nothing, or prompts the user who taps "trust" | Accepts even the bundled self-signed cert |

The middle row is the lesson: "the certificate is valid / the padlock is green" proves a CA signed
it — **not** that this is the network you meant to join.

## Typosquatting demo (valid, attacker-owned certificate)

1. Register a look-alike domain you control — e.g. `radius.acme-login.com` against the real
   `radius.acme.com`. It is genuinely yours, so a public CA will issue for it.
2. Get a real certificate for it, e.g. with Certbot:
   `certbot certonly -d radius.acme-login.com`
3. Concatenate the **full chain** (leaf + intermediates) and the private key into one PEM:
   `cat /etc/letsencrypt/live/radius.acme-login.com/fullchain.pem \`
   `    /etc/letsencrypt/live/radius.acme-login.com/privkey.pem > twin.pem`
   (Use `fullchain.pem`, not `cert.pem`, so the chain verifies on the victim.)
4. In wifit3: Focus a WPA-Enterprise AP → **Enterprise Twin** → set **Server certificate PEM** to
   `twin.pem` (remembered in `Config.eviltwin_cert_path`). Leave it blank to present the bundled
   self-signed cert instead.
5. Start the twin. A victim whose supplicant trusts public CAs (or matches the name loosely)
   validates the **valid** certificate, completes the PEAP handshake, and its credential is captured
   to `captures/` (`*_enterprise.hc5500` for MSCHAPv2, `*_enterprise_plain.txt` for GTC/PAP,
   `*_eap_identities.txt` for identities).
6. The Focus log prints the presented certificate, e.g.
   `Presenting certificate: CN=radius.acme-login.com (CA-signed by R11), valid until …` — visibly
   valid, yet it is the attacker's.

## The defence to teach alongside it

Pin the **specific** CA (not "any trusted root") and the **exact** RADIUS server name in the
supplicant profile; disable "ask the user". Best of all, EAP-TLS with client certificates removes
the password the twin is trying to steal. A valid server certificate is necessary, never sufficient.

## Layout

- `campaign.py` — `EnterpriseEvilTwinCampaign` + `EnterpriseEvilTwinInput` (host/BSSID/method/GTC/cert).
- `fake_ap.py` — beacon + probe/auth/assoc responder, relays EAPOL-EAP to a per-client `EapServer`.
- `eap_server.py` — the EAP state machine: identity, TLS tunnel, inner MSCHAPv2 / GTC / PAP capture.
- `tls.py` — the memory-BIO TLS tunnel, cert loading (`server_context`), and `describe_cert`.
- `store.py` — writes captures under `captures/`, deduped.
- `assets/eap_server.pem` — the bundled self-signed default certificate (replaceable, see above).
