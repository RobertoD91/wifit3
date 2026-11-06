"""TLS tunnel for the PEAP / EAP-TTLS phase, driven over memory BIOs (no sockets).

The rogue authenticator presents whatever certificate the operator supplies (bundled self-signed by
default). Who completes the tunnel depends on how the supplicant validates:
  - pins the exact enterprise CA + server name  -> refuses any twin (the only real defence)
  - trusts any publicly-valid CA / matches the name loosely -> accepts a *valid* certificate the
    attacker legitimately holds for a look-alike (typosquat) domain, e.g. one minted with Certbot
  - validates nothing / asks the user, who clicks trust -> accepts even the self-signed cert
Once the tunnel completes, the inner MSCHAPv2 / GTC / PAP exchange is captured. The whole point of
the demo: a *valid* certificate proves the CA signed it, not that it is the network you meant to
join. Old ciphers and TLS versions are allowed on purpose, since real supplicants still offer them.
"""
from __future__ import annotations

import logging
import ssl
import warnings
from pathlib import Path

logger = logging.getLogger(__name__)

CERT_PATH = Path(__file__).parent / "assets" / "eap_server.pem"


def describe_cert(cert_path: str | None = None) -> str:
    """A short, human-readable line about the certificate the twin will present: CN, whether it is
    self-signed or CA-signed (and by whom), and its expiry. Best-effort; used only for the demo log.

    For the typosquat demo this makes the point visible: a Certbot-issued cert for a look-alike
    domain shows as CA-signed and valid, yet it is the attacker's."""
    path = cert_path or str(CERT_PATH)
    try:
        info = ssl._ssl._test_decode_cert(path)        # stable across CPython; CPython's own tests use it
        subject = dict(part[0] for part in info.get("subject", ()))
        issuer = dict(part[0] for part in info.get("issuer", ()))
        cn = subject.get("commonName") or subject.get("organizationName") or "?"
        if subject == issuer:
            trust = "self-signed"
        else:
            trust = "CA-signed by " + (issuer.get("commonName") or issuer.get("organizationName") or "?")
        return f"CN={cn} ({trust}), valid until {info.get('notAfter', '?')}"
    except Exception:                                   # noqa: BLE001 - a demo log must never break the twin
        return "custom certificate" if cert_path else "bundled self-signed certificate"


def server_context(cert_path: str | None = None) -> ssl.SSLContext:
    """A permissive TLS server context. ``cert_path`` is a PEM holding the certificate (chain) and
    its private key; None uses the bundled self-signed rogue certificate. Bring your own (e.g. one
    minted with Certbot, or cloned to mimic the target's RADIUS CA) by pointing here."""
    path = cert_path or str(CERT_PATH)
    if cert_path and not Path(cert_path).is_file():
        raise ValueError(f"EAP server certificate not found: {cert_path}")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(path)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    _relax(ctx)
    return ctx


def _relax(ctx: ssl.SSLContext) -> None:
    """Allow old ciphers/versions real supplicants still offer, and pin the classic TLS 1.0-1.2
    EAP-TLS flow (TLS 1.3's 1-RTT flights do not map onto the PEAP message exchange)."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)   # old TLS versions are deprecated but wanted
        for step in (
            lambda c: setattr(c, "minimum_version", ssl.TLSVersion.TLSv1),
            lambda c: setattr(c, "maximum_version", ssl.TLSVersion.TLSv1_2),
            lambda c: c.set_ciphers("ALL:@SECLEVEL=0"),
        ):
            try:
                step(ctx)
            except (ssl.SSLError, ValueError):
                logger.debug("could not relax TLS context", exc_info=True)


class TlsTunnel:
    """One side of a memory-BIO TLS session. ``feed`` pushes received ciphertext in; ``pump_handshake``
    and ``write_app`` return ciphertext to send out; ``read_app`` returns decrypted plaintext."""

    def __init__(self, context: ssl.SSLContext, *, server_side: bool = True,
                 server_hostname: str | None = None) -> None:
        self._incoming = ssl.MemoryBIO()
        self._outgoing = ssl.MemoryBIO()
        self._obj = context.wrap_bio(self._incoming, self._outgoing, server_side=server_side,
                                     server_hostname=None if server_side else server_hostname)
        self.handshake_done = False

    def feed(self, data: bytes) -> None:
        if data:
            self._incoming.write(data)

    def pump_handshake(self) -> bytes:
        """Advance the handshake with whatever has been fed, returning ciphertext to send."""
        if not self.handshake_done:
            try:
                self._obj.do_handshake()
                self.handshake_done = True
            except ssl.SSLWantReadError:
                pass
        return self._outgoing.read()

    def write_app(self, plaintext: bytes) -> bytes:
        """Encrypt ``plaintext``; return the ciphertext to send."""
        self._obj.write(plaintext)
        return self._outgoing.read()

    def read_app(self) -> bytes:
        """Decrypt and return all currently available plaintext."""
        chunks = []
        while True:
            try:
                chunk = self._obj.read()
            except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                break
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)


def client_context() -> ssl.SSLContext:
    """A non-validating client context, for tests that stand in for a misconfigured supplicant."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    _relax(ctx)
    return ctx
