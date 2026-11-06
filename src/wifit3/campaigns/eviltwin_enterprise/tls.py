"""TLS tunnel for the PEAP / EAP-TTLS phase, driven over memory BIOs (no sockets).

The rogue authenticator presents a bundled self-signed certificate. A supplicant that validates its
server certificate will refuse the tunnel (that is the defence); a misconfigured one that accepts any
certificate completes it, and the inner MSCHAPv2 / GTC / PAP exchange is then captured. Old ciphers
and TLS versions are allowed on purpose, since real supplicants still offer them.
"""
from __future__ import annotations

import logging
import ssl
import warnings
from pathlib import Path

logger = logging.getLogger(__name__)

CERT_PATH = Path(__file__).parent / "assets" / "eap_server.pem"


def server_context() -> ssl.SSLContext:
    """A permissive TLS server context using the bundled rogue certificate."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(CERT_PATH))
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
