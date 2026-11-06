"""Persist harvested enterprise credentials under captures/, deduped, one file per kind.

MSCHAPv2 lands in a ``*_enterprise.hc5500`` (hashcat -m 5500); GTC/PAP plaintext in
``*_enterprise_plain.txt``; bare identities in ``*_eap_identities.txt``.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from wifit3.campaigns.eviltwin_enterprise.eap_server import Capture
from wifit3.crack.netntlm_format import plaintext_line
from wifit3.persist.common import safe_ssid
from wifit3.persist.config import Config

logger = logging.getLogger(__name__)


def capture_line(cap: Capture) -> str:
    """The on-disk line for a capture: the hashcat -m 5500 line, a ``user:pass`` line, or the
    bare identity username."""
    if cap.hashline:
        return cap.hashline
    if cap.password is not None:
        return plaintext_line(cap.username, cap.password)
    return cap.username


def _suffix(cap: Capture) -> str:
    if cap.hashline:
        return "_enterprise.hc5500"
    if cap.password is not None:
        return "_enterprise_plain.txt"
    return "_eap_identities.txt"


def save_capture(cap: Capture, captures_dir: Optional[Path] = None) -> Optional[Path]:
    """Append the capture's line to its file if not already present; return the file (None on
    error or an empty username)."""
    if not cap.username:
        return None
    directory = Path(captures_dir) if captures_dir is not None else Path(Config.captures_dir)
    path = directory / f"{safe_ssid(cap.ssid)}{_suffix(cap)}"
    line = capture_line(cap)
    try:
        directory.mkdir(parents=True, exist_ok=True)
        if path.exists() and line in path.read_text("utf-8", errors="replace").splitlines():
            return path
        with path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(line + "\n")
    except OSError:
        logger.exception("failed to save enterprise capture to %s", path)
        return None
    return path
