"""wpa-sec.stanev.org client (the RealEnder/dwpa distributed WPA auditor).

Upload is ``POST <url>`` as multipart/form-data with the capture in a ``file`` field and the
per-user API key in a ``key`` cookie; results are ``GET <url>/?api&dl=1`` with the same cookie,
returning a potfile of ``bssid:station:essid:psk`` lines. Only ``urllib`` (no third-party deps).
"""
from __future__ import annotations

import logging
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

TIMEOUT_SECONDS = 30.0
_RESULTS_QUERY = "?api&dl=1"
_ALREADY = "already submitted"


class WpaSecError(Exception):
    """wpa-sec refused the request; the message is as specific as the server allowed."""


class WpaSecUnreachable(WpaSecError):
    """No answer from wpa-sec, or an answer that isn't the expected API."""


@dataclass(frozen=True)
class WpaSecResult:
    """One cracked line of the potfile. ``bssid``/``station`` are compact lowercase MACs."""
    bssid: str
    station: str
    essid: str
    psk: str


@dataclass(frozen=True)
class SubmitResult:
    accepted: bool            # the server took the file (new upload)
    already: bool             # the server had already seen this capture
    message: str              # the server's own response text, trimmed


class WpaSecClient:
    def __init__(self, url: str, key: str) -> None:
        self.url = url.rstrip("/")
        self.key = key

    def submit(self, pcap_path: Path) -> SubmitResult:
        """Upload one pcap. Raises WpaSecUnreachable on a network failure, WpaSecError on a
        refusal; a capture the server already holds returns ``already=True``, not an error."""
        data = Path(pcap_path).read_bytes()
        body, content_type = _multipart_file("file", Path(pcap_path).name, data)
        request = urllib.request.Request(self.url, data=body, method="POST",
                                         headers={"Content-Type": content_type,
                                                  "Cookie": f"key={self.key}"})
        text = self._read(request)
        lower = text.lower()
        already = _ALREADY in lower
        accepted = not already and ("error" not in lower or not text)
        return SubmitResult(accepted=accepted, already=already, message=text)

    def results(self) -> list[WpaSecResult]:
        """Every cracked line tied to this key. Empty when nothing is cracked yet."""
        request = urllib.request.Request(self.url + "/" + _RESULTS_QUERY, method="GET",
                                         headers={"Cookie": f"key={self.key}"})
        return _parse_potfile(self._read(request))

    def _read(self, request: urllib.request.Request) -> str:
        try:
            with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
                return response.read().decode("utf-8", errors="replace").strip()
        except urllib.error.HTTPError as e:
            raise WpaSecUnreachable(f"HTTP {e.code} from {self.url}") from None
        except urllib.error.URLError as e:
            raise WpaSecUnreachable(f"Cannot reach {self.url}: {e.reason}") from None
        except OSError as e:
            raise WpaSecUnreachable(f"Cannot reach {self.url}: {e}") from None


def _multipart_file(field: str, filename: str, payload: bytes) -> tuple[bytes, str]:
    """A one-field multipart/form-data body + its Content-Type. The boundary is random so it can
    never collide with the pcap bytes."""
    boundary = "----wifit3-" + os.urandom(16).hex()
    head = (f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="{field}"; filename="{filename}"\r\n'
            f"Content-Type: application/octet-stream\r\n\r\n").encode("utf-8")
    tail = f"\r\n--{boundary}--\r\n".encode("utf-8")
    return head + payload + tail, f"multipart/form-data; boundary={boundary}"


def _parse_potfile(text: str) -> list[WpaSecResult]:
    """Parse ``bssid:station:essid:psk`` lines. The ESSID and PSK can contain ``:``, so the BSSID
    and station (fixed 12-hex MACs) are split off the front and the PSK off the back."""
    results: list[WpaSecResult] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.count(":") < 3:
            continue
        bssid, station, rest = line.split(":", 2)
        essid, _, psk = rest.rpartition(":")
        bssid, station = bssid.strip().lower(), station.strip().lower()
        if len(bssid) != 12 or not psk:
            continue
        results.append(WpaSecResult(bssid=bssid, station=station, essid=essid, psk=psk))
    return results
