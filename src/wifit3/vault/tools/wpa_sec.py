"""wpa-sec vault tool: submit a capture's handshake pcap to wpa-sec.stanev.org and watch the
distributed auditor's results for this AP's PSK.

Unlike the local crackers, wpa-sec needs the raw pcap (not the .hc22000), so a job can only run when
a handshake pcap exists for the AP (``Config.save_pcap`` must have been on at capture time). The
work is server-side and global, so the tool is ADOPTABLE (a relaunched wifit3 resumes polling) and
every job shares one throttled fetch of the key's potfile.
"""
from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from wifit3.crack.hc22000_format import Hc22000Line
from wifit3.crack.handshake import mac_compact
from wifit3.models import PersistedCapture, ToolCapability, ToolResult, ToolStatus
from wifit3.models.jobs import JobAction, JobState, ToolName
from wifit3.persist.common import bssid_to_dashed
from wifit3.persist.config import Config
from wifit3.vault.tools.base import VaultTool, require_hashlines
from wifit3.vault.tools.wpa_sec_api import WpaSecClient, WpaSecError, WpaSecUnreachable, WpaSecResult

logger = logging.getLogger(__name__)

POLL_SECONDS = 300.0            # wpa-sec cracking is distributed and slow; poll the potfile gently
_RESULTS_TTL = 120.0           # one potfile fetch serves every job polling within this window
_CRACKABLE_KINDS = ("01", "02")   # WPA*01 (PMKID) / WPA*02 (EAPOL): what wpa-sec cracks


@dataclass
class _Run:
    bssid: str
    pcap: Optional[Path]
    result: ToolResult = field(default_factory=lambda: ToolResult(
        status=ToolStatus.RUNNING, value="Submitting to wpa-sec…", actions=JobAction.STOP))
    stop_requested: threading.Event = field(default_factory=threading.Event)
    submitted: bool = False
    thread: threading.Thread = field(init=False)


class WpaSecTool(VaultTool):
    name = ToolName.WPA_SEC
    label = "wpa-sec"
    description = "Submit the handshake pcap to wpa-sec.stanev.org (distributed WPA/PMKID auditor)"
    # ADOPTABLE: the crack happens on wpa-sec's volunteers, so a relaunched wifit3 resumes polling.
    capabilities = ToolCapability.ADOPTABLE

    def __init__(self) -> None:
        self._runs: Dict[str, _Run] = {}
        self._cache_lock = threading.Lock()
        self._cached_results: list[WpaSecResult] = []
        self._cached_at = 0.0

    def can_crack(self, lines: Sequence[Hc22000Line]) -> bool:
        return any(line.kind in _CRACKABLE_KINDS for line in lines)

    def auto_crack_config(self) -> Optional[dict[str, Any]]:
        return {} if Config.wpa_sec.key else None

    def launch(self, job: JobState, capture: PersistedCapture) -> None:
        if not Config.wpa_sec.key:
            raise ValueError("wpa-sec API key is not set (Vault → wpa-sec)")
        pcap = self._handshake_pcap(capture.bssid)
        if pcap is None:
            raise ValueError("No handshake pcap for this AP; enable 'Save pcap' before capturing")
        job.tool_state["bssid"] = capture.bssid
        job.api_id = "wpa-sec"                       # marks the job adoptable across restarts
        self._spawn(job, _Run(bssid=capture.bssid, pcap=pcap))

    def poll_status(self, job: JobState, assume_dead: bool = False) -> ToolResult:
        run = self._runs.get(job.job_id)
        if run is None:
            bssid = job.tool_state.get("bssid") or self._bssid_from_hashlines(job)
            if not bssid:
                return ToolResult(status=ToolStatus.ERROR,
                                  value="wpa-sec job lost its AP before it finished")
            run = _Run(bssid=bssid, pcap=None, submitted=True)      # already uploaded; just poll
            run.result = ToolResult(status=ToolStatus.RUNNING, value="Reconnecting to wpa-sec…",
                                    actions=JobAction.STOP)
            self._spawn(job, run)
        result = run.result
        if result.status != ToolStatus.RUNNING:
            self._runs.pop(job.job_id, None)
        return result

    def apply(self, action: JobAction, job: JobState) -> bool:
        run = self._runs.get(job.job_id)
        if action is not JobAction.STOP or run is None or not run.thread.is_alive():
            return False
        run.stop_requested.set()
        return True

    # ----- worker ------------------------------------------------------------

    def _spawn(self, job: JobState, run: _Run) -> None:
        run.thread = threading.Thread(target=self._work, args=(run,), daemon=True,
                                      name=f"wpa-sec {job.job_id}")
        self._runs[job.job_id] = run
        run.thread.start()

    def _work(self, run: _Run) -> None:
        try:
            client = WpaSecClient(Config.wpa_sec.url, str(Config.wpa_sec.key))
            if not run.submitted and run.pcap is not None:
                try:
                    submit = client.submit(run.pcap)
                except WpaSecUnreachable as e:
                    run.result = ToolResult(status=ToolStatus.RUNNING, value=str(e),
                                            actions=JobAction.STOP)
                    run.stop_requested.wait(POLL_SECONDS)
                else:
                    run.submitted = True
                    note = "Already on wpa-sec" if submit.already else "Submitted to wpa-sec"
                    run.result = ToolResult(status=ToolStatus.RUNNING,
                                            value=f"{note}; waiting for a crack",
                                            actions=JobAction.STOP)
            while not run.stop_requested.is_set():
                run.result = self._poll_results(client, run.bssid)
                if run.result.status != ToolStatus.RUNNING:
                    return
                run.stop_requested.wait(POLL_SECONDS)
            run.result = ToolResult(status=ToolStatus.STOPPED, value="Stopped polling wpa-sec")
        except WpaSecError as e:
            run.result = ToolResult(status=ToolStatus.ERROR, value=str(e))
        except Exception as e:                       # noqa: BLE001 - surface any fault as job error
            logger.exception("wpa-sec job failed")
            run.result = ToolResult(status=ToolStatus.ERROR, value=str(e))

    def _poll_results(self, client: WpaSecClient, bssid: str) -> ToolResult:
        try:
            results = self._results(client)
        except WpaSecUnreachable as e:
            return ToolResult(status=ToolStatus.RUNNING, value=str(e), actions=JobAction.STOP)
        wanted = mac_compact(bssid)
        keys = tuple(dict.fromkeys(r.psk for r in results if r.bssid == wanted))
        if keys:
            return ToolResult(status=ToolStatus.SUCCESS, value=f"Cracked! Key: {', '.join(keys)}",
                              percent=100.0, keys=keys)
        return ToolResult(status=ToolStatus.RUNNING, value="On wpa-sec; waiting for a crack",
                          detail="distributed", actions=JobAction.STOP)

    def _results(self, client: WpaSecClient) -> list[WpaSecResult]:
        """The key's potfile, fetched at most once per ``_RESULTS_TTL`` across all jobs."""
        with self._cache_lock:
            if time.monotonic() - self._cached_at < _RESULTS_TTL:
                return self._cached_results
        fetched = client.results()
        with self._cache_lock:
            self._cached_results = fetched
            self._cached_at = time.monotonic()
        return fetched

    @staticmethod
    def _handshake_pcap(bssid: str) -> Optional[Path]:
        """The newest ``*_<bssid>_*.pcap`` under captures/, or None when pcap saving was off."""
        captures = Path(Config.captures_dir)
        if not captures.is_dir():
            return None
        dashed = bssid_to_dashed(bssid)
        pcaps = [p for p in captures.glob("*.pcap") if dashed in p.name.lower()]
        return max(pcaps, key=lambda p: p.stat().st_mtime) if pcaps else None

    @staticmethod
    def _bssid_from_hashlines(job: JobState) -> Optional[str]:
        try:
            lines = require_hashlines(job.hashlines_path)
        except ValueError:
            return None
        return next((line.bssid for _, line in lines if line.bssid), None)
