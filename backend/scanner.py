"""
ZapScanner — Async wrapper around the OWASP ZAP API.

Connects to a ZAP daemon container and orchestrates spider → active scan → alert retrieval.
Supports scan modes: quick, fast, deep, stealth — each with different intensity/CPU profiles.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from zapv2 import ZAPv2

logger = logging.getLogger("zscanner.scanner")


class ScanPhase(str, Enum):
    IDLE = "idle"
    SPIDER = "spider"
    ACTIVE_SCAN = "active_scan"
    COMPLETE = "complete"
    STOPPED = "stopped"
    ERROR = "error"


# ---------------------------------------------------------------------------
# Scan mode configurations — controls CPU usage and scan depth
# ---------------------------------------------------------------------------
SCAN_MODE_CONFIG = {
    "quick": {
        "spider_thread_count": 1,
        "spider_max_children": 5,
        "run_active_scan": False,
        "attack_strength": None,
        "alert_threshold": None,
        "description": "Surface-level spider only — headers, cookies, basic misconfig",
    },
    "fast": {
        "spider_thread_count": 3,
        "spider_max_children": 10,
        "run_active_scan": True,
        "attack_strength": "LOW",
        "alert_threshold": "MEDIUM",
        "description": "Standard scan with limited attack depth",
    },
    "deep": {
        "spider_thread_count": 5,
        "spider_max_children": 0,  # 0 = unlimited
        "run_active_scan": True,
        "attack_strength": "HIGH",
        "alert_threshold": "LOW",
        "description": "Comprehensive full-depth vulnerability scan",
    },
    "stealth": {
        "spider_thread_count": 1,
        "spider_max_children": 10,
        "run_active_scan": False,
        "attack_strength": None,
        "alert_threshold": None,
        "description": "Passive only — no active probing, zero noise on target",
    },
}


@dataclass
class ScanStatus:
    """Mutable scan state shared with the API layer."""
    scan_id: str
    target_url: str
    scan_mode: str = "fast"
    phase: ScanPhase = ScanPhase.IDLE
    spider_progress: int = 0
    active_scan_progress: int = 0
    alerts: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None
    started_at: float = field(default_factory=time.time)
    finished_at: float | None = None
    stop_requested: bool = False
    zap_spider_id: str | None = None
    zap_ascan_id: str | None = None
    _last_progress_time: float = field(default_factory=time.time)
    _last_progress_value: int = 0


class ZapScanner:
    """Drives ZAP spider + active scan and collects alerts."""

    POLL_INTERVAL = 1  # seconds between status polls
    STALL_TIMEOUT = 300  # 5 minutes — auto-stop if no progress

    def __init__(self, zap_base_url: str = "http://zap:8080"):
        self._zap = ZAPv2(
            proxies={
                "http": zap_base_url,
                "https": zap_base_url,
            }
        )
        self._base_url = zap_base_url

    # ------------------------------------------------------------------
    # Public entry-point
    # ------------------------------------------------------------------
    async def run_full_scan(self, status: ScanStatus) -> None:
        """Execute the complete scan pipeline, updating *status* in-place."""
        mode_cfg = SCAN_MODE_CONFIG.get(status.scan_mode, SCAN_MODE_CONFIG["fast"])

        try:
            logger.info(
                "Starting %s scan for %s [%s]",
                status.scan_mode,
                status.target_url,
                status.scan_id,
            )

            # Open the target URL in ZAP so it's aware of it
            await self._open_url(status.target_url)

            # Configure spider thread count to manage CPU
            await self._configure_spider(mode_cfg)

            # Phase 1 — Spider
            await self._run_spider(status, mode_cfg)
            if status.stop_requested:
                status.alerts = await self._get_alerts(status.target_url)
                status.phase = ScanPhase.STOPPED
                status.finished_at = time.time()
                logger.info("Scan stopped by user — collected %d partial alerts [%s]", len(status.alerts), status.scan_id)
                return

            # Phase 2 — Active Scan (skip for quick/stealth modes)
            if mode_cfg["run_active_scan"]:
                await self._configure_active_scan(mode_cfg)
                await self._run_active_scan(status)
                if status.stop_requested:
                    status.alerts = await self._get_alerts(status.target_url)
                    status.phase = ScanPhase.STOPPED
                    status.finished_at = time.time()
                    logger.info("Scan stopped by user — collected %d partial alerts [%s]", len(status.alerts), status.scan_id)
                    return
            else:
                status.active_scan_progress = 100
                logger.info(
                    "Skipping active scan for %s mode [%s]",
                    status.scan_mode,
                    status.scan_id,
                )

            # Phase 3 — Collect results
            status.alerts = await self._get_alerts(status.target_url)
            status.phase = ScanPhase.COMPLETE
            status.finished_at = time.time()
            logger.info(
                "Scan complete for %s — %d alerts found [mode=%s]",
                status.target_url,
                len(status.alerts),
                status.scan_mode,
            )

        except Exception as exc:
            logger.exception("Scan failed for %s", status.target_url)
            status.phase = ScanPhase.ERROR
            status.error = str(exc)
            status.finished_at = time.time()

    async def force_stop(self, status: ScanStatus) -> None:
        """Signal the running scan to stop and tell ZAP to abort.

        Sets stop_requested so the poll loops exit on their next iteration.
        The phase transition to STOPPED is handled by run_full_scan after
        it collects partial alerts, ensuring consistent state.
        """
        status.stop_requested = True
        try:
            if status.zap_spider_id:
                await asyncio.to_thread(self._zap.spider.stop, status.zap_spider_id)
                logger.info("Spider force-stopped [%s]", status.scan_id)
        except Exception as exc:
            logger.warning("Error stopping spider: %s", exc)
        try:
            if status.zap_ascan_id:
                await asyncio.to_thread(self._zap.ascan.stop, status.zap_ascan_id)
                logger.info("Active scan force-stopped [%s]", status.scan_id)
        except Exception as exc:
            logger.warning("Error stopping active scan: %s", exc)
        logger.info("Stop requested for scan [%s]", status.scan_id)

    # ------------------------------------------------------------------
    # Configuration helpers
    # ------------------------------------------------------------------
    async def _configure_spider(self, mode_cfg: dict) -> None:
        """Set spider thread count and max children to limit CPU usage."""
        try:
            thread_count = mode_cfg["spider_thread_count"]
            max_children = mode_cfg["spider_max_children"]

            await asyncio.to_thread(
                self._zap.spider.set_option_thread_count, thread_count
            )
            await asyncio.to_thread(
                self._zap.spider.set_option_max_children, max_children
            )
            logger.info(
                "Spider configured: threads=%d, maxChildren=%d",
                thread_count,
                max_children,
            )
        except Exception as exc:
            logger.warning("Failed to configure spider options: %s", exc)

    async def _configure_active_scan(self, mode_cfg: dict) -> None:
        """Set active scan attack strength and alert threshold."""
        try:
            strength = mode_cfg.get("attack_strength")
            threshold = mode_cfg.get("alert_threshold")

            if strength:
                # Set the default attack strength for all scan policies
                await asyncio.to_thread(
                    self._zap.ascan.set_option_default_policy, 0
                )
                # Configure strength for the default scan policy
                policies = await asyncio.to_thread(self._zap.ascan.scanners, "Default Policy")
                if isinstance(policies, list):
                    for scanner in policies:
                        scanner_id = scanner.get("id")
                        if scanner_id:
                            try:
                                await asyncio.to_thread(
                                    self._zap.ascan.set_scanner_attack_strength,
                                    scanner_id,
                                    strength,
                                )
                                if threshold:
                                    await asyncio.to_thread(
                                        self._zap.ascan.set_scanner_alert_threshold,
                                        scanner_id,
                                        threshold,
                                    )
                            except Exception:
                                pass  # Some scanners may not support all settings

                logger.info(
                    "Active scan configured: strength=%s, threshold=%s",
                    strength,
                    threshold,
                )
        except Exception as exc:
            logger.warning("Failed to configure active scan options: %s", exc)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    async def _open_url(self, target_url: str) -> None:
        """Have ZAP access the target URL so it enters the site tree."""
        await asyncio.to_thread(self._zap.urlopen, target_url)
        # Give ZAP a moment to process
        await asyncio.sleep(1)

    async def _run_spider(self, status: ScanStatus, mode_cfg: dict) -> None:
        status.phase = ScanPhase.SPIDER
        status.spider_progress = 0

        zap_id: str = await asyncio.to_thread(
            self._zap.spider.scan, status.target_url
        )

        if not zap_id or not str(zap_id).isdigit():
            raise RuntimeError(f"ZAP spider failed to start — response: {zap_id}")

        status.zap_spider_id = str(zap_id)
        logger.info("Spider started with ZAP scan ID %s", status.zap_spider_id)

        status._last_progress_time = time.time()
        status._last_progress_value = 0

        while True:
            if status.stop_requested:
                logger.info("Stop requested — aborting spider [%s]", status.scan_id)
                try:
                    await asyncio.to_thread(self._zap.spider.stop, status.zap_spider_id)
                except Exception:
                    pass
                return

            progress = int(await asyncio.to_thread(self._zap.spider.status, status.zap_spider_id))
            status.spider_progress = progress
            logger.debug("Spider progress: %d%%", progress)

            # Track stall: auto-stop if no progress for STALL_TIMEOUT
            if progress != status._last_progress_value:
                status._last_progress_value = progress
                status._last_progress_time = time.time()
            elif time.time() - status._last_progress_time > self.STALL_TIMEOUT:
                logger.warning("Spider stalled for %ds — auto-stopping [%s]", self.STALL_TIMEOUT, status.scan_id)
                try:
                    await asyncio.to_thread(self._zap.spider.stop, status.zap_spider_id)
                except Exception:
                    pass
                break

            if progress >= 100:
                break
            await asyncio.sleep(self.POLL_INTERVAL)

        status.spider_progress = 100
        logger.info("Spider completed for %s", status.target_url)

    async def _run_active_scan(self, status: ScanStatus) -> None:
        status.phase = ScanPhase.ACTIVE_SCAN
        status.active_scan_progress = 0

        zap_id: str = await asyncio.to_thread(
            self._zap.ascan.scan, status.target_url
        )

        if not zap_id or not str(zap_id).isdigit():
            raise RuntimeError(
                f"ZAP active scan failed to start — response: {zap_id}"
            )

        status.zap_ascan_id = str(zap_id)
        logger.info("Active scan started with ZAP scan ID %s", status.zap_ascan_id)

        status._last_progress_time = time.time()
        status._last_progress_value = 0

        while True:
            if status.stop_requested:
                logger.info("Stop requested — aborting active scan [%s]", status.scan_id)
                try:
                    await asyncio.to_thread(self._zap.ascan.stop, status.zap_ascan_id)
                except Exception:
                    pass
                return

            progress = int(await asyncio.to_thread(self._zap.ascan.status, status.zap_ascan_id))
            status.active_scan_progress = progress
            logger.debug("Active scan progress: %d%%", progress)

            # Track stall: auto-stop if no progress for STALL_TIMEOUT
            if progress != status._last_progress_value:
                status._last_progress_value = progress
                status._last_progress_time = time.time()
            elif time.time() - status._last_progress_time > self.STALL_TIMEOUT:
                logger.warning("Active scan stalled for %ds — auto-stopping [%s]", self.STALL_TIMEOUT, status.scan_id)
                try:
                    await asyncio.to_thread(self._zap.ascan.stop, status.zap_ascan_id)
                except Exception:
                    pass
                break

            if progress >= 100:
                break
            await asyncio.sleep(self.POLL_INTERVAL)

        status.active_scan_progress = 100
        logger.info("Active scan completed for %s", status.target_url)

    # CWE → OWASP Top 10 (2021) mapping for common vulnerability classes
    _CWE_OWASP_MAP: dict[str, str] = {
        # A01: Broken Access Control
        "285": "A01", "639": "A01", "284": "A01", "352": "A01",
        "22": "A01", "425": "A01", "538": "A01",
        # A02: Cryptographic Failures
        "327": "A02", "328": "A02", "310": "A02", "326": "A02",
        "319": "A02", "311": "A02", "312": "A02", "315": "A02",
        # A03: Injection
        "79": "A03", "89": "A03", "77": "A03", "78": "A03",
        "90": "A03", "91": "A03", "564": "A03", "917": "A03",
        # A04: Insecure Design
        "209": "A04", "256": "A04", "501": "A04",
        # A05: Security Misconfiguration
        "16": "A05", "2": "A05", "215": "A05", "548": "A05",
        "611": "A05",
        # A06: Vulnerable and Outdated Components
        "1104": "A06",
        # A07: Identification and Authentication Failures
        "287": "A07", "384": "A07", "613": "A07", "620": "A07",
        # A08: Software and Data Integrity Failures
        "345": "A08", "353": "A08", "829": "A08", "502": "A08",
        # A09: Security Logging and Monitoring Failures
        "778": "A09", "223": "A09",
        # A10: Server-Side Request Forgery
        "918": "A10",
    }

    _OWASP_NAMES: dict[str, str] = {
        "A01": "Broken Access Control",
        "A02": "Cryptographic Failures",
        "A03": "Injection",
        "A04": "Insecure Design",
        "A05": "Security Misconfiguration",
        "A06": "Vulnerable & Outdated Components",
        "A07": "Auth Failures",
        "A08": "Integrity Failures",
        "A09": "Logging & Monitoring Failures",
        "A10": "SSRF",
    }

    async def _get_alerts(self, target_url: str) -> list[dict[str, Any]]:
        """Retrieve and filter alerts for High / Medium / Low risk levels."""
        raw_alerts: list[dict] = await asyncio.to_thread(
            self._zap.core.alerts, baseurl=target_url, start=0, count=500
        )

        keep_risks = {"High", "Medium", "Low"}
        filtered: list[dict[str, Any]] = []

        for alert in raw_alerts:
            risk = alert.get("risk", "")
            if risk not in keep_risks:
                continue

            cweid = str(alert.get("cweid", ""))
            owasp_code = self._CWE_OWASP_MAP.get(cweid, "")
            owasp_category = self._OWASP_NAMES.get(owasp_code, "") if owasp_code else ""
            cwe_link = f"https://cwe.mitre.org/data/definitions/{cweid}.html" if cweid and cweid != "-1" else ""

            filtered.append(
                {
                    "id": alert.get("id", ""),
                    "name": alert.get("name", "Unknown"),
                    "risk": risk,
                    "confidence": alert.get("confidence", ""),
                    "description": alert.get("description", ""),
                    "url": alert.get("url", ""),
                    "solution": alert.get("solution", ""),
                    "reference": alert.get("reference", ""),
                    "cweid": cweid,
                    "cwe_link": cwe_link,
                    "wascid": alert.get("wascid", ""),
                    "param": alert.get("param", ""),
                    "evidence": alert.get("evidence", ""),
                    "owasp_code": owasp_code,
                    "owasp_category": owasp_category,
                }
            )

        # Sort by severity: High → Medium → Low
        severity_order = {"High": 0, "Medium": 1, "Low": 2}
        filtered.sort(key=lambda a: severity_order.get(a["risk"], 99))
        return filtered
