"""
Shared timeout management for Guacamole sessions.
Handles idle timeout detection and CAPE agent API integration.
"""
import asyncio
import logging
import time
import urllib.parse
import urllib.request
from typing import Any, cast

from lib.cuckoo.common.config import Config

# Try to import aiohttp, fall back to urllib if not available
try:
    import aiohttp

    HAS_AIOHTTP = True
except ImportError:
    aiohttp = None
    HAS_AIOHTTP = False

logger = logging.getLogger("guac-timeout")
web_cfg = Config("web")


class SessionTimeoutManager:
    """Manages idle timeout detection and CAPE agent communication for Guacamole sessions."""

    def __init__(self, vm_ip: str, user: str, session_id: str = "unknown"):
        self.vm_ip = vm_ip or "unknown"
        self.user = user or "unknown_user"
        self.session_id = session_id or "unknown_session"
        self.last_activity = self._current_time_ms()
        self.is_active = True

        try:
            self.idle_timeout_ms = max(int(getattr(web_cfg.guacamole, "idle_timeout_ms", 0)), 0)
            if self.idle_timeout_ms > 0:
                self.activity_check_interval = max(int(getattr(web_cfg.guacamole, "activity_check_interval", 30)), 1)
            else:
                self.activity_check_interval = None
        except (AttributeError, TypeError, ValueError):
            self.idle_timeout_ms = 0
            self.activity_check_interval = None

        if self.idle_timeout_ms > 0:
            logger.info(
                "Timeout manager created: %s@%s (%sms timeout)",
                self.user,
                self.vm_ip,
                self.idle_timeout_ms,
            )
        else:
            logger.info("Timeout manager created with idle timeout disabled for %s@%s", self.user, self.vm_ip)

    def _current_time_ms(self) -> int:
        """Get current time in milliseconds."""
        return int(time.time() * 1000)

    def update_activity(self) -> None:
        """Update the last activity timestamp."""
        self.last_activity = self._current_time_ms()

    def get_idle_time_ms(self) -> int:
        """Get how long the session has been idle in milliseconds."""
        return self._current_time_ms() - self.last_activity

    def is_timed_out(self) -> bool:
        """Check if the session has exceeded the idle timeout."""
        return self.idle_timeout_ms > 0 and self.get_idle_time_ms() > self.idle_timeout_ms

    async def complete_analysis(self) -> bool:
        """
        Mark the analysis as complete via CAPE agent API.
        Returns True if successful, False otherwise.
        """
        if not self.vm_ip or self.vm_ip == "unknown":
            logger.error("No valid VM IP provided, cannot complete analysis")
            return False

        url = f"http://{self.vm_ip}:8000/status"
        data = {"status": "complete"}

        try:
            if HAS_AIOHTTP:
                return await self._complete_analysis_aiohttp(url, data)
            return await self._complete_analysis_urllib(url, data)
        except Exception as e:
            logger.error("Unexpected error completing analysis for %s: %s", self.vm_ip, e)
            return False

    async def _complete_analysis_aiohttp(self, url: str, data: dict) -> bool:
        """Complete analysis using aiohttp (preferred method)."""
        if aiohttp is None:
            return False

        aiohttp_client = cast(Any, aiohttp)
        timeout = aiohttp_client.ClientTimeout(total=10)
        async with aiohttp_client.ClientSession(timeout=timeout) as session:
            async with session.post(url, data=data) as response:
                logger.info("Analysis marked complete for %s (HTTP %s)", self.vm_ip, response.status)
                return response.status == 200

    async def _complete_analysis_urllib(self, url: str, data: dict) -> bool:
        """Complete analysis using urllib (fallback method)."""

        def _sync_request():
            try:
                data_encoded = urllib.parse.urlencode(data).encode("utf-8")
                req = urllib.request.Request(url, data=data_encoded, method="POST")
                req.add_header("Content-Type", "application/x-www-form-urlencoded")

                with urllib.request.urlopen(req, timeout=10) as response:
                    status_code = response.getcode()
                    logger.info("Analysis marked complete for %s (HTTP %s)", self.vm_ip, status_code)
                    return status_code == 200
            except Exception as e:
                logger.error("Failed to complete analysis for %s: %s", self.vm_ip, e)
                return False

        return await asyncio.to_thread(_sync_request)

    def set_inactive(self) -> None:
        """Mark the session as inactive (used during cleanup)."""
        self.is_active = False
