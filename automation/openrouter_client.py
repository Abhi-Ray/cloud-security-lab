"""OpenRouter API client for AI-assisted code generation.

Provides an OpenAI-compatible chat completion interface that talks to
the OpenRouter service.  Includes daily rate-limit tracking persisted
in a local JSON file and graceful degradation when no API key is
configured.
"""

from __future__ import annotations

import json
import logging
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

import httpx

from automation.config import AgentConfig

__all__ = ["OpenRouterClient", "RateLimitExceeded", "APINotConfigured"]

logger = logging.getLogger(__name__)


class RateLimitExceeded(Exception):
    """Raised when the daily API call budget has been exhausted."""


class APINotConfigured(Exception):
    """Raised when the OpenRouter API key is not set."""


class OpenRouterClient:
    """Thin wrapper around the OpenRouter chat-completion endpoint.

    Usage::

        config = AgentConfig.from_env()
        client = OpenRouterClient(config)
        reply = client.chat([{"role": "user", "content": "Hello!"}])
        print(reply)

    Attributes:
        config: The agent configuration.
    """

    _RATE_LIMIT_FILE = ".openrouter_usage.json"

    def __init__(self, config: AgentConfig) -> None:
        self.config = config
        self._rate_file = Path(config.repo_path) / self._RATE_LIMIT_FILE

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def chat(
        self,
        messages: list[dict[str, str]],
        max_tokens: int = 2000,
    ) -> str:
        """Send a chat completion request to OpenRouter.

        Args:
            messages: List of message dicts, each with ``role`` and
                ``content`` keys (OpenAI format).
            max_tokens: Maximum number of tokens the model may generate.

        Returns:
            The assistant's reply text.

        Raises:
            APINotConfigured: If the API key is a placeholder.
            RateLimitExceeded: If the daily call budget is used up.
            httpx.HTTPStatusError: On non-2xx responses from OpenRouter.
        """
        if not self.config.is_configured():
            raise APINotConfigured(
                "OpenRouter API key is not configured.  "
                "Set OPENROUTER_API_KEY to enable AI features."
            )

        self._check_rate_limit()

        url = f"{self.config.openrouter_base_url.rstrip('/')}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.config.openrouter_api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://github.com/cloud-security-lab",
            "X-Title": "Cloud Security Lab Agent",
        }
        payload: dict[str, Any] = {
            "model": self.config.openrouter_model,
            "messages": messages,
            "max_tokens": max_tokens,
        }

        logger.info("Sending chat request to OpenRouter (model=%s)", self.config.openrouter_model)
        logger.debug("Payload: %s", json.dumps(payload, indent=2))

        try:
            with httpx.Client(timeout=60.0) as client:
                response = client.post(url, headers=headers, json=payload)
                response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            logger.error(
                "OpenRouter API returned %s: %s",
                exc.response.status_code,
                exc.response.text[:500],
            )
            raise
        except httpx.RequestError as exc:
            logger.error("Network error contacting OpenRouter: %s", exc)
            raise

        data = response.json()
        self._record_call()

        # Extract assistant reply
        try:
            content: str = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError) as exc:
            logger.error("Unexpected API response structure: %s", data)
            raise ValueError("Could not parse OpenRouter response") from exc

        logger.info("Received reply (%d chars)", len(content))
        return content

    # ------------------------------------------------------------------
    # Rate-limit helpers
    # ------------------------------------------------------------------

    def _load_usage(self) -> dict[str, Any]:
        """Load the persisted usage data from disk.

        Returns:
            A dict with ``date`` (ISO str) and ``count`` (int) keys.
        """
        if not self._rate_file.exists():
            return {"date": str(date.today()), "count": 0}

        try:
            with self._rate_file.open(encoding="utf-8") as fh:
                data = json.load(fh)
            # Reset counter if we've rolled over to a new day
            if data.get("date") != str(date.today()):
                return {"date": str(date.today()), "count": 0}
            return data
        except (json.JSONDecodeError, KeyError):
            logger.warning("Corrupt usage file — resetting counter")
            return {"date": str(date.today()), "count": 0}

    def _save_usage(self, usage: dict[str, Any]) -> None:
        """Persist usage data to disk.

        Args:
            usage: Dict with ``date`` and ``count``.
        """
        usage["last_updated"] = datetime.now(timezone.utc).isoformat()
        with self._rate_file.open("w", encoding="utf-8") as fh:
            json.dump(usage, fh, indent=2)

    def _check_rate_limit(self) -> None:
        """Raise ``RateLimitExceeded`` if the daily budget is spent."""
        usage = self._load_usage()
        if usage["count"] >= self.config.max_daily_api_calls:
            raise RateLimitExceeded(
                f"Daily API call limit reached ({self.config.max_daily_api_calls} calls). "
                f"Resets tomorrow."
            )
        remaining = self.config.max_daily_api_calls - usage["count"]
        logger.debug("Rate limit check passed — %d calls remaining today", remaining)

    def _record_call(self) -> None:
        """Increment and persist the daily call counter."""
        usage = self._load_usage()
        usage["count"] += 1
        self._save_usage(usage)
        logger.debug(
            "Recorded API call #%d/%d for %s",
            usage["count"],
            self.config.max_daily_api_calls,
            usage["date"],
        )

    # ------------------------------------------------------------------
    # Informational
    # ------------------------------------------------------------------

    def get_usage_info(self) -> dict[str, Any]:
        """Return current usage stats.

        Returns:
            Dict with ``date``, ``count``, ``limit``, and ``remaining``
            keys.
        """
        usage = self._load_usage()
        return {
            "date": usage["date"],
            "count": usage["count"],
            "limit": self.config.max_daily_api_calls,
            "remaining": max(0, self.config.max_daily_api_calls - usage["count"]),
        }
