"""Configuration management for the AI Automation Agent.

Loads settings from environment variables or a `.env` file,
providing sensible defaults for local development.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path

__all__ = ["AgentConfig"]

logger = logging.getLogger(__name__)

_PLACEHOLDER_KEY = "YOUR_OPENROUTER_API_KEY_HERE"


def _load_dotenv(repo_path: str | None = None) -> None:
    """Load variables from a `.env` file into ``os.environ``.

    Searches for `.env` in *repo_path* first, then the current working
    directory.  Only simple ``KEY=VALUE`` lines are supported (no
    interpolation, no multi-line values).  Lines starting with ``#`` are
    ignored.

    Args:
        repo_path: Optional repository root to search for `.env`.
    """
    candidates: list[Path] = []
    if repo_path:
        candidates.append(Path(repo_path) / ".env")
    candidates.append(Path.cwd() / ".env")

    for candidate in candidates:
        if candidate.is_file():
            logger.debug("Loading .env from %s", candidate)
            with candidate.open(encoding="utf-8") as fh:
                for raw_line in fh:
                    line = raw_line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "=" not in line:
                        continue
                    key, _, value = line.partition("=")
                    key = key.strip()
                    value = value.strip().strip("'\"")
                    if key and key not in os.environ:
                        os.environ[key] = value
            return  # stop after first found


@dataclass
class AgentConfig:
    """Centralised configuration for the Security Lab AI agent.

    Attributes:
        openrouter_api_key: API key for OpenRouter (placeholder by default).
        openrouter_model: Model identifier to use via OpenRouter.
        openrouter_base_url: Base URL for the OpenRouter API.
        repo_path: Absolute path to the cloud-security-lab repository.
        max_daily_api_calls: Maximum number of API calls per calendar day.
        log_level: Python logging level name (e.g. ``"INFO"``).
    """

    openrouter_api_key: str = _PLACEHOLDER_KEY
    openrouter_model: str = "openrouter/auto"
    openrouter_base_url: str = "https://openrouter.ai/api/v1"
    repo_path: str = field(default_factory=lambda: str(Path.cwd()))
    max_daily_api_calls: int = 5
    log_level: str = "INFO"

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def from_env(cls, repo_path: str | None = None) -> AgentConfig:
        """Create an ``AgentConfig`` by reading environment variables.

        Before reading the environment the method will attempt to load a
        ``.env`` file so that local development is convenient.

        Recognised environment variables (all optional):
            ``OPENROUTER_API_KEY``, ``OPENROUTER_MODEL``,
            ``OPENROUTER_BASE_URL``, ``REPO_PATH``,
            ``MAX_DAILY_API_CALLS``, ``LOG_LEVEL``.

        Args:
            repo_path: Override for ``REPO_PATH``.  When *None* the env
                var is consulted; if that is also unset the current
                working directory is used.

        Returns:
            A fully-populated configuration instance.
        """
        _load_dotenv(repo_path)

        effective_repo = repo_path or os.getenv("REPO_PATH", str(Path.cwd()))

        config = cls(
            openrouter_api_key=os.getenv("OPENROUTER_API_KEY", _PLACEHOLDER_KEY),
            openrouter_model=os.getenv("OPENROUTER_MODEL", "openrouter/auto"),
            openrouter_base_url=os.getenv(
                "OPENROUTER_BASE_URL",
                "https://openrouter.ai/api/v1",
            ),
            repo_path=effective_repo,
            max_daily_api_calls=int(os.getenv("MAX_DAILY_API_CALLS", "5")),
            log_level=os.getenv("LOG_LEVEL", "INFO"),
        )

        # Apply logging level immediately
        logging.basicConfig(
            level=getattr(logging, config.log_level.upper(), logging.INFO),
            format="%(asctime)s | %(name)-28s | %(levelname)-7s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

        if not config.is_configured():
            logger.warning(
                "OpenRouter API key is not configured — AI features will be "
                "disabled.  Set OPENROUTER_API_KEY in your environment or .env file."
            )

        return config

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def is_configured(self) -> bool:
        """Return *True* if the API key is set to a real value.

        A key is considered *not configured* if it is empty or still
        contains the placeholder string.
        """
        return bool(self.openrouter_api_key) and self.openrouter_api_key != _PLACEHOLDER_KEY
