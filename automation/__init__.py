"""AI Automation System for Cloud Security Lab.

Provides autonomous task generation, AI-assisted code generation,
and automated git workflow management for continuous security
engineering improvements.
"""

from __future__ import annotations

__all__ = [
    "AgentConfig",
    "GitManager",
    "OpenRouterClient",
    "SecurityLabAgent",
    "TaskGenerator",
]

# Lazy imports to avoid heavy dependencies at package level
from automation.ai_agent import SecurityLabAgent
from automation.config import AgentConfig
from automation.github_manager import GitManager
from automation.openrouter_client import OpenRouterClient
from automation.task_generator import TaskGenerator
