"""Git repository manager for automated commits.

Wraps common git operations via ``subprocess.run`` with proper error
handling, conventional-commit validation, and configurable authorship.
"""

from __future__ import annotations

import logging
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

__all__ = ["GitManager", "ConventionalCommitError"]

logger = logging.getLogger(__name__)

# Conventional Commit regex — type(scope): description
_CONVENTIONAL_RE = re.compile(
    r"^(?P<type>feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert)"
    r"(?:\((?P<scope>[a-zA-Z0-9_/-]+)\))?"
    r"(?P<breaking>!)?"
    r":\s+(?P<description>.+)$"
)


class ConventionalCommitError(ValueError):
    """Raised when a commit message does not follow Conventional Commits."""


@dataclass(frozen=True)
class CommitInfo:
    """Lightweight representation of a git commit.

    Attributes:
        sha: Abbreviated commit hash.
        author: Author name.
        date: Author date (ISO-like string).
        message: Full commit message subject line.
    """

    sha: str
    author: str
    date: str
    message: str


class GitManager:
    """Manages git operations for the Cloud Security Lab repository.

    All operations target the repository at *repo_path* and are executed
    via ``subprocess.run`` so that no Python git library is required.

    Args:
        repo_path: Absolute path to the repository root.
    """

    def __init__(self, repo_path: str) -> None:
        self._repo = Path(repo_path)
        if not (self._repo / ".git").is_dir():
            raise FileNotFoundError(
                f"No .git directory found at {self._repo}. "
                "Ensure repo_path points to a valid git repository."
            )
        logger.debug("GitManager initialised for %s", self._repo)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _run(
        self,
        args: list[str],
        *,
        check: bool = True,
        capture: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        """Run a git command inside the repository.

        Args:
            args: Command and arguments (e.g. ``["git", "status"]``).
            check: Raise ``CalledProcessError`` on non-zero exit.
            capture: Capture stdout/stderr.

        Returns:
            The completed process.
        """
        logger.debug("Running: %s", " ".join(args))
        result = subprocess.run(
            args,
            cwd=self._repo,
            capture_output=capture,
            text=True,
            check=check,
        )
        if result.returncode != 0 and not check:
            logger.warning(
                "Command %s exited with code %d: %s",
                " ".join(args),
                result.returncode,
                (result.stderr or "").strip(),
            )
        return result

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_status(self) -> dict[str, Any]:
        """Return a summary of the repository's current state.

        Returns:
            Dict with keys: ``branch`` (str), ``uncommitted_changes``
            (list of modified files), ``recent_commits`` (list of
            :class:`CommitInfo` dicts, last 5).
        """
        # Current branch
        branch_result = self._run(["git", "rev-parse", "--abbrev-ref", "HEAD"])
        branch = branch_result.stdout.strip()

        # Uncommitted changes
        status_result = self._run(["git", "status", "--porcelain"])
        changes = [
            line.strip() for line in status_result.stdout.splitlines() if line.strip()
        ]

        # Recent commits
        recent = self.get_recent_commits(n=5)

        return {
            "branch": branch,
            "uncommitted_changes": changes,
            "recent_commits": [
                {"sha": c.sha, "author": c.author, "date": c.date, "message": c.message}
                for c in recent
            ],
        }

    def create_branch(self, name: str) -> None:
        """Create and check out a new branch.

        If the branch already exists, it is simply checked out.

        Args:
            name: Branch name (e.g. ``"feat/rds-scanner"``).
        """
        # Check if branch exists locally
        result = self._run(
            ["git", "rev-parse", "--verify", name],
            check=False,
        )
        if result.returncode == 0:
            logger.info("Branch '%s' already exists — checking out", name)
            self._run(["git", "checkout", name])
        else:
            logger.info("Creating and checking out branch '%s'", name)
            self._run(["git", "checkout", "-b", name])

    def checkout(self, branch: str) -> None:
        """Check out an existing branch.

        Args:
            branch: Branch name to switch to.
        """
        self._run(["git", "checkout", branch])
        logger.info("Checked out branch '%s'", branch)

    def stage_files(self, files: list[str]) -> None:
        """Stage files for the next commit.

        Args:
            files: Relative (to repo root) or absolute file paths.
        """
        if not files:
            logger.warning("No files provided to stage")
            return

        resolved: list[str] = []
        for f in files:
            fp = Path(f)
            if not fp.is_absolute():
                fp = self._repo / fp
            resolved.append(str(fp))

        self._run(["git", "add", *resolved])
        logger.info("Staged %d file(s)", len(resolved))

    def commit(
        self,
        message: str,
        author_name: str = "Cloud Security Lab",
        author_email: str = "security-lab@example.com",
    ) -> str:
        """Create a commit with the given message.

        The message is validated against the Conventional Commits
        specification before committing.

        Args:
            message: Commit message (subject line only).
            author_name: Git author name.
            author_email: Git author email.

        Returns:
            The short SHA of the new commit.

        Raises:
            ConventionalCommitError: If the message format is invalid.
            subprocess.CalledProcessError: If git-commit fails.
        """
        self._validate_conventional_commit(message)

        author = f"{author_name} <{author_email}>"
        self._run([
            "git", "commit",
            "-m", message,
            "--author", author,
            "--allow-empty",  # in case no staged changes
        ])

        sha_result = self._run(["git", "rev-parse", "--short", "HEAD"])
        sha = sha_result.stdout.strip()
        logger.info("Created commit %s: %s", sha, message)
        return sha

    def push(
        self,
        remote: str = "origin",
        branch: str | None = None,
    ) -> bool:
        """Push the current branch to the remote.

        Fails gracefully (returns *False*) if no remote is configured
        or the push is rejected.

        Args:
            remote: Remote name.
            branch: Branch to push; defaults to the current branch.

        Returns:
            *True* if the push succeeded, *False* otherwise.
        """
        if branch is None:
            result = self._run(["git", "rev-parse", "--abbrev-ref", "HEAD"])
            branch = result.stdout.strip()

        # Check remote exists
        remote_check = self._run(["git", "remote", "get-url", remote], check=False)
        if remote_check.returncode != 0:
            logger.warning(
                "Remote '%s' is not configured — skipping push", remote
            )
            return False

        push_result = self._run(
            ["git", "push", remote, branch],
            check=False,
        )
        if push_result.returncode != 0:
            logger.warning("Push to %s/%s failed: %s", remote, branch, push_result.stderr.strip())
            return False

        logger.info("Pushed to %s/%s", remote, branch)
        return True

    def get_recent_commits(self, n: int = 10) -> list[CommitInfo]:
        """Return the last *n* commits on the current branch.

        Args:
            n: Number of commits to retrieve.

        Returns:
            List of :class:`CommitInfo` objects (most recent first).
        """
        fmt = "%h%x00%an%x00%aI%x00%s"
        result = self._run(
            ["git", "log", f"-{n}", f"--format={fmt}"],
            check=False,
        )
        if result.returncode != 0 or not result.stdout.strip():
            return []

        commits: list[CommitInfo] = []
        for line in result.stdout.strip().splitlines():
            parts = line.split("\x00")
            if len(parts) >= 4:
                commits.append(CommitInfo(
                    sha=parts[0],
                    author=parts[1],
                    date=parts[2],
                    message=parts[3],
                ))
        return commits

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_conventional_commit(message: str) -> None:
        """Raise if *message* does not follow Conventional Commits.

        Args:
            message: The commit message subject line.

        Raises:
            ConventionalCommitError: On format violations.
        """
        if not message or not message.strip():
            raise ConventionalCommitError("Commit message must not be empty")

        subject = message.strip().splitlines()[0]
        if not _CONVENTIONAL_RE.match(subject):
            raise ConventionalCommitError(
                f"Commit message does not follow Conventional Commits format: "
                f"'{subject}'\n"
                f"Expected: <type>(<scope>): <description>\n"
                f"Valid types: feat, fix, docs, style, refactor, perf, test, "
                f"build, ci, chore, revert"
            )

    @staticmethod
    def is_valid_conventional_commit(message: str) -> bool:
        """Return *True* if *message* follows Conventional Commits.

        Args:
            message: The commit message to validate.
        """
        if not message or not message.strip():
            return False
        subject = message.strip().splitlines()[0]
        return bool(_CONVENTIONAL_RE.match(subject))
