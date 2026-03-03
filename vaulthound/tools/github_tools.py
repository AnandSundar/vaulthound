"""
GitHub Tools for VaultHound - Secrets & Credentials Leak Hunter

This module provides GitHub API access with rate limiting and graceful degradation.
Implements scanning capabilities at different depths (shallow, deep, forensic).

Rate Limiting Reference (ASI02):
- Unauthenticated requests: 60 requests/hour
- Authenticated requests: 5,000 requests/hour

Graceful Degradation Reference (ASI08):
- System continues operating even when GitHub API rate limits are hit
- Returns partial results instead of failing completely
- Provides meaningful error messages while maintaining scan capabilities
"""

import time
import logging
import re
from typing import List, Dict, Optional, Tuple, Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum

# PyGithub for GitHub API access
try:
    from github import Github, Repository, Commit, GithubException
    from github.RateLimit import RateLimit
except ImportError:
    raise ImportError("PyGithub is required. Install with: pip install PyGithub")

# Configure logging
logger = logging.getLogger(__name__)


class ScanDepth(Enum):
    """Scan depth levels for repository analysis."""

    SHALLOW = "shallow"  # Quick scan of current files only
    DEEP = "deep"  # Full recursive scan with commit history
    FORENSIC = "forensic"  # Maximum depth including deleted files analysis


@dataclass
class RateLimitStatus:
    """Tracks rate limit status for GitHub API requests.

    ASI02: Implements rate limiting enforcement to prevent API blocking.
    Tracks both unauthenticated and authenticated rate limits.
    """

    remaining: int = 60
    limit: int = 60
    reset_time: datetime = field(default_factory=datetime.utcnow)
    is_authenticated: bool = False

    def is_exhausted(self) -> bool:
        """Check if rate limit is exhausted."""
        return self.remaining <= 0

    def wait_if_needed(self) -> None:
        """Wait if rate limit is exhausted until reset.

        ASI08: Graceful degradation - waits instead of failing.
        """
        if self.is_exhausted():
            wait_time = (self.reset_time - datetime.utcnow()).total_seconds()
            if wait_time > 0:
                logger.warning(
                    f"Rate limit exhausted. Waiting {wait_time:.1f} seconds until reset..."
                )
                time.sleep(min(wait_time, 60))  # Cap wait at 60 seconds
                self._update_after_wait()

    def _update_after_wait(self) -> None:
        """Update status after waiting (simulated for graceful degradation)."""
        self.remaining = max(self.remaining, 1)
        self.reset_time = datetime.utcnow() + timedelta(hours=1)

    def decrement(self) -> None:
        """Decrement remaining requests."""
        self.remaining -= 1
        if self.remaining < 0:
            self.remaining = 0

    def update_from_response(
        self, headers: Dict[str, str], is_authenticated: bool = False
    ) -> None:
        """Update status from GitHub API response headers.

        Args:
            headers: Response headers from GitHub API
            is_authenticated: Whether using authenticated requests
        """
        self.is_authenticated = is_authenticated

        # X-RateLimit-Limit header
        if "X-RateLimit-Limit" in headers:
            self.limit = int(headers["X-RateLimit-Limit"])

        # X-RateLimit-Remaining header
        if "X-RateLimit-Remaining" in headers:
            self.remaining = int(headers["X-RateLimit-Remaining"])

        # X-RateLimit-Reset header (Unix timestamp)
        if "X-RateLimit-Reset" in headers:
            reset_timestamp = int(headers["X-RateLimit-Reset"])
            self.reset_time = datetime.fromtimestamp(reset_timestamp)


class GitHubScanner:
    """GitHub repository scanner with rate limiting and graceful degradation.

    This class provides a convenient interface for scanning GitHub repositories
    while respecting API rate limits and handling errors gracefully.

    ASI02: Implements rate limiting to prevent API blocking
    ASI08: Implements graceful degradation for API errors

    Attributes:
        token: Optional GitHub personal access token
        client: Authenticated or unauthenticated PyGithub client
    """

    def __init__(self, token: Optional[str] = None):
        """Initialize GitHubScanner with optional token.

        Args:
            token: Optional GitHub personal access token for authenticated requests
        """
        self.token = token
        self.client = create_github_client(token)
        logger.info("GitHubScanner initialized")

    def get_repo(self, owner: str, repo: str) -> Repository:
        """Get a repository by owner and name.

        Args:
            owner: Repository owner (user or organization)
            repo: Repository name

        Returns:
            Repository object

        Raises:
            GithubException: If repository not found or not accessible
        """
        return get_repo(owner, repo, self.token)

    def validate_repo(self, repo: Repository) -> bool:
        """Validate that repository exists and is accessible.

        Args:
            repo: Repository object to validate

        Returns:
            True if repository is valid and accessible
        """
        return is_valid_repo(repo)

    def get_file_tree(
        self, repo: Repository, recursive: bool = True
    ) -> List[Dict[str, Any]]:
        """Get repository file tree.

        Args:
            repo: Repository object
            recursive: If True, gets all files recursively

        Returns:
            List of file information dictionaries
        """
        return get_file_tree(repo, recursive)

    def get_file_content(self, repo: Repository, path: str) -> str:
        """Get file content from repository.

        Args:
            repo: Repository object
            path: File path relative to repository root

        Returns:
            File content as string, or empty string if not accessible
        """
        return get_file_content(repo, path)

    def get_commit_history(
        self, repo: Repository, max_commits: int = 100
    ) -> List[Dict[str, Any]]:
        """Get commit history from repository.

        Args:
            repo: Repository object
            max_commits: Maximum number of commits to retrieve

        Returns:
            List of commit information dictionaries
        """
        return get_commit_history(repo, max_commits)

    def get_deleted_files(
        self, repo: Repository, max_commits: int = 100
    ) -> List[Dict[str, Any]]:
        """Get list of deleted files from commit history.

        Args:
            repo: Repository object
            max_commits: Maximum number of commits to analyze

        Returns:
            List of deleted file information
        """
        return get_deleted_files(repo, max_commits)


# Global rate limit tracker
_rate_limit_status = RateLimitStatus()


def create_github_client(token: Optional[str] = None) -> Github:
    """Create an authenticated GitHub client.

    ASI02: Implements authenticated client for higher rate limits.
    Authenticated: 5,000 requests/hour vs Unauthenticated: 60 requests/hour

    Args:
        token: GitHub personal access token. If None, uses unauthenticated client.

    Returns:
        Authenticated Github client instance

    Raises:
        GithubException: If authentication fails
    """
    if token:
        logger.info("Creating authenticated GitHub client (5,000 req/hr limit)")
        client = Github(token)
        _rate_limit_status.is_authenticated = True
        _rate_limit_status.limit = 5000
        _rate_limit_status.remaining = 5000
    else:
        logger.warning("Creating unauthenticated GitHub client (60 req/hr limit)")
        client = Github()
        _rate_limit_status.is_authenticated = False
        _rate_limit_status.limit = 60
        _rate_limit_status.remaining = 60

    return client


def get_repo(owner: str, repo: str, token: Optional[str] = None) -> Repository:
    """Get a GitHub repository.

    Args:
        owner: Repository owner (user or organization)
        repo: Repository name
        token: Optional GitHub token for authentication

    Returns:
        Repository object

    Raises:
        GithubException: If repository not found or not accessible
    """
    client = create_github_client(token)

    try:
        # Check rate limit before making request
        # ASI02: Rate limit check before each request
        _rate_limit_status.wait_if_needed()

        repository = client.get_repo(f"{owner}/{repo}")
        _rate_limit_status.decrement()

        logger.info(f"Successfully accessed repository: {owner}/{repo}")
        return repository

    except GithubException as e:
        logger.error(f"Failed to access repository {owner}/{repo}: {e}")
        raise


def is_valid_repo(repo: Repository) -> bool:
    """Validate that repository exists and is accessible.

    ASI08: Graceful degradation - returns False instead of raising exception.

    Args:
        repo: Repository object to validate

    Returns:
        True if repository is valid and accessible, False otherwise
    """
    try:
        # Try to get repository info to verify access
        _ = repo.id
        _ = repo.full_name
        return True
    except GithubException as e:
        logger.warning(f"Repository validation failed: {e}")
        return False
    except Exception as e:
        logger.warning(f"Unexpected error validating repository: {e}")
        return False


def parse_github_url(url: str) -> Tuple[str, str]:
    """Parse owner and repository name from GitHub URL.

    Supports various GitHub URL formats:
    - https://github.com/owner/repo
    - https://github.com/owner/repo.git
    - git@github.com:owner/repo.git
    - owner/repo

    Args:
        url: GitHub URL or owner/repo string

    Returns:
        Tuple of (owner, repo_name)

    Raises:
        ValueError: If URL format is not recognized
    """
    # Remove .git suffix if present
    url = url.rstrip(".git")

    # Pattern 1: HTTPS URL
    https_match = re.match(r"https?://github\.com/([^/]+)/([^/]+)", url)
    if https_match:
        return https_match.group(1), https_match.group(2)

    # Pattern 2: SSH URL
    ssh_match = re.match(r"git@github\.com:([^/]+)/([^/]+)", url)
    if ssh_match:
        return ssh_match.group(1), ssh_match.group(2)

    # Pattern 3: owner/repo format
    simple_match = re.match(r"^([^/]+)/([^/]+)$", url)
    if simple_match:
        return simple_match.group(1), simple_match.group(2)

    raise ValueError(f"Could not parse GitHub URL: {url}")


def get_file_tree(repo: Repository, recursive: bool = True) -> List[Dict[str, Any]]:
    """Get repository file tree.

    ASI02: Respects rate limits during recursive traversal.
    ASI08: Graceful degradation - returns partial results on error.

    Args:
        repo: Repository object
        recursive: If True, gets all files recursively

    Returns:
        List of dictionaries containing file information:
        - path: File path relative to repository root
        - type: 'file' or 'dir'
        - sha: Git object SHA
        - size: File size in bytes (files only)
        - url: API URL for the content
    """
    tree = []

    try:
        # Get the default branch
        default_branch = repo.default_branch

        # Get the tree recursively
        # ASI02: Check rate limit before API call
        _rate_limit_status.wait_if_needed()

        if recursive:
            git_tree = repo.get_git_tree(default_branch, recursive=True)
        else:
            git_tree = repo.get_git_tree(default_branch)

        _rate_limit_status.decrement()

        for item in git_tree.tree:
            if item.type in ["blob", "tree"]:  # Files and directories
                tree.append(
                    {
                        "path": item.path,
                        "type": "file" if item.type == "blob" else "dir",
                        "sha": item.sha,
                        "size": item.size if hasattr(item, "size") else 0,
                        "url": item.url if hasattr(item, "url") else "",
                    }
                )

        logger.info(f"Retrieved {len(tree)} items from file tree")

    except GithubException as e:
        # ASI08: Graceful degradation - return partial results
        logger.warning(f"Error getting file tree: {e}. Returning available results.")
        if tree:
            logger.info(f"Returning {len(tree)} items retrieved before error")
        else:
            # Try shallow approach as fallback
            logger.info("Attempting shallow scan as fallback...")
            tree = _get_shallow_tree(repo)

    return tree


def _get_shallow_tree(repo: Repository) -> List[Dict[str, Any]]:
    """Get shallow file tree (top-level only) as fallback.

    ASI08: Provides fallback mechanism for graceful degradation.
    """
    tree = []

    try:
        contents = repo.get_contents("")
        while contents:
            file_content = contents.pop(0)
            tree.append(
                {
                    "path": file_content.path,
                    "type": "file" if file_content.type == "file" else "dir",
                    "sha": file_content.sha,
                    "size": file_content.size if hasattr(file_content, "size") else 0,
                    "url": file_content.url if hasattr(file_content, "url") else "",
                }
            )
            if file_content.type == "dir":
                try:
                    sub_contents = repo.get_contents(file_content.path)
                    contents.extend(sub_contents)
                except GithubException:
                    pass  # Skip inaccessible directories
    except GithubException as e:
        logger.warning(f"Shallow tree fallback also failed: {e}")

    return tree


def get_file_content(repo: Repository, path: str) -> str:
    """Get file content from repository.

    ASI02: Rate limit awareness for each file request.
    ASI08: Returns empty string on error instead of raising exception.

    Args:
        repo: Repository object
        path: File path relative to repository root

    Returns:
        File content as string, or empty string if not accessible
    """
    try:
        # ASI02: Check rate limit before API call
        _rate_limit_status.wait_if_needed()

        content = repo.get_contents(path)
        _rate_limit_status.decrement()

        # Handle base64 encoded content
        if hasattr(content, "content"):
            import base64

            decoded = base64.b64decode(content.content)
            return decoded.decode("utf-8")

        return ""

    except GithubException as e:
        # ASI08: Graceful degradation - return empty instead of failing
        logger.warning(f"Could not get content for {path}: {e}")
        return ""
    except Exception as e:
        logger.warning(f"Unexpected error getting content for {path}: {e}")
        return ""


def get_commit_history(
    repo: Repository, max_commits: int = 100
) -> List[Dict[str, Any]]:
    """Get commit history from repository.

    ASI02: Respects rate limits when fetching commit history.
    ASI08: Returns partial results if rate limit hit during enumeration.

    Args:
        repo: Repository object
        max_commits: Maximum number of commits to retrieve

    Returns:
        List of commit information dictionaries:
        - sha: Commit SHA
        - message: Commit message
        - author: Author name and email
        - date: Commit date
        - files_changed: Number of files changed
    """
    commits = []

    try:
        # ASI02: Check rate limit before API call
        _rate_limit_status.wait_if_needed()

        commits_data = repo.get_commits()
        # Limit to requested number of commits
        commits_data = list(commits_data[:max_commits])
        _rate_limit_status.decrement()

        count = 0
        for commit in commits_data:
            if count >= max_commits:
                break

            try:
                commit_info = {
                    "sha": commit.sha,
                    "message": commit.commit.message if commit.commit else "",
                    "author": {
                        "name": (
                            commit.commit.author.name
                            if commit.commit and commit.commit.author
                            else "Unknown"
                        ),
                        "email": (
                            commit.commit.author.email
                            if commit.commit and commit.commit.author
                            else ""
                        ),
                        "date": (
                            commit.commit.author.date.isoformat()
                            if commit.commit and commit.commit.author
                            else ""
                        ),
                    },
                    "date": (
                        commit.commit.author.date.isoformat()
                        if commit.commit and commit.commit.author
                        else ""
                    ),
                    "url": commit.url,
                }
                commits.append(commit_info)
                count += 1

            except Exception as e:
                # ASI08: Skip problematic commits but continue
                logger.warning(f"Error processing commit {commit.sha}: {e}")
                continue

    except GithubException as e:
        # ASI08: Graceful degradation - return partial results
        logger.warning(f"Error getting commit history: {e}")
        if commits:
            logger.info(f"Returning {len(commits)} commits retrieved before error")
        else:
            logger.warning("No commits retrieved due to error")

    logger.info(f"Retrieved {len(commits)} commits")
    return commits


def get_commit_diff(repo: Repository, sha: str) -> str:
    """Get diff for a specific commit.

    Args:
        repo: Repository object
        sha: Commit SHA

    Returns:
        Diff content as string, or empty string if not accessible
    """
    try:
        # ASI02: Check rate limit before API call
        _rate_limit_status.wait_if_needed()

        commit = repo.get_commit(sha)
        _rate_limit_status.decrement()

        # Get the diff from the commit
        diff = commit.diff.url if hasattr(commit, "diff") else ""

        # If diff URL not available, try to get files changed
        if not diff:
            files = commit.files if hasattr(commit, "files") else []
            diff_parts = []
            for file in files:
                diff_parts.append(
                    f"--- a/{file.filename}\n+++ b/{file.filename}\n{file.patch}"
                )
            diff = "\n".join(diff_parts)

        return diff

    except GithubException as e:
        # ASI08: Graceful degradation
        logger.warning(f"Could not get diff for commit {sha}: {e}")
        return ""
    except Exception as e:
        logger.warning(f"Unexpected error getting diff for {sha}: {e}")
        return ""


def get_deleted_files(repo: Repository, max_commits: int = 100) -> List[Dict[str, Any]]:
    """Get list of deleted files from commit history (Forensic scan).

    This is the most intensive scan as it analyzes every commit to find
    files that existed in the past but have been deleted.

    ASI02: This function uses significant rate limit budget.
    Consider using authentication for forensic scans.
    ASI08: Returns partial results on rate limit hit.

    Args:
        repo: Repository object
        max_commits: Maximum number of commits to analyze

    Returns:
        List of deleted file information:
        - path: Original file path
        - deleted_in_commit: SHA of commit that deleted the file
        - last_modified: Date when file was last modified before deletion
        - size: Original file size
    """
    deleted_files = []

    try:
        # ASI02: Warn about rate limit usage for forensic scans
        logger.warning(
            "Forensic scan: analyzing commit history for deleted files. This uses significant API calls."
        )

        # Get commit history
        commits = get_commit_history(repo, max_commits)

        seen_files = set()  # Track files we've seen (still exist)

        for commit_info in commits:
            sha = commit_info["sha"]

            try:
                # ASI02: Check rate limit for each commit
                _rate_limit_status.wait_if_needed()

                commit = repo.get_commit(sha)
                _rate_limit_status.decrement()

                # Analyze files in this commit
                if hasattr(commit, "files") and commit.files:
                    for file in commit.files:
                        if file.status == "removed" or file.status == "deleted":
                            file_path = file.filename
                            if file_path not in seen_files:
                                deleted_files.append(
                                    {
                                        "path": file_path,
                                        "deleted_in_commit": sha,
                                        "commit_date": commit_info.get("date", ""),
                                        "commit_message": commit_info.get(
                                            "message", ""
                                        )[:200],
                                        "additions": file.additions,
                                        "deletions": file.deletions,
                                        "url": (
                                            file.contents_url
                                            if hasattr(file, "contents_url")
                                            else ""
                                        ),
                                    }
                                )
                        elif file.status == "added" or file.status == "modified":
                            seen_files.add(file.filename)

            except GithubException as e:
                # ASI08: Continue to next commit on error
                logger.warning(f"Error analyzing commit {sha}: {e}")
                continue

    except Exception as e:
        # ASI08: Return partial results
        logger.warning(f"Error in forensic scan: {e}")

    logger.info(f"Forensic scan found {len(deleted_files)} deleted files")
    return deleted_files


# Sensitive file patterns to look for
SENSITIVE_PATTERNS = {
    ".env": r"\.env(\..+)?$",
    "config": r"(?i)(config|configuration|settings)\..+$",
    "credentials": r"(?i)(credentials|secrets|keys|passwords|auth)\..+$",
    "ci_cd": r"(?i)\.(github|gitlab|jenkins|circleci|travis|azure)\.ya?ml$",
    "terraform": r"(?i).*tf(state)?$",
    "docker": r"(?i)Dockerfile$|\.dockerignore$",
    "ssh": r"(?i)(id_rsa|id_ed25519|known_hosts|authorized_keys)",
    "证书": r"(?i)\.(pem|crt|cer|key|p12|pfx)$",
}


def get_sensitive_files(repo: Repository) -> List[Dict[str, Any]]:
    """Get sensitive files from repository.

    Looks for:
    - Environment files (.env, .env.local, .env.production)
    - Configuration files (config.json, settings.py, etc.)
    - CI/CD configurations (.github/workflows, Jenkinsfile, etc.)
    - SSH keys and certificates
    - Terraform state files

    ASI02: Uses efficient tree traversal to minimize API calls.
    ASI08: Returns empty list on error instead of raising exception.

    Args:
        repo: Repository object

    Returns:
        List of sensitive file information:
        - path: File path
        - type: Category of sensitive file
        - sha: File SHA
        - size: File size
    """
    sensitive_files = []

    try:
        # Get file tree
        tree = get_file_tree(repo, recursive=True)

        for item in tree:
            path = item["path"].lower()

            for category, pattern in SENSITIVE_PATTERNS.items():
                if re.search(pattern, path):
                    sensitive_files.append(
                        {
                            "path": item["path"],
                            "type": category,
                            "sha": item["sha"],
                            "size": item["size"],
                            "url": item.get("url", ""),
                        }
                    )
                    break  # Don't match same file against multiple patterns

    except Exception as e:
        # ASI08: Graceful degradation
        logger.warning(f"Error getting sensitive files: {e}")

    logger.info(f"Found {len(sensitive_files)} sensitive files")
    return sensitive_files


def get_environment_files(repo: Repository) -> List[Dict[str, Any]]:
    """Get environment files specifically.

    Looks for .env files and similar configuration.

    Args:
        repo: Repository object

    Returns:
        List of environment file information
    """
    env_files = []

    try:
        tree = get_file_tree(repo, recursive=True)

        for item in tree:
            path = item["path"].lower()

            # Match .env files
            if re.match(r"^\.env(\..+)?$", path):
                env_files.append(
                    {
                        "path": item["path"],
                        "sha": item["sha"],
                        "size": item["size"],
                        "url": item.get("url", ""),
                    }
                )

    except Exception as e:
        logger.warning(f"Error getting environment files: {e}")

    return env_files


def get_config_files(repo: Repository) -> List[Dict[str, Any]]:
    """Get configuration files from repository.

    Looks for common config file formats and names.

    Args:
        repo: Repository object

    Returns:
        List of configuration file information
    """
    config_files = []

    # Common configuration file patterns
    config_patterns = [
        r"(?i)^config\..+$",
        r"(?i)^settings\..+$",
        r"(?i)^\..*rc$",
        r"(?i)^.*\.config\..+$",
        r"(?i)package\.json$",
        r"(?i)tsconfig\.json$",
        r"(?i)\.npmrc$",
        r"(?i)\.pypirc$",
        r"(i)?requirements\.txt$",
        r"(?i)Pipfile$",
        r"(?i)poetry\.lock$",
    ]

    try:
        tree = get_file_tree(repo, recursive=True)

        for item in tree:
            path = item["path"].lower()

            for pattern in config_patterns:
                if re.match(pattern, path):
                    config_files.append(
                        {
                            "path": item["path"],
                            "sha": item["sha"],
                            "size": item["size"],
                            "url": item.get("url", ""),
                        }
                    )
                    break

    except Exception as e:
        logger.warning(f"Error getting config files: {e}")

    return config_files


def get_cicd_configs(repo: Repository) -> List[Dict[str, Any]]:
    """Get CI/CD configuration files from repository.

    Looks for:
    - GitHub Actions workflows (.github/workflows/*.yml)
    - GitLab CI (.gitlab-ci.yml)
    - Jenkinsfile
    - CircleCI config (.circleci/config.yml)
    - Travis CI (.travis.yml)
    - Azure Pipelines (azure-pipelines.yml)

    Args:
        repo: Repository object

    Returns:
        List of CI/CD configuration file information
    """
    cicd_files = []

    cicd_patterns = [
        r"(?i)\.github/workflows/.*\.ya?ml$",
        r"(?i)\.github/workflows/.*\.yml$",
        r"(?i)^gitlab-ci\.yml$",
        r"(?i)^Jenkinsfile$",
        r"(?i)\.circleci/config\.yml$",
        r"(?i)^\.travis\.yml$",
        r"(?i)^azure-pipelines\.yml$",
    ]

    try:
        tree = get_file_tree(repo, recursive=True)

        for item in tree:
            path = item["path"]

            for pattern in cicd_patterns:
                if re.match(pattern, path):
                    cicd_files.append(
                        {
                            "path": item["path"],
                            "sha": item["sha"],
                            "size": item["size"],
                            "url": item.get("url", ""),
                        }
                    )
                    break

    except Exception as e:
        logger.warning(f"Error getting CI/CD configs: {e}")

    return cicd_files


def scan_repository(
    owner: str,
    repo_name: str,
    token: Optional[str] = None,
    depth: ScanDepth = ScanDepth.DEEP,
) -> Dict[str, Any]:
    """Perform a comprehensive scan of a GitHub repository.

    This is the main scanning function that coordinates all scan types.

    ASI02: Monitors rate limit throughout the scan.
    ASI08: Returns partial results if rate limit is hit during scan.

    Args:
        owner: Repository owner
        repo_name: Repository name
        token: Optional GitHub token
        depth: Scan depth (SHALLOW, DEEP, or FORENSIC)

    Returns:
        Dictionary containing scan results:
        - repo_info: Basic repository information
        - file_tree: Repository file structure
        - sensitive_files: List of potentially sensitive files
        - deleted_files: List of deleted files (FORENSIC only)
        - commit_history: Recent commits (DEEP/FORENSIC only)
        - scan_depth: Depth level used
        - errors: Any errors encountered
    """
    results = {
        "repo_info": {},
        "file_tree": [],
        "sensitive_files": [],
        "deleted_files": [],
        "commit_history": [],
        "scan_depth": depth.value,
        "errors": [],
    }

    try:
        # Get repository
        repo = get_repo(owner, repo_name, token)

        results["repo_info"] = {
            "name": repo.name,
            "full_name": repo.full_name,
            "description": repo.description or "",
            "default_branch": repo.default_branch,
            "private": repo.private,
            "url": repo.html_url,
            "stars": repo.stargazers_count,
            "forks": repo.forks_count,
            "language": repo.language or "",
            "created_at": repo.created_at.isoformat() if repo.created_at else "",
            "updated_at": repo.updated_at.isoformat() if repo.updated_at else "",
        }

        # SHALLOW: Just get current files
        logger.info(f"Starting {depth.value} scan...")

        # Get file tree
        results["file_tree"] = get_file_tree(repo, recursive=True)

        # Get sensitive files
        results["sensitive_files"] = get_sensitive_files(repo)

        # DEEP or FORENSIC: Get commit history
        if depth in [ScanDepth.DEEP, ScanDepth.FORENSIC]:
            max_commits = 500 if depth == ScanDepth.FORENSIC else 100
            results["commit_history"] = get_commit_history(repo, max_commits)

        # FORENSIC: Get deleted files
        if depth == ScanDepth.FORENSIC:
            results["deleted_files"] = get_deleted_files(repo, max_commits=500)

        logger.info(
            f"Scan completed: {len(results['file_tree'])} files, "
            f"{len(results['sensitive_files'])} sensitive files found"
        )

    except GithubException as e:
        error_msg = f"GitHub API error: {e}"
        results["errors"].append(error_msg)
        logger.error(error_msg)

    except Exception as e:
        error_msg = f"Unexpected error during scan: {e}"
        results["errors"].append(error_msg)
        logger.error(error_msg)

    return results


def get_rate_limit_status() -> Dict[str, Any]:
    """Get current rate limit status.

    Returns:
        Dictionary with rate limit information
    """
    return {
        "remaining": _rate_limit_status.remaining,
        "limit": _rate_limit_status.limit,
        "reset_time": _rate_limit_status.reset_time.isoformat(),
        "is_authenticated": _rate_limit_status.is_authenticated,
        "is_exhausted": _rate_limit_status.is_exhausted(),
    }


def reset_rate_limit() -> None:
    """Reset rate limit status (for testing purposes)."""
    global _rate_limit_status
    _rate_limit_status = RateLimitStatus()
    logger.info("Rate limit status reset")
