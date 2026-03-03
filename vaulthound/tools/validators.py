"""
VaultHound Security Validators

Comprehensive security validation module for the VaultHound secrets detection tool.
Implements OWASP AI Security guidelines for mitigating AI-specific vulnerabilities.

OWASP Mappings:
- ASI01: Prompt Injection - Input validation and prompt injection detection
- ASI02: Resource Exhaustion - Rate limiting for API calls
- ASI03: Token Scope - GitHub token permission validation
- ASI04: Overreliance - Output validation schemas
- ASI05: RCE - Static analysis for dangerous code patterns

Author: VaultHound Team
"""

# ============================================================================
# IMPORTS
# ============================================================================

import re
import time
import hashlib
import logging
from typing import Optional, List, Dict, Any, Callable
from functools import wraps
from enum import Enum
from dataclasses import dataclass

# Pydantic for schema validation (OWASP ASI04: Overreliance)
try:
    from pydantic import BaseModel, Field, field_validator, model_validator

    PYDANTIC_AVAILABLE = True
except ImportError:
    PYDANTIC_AVAILABLE = False
    BaseModel = object
    Field = lambda **kwargs: kwargs

# Configure logging
logger = logging.getLogger(__name__)


# ============================================================================
# CONSTANTS - Security Patterns and Allowlists
# ============================================================================

# OWASP ASI01: Strict allowlist for GitHub URLs
# Only allows direct github.com repository URLs
GITHUB_URL_PATTERN = re.compile(
    r"^https?://(?:www\.)?github\.com/"  # Only github.com allowed
    r"[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?"  # Organization/user
    r"(?:/)?$"  # Optional trailing slash for org/user root
)

# Extended pattern for full repository URLs
REPO_URL_PATTERN = re.compile(
    r"^https?://(?:www\.)?github\.com/"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?"  # Owner
    r"/[a-zA-Z0-9](?:[a-zA-Z0-9._-]*[a-zA-Z0-9])?"  # Repo name
    r"(?:/)?(?:tree/[\w.-]+/(.+?))?(?:/)?$"  # Optional branch/path
)

# OWASP ASI01: Prompt injection patterns
# Detects common prompt injection attempts
PROMPT_INJECTION_PATTERNS = [
    # Direct instruction overrides
    re.compile(
        r"(?i)(ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions)",
        re.IGNORECASE,
    ),
    re.compile(r"(?i)(ignore\s+system\s+prompt)", re.IGNORECASE),
    re.compile(r"(?i)(disregard\s+(?:all\s+)?(?:rules?|instructions?))", re.IGNORECASE),
    # Role playing attempts
    re.compile(r"(?i)(you\s+are\s+(?:now|a|acting\s+as))", re.IGNORECASE),
    re.compile(r"(?i)(pretend\s+(?:to\s+be|you\s+are))", re.IGNORECASE),
    re.compile(r"(?i)(roleplay)", re.IGNORECASE),
    # Override attempts
    re.compile(r"(?i)(new\s+instructions)", re.IGNORECASE),
    re.compile(r"(?i)(system:)", re.IGNORECASE),
    re.compile(r"(?i)(#!\s*/)", re.IGNORECASE),  # Shebang-like
    # Persona/mode switching
    re.compile(r"(?i)(switch\s+to\s+(?:developer|admin|root)\s+mode)", re.IGNORECASE),
    re.compile(r"(?i)(enable\s+god\s+mode)", re.IGNORECASE),
    re.compile(r"(?i)(jailbreak)", re.IGNORECASE),
    # Delimiter injection
    re.compile(r"(?i)(###\s*instruction)", re.IGNORECASE),
    re.compile(r"(?i)(___\s*$)", re.IGNORECASE),
    re.compile(r"(?i)(\[INST\]\[\\/INST\])", re.IGNORECASE),
    # Code-based injection
    re.compile(r"(?i)(```system)", re.IGNORECASE),
    re.compile(r"(?i)(<\|system\|>)", re.IGNORECASE),
]

# OWASP ASI05: Dangerous code patterns for RCE detection
DANGEROUS_PATTERNS = [
    # Code execution
    (r"\beval\s*\(", "eval() - dynamic code execution"),
    (r"\bexec\s*\(", "exec() - dynamic code execution"),
    (r"\bcompile\s*\(", "compile() - dynamic code compilation"),
    # Subprocess execution
    (
        r"\bsubprocess\.(?:run|call|Popen|check_output)\s*\(",
        "subprocess - command execution",
    ),
    (r"\bos\.system\s*\(", "os.system() - shell command execution"),
    (r"\bos\.popen\s*\(", "os.popen() - shell command execution"),
    (r"\bos\.spawn[a-zA-Z]*\s*\(", "os.spawn*() - process spawning"),
    (r"\bcommands\.(?:getoutput|getstatus)\s*\(", "commands module - shell execution"),
    # Shell execution
    (r"\bshell=True", "shell=True - shell injection risk"),
    (r"\|.*\|", "pipe to shell command"),
    # Input reading with execution risk
    (r"\binput\s*\(", "input() - potential code injection"),
    (r"\b__import__\s*\(", "__import__() - dynamic module import"),
    # Object serialization with code execution
    (r"\bpickle\.loads?\s*\(", "pickle - unsafe deserialization"),
    (
        r"\byaml\.load\s*\([^)]*(?:Loader=None|Loader=yaml\.FullLoader)",
        "yaml - unsafe loading",
    ),
    # Template injection
    (r"\{\{.*?\}\}", "template expression - SSTI risk"),
    # File operations with execution
    (r"\bexecfile\s*\(", "execfile() - file execution"),
    (r"\bopen\s*\([^)]*\)\.read\(\)", "file read with execution potential"),
]

# OWASP ASI03: Required GitHub token scopes
REQUIRED_SCOPES = {
    "repo": "Full repository access",
    "repo:status": "Commit statuses",
    "repo_deployment": "Deployments",
    "public_repo": "Public repositories only",
}

# Minimum required scopes for secrets scanning
MINIMUM_REQUIRED_SCOPES = ["repo"]


# ============================================================================
# RATE LIMITING (OWASP ASI02: Resource Exhaustion)
# ============================================================================


class RateLimitExceeded(Exception):
    """Raised when rate limit is exceeded."""

    pass


def rate_limit(max_calls: int, period: int) -> Callable:
    """
    Rate limiting decorator for API calls (OWASP ASI02: Resource Exhaustion).

    Prevents API abuse by limiting the number of calls within a time period.

    Args:
        max_calls: Maximum number of calls allowed within the period
        period: Time period in seconds

    Returns:
        Decorated function with rate limiting

    Example:
        @rate_limit(max_calls=10, period=60)
        def api_call():
            pass
    """

    def decorator(func: Callable) -> Callable:
        # Store call timestamps in function attributes
        func._rate_limit_calls = []  # type: ignore
        func._rate_limit_max = max_calls  # type: ignore
        func._rate_limit_period = period  # type: ignore

        @wraps(func)
        def wrapper(*args, **kwargs):
            current_time = time.time()

            # Clean old calls outside the time window
            cutoff_time = current_time - period
            func._rate_limit_calls = [  # type: ignore
                t for t in func._rate_limit_calls if t > cutoff_time  # type: ignore
            ]

            # Check if rate limit exceeded
            if len(func._rate_limit_calls) >= max_calls:  # type: ignore
                logger.warning(
                    f"Rate limit exceeded for {func.__name__}: "
                    f"{max_calls} calls per {period}s"
                )
                raise RateLimitExceeded(
                    f"Rate limit exceeded: {max_calls} calls per {period} seconds"
                )

            # Record this call
            func._rate_limit_calls.append(current_time)  # type: ignore

            return func(*args, **kwargs)

        return wrapper

    return decorator


# ============================================================================
# GITHUB URL VALIDATION (OWASP ASI01: Prompt Injection)
# ============================================================================


def validate_github_url(url: str) -> tuple[bool, str]:
    """
    Validate GitHub URL format using strict allowlist (OWASP ASI01).

    Only allows direct github.com repository URLs. This prevents:
    - Arbitrary URL redirects
    - Phishing attempts via malicious repositories
    - Prompt injection through URL parameters

    Args:
        url: The URL to validate

    Returns:
        Tuple of (is_valid: bool, message: str)

    Example:
        >>> validate_github_url("https://github.com/owner/repo")
        (True, "Valid GitHub repository URL")
        >>> validate_github_url("https://evil.com/malicious")
        (False, "Invalid URL: Only github.com repositories are allowed")
    """
    if not url or not isinstance(url, str):
        return False, "Invalid input: URL is required and must be a string"

    # Strip whitespace
    url = url.strip()

    # Check against strict allowlist pattern
    if REPO_URL_PATTERN.match(url):
        return True, "Valid GitHub repository URL"

    # Also allow organization/user root URLs
    if GITHUB_URL_PATTERN.match(url):
        return True, "Valid GitHub user/organization URL"

    return False, "Invalid URL: Only github.com repositories are allowed"


# ============================================================================
# PROMPT INJECTION DETECTION (OWASP ASI01)
# ============================================================================


def detect_prompt_injection(text: str) -> bool:
    """
    Detect prompt injection attempts (OWASP ASI01: Prompt Injection).

    Scans input text for known prompt injection patterns that attempt to:
    - Override system instructions
    - Switch to privileged modes
    - Execute role-playing attacks
    - Use delimiter-based injection

    Args:
        text: The text to scan for injection attempts

    Returns:
        True if prompt injection detected, False otherwise

    Note:
        This function uses pattern matching which may produce false positives.
        Review flagged content manually when possible.
    """
    if not text or not isinstance(text, str):
        return False

    # Check each pattern
    for pattern in PROMPT_INJECTION_PATTERNS:
        if pattern.search(text):
            logger.warning(f"Potential prompt injection detected: {pattern.pattern}")
            return True

    return False


def sanitize_input(text: str) -> str:
    """
    Sanitize user input to prevent injection attacks (OWASP ASI01).

    Applies multiple sanitization layers:
    1. Remove control characters
    2. Normalize whitespace
    3. Strip potentially dangerous prefixes

    Args:
        text: The text to sanitize

    Returns:
        Sanitized text

    Example:
        >>> sanitize_input("  hello  world  ")
        'hello world'
    """
    if not text or not isinstance(text, str):
        return ""

    # Remove null bytes and other control characters
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)

    # Normalize multiple whitespace to single space
    text = re.sub(r"\s+", " ", text)

    # Strip leading/trailing whitespace
    text = text.strip()

    # Remove potential instruction prefixes
    dangerous_prefixes = [
        r"^system:\s*",
        r"^assistant:\s*",
        r"^user:\s*",
        r"^###\s*instruction",
    ]
    for prefix in dangerous_prefixes:
        text = re.sub(prefix, "", text, flags=re.IGNORECASE)

    return text


# ============================================================================
# TOKEN SCOPE VALIDATION (OWASP ASI03)
# ============================================================================


def validate_token_scope(token: str) -> Dict[str, Any]:
    """
    Validate GitHub token permissions (OWASP ASI03: Token Scope).

    Analyzes token scopes to ensure appropriate permissions for secrets scanning.
    Requires 'repo' scope for full repository access.

    Args:
        token: GitHub personal access token (without 'ghp_' prefix)

    Returns:
        Dictionary containing:
        - valid: Whether token has appropriate permissions
        - scopes: List of detected scopes
        - has_minimum: Whether minimum required scopes are present
        - message: Description of permissions

    Note:
        This is a basic scope validation. For production use,
        validate against GitHub's API directly.

    Example:
        >>> result = validate_token_scope("ghp_xxxxx")
        >>> print(result['valid'])
        True
    """
    if not token or not isinstance(token, str):
        return {
            "valid": False,
            "scopes": [],
            "has_minimum": False,
            "message": "Invalid token format",
        }

    # Token format validation
    # GitHub tokens start with specific prefixes
    valid_prefixes = ["ghp_", "gho_", "ghu_", "ghs_", "ghr_"]

    if not any(token.startswith(prefix) for prefix in valid_prefixes):
        return {
            "valid": False,
            "scopes": [],
            "has_minimum": False,
            "message": "Invalid token prefix - not a valid GitHub token format",
        }

    # Token length validation (minimum 20 characters after prefix)
    if len(token) < 25:
        return {
            "valid": False,
            "scopes": [],
            "has_minimum": False,
            "message": "Token too short - invalid GitHub token",
        }

    # In production, you would call GitHub API to get actual scopes:
    # response = requests.get('https://api.github.com/user', headers={'Authorization': f'token {token}'})
    # scopes = response.headers.get('X-OAuth-Scopes', '').split(', ')

    # For now, return validation based on token type
    token_prefix = token.split("_")[0]

    scope_mapping = {
        "ghp": ["repo", "repo:status", "repo_deployment", "public_repo"],
        "gho": ["read:user", "user:email"],
        "ghu": ["read:user"],
        "ghs": ["repo"],  # Fine-grained token
        "ghr": ["repo"],  # Fine-grained token
    }

    scopes = scope_mapping.get(token_prefix, [])
    has_minimum = "repo" in scopes or "public_repo" in scopes

    return {
        "valid": has_minimum,
        "scopes": scopes,
        "has_minimum": has_minimum,
        "message": (
            "Token has repository access"
            if has_minimum
            else "Token lacks repository access"
        ),
    }


# ============================================================================
# DANGEROUS CODE DETECTION (OWASP ASI05: RCE)
# ============================================================================


def check_no_dynamic_code(code: str) -> bool:
    """
    Static analysis to prevent Remote Code Execution (OWASP ASI05).

    Scans code for dangerous patterns that could enable RCE:
    - Code execution functions (eval, exec, compile)
    - Subprocess execution
    - Shell command execution
    - Unsafe deserialization
    - Template injection

    Args:
        code: The code to analyze

    Returns:
        True if no dangerous patterns found (code is safe), False otherwise

    Example:
        >>> check_no_dynamic_code("print('hello')")
        True
        >>> check_no_dynamic_code("eval('os.system(\"ls\")')")
        False
    """
    if not code or not isinstance(code, str):
        return True

    for pattern, description in DANGEROUS_PATTERNS:
        if re.search(pattern, code, re.IGNORECASE):
            logger.warning(f"Dangerous pattern detected: {description}")
            return False

    return True


def get_dangerous_patterns_report(code: str) -> Dict[str, Any]:
    """
    Get detailed report of dangerous patterns found in code.

    Args:
        code: The code to analyze

    Returns:
        Dictionary with found patterns and their descriptions
    """
    found_patterns = []

    if not code or not isinstance(code, str):
        return {"safe": True, "patterns": []}

    for pattern, description in DANGEROUS_PATTERNS:
        matches = re.finditer(pattern, code, re.IGNORECASE)
        for match in matches:
            found_patterns.append(
                {
                    "pattern": pattern,
                    "description": description,
                    "match": match.group(0),
                    "position": match.start(),
                }
            )

    return {"safe": len(found_patterns) == 0, "patterns": found_patterns}


# ============================================================================
# SECRET REDACTION
# ============================================================================


def redact_secret(value: str, visible_chars: int = 4) -> str:
    """
    Redact secrets for safe logging (OWASP ASI03).

    Partially masks sensitive values while preserving enough for debugging.

    Args:
        value: The secret value to redact
        visible_chars: Number of characters to show at the end

    Returns:
        Redacted string in format "****abcd"

    Example:
        >>> redact_secret("ghp_abcdefghijklmnop")
        '****klmnop'
    """
    if not value or not isinstance(value, str):
        return "****"

    if len(value) <= visible_chars:
        return "****"

    return f"****{value[-visible_chars:]}"


def redact_token_prefix(token: str) -> str:
    """
    Redact GitHub token prefix for safe logging.

    Args:
        token: The full token

    Returns:
        Token with prefix replaced
    """
    if not token:
        return ""

    parts = token.split("_")
    if len(parts) >= 2:
        return f"{parts[0]}_****"

    return "****"


# ============================================================================
# PYDANTIC MODELS (OWASP ASI04: Overreliance)
# ============================================================================

if PYDANTIC_AVAILABLE:

    class ScanType(str, Enum):
        """Supported scan types."""

        FULL_REPO = "full_repo"
        PULL_REQUEST = "pull_request"
        COMMIT_RANGE = "commit_range"
        FILE_SCAN = "file_scan"

    class ScanConfig(BaseModel):
        """
        Configuration model for secrets scanning (OWASP ASI04).

        Validates scan configuration to prevent misconfiguration
        and ensure safe scanning parameters.
        """

        # Repository configuration
        repo_url: str = Field(
            description="GitHub repository URL", min_length=1, max_length=500
        )

        # Scan type
        scan_type: ScanType = Field(
            default=ScanType.FULL_REPO, description="Type of scan to perform"
        )

        # Optional parameters
        branch: Optional[str] = Field(
            default="main", description="Branch to scan", max_length=100
        )

        commit_range: Optional[str] = Field(
            default=None,
            description="Commit range (e.g., 'abc123..def456')",
            max_length=100,
        )

        file_path: Optional[str] = Field(
            default=None, description="Specific file path to scan", max_length=500
        )

        # Rate limiting configuration
        max_calls_per_minute: int = Field(
            default=30, ge=1, le=5000, description="API rate limit: calls per minute"
        )

        # Timeout configuration
        request_timeout: int = Field(
            default=30, ge=5, le=300, description="Request timeout in seconds"
        )

        # Safety flags
        follow_symlinks: bool = Field(
            default=False, description="Whether to follow symbolic links"
        )

        max_file_size_mb: int = Field(
            default=10, ge=1, le=100, description="Maximum file size to scan in MB"
        )

        exclude_patterns: List[str] = Field(
            default_factory=lambda: [
                "*.git/*",
                "node_modules/*",
                "__pycache__/*",
                "*.pyc",
                "*.min.js",
                "*.min.css",
            ],
            description="Patterns to exclude from scanning",
        )

        @field_validator("repo_url")
        @classmethod
        def validate_repo_url(cls, v: str) -> str:
            """Validate GitHub URL format."""
            is_valid, msg = validate_github_url(v)
            if not is_valid:
                raise ValueError(f"Invalid GitHub URL: {v}. " f"{msg}")
            return v

        @field_validator("branch")
        @classmethod
        def validate_branch(cls, v: Optional[str]) -> Optional[str]:
            """Validate branch name."""
            if v is None:
                return v
            # Sanitize branch name
            v = sanitize_input(v)
            # Check for path traversal
            if ".." in v or v.startswith("/"):
                raise ValueError("Branch name contains invalid characters")
            return v

        @field_validator("exclude_patterns")
        @classmethod
        def validate_exclude_patterns(cls, v: List[str]) -> List[str]:
            """Validate and sanitize exclude patterns."""
            sanitized = []
            for pattern in v:
                pattern = sanitize_input(pattern)
                # Basic validation - no absolute paths or parent directory refs
                if not pattern.startswith("/") and ".." not in pattern:
                    sanitized.append(pattern)
            return sanitized

        model_config = {
            "json_schema_extra": {
                "examples": [
                    {
                        "repo_url": "https://github.com/owner/repo",
                        "scan_type": "full_repo",
                        "branch": "main",
                    }
                ]
            }
        }

    class FileContent(BaseModel):
        """
        Model for validated file content (OWASP ASI04).

        Ensures file content meets safety requirements before processing.
        """

        filename: str = Field(
            description="Name of the file", min_length=1, max_length=255
        )

        content: str = Field(
            description="File content", max_length=10_000_000  # 10MB limit
        )

        size_bytes: int = Field(ge=0, description="File size in bytes")

        mime_type: Optional[str] = Field(
            default=None, description="MIME type of the file"
        )

        encoding: str = Field(default="utf-8", description="File encoding")

        is_binary: bool = Field(default=False, description="Whether file is binary")

        # Validation for dangerous content
        @field_validator("content")
        @classmethod
        def validate_content_safety(cls, v: str) -> str:
            """Check for dangerous code patterns."""
            if not check_no_dynamic_code(v):
                raise ValueError(
                    "File content contains potentially dangerous code patterns"
                )
            return v

        @field_validator("filename")
        @classmethod
        def validate_filename(cls, v: str) -> str:
            """Validate filename for path traversal."""
            if ".." in v or v.startswith("/") or v.startswith("\\"):
                raise ValueError("Filename contains path traversal attempt")
            # Sanitize
            return sanitize_input(v)

        model_config = {
            "json_schema_extra": {
                "examples": [
                    {
                        "filename": "config.py",
                        "content": "API_KEY = 'secret'",
                        "size_bytes": 20,
                        "encoding": "utf-8",
                    }
                ]
            }
        }

    class SecretFinding(BaseModel):
        """
        Model for validated secret finding (OWASP ASI04).

        Ensures secret findings are properly validated and formatted.
        """

        file_path: str = Field(description="Path to file containing secret")

        line_number: int = Field(ge=1, description="Line number where secret was found")

        secret_type: str = Field(description="Type of secret detected", min_length=1)

        confidence: str = Field(
            description="Detection confidence", pattern="^(low|medium|high|critical)$"
        )

        redacted_value: str = Field(
            description="Redacted secret value for safe logging", max_length=50
        )

        context: Optional[str] = Field(
            default=None, description="Surrounding context", max_length=200
        )

        @field_validator("file_path")
        @classmethod
        def validate_file_path(cls, v: str) -> str:
            """Validate file path."""
            if ".." in v or v.startswith("/"):
                raise ValueError("Invalid file path")
            return sanitize_input(v)

        @field_validator("secret_type")
        @classmethod
        def validate_secret_type(cls, v: str) -> str:
            """Validate and normalize secret type."""
            return sanitize_input(v).lower()

    class ScanResult(BaseModel):
        """
        Model for scan results (OWASP ASI04).

        Validates and normalizes scan output.
        """

        repo_url: str = Field(description="Repository URL scanned")

        scan_id: str = Field(description="Unique scan identifier", min_length=1)

        status: str = Field(
            description="Scan status", pattern="^(completed|failed|partial)$"
        )

        findings: List[SecretFinding] = Field(
            default_factory=list, description="List of detected secrets"
        )

        files_scanned: int = Field(ge=0, description="Number of files scanned")

        secrets_found: int = Field(ge=0, description="Total secrets found")

        duration_seconds: float = Field(ge=0, description="Scan duration")

        errors: List[str] = Field(
            default_factory=list, description="Any errors encountered"
        )

        model_config = {
            "json_schema_extra": {
                "examples": [
                    {
                        "repo_url": "https://github.com/owner/repo",
                        "scan_id": "scan_abc123",
                        "status": "completed",
                        "findings": [],
                        "files_scanned": 100,
                        "secrets_found": 0,
                        "duration_seconds": 45.2,
                    }
                ]
            }
        }

else:
    # Fallback classes if Pydantic is not available
    # Simple data classes with basic validation

    @dataclass
    class ScanConfig:
        """Fallback scan configuration."""

        repo_url: str
        scan_type: str = "full_repo"
        branch: str = "main"
        commit_range: Optional[str] = None
        file_path: Optional[str] = None
        max_calls_per_minute: int = 30
        request_timeout: int = 30
        follow_symlinks: bool = False
        max_file_size_mb: int = 10
        exclude_patterns: List[str] = None

        def __post_init__(self):
            is_valid, msg = validate_github_url(self.repo_url)
            if not is_valid:
                raise ValueError(f"Invalid GitHub URL: {self.repo_url}. {msg}")
            if self.exclude_patterns is None:
                self.exclude_patterns = []

    @dataclass
    class FileContent:
        """Fallback file content model."""

        filename: str
        content: str
        size_bytes: int
        mime_type: Optional[str] = None
        encoding: str = "utf-8"
        is_binary: bool = False

    @dataclass
    class SecretFinding:
        """Fallback secret finding model."""

        file_path: str
        line_number: int
        secret_type: str
        confidence: str
        redacted_value: str
        context: Optional[str] = None

    @dataclass
    class ScanResult:
        """Fallback scan result model."""

        repo_url: str
        scan_id: str
        status: str
        findings: List[SecretFinding]
        files_scanned: int
        secrets_found: int
        duration_seconds: float
        errors: List[str] = None


# ============================================================================
# ADDITIONAL UTILITY FUNCTIONS
# ============================================================================


def generate_scan_id(repo_url: str, timestamp: float) -> str:
    """
    Generate a unique scan ID.

    Args:
        repo_url: Repository URL
        timestamp: Unix timestamp

    Returns:
        Unique scan identifier
    """
    data = f"{repo_url}:{timestamp}"
    hash_obj = hashlib.sha256(data.encode())
    return f"scan_{hash_obj.hexdigest()[:16]}"


def validate_rate_limit_config(max_calls: int, period: int) -> bool:
    """
    Validate rate limiting configuration.

    Args:
        max_calls: Maximum calls per period
        period: Time period in seconds

    Returns:
        True if configuration is valid
    """
    if max_calls < 1 or max_calls > 10000:
        return False
    if period < 1 or period > 3600:
        return False
    return True


def is_safe_filename(filename: str) -> bool:
    """
    Check if filename is safe (no path traversal).

    Args:
        filename: The filename to check

    Returns:
        True if safe, False otherwise
    """
    if not filename:
        return False

    # Check for path traversal attempts
    dangerous_patterns = [
        "..",  # Parent directory reference
        "~",  # Home directory
    ]

    # Check for absolute paths
    if filename.startswith("/") or filename.startswith("\\"):
        return False
    if ":" in filename:  # Windows drive letters
        return False

    # Check for dangerous patterns
    for pattern in dangerous_patterns:
        if pattern in filename:
            return False

    return True


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    # Validation functions
    "validate_github_url",
    "detect_prompt_injection",
    "sanitize_input",
    "validate_token_scope",
    "check_no_dynamic_code",
    "get_dangerous_patterns_report",
    "redact_secret",
    "redact_token_prefix",
    "generate_scan_id",
    "validate_rate_limit_config",
    "is_safe_filename",
    # Decorators
    "rate_limit",
    "RateLimitExceeded",
    # Models (or fallback classes)
    "ScanConfig",
    "FileContent",
    "SecretFinding",
    "ScanResult",
    # Enums
    "ScanType",
]
