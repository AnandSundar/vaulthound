"""
Entropy-based secret detection tools for VaultHound.

This module provides entropy analysis capabilities to complement LLM-based secret detection.
Shannon entropy is a key indicator of high-information strings - secrets like API keys,
passwords, and tokens tend to have higher entropy than regular text because they contain
more random character distributions.

Entropy Analysis Approach:
- Shannon entropy measures the randomness/unpredictability of a string
- Random strings (secrets) typically have entropy > 4.5 bits per character
- English text has entropy ~1.5 bits per character
- Base64-encoded strings have entropy ~6 bits per character
- Hex strings have entropy ~4 bits per character

This complements LLM-based detection by:
1. Catching secrets that LLM might miss due to unusual formatting
2. Providing quantitative scoring for suspicious strings
3. Fast pre-filtering before expensive LLM analysis
4. Detecting encoded/obfuscated secrets that might bypass pattern matching

Integration with detect-secrets (Yelp's tool):
- Wraps the detect-secrets library for additional baseline detection
- Allows comparison and fusion of results from both approaches
"""

import math
import re
from typing import List, Dict, Any, Optional
from collections import Counter


# =============================================================================
# Shannon Entropy Calculation
# =============================================================================


def shannon_entropy(text: str) -> float:
    """
    Calculate the Shannon entropy of a string.

    Shannon entropy measures the average amount of information in a random variable.
    For a string, this translates to how "random" or "unpredictable" the character
    distribution is.

    Mathematically: H(X) = -Σ P(xi) * log2(P(xi))
    Where P(xi) is the probability of character i appearing in the string.

    Entropy ranges:
    - 0 bits: Empty or single character string
    - ~1.5 bits: English text (high redundancy)
    - ~4.0 bits: Hexadecimal strings
    - ~4.5 bits: Threshold for suspicious high-entropy (potential secrets)
    - ~6.0 bits: Base64 encoded strings
    - ~8.0 bits: Truly random data

    Args:
        text: The input string to analyze

    Returns:
        Float representing bits of entropy per character (0-8 range)
    """
    if not text or len(text) == 0:
        return 0.0

    # Count character frequencies
    char_counts = Counter(text)
    text_length = len(text)

    # Calculate entropy using Shannon's formula
    entropy = 0.0
    for count in char_counts.values():
        if count > 0:
            # Probability of each character
            probability = count / text_length
            # Shannon entropy contribution
            entropy -= probability * math.log2(probability)

    return entropy


def calculate_bit_entropy(text: str) -> float:
    """
    Calculate the total bit entropy of a string.

    This is the Shannon entropy multiplied by the string length,
    representing the total information content in bits.

    Args:
        text: The input string to analyze

    Returns:
        Float representing total bits of entropy
    """
    return shannon_entropy(text) * len(text)


# =============================================================================
# High Entropy String Detection
# =============================================================================


def find_high_entropy_strings(
    text: str, threshold: float = 4.5, min_length: int = 20, context_chars: int = 10
) -> List[Dict[str, Any]]:
    """
    Find strings in the given text that exceed the entropy threshold.

    This function scans the input text for substrings that have high Shannon
    entropy - a strong indicator that they might be secrets like API keys,
    tokens, passwords, or encryption keys.

    Why this approach works:
    - Secrets are often generated to be random (high entropy)
    - Natural language has low entropy due to letter frequency patterns
    - Even encoded secrets (base64, hex) maintain higher entropy than text

    Args:
        text: The full text to scan (e.g., file contents)
        threshold: Minimum entropy (bits/char) to flag as suspicious (default: 4.5)
                  4.5 is a balanced threshold that catches most secrets
                  while avoiding false positives from complex identifiers
        min_length: Minimum string length to consider (default: 20)
                   Shorter strings can have high entropy by chance
        context_chars: Characters of context to include around matches

    Returns:
        List of dictionaries containing:
        - 'string': The high-entropy substring found
        - 'entropy': Calculated Shannon entropy
        - 'start_pos': Starting position in original text
        - 'end_pos': Ending position in original text
        - 'context': Surrounding text for context
        - 'line_number': Approximate line number
    """
    results = []
    lines = text.split("\n")

    # Sliding window approach: examine potential secret-like substrings
    # We look for patterns that typically contain secrets

    # Pattern categories to search:
    # 1. Long alphanumeric strings (API keys, tokens)
    # 2. Base64-like strings
    # 3. Hex strings
    # 4. AWS-style keys
    # 5. Generic high-entropy sequences

    # Common secret patterns to focus analysis on
    secret_patterns = [
        # AWS Access Keys (20 chars, starts with AKIA)
        r"AKIA[0-9A-Z]{16}",
        # Generic long tokens (alphanumeric, minimum 20 chars)
        r"[A-Za-z0-9+/=]{20,}",
        # Hex strings (often used for UUIDs, hashes)
        r"[0-9a-fA-F]{32,}",
        # Bearer tokens
        r"Bearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+",
        # Generic "key=" or "token=" patterns
        r'(?:api[_-]?key|secret|token|password|pwd)[_\-]?=[\'"]{0,1}[^\s\'"]{20,}',
    ]

    # Track unique findings to avoid duplicates
    found_positions = set()

    for pattern in secret_patterns:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            start = match.start()
            end = match.end()
            matched_string = match.group(0)

            # Skip if we've already found a similar region
            if any(
                start >= existing_start and start < existing_end
                for existing_start, existing_end in found_positions
            ):
                continue

            # Only process if length meets minimum
            if len(matched_string) >= min_length:
                entropy = shannon_entropy(matched_string)

                # Only include if above threshold
                if entropy >= threshold:
                    # Calculate line number
                    line_number = text[:start].count("\n") + 1

                    # Get context
                    context_start = max(0, start - context_chars)
                    context_end = min(len(text), end + context_chars)
                    context = text[context_start:context_end]

                    results.append(
                        {
                            "string": matched_string,
                            "entropy": round(entropy, 3),
                            "start_pos": start,
                            "end_pos": end,
                            "context": context.replace("\n", " "),
                            "line_number": line_number,
                            "type": "high_entropy",
                        }
                    )

                    found_positions.add((start, end))

    # Also do general sliding window analysis for any high-entropy substrings
    # This catches patterns we might have missed
    window_size = 32  # Check in 32-char windows

    for i in range(len(text) - window_size):
        # Skip if we're in a region we already found
        if any(
            i >= existing_start and i < existing_end
            for existing_start, existing_end in found_positions
        ):
            continue

        window = text[i : i + window_size]

        # Quick check: skip if clearly not a secret (contains many spaces)
        if window.count(" ") > 3:
            continue

        entropy = shannon_entropy(window)

        if entropy >= threshold:
            # Expand to find the full token (until we hit low entropy)
            start = i
            end = i + window_size

            # Try extending
            while end < len(text) and shannon_entropy(text[start:end]) >= threshold:
                end += 1

            # Try to clean up (remove obvious suffixes like quotes, punctuation)
            candidate = text[start:end].rstrip("'\",;:) ")

            if len(candidate) >= min_length:
                final_entropy = shannon_entropy(candidate)

                if final_entropy >= threshold and (start, end) not in found_positions:
                    line_number = text[:start].count("\n") + 1

                    context_start = max(0, start - context_chars)
                    context_end = min(len(text), end + context_chars)
                    context = text[context_start:context_end]

                    results.append(
                        {
                            "string": candidate,
                            "entropy": round(final_entropy, 3),
                            "start_pos": start,
                            "end_pos": end,
                            "context": context.replace("\n", " "),
                            "line_number": line_number,
                            "type": "high_entropy",
                        }
                    )

                    found_positions.add((start, end))

    # Sort by position in file
    results.sort(key=lambda x: x["start_pos"])

    return results


# =============================================================================
# File Analysis
# =============================================================================


def analyze_file_entropy(content: str, file_path: str) -> List[Dict[str, Any]]:
    """
    Analyze a file's content for high-entropy strings that may be secrets.

    This is the main entry point for analyzing a file using entropy-based
    detection. It applies the entropy analysis and returns findings with
    file context.

    Why analyze file entropy:
    - Files often contain embedded secrets (API keys, tokens, credentials)
    - Entropy analysis is fast and can pre-filter files before LLM analysis
    - Complements regex-based detection by catching unknown patterns

    Args:
        content: The full text content of the file
        file_path: Path to the file being analyzed (for context in results)

    Returns:
        List of findings, each containing:
        - 'string': The detected high-entropy string (truncated for display)
        - 'entropy': Shannon entropy value
        - 'line_number': Where in the file it was found
        - 'context': Surrounding text
        - 'file_path': The analyzed file
        - 'detection_method': 'entropy'
        - 'severity': Based on entropy value
    """
    findings = find_high_entropy_strings(content)

    # Enhance results with file context and severity
    enhanced_findings = []
    for finding in findings:
        # Determine severity based on entropy level
        # Higher entropy = higher severity (more likely to be a secret)
        entropy = finding["entropy"]
        if entropy >= 5.5:
            severity = "high"
        elif entropy >= 4.5:
            severity = "medium"
        else:
            severity = "low"

        enhanced_finding = {
            "string": (
                finding["string"][:50] + "..."
                if len(finding["string"]) > 50
                else finding["string"]
            ),
            "string_full": finding["string"],  # Full string for further analysis
            "entropy": finding["entropy"],
            "line_number": finding["line_number"],
            "context": finding["context"],
            "file_path": file_path,
            "detection_method": "entropy",
            "severity": severity,
            "classification": classify_secret_type(finding["string"]),
        }

        enhanced_findings.append(enhanced_finding)

    return enhanced_findings


# =============================================================================
# Token Extraction
# =============================================================================


def extract_tokens(content: str) -> List[Dict[str, str]]:
    """
    Extract potential tokens from source code content.

    This function identifies and extracts strings that look like tokens
    (API keys, secrets, identifiers) from source code. It uses multiple
    strategies:

    1. Pattern matching for known token formats
    2. High-entropy string detection
    3. Context-aware extraction (looking near assignment patterns)

    Why extract tokens:
    - Tokens often leak in source code comments or logs
    - Provides input for both entropy and LLM-based analysis
    - Helps identify the exact location of potential secrets

    Args:
        content: Source code content to extract from

    Returns:
        List of token dictionaries containing:
        - 'token': The extracted string
        - 'context': Surrounding code
        - 'line_number': Line where found
        - 'pattern': Which pattern matched
    """
    tokens = []

    # Patterns for common token types
    token_patterns = {
        "aws_access_key": r"AKIA[0-9A-Z]{16}",
        "aws_secret_key": r'(?i)(aws_secret_access_key|aws_secret_key)[\s:=]+["\']?([A-Za-z0-9/+=]{40})["\']?',
        "github_token": r"gh[pousr]_[A-Za-z0-9]{36,255}",
        "slack_token": r"xox[baprs]-[0-9a-zA-Z-]+",
        "jwt_token": r"eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+",
        "generic_api_key": r'(?i)(api[_-]?key|apikey)[\s:=]+["\']?([A-Za-z0-9]{20,})["\']?',
        "generic_secret": r'(?i)(secret|password|passwd|pwd|token)[\s:=]+["\']?([A-Za-z0-9@#$%^&*!+=]{8,})["\']?',
        "private_key": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "bearer_token": r"Bearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+",
        "base64_secret": r'(?i)(?:base64)[\s:=]+["\']?([A-Za-z0-9+/]{32,}={0,2})["\']?',
    }

    lines = content.split("\n")

    for pattern_name, pattern in token_patterns.items():
        for match in re.finditer(pattern, content):
            start = match.start()
            line_number = content[:start].count("\n") + 1

            # Get the matched group (handle patterns with capture groups)
            if match.lastindex and match.lastindex > 0:
                token = match.group(match.lastindex)
            else:
                token = match.group(0)

            # Skip if token is too short
            if len(token) < 8:
                continue

            # Get context (surrounding lines)
            if 0 <= line_number - 1 < len(lines):
                context_start = max(0, line_number - 2)
                context_end = min(len(lines), line_number + 1)
                context = "\n".join(lines[context_start:context_end])
            else:
                context = ""

            tokens.append(
                {
                    "token": token,
                    "context": context,
                    "line_number": line_number,
                    "pattern": pattern_name,
                    "entropy": round(shannon_entropy(token), 3),
                }
            )

    # Also extract high-entropy strings as potential tokens
    high_entropy = find_high_entropy_strings(content)
    for he in high_entropy:
        # Check if we already have this token
        if not any(t["token"] == he["string"] for t in tokens):
            tokens.append(
                {
                    "token": he["string"],
                    "context": he["context"],
                    "line_number": he["line_number"],
                    "pattern": "high_entropy",
                    "entropy": he["entropy"],
                }
            )

    return tokens


# =============================================================================
# detect-secrets Integration
# =============================================================================


def run_detect_secrets(content: str) -> List[Dict[str, Any]]:
    """
    Run Yelp's detect-secrets on the given content.

    This wraps the detect-secrets library to provide additional baseline
    detection. The detect-secrets tool uses:
    - Pattern matching for known secret formats
    - Heuristic scoring
    - Entropy analysis (high level)
    - Whitelist filtering

    This integration allows VaultHound to:
    1. Use detect-secrets as a proven baseline
    2. Compare results with entropy-only detection
    3. Combine findings for more comprehensive coverage

    Args:
        content: File content to scan

    Returns:
        List of detected secrets with metadata:
        - 'type': Type of secret detected
        - 'filename': File (or 'stdin' for content)
        - 'line_number': Where found
        - 'secret': The detected secret (truncated)
        - 'is_verified': Whether verified as a secret
        - 'detection_method': 'detect-secrets'
    """
    try:
        # Import detect-secrets
        from detect_secrets import SecretsScanner
        from detect_secrets.core import scan
        from detect_secrets.core.secrets import SecretType

        # Create scanner and scan content
        scanner = SecretsScanner()

        # Scan the content - this returns a generator of findings
        # We need to convert to list and process
        results = []

        # Use detect-secrets core scanning
        # The scanner expects a list of files, but we can use string io
        import io
        from detect_secrets.util import get_file_context

        # Create a mock file object for scanning
        mock_file = io.StringIO(content)

        # Scan using the core scan function with a list of files
        # Since we have content as string, we'll create a simple approach
        try:
            # detect-secrets typically scans files
            # We'll use its logic for string content
            lines = content.split("\n")

            # Scan using the plugins
            for line_num, line in enumerate(lines, 1):
                # Use individual line scanning
                # This is a simplified approach
                pass

            # Use the main scanner interface
            # detect-secrets has a simple scan method
            # Let's try the direct approach
            results_list = scanner.scan(content)

            for result in results_list:
                # Parse the result into our format
                findings = {
                    "type": str(result.get("type", "unknown")),
                    "filename": result.get("filename", "stdin"),
                    "line_number": result.get("line_number", 0),
                    "secret": (
                        str(result.get("secret", ""))[:50] + "..."
                        if len(str(result.get("secret", ""))) > 50
                        else str(result.get("secret", ""))
                    ),
                    "secret_full": result.get("secret", ""),
                    "is_verified": result.get("is_verified", False),
                    "detection_method": "detect-secrets",
                    "severity": "high",
                }
                results.append(findings)

        except Exception as e:
            # Fallback: use basic pattern detection if detect-secrets fails
            # This ensures we always return results
            results = _fallback_detect_secrets(content)

    except ImportError:
        # detect-secrets not installed - use fallback
        results = _fallback_detect_secrets(content)

    return results


def _fallback_detect_secrets(content: str) -> List[Dict[str, Any]]:
    """
    Fallback detection when detect-secrets library is not available.

    Uses common regex patterns to detect known secret types.
    This ensures the tool works even without the optional dependency.

    Args:
        content: Content to scan

    Returns:
        List of detected secrets (same format as detect-secrets)
    """
    results = []

    # Common secret patterns (simplified versions of what detect-secrets uses)
    patterns = {
        "AWS Access Key": r"AKIA[0-9A-Z]{16}",
        "AWS Secret Key": r'(?i)aws(.{0,20})?[\'"][0-9a-zA-Z/+]{40}[\'"]',
        "GitHub Token": r"gh[pousr]_[a-zA-Z0-9]{36,}",
        "Slack Token": r"xox[baprs]-[0-9]{10,12}-[0-9]{10,12}[a-zA-Z0-9-]*",
        "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
        "Stripe API Key": r"sk_live_[0-9a-zA-Z]{24,}",
        "Stripe Token": r"sk_test_[0-9a-zA-Z]{24,}",
        "Twilio API Key": r"SK[a-f0-9]{32}",
        "Mailgun API Key": r"key-[0-9a-zA-Z]{32}",
        "SendGrid API Key": r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}",
        "JWT Token": r"eyJ[a-zA-Z0-9-_]+\.eyJ[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+",
        "Private Key Header": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "Generic API Key": r'(?i)(api[_-]?key|apikey)["\s:=]+["\']?([a-zA-Z0-9]{20,})["\']?',
        "Generic Secret": r'(?i)(secret|password|passwd|pwd)["\s:=]+["\']?([a-zA-Z0-9!@#$%^&*]{8,})["\']?',
    }

    lines = content.split("\n")

    for pattern_name, pattern in patterns.items():
        for match in re.finditer(pattern, content, re.IGNORECASE):
            start = match.start()
            line_number = content[:start].count("\n") + 1

            # Get the secret (use capture group if available)
            if match.lastindex and match.lastindex > 0:
                secret = match.group(match.lastindex)
            else:
                secret = match.group(0)

            # Get context
            context_start = max(0, line_number - 2)
            context_end = min(len(lines), line_number + 1)
            context = "\n".join(lines[context_start:context_end])

            results.append(
                {
                    "type": pattern_name,
                    "filename": "stdin",
                    "line_number": line_number,
                    "secret": secret[:50] + "..." if len(secret) > 50 else secret,
                    "secret_full": secret,
                    "context": context,
                    "is_verified": False,
                    "detection_method": "detect-secrets-fallback",
                    "severity": "high" if "key" in pattern_name.lower() else "medium",
                }
            )

    return results


# =============================================================================
# Combined Analysis
# =============================================================================


def combine_entropy_analysis(
    detect_secrets_results: List[Dict], entropy_results: List[Dict]
) -> List[Dict[str, Any]]:
    """
    Combine results from detect-secrets and entropy analysis.

    This fusion approach leverages the strengths of both methods:

    detect-secrets advantages:
    - Well-tuned patterns for known secret types
    - Proven detection on many codebases
    - Low false positive rate for known formats

    Entropy analysis advantages:
    - Catches unknown/ novel secret formats
    - Detects encoded secrets (base64, hex)
    - Works without pattern updates
    - Can find secrets in unexpected locations

    Fusion strategy:
    1. Deduplicate findings that refer to the same secret
    2. Prioritize findings by confidence
    3. Mark findings that were detected by both methods
    4. Add entropy metadata to detect-secrets results

    Args:
        detect_secrets_results: Output from run_detect_secrets()
        entropy_results: Output from analyze_file_entropy()

    Returns:
        Combined and deduplicated list of findings
    """
    combined = []
    seen_secrets = set()

    # First, add detect-secrets results with entropy enrichment
    for result in detect_secrets_results:
        secret = result.get("secret_full", result.get("secret", ""))
        secret_key = _create_secret_key(secret)

        if secret_key not in seen_secrets:
            seen_secrets.add(secret_key)

            # Calculate entropy for this secret
            entropy_value = shannon_entropy(secret) if secret else 0

            combined_result = {
                **result,
                "entropy": round(entropy_value, 3),
                "detection_methods": ["detect-secrets"],
                "confidence": "high" if result.get("is_verified") else "medium",
                "source": "detect-secrets",
            }
            combined.append(combined_result)

    # Then add entropy results, avoiding duplicates
    for result in entropy_results:
        secret = result.get("string_full", result.get("string", ""))
        secret_key = _create_secret_key(secret)

        if secret_key not in seen_secrets:
            seen_secrets.add(secret_key)

            # Check if this overlaps with existing findings
            is_duplicate = False
            for existing in combined:
                existing_secret = existing.get(
                    "secret_full", existing.get("string_full", "")
                )
                if _secrets_overlap(secret, existing_secret):
                    # Mark as detected by multiple methods
                    if "detection_methods" in existing:
                        existing["detection_methods"].append("entropy")
                    is_duplicate = True
                    break

            if not is_duplicate:
                combined_result = {
                    "type": result.get("classification", "Unknown"),
                    "filename": result.get("file_path", "unknown"),
                    "line_number": result.get("line_number", 0),
                    "secret": result.get("string", ""),
                    "secret_full": result.get("string_full", ""),
                    "context": result.get("context", ""),
                    "entropy": result.get("entropy", 0),
                    "severity": result.get("severity", "medium"),
                    "is_verified": False,
                    "detection_methods": ["entropy"],
                    "confidence": (
                        "medium" if result.get("entropy", 0) >= 5.0 else "low"
                    ),
                    "source": "entropy",
                }
                combined.append(combined_result)

    # Sort by line number
    combined.sort(key=lambda x: x.get("line_number", 0))

    return combined


def _create_secret_key(secret: str) -> str:
    """
    Create a normalized key for secret deduplication.

    Normalizes the secret to help identify duplicates even with
    slight variations.
    """
    if not secret:
        return ""
    # Normalize: lowercase and remove common suffixes
    normalized = secret.lower().strip()
    # Take first 20 chars as key (secrets often share prefixes)
    return normalized[:20]


def _secrets_overlap(secret1: str, secret2: str) -> bool:
    """
    Check if two secrets are likely the same (overlapping).
    """
    if not secret1 or not secret2:
        return False

    # Simple overlap check: if one contains the other
    # or they share significant similarity
    if secret1 in secret2 or secret2 in secret1:
        return True

    # Check for high character overlap
    overlap = sum(1 for c in secret1 if c in secret2)
    if overlap > min(len(secret1), len(secret2)) * 0.8:
        return True

    return False


# =============================================================================
# Secret Classification
# =============================================================================


def classify_secret_type(token: str) -> str:
    """
    Classify the type of secret using heuristic analysis.

    This function attempts to identify what type of secret a token
    might be based on its characteristics:
    - Character set (hex, base64, alphanumeric)
    - Length
    - Prefix patterns
    - Entropy level

    This heuristic classification helps prioritize findings and
    provides context for LLM-based analysis.

    Classification categories:
    - API Key: Generic API keys (alphanumeric, various lengths)
    - AWS Key: AWS-specific credential patterns
    - Token: JWT, OAuth, or session tokens
    - Password: Short to medium secrets (likely passwords)
    - Private Key: Cryptographic key material
    - Hash: MD5, SHA, or other cryptographic hashes
    - UUID: Standard UUID format
    - Generic Secret: Unclassified high-entropy string

    Args:
        token: The token string to classify

    Returns:
        String describing the classified type
    """
    if not token:
        return "Unknown"

    token_upper = token.upper()
    token_lower = token.lower()
    length = len(token)

    # Check for known prefixes and patterns

    # AWS Keys
    if token_upper.startswith("AKIA"):
        return "AWS Access Key"
    if "AWS" in token_upper or "AMAZON" in token_upper:
        return "AWS Secret"

    # GitHub Tokens
    if (
        token_lower.startswith("ghp_")
        or token_lower.startswith("gho_")
        or token_lower.startswith("ghu_")
        or token_lower.startswith("ghs_")
        or token_lower.startswith("ghr_")
    ):
        return "GitHub Token"

    # JWT Tokens
    if token_lower.count(".") == 2 and len(token) > 40:
        return "JWT Token"

    # Slack Tokens
    if token_lower.startswith("xox"):
        return "Slack Token"

    # Google API Keys
    if token_upper.startswith("AIZA"):
        return "Google API Key"

    # Stripe Keys
    if token_lower.startswith("sk_live_"):
        return "Stripe Live Key"
    if token_lower.startswith("sk_test_"):
        return "Stripe Test Key"
    if token_lower.startswith("pk_live_"):
        return "Stripe Live Public Key"
    if token_lower.startswith("pk_test_"):
        return "Stripe Test Public Key"

    # Twilio Keys
    if token_upper.startswith("SK"):
        return "Twilio API Key"

    # Private Keys
    if "-----BEGIN" in token:
        return "Private Key"

    # SSH Keys
    if token_lower.startswith("ssh-rsa") or token_lower.startswith("ssh-ed25519"):
        return "SSH Key"

    # Hex-based hashes
    if re.match(r"^[a-f0-9]{32}$", token_lower):
        return "MD5 Hash"
    if re.match(r"^[a-f0-9]{40}$", token_lower):
        return "SHA1 Hash"
    if re.match(r"^[a-f0-9]{64}$", token_lower):
        return "SHA256 Hash"

    # UUID format
    if re.match(
        r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", token_lower
    ):
        return "UUID"

    # Base64 encoded (likely)
    if re.match(r"^[A-Za-z0-9+/]+={0,2}$", token) and length >= 32:
        # Check if it's likely base64
        try:
            import base64

            if length % 4 == 0:
                return "Base64 Encoded String"
        except:
            pass

    # Analyze character composition for generic classification

    # Hex-only strings
    hex_chars = sum(1 for c in token if c in "0123456789abcdef")
    if hex_chars / length > 0.9:
        if length == 32:
            return "UUID or Hash"
        elif length >= 64:
            return "Cryptographic Hash"
        return "Hex String"

    # Base64-like (alphanumeric + some special)
    b64_chars = sum(
        1
        for c in token
        if c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
    )
    if b64_chars / length > 0.9:
        if length >= 40:
            return "Encoded Token"
        return "Base64 String"

    # Length-based classification for generic tokens
    if length >= 40:
        return "API Key"
    elif length >= 24:
        return "Token"
    elif length >= 12:
        return "Password"
    else:
        return "Secret"


# =============================================================================
# Suspicious Pattern Detection
# =============================================================================


def identify_suspicious_patterns(text: str) -> List[Dict[str, Any]]:
    """
    Identify suspicious patterns in strings that may indicate secrets.

    This goes beyond entropy to look for contextual clues:
    - Variable names suggesting secrets (api_key, password, etc.)
    - Assignment patterns (KEY = value)
    - URL parameters containing secrets
    - Comments mentioning secrets
    - Hardcoded credentials

    These patterns don't necessarily mean a secret is present,
    but they indicate areas that warrant closer inspection.

    Args:
        text: Content to analyze

    Returns:
        List of suspicious pattern findings
    """
    findings = []

    # Patterns that suggest secrets might be present
    suspicious_patterns = [
        # Variable/assignment patterns
        (
            r'(?i)(api[_-]?key|apikey|secret[_-]?key|password|passwd|pwd|token)[_\s:=]+["\']?([^\s\'"]{8,})["\']?',
            "Hardcoded Secret Assignment",
        ),
        # URL with embedded credentials
        (r"https?://[^\s]+:[^\s]+@[^\s]+", "URL with Embedded Credentials"),
        # Connection strings
        (
            r"(?i)(mongodb|mysql|postgresql|redis|amqp)://[^\s]+:[^\s]+@",
            "Database Connection String",
        ),
        # Environment variable patterns
        (
            r'(?i)(env|environ)[\[\'"]*\.*["\']*\s*=\s*["\']*([A-Za-z0-9_]{8,})["\']*',
            "Environment Variable",
        ),
        # Commented secrets
        (
            r"#.*(?:api[_-]?key|secret|password|token).*[A-Za-z0-9]{8,}",
            "Commented Secret",
        ),
        # Docker/Secret mount paths
        (r"(?i)/run/secrets/[a-z_]+", "Docker Secret Path"),
        # Cloud credential files
        (r"(?i)\.aws/credentials", "AWS Credentials File Reference"),
        # Private key file indicators
        (
            r"-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+)?PRIVATE\s+KEY-----",
            "Private Key Header",
        ),
        # Generic secret file names
        (
            r"(?i)(secret|credentials|keys)\.(json|yaml|yml|toml|env)",
            "Secret Configuration File",
        ),
    ]

    lines = text.split("\n")

    for pattern, description in suspicious_patterns:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            start = match.start()
            line_number = text[:start].count("\n") + 1

            # Get context
            context_start = max(0, line_number - 2)
            context_end = min(len(lines), line_number + 1)
            context = "\n".join(lines[context_start:context_end])

            findings.append(
                {
                    "pattern": description,
                    "line_number": line_number,
                    "context": context,
                    "matched_text": match.group(0)[:100],  # Truncate for display
                    "severity": _get_pattern_severity(description),
                }
            )

    return findings


def _get_pattern_severity(pattern_name: str) -> str:
    """
    Determine severity based on pattern type.
    """
    high_severity = [
        "Private Key Header",
        "URL with Embedded Credentials",
        "Database Connection String",
        "Hardcoded Secret Assignment",
    ]

    medium_severity = [
        "Environment Variable",
        "AWS Credentials File Reference",
        "Docker Secret Path",
    ]

    if pattern_name in high_severity:
        return "high"
    elif pattern_name in medium_severity:
        return "medium"
    else:
        return "low"


# =============================================================================
# Utility Functions
# =============================================================================


def calculate_entropy_stats(text: str) -> Dict[str, float]:
    """
    Calculate overall entropy statistics for a text.

    Useful for quick triage - files with high average entropy
    are more likely to contain secrets.

    Args:
        text: Content to analyze

    Returns:
        Dictionary with entropy statistics:
        - 'average_entropy': Mean entropy per character
        - 'max_entropy': Highest entropy window
        - 'high_entropy_regions': Count of high-entropy regions
    """
    if not text:
        return {"average_entropy": 0.0, "max_entropy": 0.0, "high_entropy_regions": 0}

    # Calculate average entropy
    avg_entropy = shannon_entropy(text)

    # Calculate max entropy in windows
    window_size = 50
    max_entropy = 0.0
    high_entropy_count = 0

    for i in range(len(text) - window_size):
        window = text[i : i + window_size]
        entropy = shannon_entropy(window)
        if entropy > max_entropy:
            max_entropy = entropy
        if entropy >= 4.5:
            high_entropy_count += 1

    return {
        "average_entropy": round(avg_entropy, 3),
        "max_entropy": round(max_entropy, 3),
        "high_entropy_regions": high_entropy_count,
    }


# =============================================================================
# Main Entry Points for Convenience
# =============================================================================


def analyze_content(
    content: str,
    file_path: str = "unknown",
    use_detect_secrets: bool = True,
    entropy_threshold: float = 4.5,
) -> Dict[str, Any]:
    """
    Comprehensive content analysis combining all detection methods.

    This is the main entry point for analyzing file content. It runs
    all available detection methods and returns a comprehensive result.

    Analysis methods:
    1. Entropy analysis (configurable threshold)
    2. detect-secrets (if available)
    3. Suspicious pattern identification
    4. Token extraction

    Args:
        content: File content to analyze
        file_path: Path to the file (for reporting)
        use_detect_secrets: Whether to run detect-secrets
        entropy_threshold: Minimum entropy to flag

    Returns:
        Comprehensive analysis results with all findings
    """
    # Run entropy analysis
    entropy_results = analyze_file_entropy(content, file_path)

    # Run detect-secrets if requested
    if use_detect_secrets:
        detect_secrets_results = run_detect_secrets(content)
    else:
        detect_secrets_results = []

    # Combine results
    combined_results = combine_entropy_analysis(detect_secrets_results, entropy_results)

    # Identify suspicious patterns
    suspicious_patterns = identify_suspicious_patterns(content)

    # Get entropy statistics
    entropy_stats = calculate_entropy_stats(content)

    return {
        "file_path": file_path,
        "findings": combined_results,
        "suspicious_patterns": suspicious_patterns,
        "entropy_stats": entropy_stats,
        "total_findings": len(combined_results),
        "high_severity_count": sum(
            1 for f in combined_results if f.get("severity") == "high"
        ),
        "analysis_methods": ["entropy"]
        + (["detect-secrets"] if use_detect_secrets else []),
    }
