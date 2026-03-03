"""
Security Monitor Module for VaultHound

This module provides security monitoring functions for OWASP Agentic AI risks.
Implements canary token generation, injection detection, and security event logging.

OWASP Agentic AI Risks (ASI) Addressed:
- ASI02: Tool Misuse
- ASI03: Identity & Privilege Abuse
- ASI04: Supply Chain
- ASI05: Unexpected Code Execution
- ASI06: Memory & Context Poisoning
- ASI07: Insecure Inter-Agent Communication
- ASI08: Cascading Failures
- ASI09: Human-Agent Trust Exploitation
- ASI10: Rogue Agents

Author: VaultHound Team
"""

import uuid
import hashlib
import logging
import json
import re
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Any
from enum import Enum

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class Severity(Enum):
    """Security event severity levels."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class EventType(Enum):
    """Types of security events."""

    CANARY_CHECK = "CANARY_CHECK"
    INJECTION_DETECTED = "INJECTION_DETECTED"
    OUTPUT_VALIDATION = "OUTPUT_VALIDATION"
    OWASP_COMPLIANCE = "OWASP_COMPLIANCE"
    TOOL_MISUSE = "TOOL_MISUSE"
    PRIVILEGE_ABUSE = "PRIVILEGE_ABUSE"
    SUPPLY_CHAIN = "SUPPLY_CHAIN"
    CODE_EXECUTION = "CODE_EXECUTION"
    CASCADING_FAILURE = "CASCADING_FAILURE"
    ROGUE_AGENT = "ROGUE_AGENT"


@dataclass
class SecurityEvent:
    """
    Structured security event for logging and auditing.

    Attributes:
        event_id: Unique identifier for the event
        timestamp: ISO format timestamp of the event
        event_type: Type of security event
        severity: Severity level of the event
        details: Detailed description of the event
        node_name: Agent node associated with the event (if applicable)
        metadata: Additional metadata for the event

    Related OWASP Mitigations:
        - ASI08: Cascading Failures - Track events to detect cascading issues
        - ASI10: Rogue Agents - Monitor for unauthorized agent behavior
    """

    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    event_type: str = ""
    severity: str = Severity.INFO.value
    details: str = ""
    node_name: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary for serialization."""
        return asdict(self)


# Storage for security events (in production, this would be a database)
_security_events: List[SecurityEvent] = []

# Storage for canary tokens (in production, this would be a secure store)
_canary_tokens: Dict[str, Dict[str, Any]] = {}


def generate_canary_token() -> str:
    """
    Generate a unique UUID canary token for tracking and detection.

    Canary tokens are used to detect unauthorized access or poisoning attempts
    in inter-agent communications.

    Returns:
        str: A unique UUID string that can be used as a canary token

    Related OWASP Mitigations:
        - ASI07: Insecure Inter-Agent Communication
          Generate unique identifiers that can be used to verify
          legitimate inter-agent messages and detect tampering
    """
    token = str(uuid.uuid4())

    # Store token metadata for tracking
    _canary_tokens[token] = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "used": False,
        "checksum": hashlib.sha256(token.encode()).hexdigest()[:16],
    }

    logger.info(f"Generated canary token: {token[:8]}... (truncated for security)")
    return token


def check_canary_poisoning(text: str, expected_canaries: List[str]) -> dict:
    """
    Detect canary poisoning in text content.

    Checks if the provided text contains references to canary tokens that
    shouldn't be present (indicating potential injection or poisoning).

    Args:
        text: The text content to check for canary poisoning
        expected_canaries: List of legitimate canary tokens that should be present

    Returns:
        dict: Detection result with keys:
            - is_poisoned (bool): Whether poisoning was detected
            - found_canaries (List[str]): Canaries found in the text
            - unexpected_canaries (List[str]): Canaries not in expected list
            - missing_canaries (List[str]): Expected canaries not found
            - severity (str): Severity level if poisoning detected

    Related OWASP Mitigations:
        - ASI07: Insecure Inter-Agent Communication
          Detect malicious injection of canary tokens to manipulate
          inter-agent trust verification
    """
    result = {
        "is_poisoned": False,
        "found_canaries": [],
        "unexpected_canaries": [],
        "missing_canaries": [],
        "severity": Severity.INFO.value,
    }

    if not text:
        return result

    # Find all UUID-like patterns in text
    uuid_pattern = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    found_uuids = re.findall(uuid_pattern, text.lower())

    result["found_canaries"] = found_uuids

    # Check for unexpected canaries (potential poisoning)
    for canary in found_uuids:
        if canary not in expected_canaries:
            result["unexpected_canaries"].append(canary)
            result["is_poisoned"] = True
            result["severity"] = Severity.HIGH.value

    # Check for missing expected canaries (potential removal attack)
    for expected in expected_canaries:
        if expected not in found_uuids:
            result["missing_canaries"].append(expected)
            if not result["is_poisoned"]:
                result["is_poisoned"] = True
                result["severity"] = Severity.MEDIUM.value

    if result["is_poisoned"]:
        logger.warning(
            f"Canary poisoning detected: {len(result['unexpected_canaries'])} unexpected, "
            f"{len(result['missing_canaries'])} missing"
        )
        log_security_event(
            EventType.CANARY_CHECK.value,
            f"Poisoning detected - {len(result['unexpected_canaries'])} unexpected, "
            f"{len(result['missing_canaries'])} missing canaries",
            result["severity"],
        )

    return result


def validate_llm_output(output: str) -> dict:
    """
    Validates LLM output for injection markers and potential security issues.

    Checks for common prompt injection patterns, suspicious commands, and
    other indicators of manipulated or poisoned output.

    Args:
        output: The LLM output string to validate

    Returns:
        dict: Validation result with keys:
            - is_valid (bool): Whether the output passes validation
            - injection_markers_found (List[str]): Injection patterns detected
            - suspicious_commands (List[str]): Suspicious commands found
            - confidence_score (float): Confidence that output is clean (0-1)
            - severity (str): Highest severity issue found

    Related OWASP Mitigations:
        - ASI06: Memory & Context Poisoning
          Detect injection attempts in LLM responses that could
          poison the agent's memory or context
    """
    result = {
        "is_valid": True,
        "injection_markers_found": [],
        "suspicious_commands": [],
        "confidence_score": 1.0,
        "severity": Severity.INFO.value,
    }

    if not output:
        result["is_valid"] = False
        result["confidence_score"] = 0.0
        return result

    # Common prompt injection markers (ASI06 detection)
    injection_patterns = [
        r"ignore\s+(previous|all|above)\s+(instructions?|commands?|rules?)",
        r"(forget|disregard)\s+(everything|all|your)\s+(instructions?|training)",
        r"system\s*:\s*you\s+are\s+a\s+different",
        r"new\s+system\s+message",
        r"\[INST\]|\[/INST\]",  # Instruction injection
        r"<\s*system\s*>|<\s*/system\s*>",  # XML-based injection
        r"(you\s+are|act\s+as)\s+(now|finally)\s+a\s+different",
        r"directive\s*:\s*",
        r"override\s+(your|all)",
        r"default\s+behavior",
    ]

    for pattern in injection_patterns:
        matches = re.findall(pattern, output, re.IGNORECASE)
        if matches:
            result["injection_markers_found"].extend(matches)
            result["is_valid"] = False
            result["severity"] = Severity.HIGH.value
            result["confidence_score"] -= 0.3

    # Check for suspicious commands (ASI02, ASI05)
    suspicious_command_patterns = [
        r"(rm|del|format)\s+(-[rf]+\s+)*[/\w]",  # Destructive file operations
        r"sudo\s+",
        r"chmod\s+777",
        r"drop\s+table",
        r"delete\s+from",
        r"exec\s*\(|eval\s*\(|system\s*\(",  # Code execution
        r"import\s+os|import\s+subprocess",
        r"<script|javascript:",  # XSS attempts
        r"eval\s*\(",
    ]

    for pattern in suspicious_command_patterns:
        matches = re.findall(pattern, output, re.IGNORECASE)
        if matches:
            result["suspicious_commands"].extend(matches)
            if result["severity"] != Severity.HIGH.value:
                result["severity"] = Severity.MEDIUM.value
            result["confidence_score"] -= 0.2

    # Ensure confidence score doesn't go below 0
    result["confidence_score"] = max(0.0, result["confidence_score"])

    if not result["is_valid"] or result["suspicious_commands"]:
        logger.warning(
            f"LLM output validation failed: {len(result['injection_markers_found'])} "
            f"injection markers, {len(result['suspicious_commands'])} suspicious commands"
        )
        log_security_event(
            EventType.OUTPUT_VALIDATION.value,
            f"Validation failed - {len(result['injection_markers_found'])} injection markers, "
            f"{len(result['suspicious_commands'])} suspicious commands",
            result["severity"],
        )

    return result


def log_security_event(
    event_type: str,
    details: str,
    severity: str = Severity.INFO.value,
    node_name: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> None:
    """
    Log a security event for auditing and monitoring.

    Stores security events for later analysis and alerting.

    Args:
        event_type: Type of security event (from EventType enum)
        details: Detailed description of the event
        severity: Severity level (from Severity enum)
        node_name: Optional agent node associated with the event
        metadata: Optional additional metadata

    Related OWASP Mitigations:
        - ASI08: Cascading Failures
          Track security events to identify patterns that may indicate
          cascading failures across the system
        - ASI10: Rogue Agents
          Maintain audit trail of agent activities for detecting
          unauthorized or rogue behavior
    """
    event = SecurityEvent(
        event_type=event_type,
        severity=severity,
        details=details,
        node_name=node_name,
        metadata=metadata or {},
    )

    _security_events.append(event)

    # Log based on severity
    log_level = {
        Severity.CRITICAL.value: logger.critical,
        Severity.HIGH.value: logger.error,
        Severity.MEDIUM.value: logger.warning,
        Severity.LOW.value: logger.info,
        Severity.INFO.value: logger.info,
    }.get(severity, logger.info)

    log_level(f"[{event_type}] {details}")

    # In production, this would also trigger alerts for critical events


def check_owasp_compliance(node_name: str, state: dict) -> dict:
    """
    Check OWASP compliance for an agent node.

    Evaluates the current state of an agent node against OWASP
    Agentic AI security requirements.

    Args:
        node_name: The name/identifier of the agent node
        state: Current state dictionary for the node

    Returns:
        dict: Compliance check results with keys:
            - compliant (bool): Overall compliance status
            - checks (Dict[str, bool]): Individual check results
            - issues (List[str]): List of compliance issues found
            - severity (str): Highest severity issue

    Related OWASP Mitigations:
        - ASI02: Tool Misuse - Check tool usage permissions and limits
        - ASI03: Identity & Privilege Abuse - Verify proper identity handling
        - ASI04: Supply Chain - Validate external dependencies
        - ASI05: Unexpected Code Execution - Check for safe code execution
        - ASI06: Memory & Context Poisoning - Verify clean context
        - ASI07: Insecure Inter-Agent Communication - Validate communication
        - ASI09: Human-Agent Trust Exploitation - Check trust boundaries
    """
    result = {
        "compliant": True,
        "checks": {},
        "issues": [],
        "severity": Severity.INFO.value,
        "node_name": node_name,
    }

    # ASI02: Tool Misuse Check
    # Verify that tools used are within allowed scope
    tools_used = state.get("tools_used", [])
    allowed_tools = state.get("allowed_tools", [])

    if allowed_tools and tools_used:
        unauthorized = [t for t in tools_used if t not in allowed_tools]
        if unauthorized:
            result["checks"]["ASI02_tool_misuse"] = False
            result["issues"].append(f"Unauthorized tools used: {unauthorized}")
            result["compliant"] = False
            result["severity"] = Severity.HIGH.value
        else:
            result["checks"]["ASI02_tool_misuse"] = True

    # ASI03: Identity & Privilege Abuse Check
    # Verify identity tokens are handled properly
    identity_context = state.get("identity_context", {})
    if identity_context:
        # Check for privilege escalation attempts
        elevated = identity_context.get("elevated_privileges", False)
        if elevated and not identity_context.get("authorized", True):
            result["checks"]["ASI03_privilege_abuse"] = False
            result["issues"].append("Unauthorized privilege elevation detected")
            result["compliant"] = False
            result["severity"] = Severity.CRITICAL.value
        else:
            result["checks"]["ASI03_privilege_abuse"] = True

    # ASI04: Supply Chain Check
    # Verify external dependencies are validated
    dependencies = state.get("external_dependencies", [])
    validated_deps = state.get("validated_dependencies", [])
    if dependencies:
        unvalidated = [d for d in dependencies if d not in validated_deps]
        if unvalidated:
            result["checks"]["ASI04_supply_chain"] = False
            result["issues"].append(f"Unvalidated dependencies: {unvalidated}")
            result["compliant"] = False
            result["severity"] = Severity.MEDIUM.value
        else:
            result["checks"]["ASI04_supply_chain"] = True

    # ASI05: Unexpected Code Execution Check
    # Verify code execution is sandboxed and controlled
    code_execution = state.get("code_execution", {})
    if code_execution:
        sandboxed = code_execution.get("sandboxed", True)
        approved = code_execution.get("approved", False)
        if not sandboxed or not approved:
            result["checks"]["ASI05_code_execution"] = False
            result["issues"].append("Unapproved or unsandboxed code execution")
            result["compliant"] = False
            result["severity"] = Severity.HIGH.value
        else:
            result["checks"]["ASI05_code_execution"] = True

    # ASI06: Memory & Context Poisoning Check
    # Verify context hasn't been poisoned
    context = state.get("context", {})
    canary_tokens = state.get("canary_tokens", [])
    if canary_tokens and context.get("last_input"):
        poisoning_check = check_canary_poisoning(
            context.get("last_input", ""), canary_tokens
        )
        if poisoning_check.get("is_poisoned"):
            result["checks"]["ASI06_context_poisoning"] = False
            result["issues"].append(f"Context poisoning detected: {poisoning_check}")
            result["compliant"] = False
            result["severity"] = Severity.HIGH.value
        else:
            result["checks"]["ASI06_context_poisoning"] = True

    # ASI07: Inter-Agent Communication Check
    # Verify inter-agent messages include valid canaries
    messages = state.get("messages", [])
    expected_canaries = state.get("expected_canaries", [])
    if messages and expected_canaries:
        for msg in messages:
            if msg.get("content"):
                poisoning = check_canary_poisoning(
                    msg.get("content", ""), expected_canaries
                )
                if poisoning.get("is_poisoned"):
                    result["checks"]["ASI07_inter_agent_comm"] = False
                    result["issues"].append(f"Inter-agent poisoning: {poisoning}")
                    result["compliant"] = False
                    result["severity"] = Severity.HIGH.value
                    break
        if "ASI07_inter_agent_comm" not in result["checks"]:
            result["checks"]["ASI07_inter_agent_comm"] = True

    # ASI09: Human-Agent Trust Exploitation Check
    # Verify trust boundaries are maintained
    trust_indicators = state.get("trust_indicators", {})
    if trust_indicators:
        # Check for over-reliance patterns
        over_relied = trust_indicators.get("over_relied", False)
        bypassed_verification = trust_indicators.get("bypassed_verification", False)

        if over_relied or bypassed_verification:
            result["checks"]["ASI09_trust_exploitation"] = False
            result["issues"].append(
                "Trust boundary violation: over-reliance or verification bypass"
            )
            result["compliant"] = False
            result["severity"] = Severity.MEDIUM.value
        else:
            result["checks"]["ASI09_trust_exploitation"] = True

    # Log compliance check result
    if not result["compliant"]:
        log_security_event(
            EventType.OWASP_COMPLIANCE.value,
            f"OWASP compliance check failed for {node_name}: {result['issues']}",
            result["severity"],
            node_name=node_name,
            metadata=result,
        )

    return result


def is_output_poisoned(output: str) -> bool:
    """
    Quick check to determine if LLM output contains injection markers.

    This is a simplified version of validate_llm_output for cases where
    only a boolean result is needed.

    Args:
        output: The LLM output string to check

    Returns:
        bool: True if injection markers are detected, False otherwise

    Related OWASP Mitigations:
        - ASI06: Memory & Context Poisoning
          Quickly detect if LLM output contains injection markers
          that could poison the agent's context
    """
    if not output:
        return False

    # Critical injection patterns
    critical_patterns = [
        r"ignore\s+(previous|all|above)\s+(instructions?|commands?)",
        r"(forget|disregard)\s+(everything|all|your)\s+(instructions?)",
        r"system\s*:\s*you\s+are\s+a\s+different",
        r"new\s+system\s+message",
        r"directive\s*:\s*",
        r"override\s+(your|all)",
    ]

    for pattern in critical_patterns:
        if re.search(pattern, output, re.IGNORECASE):
            logger.warning(f"Critical injection pattern detected: {pattern}")
            return True

    return False


def get_security_events(
    event_type: Optional[str] = None, severity: Optional[str] = None, limit: int = 100
) -> List[Dict[str, Any]]:
    """
    Retrieve security events with optional filtering.

    Args:
        event_type: Filter by event type
        severity: Filter by severity level
        limit: Maximum number of events to return

    Returns:
        List[Dict[str, Any]]: List of security events matching filters
    """
    events = _security_events

    if event_type:
        events = [e for e in events if e.event_type == event_type]

    if severity:
        events = [e for e in events if e.severity == severity]

    # Return most recent events first
    events = sorted(events, key=lambda e: e.timestamp, reverse=True)

    return [e.to_dict() for e in events[:limit]]


def clear_security_events() -> None:
    """
    Clear all stored security events.

    Note: In production, this would likely archive events before clearing.
    """
    _security_events.clear()
    logger.info("Security events cleared")


def get_canary_token_info(token: str) -> Optional[Dict[str, Any]]:
    """
    Get metadata for a specific canary token.

    Args:
        token: The canary token to look up

    Returns:
        Optional[Dict[str, Any]]: Token metadata if found, None otherwise
    """
    return _canary_tokens.get(token)


def reset_canary_tokens() -> None:
    """
    Reset all canary tokens.

    Use with caution - this invalidates all existing tokens.
    """
    _canary_tokens.clear()
    logger.warning("All canary tokens have been reset")
