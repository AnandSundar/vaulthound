"""
VaultHound UI Components Module

This module provides reusable UI components for the VaultHound secret scanning application.
All components use the autumn theme colors from theme.py and follow consistent styling patterns.

Components include:
- Sidebar configuration components
- Scan controls and progress displays
- Findings display with severity coloring
- Metrics and statistics displays
- Report generation components

Author: VaultHound Team
"""

import streamlit as st
import pandas as pd
from datetime import datetime
from typing import List, Optional, Dict, Any
from dataclasses import asdict

# Import theme and models
from vaulthound.ui.theme import (
    AUTUMN_PALETTE,
    get_theme_colors,
    get_severity_colors,
    inject_theme,
    apply_card_styling,
)
from vaulthound.agents.state import (
    FindingModel,
    ScanStatus,
    SeverityLevel,
    SecretType,
)
from vaulthound.agents.security_monitor import SecurityEvent
from vaulthound.db.sqlite_store import SQLiteStore


# =============================================================================
# SIDEBAR COMPONENTS
# =============================================================================


def render_sidebar() -> Dict[str, Any]:
    """
    Renders the main sidebar with all scan configuration options.

    This is the primary configuration interface for setting up a new scan.
    It includes token input, scan depth selection, and other scan options.

    Returns:
        Dict containing all configured scan parameters:
        - token: GitHub/GitLab access token
        - repo_url: Repository URL to scan
        - scan_depth: Depth level for scanning
        - enable_canary: Whether to inject canary tokens
        - scan_branch: Specific branch to scan (optional)

    Example:
        >>> config = render_sidebar()
        >>> if config['start_scan']:
        ...     run_scan(config)
    """
    with st.sidebar:
        # Apply card styling for sidebar sections
        st.markdown(apply_card_styling(), unsafe_allow_html=True)

        # Header
        st.title("🔍 VaultHound")
        st.markdown("### Secret Detection Scanner")
        st.markdown("---")

        # Token from environment variable
        import os

        token = os.environ.get("GITHUB_TOKEN", "")

        # Show token status
        st.markdown("### 🔑 GitHub Token")
        if token:
            st.success("✅ Loaded from .env file")
        else:
            st.warning("⚠️ Set GITHUB_TOKEN in .env file")

        # OpenAI API Key from environment
        openai_key = os.environ.get("OPENAI_API_KEY", "")

        # Show OpenAI status
        if openai_key:
            st.success("✅ OpenAI API Key loaded")
        else:
            st.info("💡 Optional: Set OPENAI_API_KEY in .env")

        st.markdown("---")

        # Scan depth selector
        scan_depth = render_scan_depth_selector()

        # Scan history section
        st.markdown("---")
        render_scan_history()

        # Kill switch
        st.markdown("---")
        kill_switch = render_kill_switch()

        # Return configuration dictionary
        return {
            "token": token,
            "openai_key": openai_key,
            "scan_depth": scan_depth,
            "kill_switch": kill_switch,
        }


# NOTE: Token and API key functions are now handled via environment variables
# See .env file for configuration


def render_scan_depth_selector() -> str:
    """
    Renders a dropdown for selecting the scan depth/level.

    Scan depth determines how thoroughly the repository is scanned:
    - Quick: Fast scan of recent commits and current files
    - Standard: Balanced scan with moderate depth
    - Deep: Comprehensive scan including git history
    - Full: Complete scan including all branches and tags

    Returns:
        str: The selected scan depth level

    Example:
        >>> depth = render_scan_depth_selector()
        >>> scanner = SecretScanner(depth=depth)
    """
    st.markdown("### 📊 Scan Depth")

    scan_depth_options = {
        "quick": {
            "label": "⚡ Quick Scan",
            "description": "Fast scan of recent commits and current files",
            "depth": 1,
        },
        "standard": {
            "label": "🔍 Standard Scan",
            "description": "Balanced scan with moderate depth",
            "depth": 2,
        },
        "deep": {
            "label": "🔎 Deep Scan",
            "description": "Comprehensive scan including git history",
            "depth": 3,
        },
        "full": {
            "label": "🎯 Full Scan",
            "description": "Complete scan including all branches and tags",
            "depth": 4,
        },
    }

    # Create options list for dropdown
    options_list = list(scan_depth_options.keys())
    labels = [scan_depth_options[k]["label"] for k in options_list]

    # Add descriptions as help text
    selected = st.selectbox(
        "Scan Depth",
        options=options_list,
        format_func=lambda x: scan_depth_options[x]["label"],
        help=scan_depth_options["standard"]["description"],
    )

    # Show description for selected option
    st.caption(scan_depth_options[selected]["description"])

    return selected


def render_kill_switch() -> bool:
    """
    Renders a prominent red kill switch button for emergency scan termination.

    The kill switch is styled in deep red to make it clearly distinguishable
    from other actions. It provides a way to immediately stop any running scan.

    Returns:
        bool: True if the kill switch was activated, False otherwise

    Example:
        >>> if render_kill_switch():
        ...     terminate_scan()
    """
    st.markdown("### 🛑 Emergency Controls")

    # Custom CSS for the kill switch button
    kill_switch_css = """
    <style>
        .kill-switch-button {
            background-color: #c0392b;
            color: white;
            border: 2px solid #8b2e0f;
            border-radius: 8px;
            padding: 12px 20px;
            font-weight: bold;
            font-size: 16px;
            cursor: pointer;
            width: 100%;
            transition: all 0.2s ease;
            text-align: center;
        }
        .kill-switch-button:hover {
            background-color: #8b2e0f;
            border-color: #c0392b;
            box-shadow: 0 0 15px rgba(192, 57, 43, 0.5);
        }
        .kill-switch-button:active {
            transform: scale(0.98);
        }
    </style>
    """
    st.markdown(kill_switch_css, unsafe_allow_html=True)

    # Kill switch button
    if st.button(
        "🛑 STOP ALL SCANS",
        help="Immediately terminate all running scans",
        use_container_width=True,
    ):
        st.session_state.scan_running = False
        st.error("⚠️ All scans have been terminated")
        return True

    return False


def render_scan_history() -> None:
    """
    Renders an expandable section showing scan history from SQLite database.

    Displays previous scans with their status, findings count, and timestamps.
    Users can expand each scan to see more details or reload previous results.

    Example:
        >>> render_scan_history()
    """
    st.markdown("### 📜 Scan History")

    # Initialize SQLite store
    try:
        store = SQLiteStore()
        store.init_db()
        scans = store.get_all_scans()
        store.close()
    except Exception as e:
        st.warning(f"Could not load scan history: {e}")
        return

    if not scans:
        st.caption("No previous scans found")
        return

    # Show most recent scans (limit to 10)
    recent_scans = scans[:10]

    with st.expander(f"View Recent Scans ({len(recent_scans)})"):
        for scan in recent_scans:
            # Parse scan data
            scan_id = scan.get("id", "N/A")
            repo = scan.get("repo_url", "Unknown")
            status = scan.get("status", "unknown")
            findings_count = scan.get("findings_count", 0)
            start_time = scan.get("start_time", "Unknown")

            # Format timestamp
            if isinstance(start_time, str):
                try:
                    dt = datetime.fromisoformat(start_time.replace("Z", "+00:00"))
                    start_time = dt.strftime("%Y-%m-%d %H:%M")
                except:
                    pass

            # Status color indicator
            status_colors = {
                "completed": "🟢",
                "failed": "🔴",
                "in_progress": "🟡",
                "cancelled": "⚪",
            }
            status_icon = status_colors.get(status, "⚪")

            # Display scan summary
            st.markdown(
                f"""
                **{status_icon} {repo}**
                
                - Status: {status}
                - Findings: {findings_count}
                - Date: {start_time}
                """
            )
            st.markdown("---")


# =============================================================================
# FINDINGS DISPLAY COMPONENTS
# =============================================================================


def render_findings_table(findings: List[FindingModel]) -> None:
    """
    Renders a color-coded findings table with severity-based styling.

    Creates an interactive dataframe showing all findings with:
    - Severity badges with appropriate colors
    - Secret type icons
    - File path and line number
    - Quick actions for each finding

    Args:
        findings: List of FindingModel objects to display

    Example:
        >>> findings = scanner.get_findings()
        >>> render_findings_table(findings)
    """
    if not findings:
        st.info("No findings to display")
        return

    # Convert findings to dataframe
    data = []
    for finding in findings:
        data.append(
            {
                "ID": finding.id[:8],  # Short ID for display
                "Severity": finding.severity,
                "Secret Type": finding.secret_type,
                "File": finding.file_path.split("/")[-1],  # Just filename
                "Line": finding.line_number,
                "Entropy": (
                    f"{finding.entropy_score:.2f}" if finding.entropy_score else "N/A"
                ),
                "Confirmed": "✅" if finding.confirmed_real else "❌",
            }
        )

    df = pd.DataFrame(data)

    # Apply severity-based column styling
    severity_colors = get_severity_colors()

    # Create styled dataframe
    def style_severity(val):
        color = severity_colors.get(val, AUTUMN_PALETTE["text_secondary"])
        return f"color: {color}; font-weight: bold"

    # Apply styling
    styled_df = df.style.applymap(style_severity, subset=["Severity"])

    # Display the table
    st.dataframe(
        styled_df,
        use_container_width=True,
        hide_index=True,
    )

    # Summary statistics
    st.markdown(f"**Total Findings:** {len(findings)}")

    # Severity breakdown
    severity_counts = {}
    for finding in findings:
        sev = finding.severity
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    if severity_counts:
        st.markdown("**By Severity:**")
        cols = st.columns(len(severity_counts))
        for i, (sev, count) in enumerate(
            sorted(
                severity_counts.items(),
                key=lambda x: ["critical", "high", "medium", "low", "info"].index(x[0]),
            )
        ):
            with cols[i]:
                render_severity_badge(sev, count)


def render_severity_badge(severity: str, count: Optional[int] = None) -> None:
    """
    Renders a styled severity badge with appropriate color coding.

    Badge colors follow the severity color mapping:
    - Critical: Deep red (#c0392b)
    - High: Deep crimson (#8b2e0f)
    - Medium: Harvest gold (#d4a017)
    - Low: Amber gold (#c4922a)
    - Info: Forest green (#5a8a3c)

    Args:
        severity: The severity level string
        count: Optional count to display alongside the badge

    Example:
        >>> render_severity_badge("critical", 5)
        >>> render_severity_badge("high")
    """
    severity_colors = get_severity_colors()
    color = severity_colors.get(severity.lower(), AUTUMN_PALETTE["text_secondary"])

    # Determine text color based on background
    text_color = (
        "white"
        if severity.lower() in ["critical", "high", "info"]
        else AUTUMN_PALETTE["background"]
    )

    badge_html = f"""
    <span style="
        background-color: {color};
        color: {text_color};
        padding: 4px 12px;
        border-radius: 12px;
        font-size: 12px;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        margin-right: 4px;
    ">
        {severity.upper()}
    </span>
    """

    if count is not None:
        badge_html += f" <strong>({count})</strong>"

    st.markdown(badge_html, unsafe_allow_html=True)


def render_finding_detail(finding: FindingModel) -> None:
    """
    Renders a detailed view of a single finding with all metadata.

    Displays comprehensive information about a finding including:
    - Severity and secret type
    - File location and git context
    - Entropy analysis
    - Commit information
    - Code context (before/after lines)
    - Remediation status

    Args:
        finding: The FindingModel object to display in detail

    Example:
        >>> finding = get_finding_by_id(finding_id)
        >>> render_finding_detail(finding)
    """
    # Apply card styling
    st.markdown(apply_card_styling(), unsafe_allow_html=True)

    # Header with severity badge
    col1, col2 = st.columns([3, 1])
    with col1:
        st.markdown(f"### 🔍 Finding Details")
    with col2:
        render_severity_badge(finding.severity.value)

    # Main info card
    st.markdown(
        f"""
    <div class="vh-card" style="margin-top: 0;">
        <div class="vh-card-header">
            {finding.secret_type.value.upper()} Detected
        </div>
        <div class="vh-card-content">
            <p><strong>File:</strong> <code>{finding.file_path}</code></p>
            <p><strong>Line:</strong> {finding.line_number}</p>
            <p><strong>Entropy Score:</strong> {finding.entropy_score:.2f if finding.entropy_score else 'N/A'}</p>
        </div>
    </div>
    """,
        unsafe_allow_html=True,
    )

    # Git context section
    if finding.commit_sha or finding.commit_author:
        st.markdown("### 📝 Git Context")

        git_info = []
        if finding.commit_sha:
            git_info.append(f"**Commit:** `{finding.commit_sha[:7]}`")
        if finding.commit_author:
            git_info.append(f"**Author:** {finding.commit_author}")
        if finding.commit_date:
            git_info.append(f"**Date:** {finding.commit_date}")
        if finding.commit_message:
            git_info.append(f"**Message:** {finding.commit_message}")

        if git_info:
            st.markdown("  \n".join(git_info))

    # Code context section
    if finding.context_before or finding.context_after:
        st.markdown("### 💻 Code Context")

        context_code = ""
        if finding.context_before:
            for i, line in enumerate(finding.context_before):
                context_code += f"{finding.line_number - len(finding.context_before) + i + 1:4d} | {line}\n"

        # Highlight the finding line
        context_code += f"{finding.line_number:4d} | **>>> SECRET DETECTED <<<**\n"

        if finding.context_after:
            for i, line in enumerate(finding.context_after):
                context_code += f"{finding.line_number + i + 1:4d} | {line}\n"

        st.code(context_code, language="python")

    # Status and notes
    st.markdown("### 📋 Status")

    col1, col2 = st.columns(2)
    with col1:
        confirmed = (
            "✅ Confirmed Real" if finding.confirmed_real else "❌ Not Confirmed"
        )
        st.markdown(f"**Confirmation:** {confirmed}")
    with col2:
        fp = (
            "⚠️ Marked False Positive"
            if finding.false_positive
            else "✓ Not False Positive"
        )
        st.markdown(f"**False Positive:** {fp}")

    if finding.notes:
        st.markdown(f"**Notes:** {finding.notes}")


# =============================================================================
# PROGRESS AND STATUS COMPONENTS
# =============================================================================


def render_progress_display(status: str, progress: Optional[float] = None) -> None:
    """
    Renders a progress indicator based on scan status.

    Provides visual feedback for different scan states:
    - Pending: Static waiting indicator
    - In Progress: Animated progress bar
    - Completed: Success checkmark
    - Failed: Error indicator

    Args:
        status: The current scan status string
        progress: Optional progress percentage (0-100)

    Example:
        >>> render_progress_display("in_progress", 45.5)
        >>> render_progress_display("completed")
    """
    status_lower = status.lower()

    # Status messages and styling
    status_config = {
        "pending": {
            "icon": "⏳",
            "message": "Scan queued and waiting to start...",
            "color": AUTUMN_PALETTE["text_secondary"],
        },
        "in_progress": {
            "icon": "🔄",
            "message": "Scan in progress...",
            "color": AUTUMN_PALETTE["primary"],
        },
        "completed": {
            "icon": "✅",
            "message": "Scan completed successfully",
            "color": AUTUMN_PALETTE["success"],
        },
        "failed": {
            "icon": "❌",
            "message": "Scan failed",
            "color": AUTUMN_PALETTE["danger"],
        },
        "cancelled": {
            "icon": "🛑",
            "message": "Scan cancelled by user",
            "color": AUTUMN_PALETTE["warning"],
        },
    }

    config = status_config.get(status_lower, status_config["pending"])

    # Display status with icon
    st.markdown(
        f"""
    <div style="
        padding: 16px;
        border-radius: 8px;
        background-color: {AUTUMN_PALETTE['surface']};
        border-left: 4px solid {config['color']};
        margin: 12px 0;
    ">
        <span style="font-size: 24px; margin-right: 8px;">{config['icon']}</span>
        <span style="color: {config['color']}; font-weight: 600;">{config['message']}</span>
    </div>
    """,
        unsafe_allow_html=True,
    )

    # Show progress bar for in-progress scans
    if status_lower == "in_progress" and progress is not None:
        st.progress(progress / 100.0)
        st.markdown(f"**Progress:** {progress:.1f}%")

    # Status-specific details
    if status_lower == "in_progress":
        st.info("Scanning repository for secrets... This may take a few minutes.")
    elif status_lower == "completed":
        st.success("All secrets have been detected and cataloged.")
    elif status_lower == "failed":
        st.error("An error occurred during scanning. Check logs for details.")


# =============================================================================
# METRICS AND STATISTICS COMPONENTS
# =============================================================================


def render_metrics_row(findings: List[FindingModel]) -> None:
    """
    Renders a row of metric cards showing scan statistics.

    Displays key metrics including:
    - Total findings count
    - Critical findings count
    - High severity count
    - Unique files affected

    Args:
        findings: List of FindingModel objects to calculate metrics from

    Example:
        >>> findings = scanner.get_findings()
        >>> render_metrics_row(findings)
    """
    if not findings:
        st.info("Run a scan to see metrics")
        return

    # Calculate metrics
    total_findings = len(findings)
    critical_count = sum(1 for f in findings if f.severity == SeverityLevel.CRITICAL)
    high_count = sum(1 for f in findings if f.severity == SeverityLevel.HIGH)
    medium_count = sum(1 for f in findings if f.severity == SeverityLevel.MEDIUM)
    low_count = sum(1 for f in findings if f.severity == SeverityLevel.LOW)

    # Unique files
    unique_files = len(set(f.file_path for f in findings))

    # Average entropy
    entropies = [f.entropy_score for f in findings if f.entropy_score]
    avg_entropy = sum(entropies) / len(entropies) if entropies else 0

    # Create metrics row
    cols = st.columns(6)

    with cols[0]:
        st.metric("Total Findings", total_findings)

    with cols[1]:
        st.metric(
            "Critical",
            critical_count,
            delta_color="inverse" if critical_count > 0 else "normal",
        )

    with cols[2]:
        st.metric(
            "High", high_count, delta_color="inverse" if high_count > 0 else "normal"
        )

    with cols[3]:
        st.metric("Medium", medium_count)

    with cols[4]:
        st.metric("Files Affected", unique_files)

    with cols[5]:
        st.metric("Avg Entropy", f"{avg_entropy:.2f}")


# =============================================================================
# REPORT GENERATION COMPONENTS
# =============================================================================


def render_owasp_table() -> None:
    """
    Renders an OWASP Agentic AI Security compliance table.

    Displays the OWASP ASI (Agentic AI Security) categories and their
    compliance status within VaultHound. This helps users understand
    what security risks are being addressed.

    Example:
        >>> render_owasp_table()
    """
    st.markdown("### 🛡️ OWASP Agentic AI Security Compliance")

    # OWASP ASI categories
    owasp_categories = [
        {
            "id": "ASI01",
            "name": "Insecure Input Generation",
            "description": "Protection against malicious inputs to agents",
            "status": "✅ Implemented",
            "status_color": AUTUMN_PALETTE["success"],
        },
        {
            "id": "ASI02",
            "name": "Tool Misuse",
            "description": "Controls for tool usage and abuse prevention",
            "status": "✅ Implemented",
            "status_color": AUTUMN_PALETTE["success"],
        },
        {
            "id": "ASI03",
            "name": "Identity & Privilege Abuse",
            "description": "Authentication and authorization controls",
            "status": "✅ Implemented",
            "status_color": AUTUMN_PALETTE["success"],
        },
        {
            "id": "ASI04",
            "name": "Supply Chain Vulnerabilities",
            "description": "Protection against compromised dependencies",
            "status": "✅ Implemented",
            "status_color": AUTUMN_PALETTE["success"],
        },
        {
            "id": "ASI05",
            "name": "Unexpected Code Execution",
            "description": "Prevention of arbitrary code execution risks",
            "status": "✅ Implemented",
            "status_color": AUTUMN_PALETTE["success"],
        },
        {
            "id": "ASI06",
            "name": "Memory & Context Poisoning",
            "description": "Protection against context manipulation",
            "status": "✅ Implemented",
            "status_color": AUTUMN_PALETTE["success"],
        },
        {
            "id": "ASI07",
            "name": "Insecure Inter-Agent Communication",
            "description": "Secure communication between agents",
            "status": "✅ Implemented",
            "status_color": AUTUMN_PALETTE["success"],
        },
        {
            "id": "ASI08",
            "name": "Cascading Failures",
            "description": "Failure isolation and recovery",
            "status": "✅ Implemented",
            "status_color": AUTUMN_PALETTE["success"],
        },
        {
            "id": "ASI09",
            "name": "Human-Agent Trust Exploitation",
            "description": "Controls to prevent trust abuse",
            "status": "✅ Implemented",
            "status_color": AUTUMN_PALETTE["success"],
        },
        {
            "id": "ASI10",
            "name": "Rogue Agents",
            "description": "Detection of unauthorized agent behavior",
            "status": "✅ Implemented",
            "status_color": AUTUMN_PALETTE["success"],
        },
    ]

    # Create dataframe for display
    df = pd.DataFrame(owasp_categories)

    # Display as table
    st.table(df)


def render_security_events_log(events: List[SecurityEvent]) -> None:
    """
    Renders a security events log with severity-based coloring.

    Displays security events captured during scanning with:
    - Timestamp
    - Event type
    - Severity level
    - Details

    Args:
        events: List of SecurityEvent objects to display

    Example:
        >>> events = security_monitor.get_events()
        >>> render_security_events_log(events)
    """
    st.markdown("### 🔐 Security Events Log")

    if not events:
        st.info("No security events recorded")
        return

    # Convert events to dataframe
    data = []
    for event in events:
        # Convert dataclass to dict if needed
        if hasattr(event, "__dataclass_fields__"):
            event_dict = asdict(event)
        else:
            event_dict = event

        data.append(
            {
                "Timestamp": event_dict.get("timestamp", "N/A"),
                "Event Type": event_dict.get("event_type", "UNKNOWN"),
                "Severity": event_dict.get("severity", "INFO"),
                "Details": event_dict.get("details", "")[:100],  # Truncate for table
            }
        )

    df = pd.DataFrame(data)

    # Severity styling
    severity_colors = {
        "CRITICAL": AUTUMN_PALETTE["danger"],
        "HIGH": AUTUMN_PALETTE["highlight"],
        "MEDIUM": AUTUMN_PALETTE["warning"],
        "LOW": AUTUMN_PALETTE["secondary"],
        "INFO": AUTUMN_PALETTE["success"],
    }

    def style_severity(val):
        color = severity_colors.get(val, AUTUMN_PALETTE["text_secondary"])
        return f"color: {color}; font-weight: bold"

    # Display styled table
    styled_df = df.style.applymap(style_severity, subset=["Severity"])

    st.dataframe(
        styled_df,
        use_container_width=True,
        hide_index=True,
    )

    # Event count summary
    event_counts = {}
    for event in events:
        event_type = event.event_type if hasattr(event, "event_type") else "UNKNOWN"
        event_counts[event_type] = event_counts.get(event_type, 0) + 1

    st.markdown("**Event Summary:**")
    for event_type, count in sorted(event_counts.items()):
        st.markdown(f"- {event_type}: {count}")


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================


def create_summary_card(title: str, content: str, icon: str = "📊") -> None:
    """
    Creates a styled summary card with title and content.

    Args:
        title: The card title
        content: The card content/markdown
        icon: Optional icon to display

    Example:
        >>> create_summary_card("Scan Results", "Found 5 secrets")
    """
    st.markdown(
        f"""
    <div class="vh-card">
        <div class="vh-card-header">
            {icon} {title}
        </div>
        <div class="vh-card-content">
            {content}
        </div>
    </div>
    """,
        unsafe_allow_html=True,
    )


def render_confirmed_findings_summary(findings: List[FindingModel]) -> None:
    """
    Renders a summary of confirmed (real) vs false positive findings.

    Args:
        findings: List of all findings to analyze

    Example:
        >>> findings = scanner.get_findings()
        >>> render_confirmed_findings_summary(findings)
    """
    if not findings:
        return

    confirmed = sum(1 for f in findings if f.confirmed_real)
    false_positives = sum(1 for f in findings if f.false_positive)
    unconfirmed = len(findings) - confirmed - false_positives

    cols = st.columns(3)

    with cols[0]:
        st.metric(
            "Confirmed Real",
            confirmed,
            delta_color="inverse" if confirmed > 0 else "normal",
        )

    with cols[1]:
        st.metric(
            "False Positives",
            false_positives,
            delta_color="normal" if false_positives > 0 else "inverse",
        )

    with cols[2]:
        st.metric("Unconfirmed", unconfirmed)


def render_export_options(findings: List[FindingModel]) -> None:
    """
    Renders export options for findings data.

    Provides options to export findings in various formats:
    - JSON
    - CSV
    - Markdown report

    Args:
        findings: List of findings to export

    Example:
        >>> findings = scanner.get_findings()
        >>> render_export_options(findings)
    """
    st.markdown("### 📤 Export Options")

    if not findings:
        st.warning("No findings to export")
        return

    col1, col2, col3 = st.columns(3)

    # JSON export
    with col1:
        import json

        findings_json = json.dumps(
            [f.model_dump() for f in findings],
            indent=2,
            default=str,
        )
        st.download_button(
            label="📄 Export JSON",
            data=findings_json,
            file_name="vaulthound_findings.json",
            mime="application/json",
        )

    # CSV export
    with col2:
        import pandas as pd

        data = []
        for f in findings:
            data.append(
                {
                    "id": f.id,
                    "secret_type": f.secret_type,
                    "severity": f.severity,
                    "file_path": f.file_path,
                    "line_number": f.line_number,
                    "entropy_score": f.entropy_score,
                    "confirmed_real": f.confirmed_real,
                    "false_positive": f.false_positive,
                }
            )
        df = pd.DataFrame(data)
        csv = df.to_csv(index=False)
        st.download_button(
            label="📊 Export CSV",
            data=csv,
            file_name="vaulthound_findings.csv",
            mime="text/csv",
        )

    # Markdown report
    with col3:
        md = generate_markdown_report(findings)
        st.download_button(
            label="📝 Export Report",
            data=md,
            file_name="vaulthound_report.md",
            mime="text/markdown",
        )


def generate_markdown_report(findings: List[FindingModel]) -> str:
    """
    Generates a markdown report of findings.

    Args:
        findings: List of findings to include in report

    Returns:
        str: Markdown formatted report

    Example:
        >>> report = generate_markdown_report(findings)
        >>> save_to_file(report)
    """
    md = """# VaultHound Secret Detection Report

## Summary

"""

    # Add summary statistics
    total = len(findings)
    critical = sum(1 for f in findings if f.severity == SeverityLevel.CRITICAL)
    high = sum(1 for f in findings if f.severity == SeverityLevel.HIGH)
    medium = sum(1 for f in findings if f.severity == SeverityLevel.MEDIUM)
    low = sum(1 for f in findings if f.severity == SeverityLevel.LOW)

    md += f"- **Total Findings:** {total}\n"
    md += f"- **Critical:** {critical}\n"
    md += f"- **High:** {high}\n"
    md += f"- **Medium:** {medium}\n"
    md += f"- **Low:** {low}\n"

    md += "\n## Findings\n\n"

    # Add each finding
    for i, f in enumerate(findings, 1):
        md += f"### {i}. {f.secret_type.value.upper()} ({f.severity.value.upper()})\n\n"
        md += f"- **File:** `{f.file_path}`\n"
        md += f"- **Line:** {f.line_number}\n"
        if f.entropy_score:
            md += f"- **Entropy:** {f.entropy_score:.2f}\n"
        if f.commit_sha:
            md += f"- **Commit:** `{f.commit_sha[:7]}`\n"
        md += "\n---\n"

    return md
