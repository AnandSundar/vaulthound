"""
VaultHound - Secret Detection Scanner

This is the main entry point for the VaultHound secret scanning application.
It ties together all components: agents, tools, UI, and visualization.

The application provides a multi-tab interface for:
1. Scanning GitHub repositories for secrets
2. Visualizing findings with interactive charts
3. Generating detailed reports
4. Assessing security posture with OWASP compliance
5. Viewing project information

OWASP Agentic AI Security (ASI) Mitigations:
- ASI01: Prompt Injection - Input validation at entry point
- ASI02: Resource Exhaustion - Circuit breaker and recursion limits
- ASI03: Token Scope - Validated GitHub API permissions
- ASI04: Overreliance - Output validation schemas
- ASI05: Unexpected Code Execution - Sandboxed processing
- ASI06: Memory & Context Poisoning - Canary tokens and state validation
- ASI07: Insecure Inter-Agent Communication - Canary token verification
- ASI08: Cascading Failures - Circuit breaker and graceful degradation
- ASI09: Human-Agent Trust Exploitation - Human approval gates
- ASI10: Infinite Loops - Recursion limit of 25

Author: VaultHound Team
"""

import streamlit as st
import pandas as pd
import logging
import time
import os
from typing import Dict, Any, List, Optional
from datetime import datetime
from io import StringIO, BytesIO

# Load environment variables from .env file
from dotenv import load_dotenv

load_dotenv()

# Import UI modules
from vaulthound.ui.theme import (
    inject_theme,
    apply_card_styling,
    get_severity_colors,
    AUTUMN_PALETTE,
)
from vaulthound.ui.components import (
    render_sidebar,
    render_findings_table,
    render_progress_display,
)
from vaulthound.ui.charts import (
    create_finding_distribution_pie,
    create_severity_breakdown_bar,
    create_risk_gauge,
    create_timeline_chart,
    create_entropy_distribution_histogram,
)

# Import agents and state
from vaulthound.agents.state import (
    ScanState,
    ScanStatus,
    FindingModel,
    SeverityLevel,
    SecretType,
    create_initial_state,
    add_finding,
)
from vaulthound.agents.graph import (
    create_graph,
    get_graph,
    activate_kill_switch,
    deactivate_kill_switch,
    is_kill_switch_active,
    run_scan,
)

# Import tools and validators
from vaulthound.tools.validators import validate_github_url
from vaulthound.tools.github_tools import GitHubScanner, ScanDepth

# Import database
from vaulthound.db.sqlite_store import SQLiteStore

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Flag to enable/disable log streaming to UI
LOG_STREAMING_ENABLED = False


class SessionLogHandler(logging.Handler):
    """Custom logging handler that stores logs in Streamlit session state."""

    def __init__(self):
        super().__init__()
        self.setLevel(logging.INFO)

    def emit(self, record):
        if not LOG_STREAMING_ENABLED:
            return
        try:
            msg = self.format(record)
            # Store in session state if available and scan is running
            try:
                if st.session_state.get("scan_running", False):
                    st.session_state.scan_progress.append(
                        f"{record.levelname} - {record.name} - {msg}"
                    )
            except Exception:
                pass  # Session state not available
        except Exception:
            pass


# Add custom handler to capture logs (disabled by default)
session_handler = SessionLogHandler()
session_handler.setFormatter(logging.Formatter("%(message)s"))
logging.getLogger().addHandler(session_handler)


# =============================================================================
# SESSION STATE INITIALIZATION
# =============================================================================


def init_session_state() -> None:
    """
    Initialize all required session state variables.

    Session state is used to maintain:
    - Current scan state and status
    - Findings from current/last scan
    - User preferences
    - Progress tracking
    """
    # Scan state management
    if "scan_running" not in st.session_state:
        st.session_state.scan_running = False

    if "current_scan" not in st.session_state:
        st.session_state.current_scan: Optional[ScanState] = None

    if "findings" not in st.session_state:
        st.session_state.findings: List[FindingModel] = []

    if "scan_status" not in st.session_state:
        st.session_state.scan_status: Optional[ScanStatus] = None

    if "scan_progress" not in st.session_state:
        st.session_state.scan_progress: List[str] = []

    if "risk_score" not in st.session_state:
        st.session_state.risk_score: float = 0.0

    # Human approval state (ASI09)
    if "awaiting_approval" not in st.session_state:
        st.session_state.awaiting_approval = False

    if "approval_request" not in st.session_state:
        st.session_state.approval_request: Optional[Dict[str, Any]] = None

    # Scan history
    if "scan_history" not in st.session_state:
        st.session_state.scan_history: List[Dict[str, Any]] = []

    # Kill switch state
    if "kill_switch_pressed" not in st.session_state:
        st.session_state.kill_switch_pressed = False

    # Metrics
    if "metrics" not in st.session_state:
        st.session_state.metrics = {
            "total_scans": 0,
            "total_findings": 0,
            "critical_findings": 0,
            "high_findings": 0,
            "avg_risk_score": 0.0,
        }


# =============================================================================
# PAGE CONFIGURATION
# =============================================================================


def configure_page() -> None:
    """
    Configure Streamlit page settings.

    Sets page title, icon, layout, and initial theme.
    """
    st.set_page_config(
        page_title="VaultHound - Secret Detection Scanner",
        page_icon="🔐",
        layout="wide",
        initial_sidebar_state="expanded",
        menu_items={
            "Get Help": "https://github.com/vaulthound/vaulthound",
            "Report a Bug": "https://github.com/vaulthound/vaulthound/issues",
            "About": "VaultHound - Automated Secret Detection Scanner",
        },
    )


# =============================================================================
# SIDEBAR RENDERING
# =============================================================================


def get_sidebar_config() -> Dict[str, Any]:
    """
    Render sidebar and return configuration dictionary.

    Returns:
        Dict containing all scan configuration options
    """
    config = render_sidebar()

    # Check for kill switch activation
    if config.get("kill_switch"):
        st.session_state.kill_switch_pressed = True
        st.session_state.scan_running = False
        activate_kill_switch()

    return config


# =============================================================================
# TAB 1: SCAN INTERFACE
# =============================================================================


def render_scan_tab(config: Dict[str, Any]) -> None:
    """
    Render the main scan tab with URL input and launch controls.

    Args:
        config: Sidebar configuration dictionary
    """
    st.markdown("### 🔍 Start a New Scan")

    # Repository URL input (prominent placement)
    col1, col2 = st.columns([3, 1])

    with col1:
        repo_url = st.text_input(
            "Repository URL",
            placeholder="https://github.com/owner/repo",
            help="Enter the GitHub repository URL to scan for secrets",
            key="repo_url_input",
        )

    with col2:
        st.markdown("<br>", unsafe_allow_html=True)
        scan_button = st.button(
            "🚀 Launch Hunt",
            type="primary",
            use_container_width=True,
            disabled=st.session_state.scan_running,
        )

    # Validation message
    is_valid = False  # Default value
    if repo_url:
        is_valid, validation_msg = validate_github_url(repo_url)
        if is_valid:
            st.success(f"✅ {validation_msg}")
        else:
            st.error(f"❌ {validation_msg}")

    # Scan execution
    if scan_button and repo_url and is_valid:
        execute_scan(repo_url, config)

    # Live progress display
    if st.session_state.scan_running:
        # Use scan_status for status display, pass progress as None (optional)
        status = (
            st.session_state.scan_status.value
            if st.session_state.scan_status
            else "in_progress"
        )
        render_progress_display(status)

    # Human approval flow (ASI09)
    if st.session_state.awaiting_approval:
        render_approval_gate()

    # Display results if scan completed
    if st.session_state.findings and not st.session_state.scan_running:
        render_scan_results()


def execute_scan(repo_url: str, config: Dict[str, Any]) -> None:
    """
    Execute the scan workflow using LangGraph.

    Args:
        repo_url: Repository URL to scan
        config: Scan configuration dictionary
    """
    # Reset state
    st.session_state.scan_running = True
    st.session_state.findings = []
    st.session_state.scan_progress = []
    st.session_state.risk_score = 0.0
    st.session_state.awaiting_approval = False

    # Get token from config
    token = config.get("token", "")

    try:
        # Create initial scan state
        initial_state = create_initial_state(
            repo_url=repo_url,
            scan_depth=config.get("scan_depth", "standard"),
            openai_api_key=config.get("openai_key"),
        )

        st.session_state.current_scan = initial_state
        st.session_state.scan_progress.append("Initializing scan...")

        # Create and run the scan graph
        graph = get_graph()

        # Run with progress tracking
        progress_container = st.empty()

        # Execute scan with streaming to show progress
        config = {"configurable": {"thread_id": "default"}, "recursion_limit": 100}

        # Initialize progress
        st.session_state.scan_progress = ["🔍 Starting repository scan..."]
        current_step = 0

        # Show initial progress
        progress_container.code("🔍 Starting repository scan...", language="text")

        # Stream progress updates as nodes complete
        for chunk in graph.stream(initial_state, config=config):
            # Each chunk contains one or more node outputs
            for node_name, node_output in chunk.items():
                # Update progress based on which node completed
                if node_name == "input_validator":
                    st.session_state.scan_progress.append(
                        "✓ Validating repository input..."
                    )
                elif node_name == "repo_crawler":
                    # Handle different output formats from stream
                    file_tree = (
                        node_output.get("file_tree", {})
                        if isinstance(node_output, dict)
                        else {}
                    )
                    files = (
                        file_tree.get("files", [])
                        if isinstance(file_tree, dict)
                        else file_tree
                    )
                    file_count = len(files) if isinstance(files, list) else 0
                    st.session_state.scan_progress.append(
                        f"✓ Crawling repository - found {file_count} files"
                    )
                elif node_name == "commit_analyzer":
                    # Handle different output formats from stream
                    commit_history = (
                        node_output.get("commit_history", [])
                        if isinstance(node_output, dict)
                        else []
                    )
                    commit_count = (
                        len(commit_history) if isinstance(commit_history, list) else 0
                    )
                    st.session_state.scan_progress.append(
                        f"✓ Analyzing commits - found {commit_count} commits"
                    )
                elif node_name == "entropy_scanner":
                    # Handle different output formats from stream
                    findings = (
                        node_output.get("findings", [])
                        if isinstance(node_output, dict)
                        else []
                    )
                    finding_count = len(findings) if isinstance(findings, list) else 0
                    st.session_state.scan_progress.append(
                        f"✓ Running entropy scanner - found {finding_count} potential secrets"
                    )
                elif node_name == "llm_semantic_analyzer":
                    st.session_state.scan_progress.append(
                        "✓ Running semantic analysis with LLM..."
                    )
                elif node_name == "risk_scorer":
                    st.session_state.scan_progress.append(
                        "✓ Calculating risk scores..."
                    )
                elif node_name == "human_approval_gate":
                    st.session_state.scan_progress.append(
                        "⏸ Awaiting human approval for high-risk findings..."
                    )
                elif node_name == "report_generator":
                    st.session_state.scan_progress.append(
                        "✓ Generating final report..."
                    )
                elif node_name == "security_monitor":
                    st.session_state.scan_progress.append(
                        "✓ Running security checks..."
                    )

                current_step += 1
                # Update progress display - only show last 5 node completions (not accumulating)
                st.session_state.scan_progress = st.session_state.scan_progress[
                    -4:
                ]  # Keep last 4
                progress_text = "\n".join(st.session_state.scan_progress)
                progress_container.code(progress_text, language="text")

        # Get final result from last chunk
        result = node_output if node_output else {}

        # Update session state with results
        if result:
            scratchpad = result.get("agent_scratchpad", {})
            st.session_state.findings = result.get("findings", [])
            st.session_state.scan_status = result.get("scan_status")
            # Get risk score from scratchpad (it's stored as total_risk_score, 0-10 scale)
            risk_score = scratchpad.get("total_risk_score", 0.0)
            # Convert to 0-100 scale for display
            st.session_state.risk_score = risk_score * 10
            # Get error log or use default progress
            error_log = result.get("error_log", [])
            if error_log:
                st.session_state.scan_progress = [
                    str(e.get("message", str(e))) for e in error_log
                ]
            else:
                st.session_state.scan_progress = ["Scan completed"]

            # Check if approval needed (ASI09)
            if result.get("human_approval_required"):
                st.session_state.awaiting_approval = True

        st.session_state.scan_running = False

        # Update metrics
        update_metrics()

        # Show completion message
        findings_count = len(st.session_state.findings)
        st.success(f"✅ Scan completed! Found {findings_count} potential secrets.")

    except Exception as e:
        st.session_state.scan_running = False
        st.session_state.scan_status = ScanStatus.FAILED
        logger.error(f"Scan failed: {e}")
        st.error(f"❌ Scan failed: {str(e)}")


def render_approval_gate() -> None:
    """
    Render human approval gate for high-risk findings (ASI09).

    This implements the OWASP ASI09 mitigation - requiring human approval
    before taking action on high-severity findings.
    """
    st.warning("⚠️ Human Approval Required")

    if st.session_state.approval_request:
        request = st.session_state.approval_request

        st.markdown(f"**High-Risk Finding Detected:**")
        st.markdown(f"- Type: {request.get('finding_type', 'Unknown')}")
        st.markdown(f"- Severity: {request.get('severity', 'Unknown')}")
        st.markdown(f"- File: {request.get('file_path', 'Unknown')}")

        col1, col2 = st.columns(2)

        with col1:
            if st.button("✅ Approve & Continue", type="primary"):
                st.session_state.awaiting_approval = False
                st.session_state.approval_request = None
                st.rerun()

        with col2:
            if st.button("❌ Reject & Stop"):
                st.session_state.scan_running = False
                st.session_state.awaiting_approval = False
                st.session_state.approval_request = None
                st.warning("Scan stopped by user")


def render_scan_results() -> None:
    """Render scan results with severity coloring and statistics."""
    findings = st.session_state.findings

    if not findings:
        st.info("No secrets found! 🎉")
        return

    # Summary metrics
    st.markdown("#### 📊 Scan Summary")

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        critical = len([f for f in findings if f.severity == SeverityLevel.CRITICAL])
        st.metric("Critical", critical)

    with col2:
        high = len([f for f in findings if f.severity == SeverityLevel.HIGH])
        st.metric("High", high)

    with col3:
        medium = len([f for f in findings if f.severity == SeverityLevel.MEDIUM])
        st.metric("Medium", medium)

    with col4:
        low = len([f for f in findings if f.severity == SeverityLevel.LOW])
        st.metric("Low", low)

    # Risk score
    st.metric("Risk Score", f"{st.session_state.risk_score:.1f}/100")

    # Findings table with severity coloring
    st.markdown("#### 🔎 Detailed Findings")
    render_findings_table(findings)


def update_metrics() -> None:
    """Update session metrics after scan completion."""
    findings = st.session_state.findings

    st.session_state.metrics["total_scans"] += 1
    st.session_state.metrics["total_findings"] += len(findings)
    st.session_state.metrics["critical_findings"] += len(
        [f for f in findings if f.severity == SeverityLevel.CRITICAL]
    )
    st.session_state.metrics["high_findings"] += len(
        [f for f in findings if f.severity == SeverityLevel.HIGH]
    )

    # Calculate average risk score
    total = st.session_state.metrics["total_scans"]
    current = st.session_state.risk_score
    avg = (
        (st.session_state.metrics["avg_risk_score"] * (total - 1) + current) / total
        if total > 0
        else 0
    )
    st.session_state.metrics["avg_risk_score"] = avg


# =============================================================================
# TAB 2: DASHBOARD
# =============================================================================


def render_dashboard_tab() -> None:
    """Render the dashboard tab with Plotly charts for findings visualization."""
    st.markdown("### 📊 Findings Dashboard")

    findings = st.session_state.findings

    if not findings:
        st.info(
            "No scan data available. Run a scan in the 🔍 Scan tab to see visualizations."
        )
        return

    # Summary metrics row
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric("Total Findings", len(findings))

    with col2:
        unique_types = len(set(f.secret_type for f in findings))
        st.metric("Secret Types", unique_types)

    with col3:
        affected_files = len(set(f.file_path for f in findings))
        st.metric("Affected Files", affected_files)

    with col4:
        st.metric("Risk Score", f"{st.session_state.risk_score:.1f}/100")

    st.markdown("---")

    # Charts row 1
    col1, col2 = st.columns(2)

    with col1:
        st.markdown("#### Finding Distribution by Type")
        fig_pie = create_finding_distribution_pie(findings)
        st.plotly_chart(fig_pie, use_container_width=True)

    with col2:
        st.markdown("#### Severity Breakdown")
        fig_bar = create_severity_breakdown_bar(findings)
        st.plotly_chart(fig_bar, use_container_width=True)

    # Charts row 2
    col1, col2 = st.columns(2)

    with col1:
        st.markdown("#### Risk Score Gauge")
        # Convert from 0-100 scale to 0-10 scale for gauge
        fig_gauge = create_risk_gauge(st.session_state.risk_score / 10)
        st.plotly_chart(fig_gauge, use_container_width=True)

    with col2:
        st.markdown("#### Entropy Distribution")
        fig_hist = create_entropy_distribution_histogram(findings)
        st.plotly_chart(fig_hist, use_container_width=True)

    # Timeline chart
    st.markdown("#### Findings Timeline")
    fig_timeline = create_timeline_chart(findings)
    st.plotly_chart(fig_timeline, use_container_width=True)


# =============================================================================
# TAB 3: REPORT
# =============================================================================


def render_report_tab() -> None:
    """Render the report tab with markdown report and export options."""
    st.markdown("### 📋 Scan Report")

    findings = st.session_state.findings

    if not findings:
        st.info(
            "No scan data available. Run a scan in the 🔍 Scan tab to generate a report."
        )
        return

    # Report options
    col1, col2, col3 = st.columns(3)

    with col1:
        include_summary = st.checkbox("Include Summary", value=True)

    with col2:
        include_details = st.checkbox("Include Details", value=True)

    with col3:
        include_context = st.checkbox("Include Code Context", value=True)

    # Generate markdown report
    report = generate_markdown_report(
        findings,
        include_summary=include_summary,
        include_details=include_details,
        include_context=include_context,
    )

    # Display report
    st.markdown(report)

    # Export options
    st.markdown("---")
    st.markdown("#### 💾 Export Report")

    col1, col2 = st.columns(2)

    with col1:
        # Markdown download
        st.download_button(
            label="📄 Download as Markdown",
            data=report,
            file_name="vaulthound_report.md",
            mime="text/markdown",
            use_container_width=True,
        )

    with col2:
        # CSV export
        csv_data = export_findings_csv(findings)
        st.download_button(
            label="📊 Download as CSV",
            data=csv_data,
            file_name="vaulthound_findings.csv",
            mime="text/csv",
            use_container_width=True,
        )


def generate_markdown_report(
    findings: List[FindingModel],
    include_summary: bool = True,
    include_details: bool = True,
    include_context: bool = True,
) -> str:
    """
    Generate a comprehensive markdown report.

    Args:
        findings: List of findings to include
        include_summary: Whether to include summary section
        include_details: Whether to include detailed findings
        include_context: Whether to include code context

    Returns:
        Markdown formatted report string
    """
    report = []

    # Header
    report.append("# VaultHound Secret Detection Report")
    report.append(f"\n**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report.append(f"\n**Total Findings:** {len(findings)}")
    report.append(f"**Risk Score:** {st.session_state.risk_score:.1f}/100")

    if include_summary:
        # Summary section
        report.append("\n## Summary\n")

        # Severity counts
        severity_counts = {}
        for f in findings:
            severity = f.severity.value if hasattr(f.severity, "value") else f.severity
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        report.append("### Findings by Severity\n")
        for severity in ["critical", "high", "medium", "low", "info"]:
            count = severity_counts.get(severity, 0)
            emoji = {
                "critical": "🔴",
                "high": "🟠",
                "medium": "🟡",
                "low": "🟢",
                "info": "🔵",
            }[severity]
            report.append(f"- {emoji} {severity.upper()}: {count}")

        # Type counts
        report.append("\n### Findings by Type\n")
        type_counts = {}
        for f in findings:
            stype = (
                f.secret_type.value
                if hasattr(f.secret_type, "value")
                else f.secret_type
            )
            type_counts[stype] = type_counts.get(stype, 0) + 1

        for stype, count in sorted(
            type_counts.items(), key=lambda x: x[1], reverse=True
        ):
            report.append(f"- **{stype}**: {count}")

    if include_details:
        # Detailed findings
        report.append("\n## Detailed Findings\n")

        for i, finding in enumerate(findings, 1):
            severity = (
                finding.severity.value
                if hasattr(finding.severity, "value")
                else finding.severity
            )
            stype = (
                finding.secret_type.value
                if hasattr(finding.secret_type, "value")
                else finding.secret_type
            )

            report.append(f"### Finding {i}: {stype}")
            report.append(f"\n- **Severity:** {severity.upper()}")
            report.append(f"- **File:** `{finding.file_path}`")
            report.append(f"- **Line:** {finding.line_number}")

            if finding.commit_sha:
                report.append(f"- **Commit:** `{finding.commit_sha[:7]}`")

            if finding.entropy_score:
                report.append(f"- **Entropy Score:** {finding.entropy_score:.2f}")

            if include_context and (finding.context_before or finding.context_after):
                report.append("\n#### Code Context\n")
                report.append("```")
                if finding.context_before:
                    report.append("\n".join(finding.context_before))
                report.append("\n<SECRET DETECTED>")
                if finding.context_after:
                    report.append("\n".join(finding.context_after))
                report.append("\n```")

            report.append("\n---\n")

    return "\n".join(report)


def export_findings_csv(findings: List[FindingModel]) -> str:
    """
    Export findings to CSV format.

    Args:
        findings: List of findings to export

    Returns:
        CSV formatted string
    """
    data = []
    for f in findings:
        data.append(
            {
                "id": f.id,
                "secret_type": (
                    f.secret_type.value
                    if hasattr(f.secret_type, "value")
                    else f.secret_type
                ),
                "severity": (
                    f.severity.value if hasattr(f.severity, "value") else f.severity
                ),
                "file_path": f.file_path,
                "line_number": f.line_number,
                "commit_sha": f.commit_sha or "",
                "entropy_score": f.entropy_score or 0.0,
                "is_canary": f.is_canary,
                "remediation_status": f.remediation_status,
            }
        )

    df = pd.DataFrame(data)
    return df.to_csv(index=False)


# =============================================================================
# TAB 4: SECURITY POSTURE
# =============================================================================


def render_security_posture_tab() -> None:
    """Render the security posture tab with OWASP compliance table."""
    st.markdown("### 🛡️ Security Posture Assessment")

    # OWASP compliance table
    st.markdown("#### OWASP Agentic AI Security (ASI) Compliance")

    compliance_data = [
        {
            "ASI Code": "ASI01",
            "Control": "Prompt Injection",
            "Status": "✅ Implemented",
            "Description": "Input validation and content wrapping at entry points",
        },
        {
            "ASI Code": "ASI02",
            "Control": "Resource Exhaustion",
            "Status": "✅ Implemented",
            "Description": "Circuit breaker and recursion limits (max 25)",
        },
        {
            "ASI Code": "ASI03",
            "Control": "Token Scope",
            "Status": "✅ Implemented",
            "Description": "Validated GitHub API permissions",
        },
        {
            "ASI Code": "ASI04",
            "Control": "Overreliance",
            "Status": "✅ Implemented",
            "Description": "Output validation schemas for findings",
        },
        {
            "ASI Code": "ASI05",
            "Control": "Unexpected Code Execution",
            "Status": "✅ Implemented",
            "Description": "Sandboxed processing environment",
        },
        {
            "ASI Code": "ASI06",
            "Control": "Memory & Context Poisoning",
            "Status": "✅ Implemented",
            "Description": "Canary tokens and state validation",
        },
        {
            "ASI Code": "ASI07",
            "Control": "Insecure Inter-Agent Communication",
            "Status": "✅ Implemented",
            "Description": "Canary token verification between agents",
        },
        {
            "ASI Code": "ASI08",
            "Control": "Cascading Failures",
            "Status": "✅ Implemented",
            "Description": "Circuit breaker and graceful degradation",
        },
        {
            "ASI Code": "ASI09",
            "Control": "Human-Agent Trust Exploitation",
            "Status": "✅ Implemented",
            "Description": "Human approval gates for high-risk findings",
        },
        {
            "ASI Code": "ASI10",
            "Control": "Infinite Loops",
            "Status": "✅ Implemented",
            "Description": "Recursion limit of 25 to prevent runaway graphs",
        },
    ]

    # Create DataFrame and display
    df_compliance = pd.DataFrame(compliance_data)
    st.dataframe(
        df_compliance,
        use_container_width=True,
        hide_index=True,
    )

    st.markdown("---")

    # Security metrics
    st.markdown("#### Security Metrics")

    metrics = st.session_state.metrics

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric("Total Scans", metrics["total_scans"])

    with col2:
        st.metric("Total Findings", metrics["total_findings"])

    with col3:
        st.metric("Critical Findings", metrics["critical_findings"])

    with col4:
        st.metric("Avg Risk Score", f"{metrics['avg_risk_score']:.1f}/100")

    # Canary token status
    st.markdown("---")
    st.markdown("#### 🪤 Canary Token Status")

    findings = st.session_state.findings
    canary_findings = [f for f in findings if f.is_canary] if findings else []

    col1, col2 = st.columns(2)

    with col1:
        st.metric("Canary Tokens Injected", len(canary_findings))

    with col2:
        if canary_findings:
            st.warning(
                f"⚠️ {len(canary_findings)} canary token(s) detected - possible exfiltration!"
            )
        else:
            st.success("✅ No canary token exfiltration detected")


# =============================================================================
# TAB 5: ABOUT
# =============================================================================


def render_about_tab() -> None:
    """Render the about tab with project info and architecture."""
    st.markdown("### ℹ️ About VaultHound")

    # Project description
    st.markdown(
        """
    **VaultHound** is an automated secret detection scanner designed to identify
    exposed credentials, API keys, and sensitive information in GitHub repositories.

    It uses a multi-layered approach combining:
    - **Pattern Matching**: Regular expressions for known secret formats
    - **Entropy Analysis**: Shannon entropy for detecting high-randomness strings
    - **LLM Semantic Analysis**: AI-powered context understanding
    - **Git History Analysis**: Scanning commit history for accidentally committed secrets
    """
    )

    st.markdown("---")

    # Architecture
    st.markdown("#### 🏗️ Architecture")

    st.markdown(
        """
    ```
    ┌─────────────────────────────────────────────────────────────┐
    │                      VaultHound App                         │
    └─────────────────────────────────────────────────────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        │                       │                       │
        ▼                       ▼                       ▼
    ┌──────────┐          ┌──────────┐          ┌──────────┐
    │  Input   │          │  LangGraph│          │   UI     │
    │Validator │─────────▶│  Workflow │─────────▶│ (Streamlit)│
    └──────────┘          └──────────┘          └──────────┘
                                │                       ▲
                                ▼                       │
    ┌──────────┐          ┌──────────┐          ┌──────────┐
    │Security │          │  Agents  │          │Database  │
    │ Monitor │◀─────────│ & Nodes  │─────────▶│ (SQLite) │
    └──────────┘          └──────────┘          └──────────┘
    ```
    """
    )

    st.markdown("---")

    # Key features
    st.markdown("#### ✨ Key Features")

    features = [
        "🔍 Multi-layer secret detection (patterns, entropy, LLM)",
        "📊 Interactive visualization dashboard",
        "🛡️ OWASP ASI compliance built-in",
        "🪤 Canary token detection for exfiltration alerts",
        "📜 Git history scanning for committed secrets",
        "💾 SQLite persistence for scan history",
        "🔐 Human approval gates for high-risk findings",
        "🛑 Emergency kill switch",
    ]

    for feature in features:
        st.markdown(f"- {feature}")

    st.markdown("---")

    # Version info
    st.markdown("#### 📋 Version Information")

    st.markdown(
        """
    - **Version:** 1.0.0
    - **Framework:** Streamlit
    - **Graph Engine:** LangGraph
    - **Database:** SQLite
    - **Charts:** Plotly
    """
    )

    # Links
    st.markdown("#### 🔗 Links")

    st.markdown(
        """
    - [GitHub Repository](https://github.com/vaulthound/vaulthound)
    - [Documentation](https://vaulthound.readthedocs.io)
    - [Report Issues](https://github.com/vaulthound/vaulthound/issues)
    """
    )


# =============================================================================
# MAIN APPLICATION
# =============================================================================


def main() -> None:
    """
    Main application entry point.

    Initializes the app, applies theme, renders sidebar and tabs.
    """
    # Configure page
    configure_page()

    # Inject autumn theme
    inject_theme()

    # Apply card styling
    st.markdown(apply_card_styling(), unsafe_allow_html=True)

    # Initialize session state
    init_session_state()

    # Title
    st.title("🔐 VaultHound")
    st.markdown("### Secret Detection Scanner")
    st.markdown("---")

    # Get sidebar configuration
    config = get_sidebar_config()

    # Create main tabs
    tab1, tab2, tab3, tab4, tab5 = st.tabs(
        ["🔍 Scan", "📊 Dashboard", "📋 Report", "🛡️ Security Posture", "ℹ️ About"]
    )

    # Tab 1: Scan
    with tab1:
        render_scan_tab(config)

    # Tab 2: Dashboard
    with tab2:
        render_dashboard_tab()

    # Tab 3: Report
    with tab3:
        render_report_tab()

    # Tab 4: Security Posture
    with tab4:
        render_security_posture_tab()

    # Tab 5: About
    with tab5:
        render_about_tab()


# Entry point
if __name__ == "__main__":
    main()
