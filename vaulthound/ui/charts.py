"""
VaultHound Charts Module

This module provides all Plotly chart functions for visualizing secret scanning results.
All charts use the autumn theme colors from theme.py and include interactive features.

Chart Types:
- Pie chart: Finding distribution by secret type
- Bar chart: Risk score by file path
- Timeline chart: Findings by commit date
- Gauge chart: Overall repository risk score
- Bar chart: Severity breakdown
- Histogram: Entropy score distribution

Author: VaultHound Team
"""

import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
from typing import List, Dict, Any, Optional
from collections import Counter
from datetime import datetime
import pandas as pd

# Import theme colors
from vaulthound.ui.theme import (
    AUTUMN_PALETTE,
    get_theme_colors,
    get_severity_colors,
)
from vaulthound.agents.state import FindingModel, SeverityLevel, SecretType


# =============================================================================
# CHART COLOR PALETTE
# =============================================================================


# Extended color palette for charts with multiple data points
CHART_COLORS = [
    AUTUMN_PALETTE["primary"],  # Burnt orange
    AUTUMN_PALETTE["secondary"],  # Amber gold
    AUTUMN_PALETTE["highlight"],  # Deep crimson
    AUTUMN_PALETTE["success"],  # Forest green
    AUTUMN_PALETTE["warning"],  # Harvest gold
    AUTUMN_PALETTE["danger"],  # Deep red
    AUTUMN_PALETTE["muted"],  # Muted brown
    AUTUMN_PALETTE["border"],  # Dark bark
    "#8b4513",  # Saddle brown
    "#cd853f",  # Peru
    "#deb887",  # Burlywood
    "#f4a460",  # Sandy brown
]


# =============================================================================
# BASE LAYOUT CONFIGURATION
# =============================================================================


def get_base_layout(
    title: str,
    height: int = 400,
    show_legend: bool = True,
) -> go.Layout:
    """
    Creates a base Plotly layout with autumn theme styling.

    Args:
        title: Chart title
        height: Chart height in pixels
        show_legend: Whether to show legend

    Returns:
        Configured Plotly Layout object
    """
    return go.Layout(
        title={
            "text": title,
            "font": {
                "family": "Crimson Pro, Georgia, serif",
                "size": 20,
                "color": AUTUMN_PALETTE["text_primary"],
            },
            "x": 0.5,
            "xanchor": "center",
        },
        paper_bgcolor=AUTUMN_PALETTE["surface"],
        plot_bgcolor=AUTUMN_PALETTE["background"],
        font={
            "family": "JetBrains Mono, Consolas, monospace",
            "size": 12,
            "color": AUTUMN_PALETTE["text_primary"],
        },
        height=height,
        showlegend=show_legend,
        legend=dict(
            font=dict(
                family="JetBrains Mono, Consolas, monospace",
                size=11,
                color=AUTUMN_PALETTE["text_secondary"],
            ),
            bgcolor=AUTUMN_PALETTE["surface"],
            bordercolor=AUTUMN_PALETTE["border"],
            borderwidth=1,
        ),
        margin=dict(l=60, r=40, t=80, b=60),
        hovermode="closest",
        hoverlabel=dict(
            bgcolor=AUTUMN_PALETTE["surface"],
            bordercolor=AUTUMN_PALETTE["primary"],
            font=dict(
                family="JetBrains Mono, Consolas, monospace",
                size=11,
                color=AUTUMN_PALETTE["text_primary"],
            ),
        ),
        xaxis=dict(
            gridcolor=AUTUMN_PALETTE["border"],
            linecolor=AUTUMN_PALETTE["border"],
            tickfont=dict(color=AUTUMN_PALETTE["text_secondary"]),
            titlefont=dict(color=AUTUMN_PALETTE["text_primary"]),
        ),
        yaxis=dict(
            gridcolor=AUTUMN_PALETTE["border"],
            linecolor=AUTUMN_PALETTE["border"],
            tickfont=dict(color=AUTUMN_PALETTE["text_secondary"]),
            titlefont=dict(color=AUTUMN_PALETTE["text_primary"]),
        ),
    )


# =============================================================================
# PIE CHART: FINDING DISTRIBUTION BY TYPE
# =============================================================================


def create_finding_distribution_pie(findings: List[FindingModel]) -> go.Figure:
    """
    Creates a pie chart showing the distribution of findings by secret type.

    This chart helps users understand what types of secrets are most commonly
    found in their repository, which can guide remediation priorities.

    Args:
        findings: List of FindingModel objects to visualize

    Returns:
        Plotly Figure object with pie chart

    Example:
        >>> findings = db.get_all_findings()
        >>> fig = create_finding_distribution_pie(findings)
        >>> st.plotly_chart(fig)
    """
    if not findings:
        # Return empty chart with placeholder
        fig = go.Figure()
        fig.update_layout(
            get_base_layout("Finding Distribution by Type", height=350),
            annotations=[
                dict(
                    text="No findings to display",
                    font=dict(size=16, color=AUTUMN_PALETTE["text_secondary"]),
                    showarrow=False,
                    x=0.5,
                    y=0.5,
                )
            ],
        )
        return fig

    # Count findings by secret type
    type_counts = Counter(f.secret_type.value for f in findings)

    # Sort by count descending
    sorted_types = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)

    labels = [item[0] for item in sorted_types]
    values = [item[1] for item in sorted_types]

    # Create pie chart
    fig = go.Figure(
        data=[
            go.Pie(
                labels=labels,
                values=values,
                hole=0.4,
                marker=dict(colors=CHART_COLORS[: len(labels)]),
                textinfo="label+percent",
                textposition="outside",
                textfont=dict(
                    family="JetBrains Mono, Consolas, monospace",
                    size=11,
                    color=AUTUMN_PALETTE["text_primary"],
                ),
                hovertemplate=(
                    "<b>%{label}</b><br>"
                    "Count: %{value}<br>"
                    "Percentage: %{percent}<extra></extra>"
                ),
                pull=[0.02] * len(labels),
            )
        ]
    )

    fig.update_layout(
        get_base_layout("Finding Distribution by Secret Type", height=400),
    )

    return fig


# =============================================================================
# BAR CHART: RISK SCORE BY FILE PATH
# =============================================================================


def create_risk_by_file_bar(findings: List[FindingModel]) -> go.Figure:
    """
    Creates a horizontal bar chart showing risk scores by file path.

    This chart helps identify which files have the highest concentration
    of secrets/secrets, allowing users to prioritize remediation efforts.

    Args:
        findings: List of FindingModel objects to visualize

    Returns:
        Plotly Figure object with horizontal bar chart

    Example:
        >>> findings = db.get_all_findings()
        >>> fig = create_risk_by_file_bar(findings)
        >>> st.plotly_chart(fig)
    """
    if not findings:
        # Return empty chart with placeholder
        fig = go.Figure()
        fig.update_layout(
            get_base_layout("Risk Score by File Path", height=350),
            annotations=[
                dict(
                    text="No findings to display",
                    font=dict(size=16, color=AUTUMN_PALETTE["text_secondary"]),
                    showarrow=False,
                    x=0.5,
                    y=0.5,
                )
            ],
        )
        return fig

    # Calculate risk score by file (count * average severity weight)
    severity_weights = {
        "critical": 10,
        "high": 7,
        "medium": 4,
        "low": 2,
        "info": 1,
    }

    file_risks: Dict[str, float] = {}
    file_counts: Dict[str, int] = {}

    for finding in findings:
        file_path = finding.file_path
        severity = (
            finding.severity
            if isinstance(finding.severity, str)
            else finding.severity.value
        )
        weight = severity_weights.get(severity, 1)

        if file_path not in file_risks:
            file_risks[file_path] = 0
            file_counts[file_path] = 0

        file_risks[file_path] += weight
        file_counts[file_path] += 1

    # Calculate average risk score per file
    for file_path in file_risks:
        file_risks[file_path] = file_risks[file_path] / file_counts[file_path]

    # Sort by risk score and take top 15
    sorted_files = sorted(file_risks.items(), key=lambda x: x[1], reverse=True)[:15]

    file_paths = [item[0] for item in sorted_files]
    risk_scores = [item[1] for item in sorted_files]

    # Determine colors based on risk level
    colors = []
    for score in risk_scores:
        if score >= 7:
            colors.append(AUTUMN_PALETTE["danger"])
        elif score >= 4:
            colors.append(AUTUMN_PALETTE["warning"])
        else:
            colors.append(AUTUMN_PALETTE["secondary"])

    # Truncate long file paths for display
    display_paths = []
    for path in file_paths:
        if len(path) > 40:
            display_paths.append("..." + path[-37:])
        else:
            display_paths.append(path)

    fig = go.Figure(
        data=[
            go.Bar(
                x=risk_scores,
                y=display_paths,
                orientation="h",
                marker=dict(
                    color=colors,
                    line=dict(color=AUTUMN_PALETTE["border"], width=1),
                ),
                text=[f"{score:.1f}" for score in risk_scores],
                textposition="outside",
                textfont=dict(color=AUTUMN_PALETTE["text_primary"]),
                hovertemplate=(
                    "<b>%{y}</b><br>"
                    "Risk Score: %{x:.1f}<br>"
                    "Findings: "
                    + str(
                        {
                            file_paths[i]: file_counts[file_paths[i]]
                            for i in range(len(file_paths))
                        }
                    )
                    + "<extra></extra>"
                ),
            )
        ]
    )

    fig.update_layout(
        get_base_layout("Risk Score by File Path", height=500),
        xaxis_title="Risk Score (weighted by severity)",
        yaxis_title="File Path",
        xaxis=dict(range=[0, max(risk_scores) * 1.2] if risk_scores else [0, 10]),
    )

    return fig


# =============================================================================
# TIMELINE CHART: FINDINGS BY COMMIT DATE
# =============================================================================


def create_timeline_chart(findings: List[FindingModel]) -> go.Figure:
    """
    Creates a timeline chart showing findings grouped by commit date.

    This chart helps identify patterns in when secrets were introduced,
    which can be useful for understanding the history of credential leakage.

    Args:
        findings: List of FindingModel objects to visualize

    Returns:
        Plotly Figure object with timeline chart

    Example:
        >>> findings = db.get_all_findings()
        >>> fig = create_timeline_chart(findings)
        >>> st.plotly_chart(fig)
    """
    if not findings:
        # Return empty chart with placeholder
        fig = go.Figure()
        fig.update_layout(
            get_base_layout("Findings Timeline by Commit Date", height=350),
            annotations=[
                dict(
                    text="No findings to display",
                    font=dict(size=16, color=AUTUMN_PALETTE["text_secondary"]),
                    showarrow=False,
                    x=0.5,
                    y=0.5,
                )
            ],
        )
        return fig

    # Group findings by commit date
    date_counts: Dict[str, int] = {}
    severity_by_date: Dict[str, Dict[str, int]] = {}

    for finding in findings:
        if finding.commit_date:
            # Handle both datetime objects and string dates
            if isinstance(finding.commit_date, datetime):
                date_key = finding.commit_date.strftime("%Y-%m-%d")
            elif isinstance(finding.commit_date, str):
                try:
                    date_key = datetime.fromisoformat(
                        finding.commit_date.replace("Z", "+00:00")
                    ).strftime("%Y-%m-%d")
                except (ValueError, AttributeError):
                    date_key = (
                        finding.commit_date[:10]
                        if len(finding.commit_date) >= 10
                        else finding.commit_date
                    )
            else:
                continue

            date_counts[date_key] = date_counts.get(date_key, 0) + 1

            severity = (
                finding.severity
                if isinstance(finding.severity, str)
                else finding.severity.value
            )
            if date_key not in severity_by_date:
                severity_by_date[date_key] = {
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "info": 0,
                }
            severity_by_date[date_key][severity] = (
                severity_by_date[date_key].get(severity, 0) + 1
            )

    if not date_counts:
        # No valid dates found
        fig = go.Figure()
        fig.update_layout(
            get_base_layout("Findings Timeline by Commit Date", height=350),
            annotations=[
                dict(
                    text="No commit dates available",
                    font=dict(size=16, color=AUTUMN_PALETTE["text_secondary"]),
                    showarrow=False,
                    x=0.5,
                    y=0.5,
                )
            ],
        )
        return fig

    # Sort by date
    sorted_dates = sorted(date_counts.keys())

    # Create traces for each severity level
    severity_colors = get_severity_colors()

    fig = go.Figure()

    # Add area chart for total findings
    fig.add_trace(
        go.Scatter(
            x=sorted_dates,
            y=[date_counts[d] for d in sorted_dates],
            mode="lines+markers",
            fill="tozeroy",
            name="Total Findings",
            line=dict(
                color=AUTUMN_PALETTE["primary"],
                width=3,
            ),
            marker=dict(
                size=10,
                color=AUTUMN_PALETTE["primary"],
                line=dict(color=AUTUMN_PALETTE["surface"], width=2),
            ),
            hovertemplate=("<b>%{x}</b><br>" "Total Findings: %{y}<extra></extra>"),
        )
    )

    fig.update_layout(
        get_base_layout("Findings Timeline by Commit Date", height=400),
        xaxis_title="Commit Date",
        yaxis_title="Number of Findings",
        xaxis=dict(
            type="date",
            tickformat="%Y-%m-%d",
            dtick="M1",
        ),
    )

    return fig


# =============================================================================
# GAUGE CHART: OVERALL REPO RISK SCORE
# =============================================================================


def create_risk_gauge(score: float) -> go.Figure:
    """
    Creates a gauge chart showing the overall repository risk score.

    The risk score is calculated from the findings and ranges from 0 (safe)
    to 10 (critical risk). This provides a quick at-a-glance view of the
    repository's security posture.

    Args:
        score: Risk score (0-10)

    Returns:
        Plotly Figure object with gauge chart

    Example:
        >>> score = calculate_overall_risk(findings)
        >>> fig = create_risk_gauge(score)
        >>> st.plotly_chart(fig)
    """
    # Clamp score to valid range
    score = max(0, min(10, score))

    # Determine color based on score
    if score >= 7:
        gauge_color = AUTUMN_PALETTE["danger"]
        level_text = "CRITICAL"
    elif score >= 5:
        gauge_color = AUTUMN_PALETTE["warning"]
        level_text = "HIGH"
    elif score >= 3:
        gauge_color = AUTUMN_PALETTE["secondary"]
        level_text = "MEDIUM"
    else:
        gauge_color = AUTUMN_PALETTE["success"]
        level_text = "LOW"

    fig = go.Figure(
        go.Indicator(
            mode="gauge+number+delta",
            value=score,
            domain=dict(x=[0, 1], y=[0, 1]),
            title=dict(
                text="Repository Risk Score",
                font=dict(
                    family="Crimson Pro, Georgia, serif",
                    size=18,
                    color=AUTUMN_PALETTE["text_primary"],
                ),
            ),
            number=dict(
                font=dict(
                    family="Crimson Pro, Georgia, serif",
                    size=48,
                    color=gauge_color,
                ),
                suffix="",
            ),
            delta=dict(
                reference=5,
                increasing=dict(color=AUTUMN_PALETTE["danger"]),
                decreasing=dict(color=AUTUMN_PALETTE["success"]),
            ),
            gauge=dict(
                axis=dict(
                    range=[0, 10],
                    tickwidth=1,
                    tickcolor=AUTUMN_PALETTE["text_secondary"],
                    tickfont=dict(color=AUTUMN_PALETTE["text_secondary"]),
                    dtick=2,
                ),
                bar=dict(
                    color=gauge_color,
                    thickness=0.8,
                ),
                bgcolor=AUTUMN_PALETTE["background"],
                borderwidth=2,
                bordercolor=AUTUMN_PALETTE["border"],
                steps=[
                    dict(
                        range=[0, 3],
                        color=AUTUMN_PALETTE["success"],
                    ),
                    dict(
                        range=[3, 5],
                        color=AUTUMN_PALETTE["secondary"],
                    ),
                    dict(
                        range=[5, 7],
                        color=AUTUMN_PALETTE["warning"],
                    ),
                    dict(
                        range=[7, 10],
                        color=AUTUMN_PALETTE["danger"],
                    ),
                ],
                threshold=dict(
                    line=dict(
                        color=AUTUMN_PALETTE["text_primary"],
                        width=3,
                    ),
                    thickness=0.85,
                    value=score,
                ),
            ),
        )
    )

    fig.update_layout(
        paper_bgcolor=AUTUMN_PALETTE["surface"],
        font=dict(
            family="JetBrains Mono, Consolas, monospace",
            color=AUTUMN_PALETTE["text_primary"],
        ),
        height=350,
        margin=dict(l=40, r=40, t=80, b=40),
    )

    return fig


# =============================================================================
# BAR CHART: SEVERITY BREAKDOWN
# =============================================================================


def create_severity_breakdown_bar(findings: List[FindingModel]) -> go.Figure:
    """
    Creates a bar chart showing the breakdown of findings by severity level.

    This chart provides a quick overview of the severity distribution,
    helping users understand the overall risk profile of their findings.

    Args:
        findings: List of FindingModel objects to visualize

    Returns:
        Plotly Figure object with bar chart

    Example:
        >>> findings = db.get_all_findings()
        >>> fig = create_severity_breakdown_bar(findings)
        >>> st.plotly_chart(fig)
    """
    if not findings:
        # Return empty chart with placeholder
        fig = go.Figure()
        fig.update_layout(
            get_base_layout("Findings by Severity", height=350),
            annotations=[
                dict(
                    text="No findings to display",
                    font=dict(size=16, color=AUTUMN_PALETTE["text_secondary"]),
                    showarrow=False,
                    x=0.5,
                    y=0.5,
                )
            ],
        )
        return fig

    # Count findings by severity
    severity_counts = Counter()
    for finding in findings:
        severity = (
            finding.severity
            if isinstance(finding.severity, str)
            else finding.severity.value
        )
        severity_counts[severity] += 1

    # Define order and labels
    severity_order = ["critical", "high", "medium", "low", "info"]
    severity_labels = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Info",
    }

    # Get colors
    severity_colors = get_severity_colors()

    counts = [severity_counts.get(sev, 0) for sev in severity_order]
    colors = [
        severity_colors.get(sev, AUTUMN_PALETTE["muted"]) for sev in severity_order
    ]
    labels = [severity_labels[sev] for sev in severity_order]

    fig = go.Figure(
        data=[
            go.Bar(
                x=labels,
                y=counts,
                marker=dict(
                    color=colors,
                    line=dict(color=AUTUMN_PALETTE["border"], width=1),
                ),
                text=counts,
                textposition="outside",
                textfont=dict(
                    family="JetBrains Mono, Consolas, monospace",
                    size=12,
                    color=AUTUMN_PALETTE["text_primary"],
                ),
                hovertemplate=("<b>%{x}</b><br>" "Count: %{y}<extra></extra>"),
            )
        ]
    )

    fig.update_layout(
        get_base_layout("Findings by Severity Level", height=400),
        xaxis_title="Severity Level",
        yaxis_title="Number of Findings",
        yaxis=dict(range=[0, max(counts) * 1.2] if counts else [0, 10]),
    )

    return fig


# =============================================================================
# HISTOGRAM: ENTROPY SCORE DISTRIBUTION
# =============================================================================


def create_entropy_distribution_histogram(findings: List[FindingModel]) -> go.Figure:
    """
    Creates a histogram showing the distribution of entropy scores.

    Entropy score is a measure of randomness - higher entropy scores indicate
    more likely to be actual secrets. This chart helps identify the distribution
    of finding confidence levels.

    Args:
        findings: List of FindingModel objects to visualize

    Returns:
        Plotly Figure object with histogram

    Example:
        >>> findings = db.get_all_findings()
        >>> fig = create_entropy_distribution_histogram(findings)
        >>> st.plotly_chart(fig)
    """
    if not findings:
        # Return empty chart with placeholder
        fig = go.Figure()
        fig.update_layout(
            get_base_layout("Entropy Score Distribution", height=350),
            annotations=[
                dict(
                    text="No findings to display",
                    font=dict(size=16, color=AUTUMN_PALETTE["text_secondary"]),
                    showarrow=False,
                    x=0.5,
                    y=0.5,
                )
            ],
        )
        return fig

    # Extract entropy scores
    entropy_scores = []
    for finding in findings:
        if finding.entropy_score is not None:
            entropy_scores.append(finding.entropy_score)

    if not entropy_scores:
        fig = go.Figure()
        fig.update_layout(
            get_base_layout("Entropy Score Distribution", height=350),
            annotations=[
                dict(
                    text="No entropy scores available",
                    font=dict(size=16, color=AUTUMN_PALETTE["text_secondary"]),
                    showarrow=False,
                    x=0.5,
                    y=0.5,
                )
            ],
        )
        return fig

    fig = go.Figure(
        data=[
            go.Histogram(
                x=entropy_scores,
                nbinsx=20,
                marker_color=AUTUMN_PALETTE["primary"],
                marker_line_color=AUTUMN_PALETTE["border"],
                marker_line_width=1.5,
                hovertemplate=(
                    "Entropy Score: %{x:.2f}<br>" "Count: %{y}<extra></extra>"
                ),
            )
        ]
    )

    fig.update_layout(
        get_base_layout("Entropy Score Distribution", height=400),
        xaxis_title="Entropy Score",
        yaxis_title="Count",
        xaxis=dict(range=[0, 8]),
        bargap=0.1,
    )

    # Add vertical lines for interpretation
    fig.add_vline(
        x=3.5,
        line_dash="dash",
        line_color=AUTUMN_PALETTE["success"],
        annotation_text="Low",
        annotation_position="top right",
    )
    fig.add_vline(
        x=4.5,
        line_dash="dash",
        line_color=AUTUMN_PALETTE["warning"],
        annotation_text="Medium",
        annotation_position="top right",
    )
    fig.add_vline(
        x=5.5,
        line_dash="dash",
        line_color=AUTUMN_PALETTE["danger"],
        annotation_text="High",
        annotation_position="top right",
    )

    return fig


# =============================================================================
# COMBINED DASHBOARD CHART
# =============================================================================


def create_risk_summary_dashboard(
    findings: List[FindingModel],
    overall_risk_score: float,
) -> go.Figure:
    """
    Creates a combined dashboard with multiple chart types.

    This provides a comprehensive overview of findings in a single chart,
    useful for high-level reporting and executive summaries.

    Args:
        findings: List of FindingModel objects to visualize
        overall_risk_score: Overall repository risk score (0-10)

    Returns:
        Plotly Figure object with subplots

    Example:
        >>> findings = db.get_all_findings()
        >>> score = calculate_risk_score(findings)
        >>> fig = create_risk_summary_dashboard(findings, score)
        >>> st.plotly_chart(fig)
    """
    # Create subplots
    fig = make_subplots(
        rows=2,
        cols=2,
        subplot_titles=(
            "Risk by File Path",
            "Severity Breakdown",
            "Finding Types",
            "Risk Gauge",
        ),
        specs=[
            [{"type": "bar"}, {"type": "bar"}],
            [{"type": "pie"}, {"type": "indicator"}],
        ],
        horizontal_spacing=0.12,
        vertical_spacing=0.15,
    )

    # 1. Risk by file (horizontal bar) - top left
    severity_weights = {"critical": 10, "high": 7, "medium": 4, "low": 2, "info": 1}
    file_risks: Dict[str, float] = {}
    file_counts: Dict[str, int] = {}

    for finding in findings:
        file_path = finding.file_path
        severity = (
            finding.severity
            if isinstance(finding.severity, str)
            else finding.severity.value
        )
        weight = severity_weights.get(severity, 1)

        if file_path not in file_risks:
            file_risks[file_path] = 0
            file_counts[file_path] = 0

        file_risks[file_path] += weight
        file_counts[file_path] += 1

    for file_path in file_risks:
        file_risks[file_path] = file_risks[file_path] / file_counts[file_path]

    sorted_files = sorted(file_risks.items(), key=lambda x: x[1], reverse=True)[:8]
    display_paths = [
        ("..." + path[-20:] if len(path) > 23 else path) for path, _ in sorted_files
    ]
    risk_scores = [score for _, score in sorted_files]

    if sorted_files:
        fig.add_trace(
            go.Bar(
                x=risk_scores,
                y=display_paths,
                orientation="h",
                marker_color=AUTUMN_PALETTE["primary"],
                hovertemplate="<b>%{y}</b><br>Risk: %{x:.1f}<extra></extra>",
            ),
            row=1,
            col=1,
        )

    # 2. Severity breakdown - top right
    severity_counts = Counter()
    for finding in findings:
        severity = (
            finding.severity
            if isinstance(finding.severity, str)
            else finding.severity.value
        )
        severity_counts[severity] += 1

    severity_order = ["critical", "high", "medium", "low", "info"]
    severity_colors_list = get_severity_colors()
    counts = [severity_counts.get(sev, 0) for sev in severity_order]
    colors = [
        severity_colors_list.get(sev, AUTUMN_PALETTE["muted"]) for sev in severity_order
    ]

    fig.add_trace(
        go.Bar(
            x=["Critical", "High", "Medium", "Low", "Info"],
            y=counts,
            marker_color=colors,
            hovertemplate="<b>%{x}</b><br>Count: %{y}<extra></extra>",
        ),
        row=1,
        col=2,
    )

    # 3. Finding types pie - bottom left
    type_counts = Counter(f.secret_type.value for f in findings)
    sorted_types = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)[:6]
    labels = [item[0] for item in sorted_types]
    values = [item[1] for item in sorted_types]

    fig.add_trace(
        go.Pie(
            labels=labels,
            values=values,
            hole=0.4,
            marker_colors=CHART_COLORS[: len(labels)],
            textinfo="label+percent",
            hovertemplate="<b>%{label}</b><br>Count: %{value}<br>%{percent}<extra></extra>",
        ),
        row=2,
        col=1,
    )

    # 4. Risk gauge - bottom right
    score = max(0, min(10, overall_risk_score))
    gauge_color = (
        AUTUMN_PALETTE["danger"]
        if score >= 7
        else AUTUMN_PALETTE["warning"] if score >= 3 else AUTUMN_PALETTE["success"]
    )

    fig.add_trace(
        go.Indicator(
            mode="gauge+number",
            value=score,
            gauge=dict(
                axis=dict(range=[0, 10], tickwidth=1),
                bar=dict(color=gauge_color, thickness=0.8),
                bgcolor=AUTUMN_PALETTE["background"],
                borderwidth=2,
                bordercolor=AUTUMN_PALETTE["border"],
            ),
            number=dict(font_size=36, color=gauge_color),
        ),
        row=2,
        col=2,
    )

    # Update layout
    fig.update_layout(
        title=dict(
            text="VaultHound Risk Summary Dashboard",
            font=dict(
                family="Crimson Pro, Georgia, serif",
                size=22,
                color=AUTUMN_PALETTE["text_primary"],
            ),
            x=0.5,
            xanchor="center",
        ),
        paper_bgcolor=AUTUMN_PALETTE["surface"],
        plot_bgcolor=AUTUMN_PALETTE["background"],
        font=dict(
            family="JetBrains Mono, Consolas, monospace",
            size=11,
            color=AUTUMN_PALETTE["text_primary"],
        ),
        height=700,
        showlegend=False,
    )

    # Update axes
    fig.update_xaxes(title_text="Risk Score", row=1, col=1)
    fig.update_yaxes(autorange="reversed", row=1, col=1)
    fig.update_xaxes(title_text="Count", row=1, col=2)
    fig.update_yaxes(title_text="Severity", row=1, col=2)

    return fig


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================


def calculate_overall_risk_score(findings: List[FindingModel]) -> float:
    """
    Calculates the overall risk score from a list of findings.

    The score is calculated using a weighted average based on severity levels,
    with critical findings contributing the most to the overall score.

    Args:
        findings: List of FindingModel objects

    Returns:
        Risk score from 0-10
    """
    if not findings:
        return 0.0

    severity_weights = {
        "critical": 10,
        "high": 7,
        "medium": 4,
        "low": 2,
        "info": 1,
    }

    total_weight = 0
    total_severity = 0

    for finding in findings:
        severity = (
            finding.severity
            if isinstance(finding.severity, str)
            else finding.severity.value
        )
        weight = severity_weights.get(severity, 1)
        total_weight += weight
        total_severity += 1

    if total_severity == 0:
        return 0.0

    # Calculate average and normalize to 0-10
    avg_weight = total_weight / total_severity
    normalized_score = min(10, avg_weight)

    return round(normalized_score, 1)


def create_empty_chart(message: str = "No data available") -> go.Figure:
    """
    Creates an empty chart with a placeholder message.

    Args:
        message: Message to display in the chart

    Returns:
        Plotly Figure object with placeholder
    """
    fig = go.Figure()
    fig.update_layout(
        get_base_layout("Chart", height=300),
        annotations=[
            dict(
                text=message,
                font=dict(size=14, color=AUTUMN_PALETTE["text_secondary"]),
                showarrow=False,
                x=0.5,
                y=0.5,
            )
        ],
    )
    return fig
