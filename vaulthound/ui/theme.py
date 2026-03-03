"""
VaultHound Autumn Theme - UI Styling Module

This module provides the warm autumn color palette and CSS injection for the VaultHound UI.
The theme is designed with psychological color theory in mind - warm, earthy tones that evoke
feelings of security, trust, and autumnal comfort while maintaining high contrast for readability.

Color Psychology:
- Deep espresso (#1a1008): Grounding, stable, evokes traditional vault security
- Burnt orange (#e07b39): Energetic but warm, draws attention without aggression
- Amber gold (#c4922a): Wealth, prosperity - fitting for credential/security context
- Warm cream (#f5e6d0): Easy on eyes, reduces strain during long scanning sessions

Author: VaultHound Team
"""

import streamlit as st
from typing import Dict, Any, Optional


# =============================================================================
# AUTUMN COLOR PALETTE DEFINITIONS
# =============================================================================
# Primary autumn theme colors with psychological associations

AUTUMN_PALETTE = {
    # Core background colors - deep, grounding tones
    "background": "#1a1008",  # Deep espresso - security, stability
    "surface": "#2d1f0e",  # Dark walnut - warmth, comfort
    "border": "#4a3018",  # Dark bark - definition without harshness
    # Accent colors - attention-grabbing but not aggressive
    "primary": "#e07b39",  # Burnt orange - energy, urgency, alerts
    "secondary": "#c4922a",  # Amber gold - value, credentials, secrets
    "highlight": "#8b2e0f",  # Deep crimson - critical severity, warnings
    # Text colors - optimized for readability
    "text_primary": "#f5e6d0",  # Warm cream - high contrast on dark
    "text_secondary": "#b89a7a",  # Muted tan - less visual fatigue
    # Semantic colors - universally understood meanings
    "success": "#5a8a3c",  # Forest green - safe, verified
    "warning": "#d4a017",  # Harvest gold - caution, medium risk
    "danger": "#c0392b",  # Deep red - critical, high risk
    # Additional utility colors
    "muted": "#6b4423",  # Muted brown - secondary elements
    "hover": "#3d2a14",  # Hover state - subtle interactivity
    "code_background": "#241709",  # Code block - slightly lighter than background
}


# =============================================================================
# COLOR PALETTE FUNCTIONS
# =============================================================================


def get_theme_colors() -> Dict[str, str]:
    """
    Returns the complete autumn color palette dictionary.

    Returns:
        Dict containing all theme colors keyed by semantic name.
    """
    return AUTUMN_PALETTE.copy()


def get_color_palette() -> Dict[str, str]:
    """
    Returns color palette for use in charts and visualizations.
    Alias for get_theme_colors() for chart-specific use cases.

    Returns:
        Dict containing chart-appropriate color palette.
    """
    return get_theme_colors()


def get_severity_colors() -> Dict[str, str]:
    """
    Returns severity-specific color mapping for vulnerability/ticket levels.
    Uses highlight and danger colors for critical levels to draw attention.

    Returns:
        Dict mapping severity levels to their corresponding colors.
    """
    return {
        "critical": AUTUMN_PALETTE["danger"],  # Deep red - immediate attention
        "high": AUTUMN_PALETTE["highlight"],  # Deep crimson - serious concern
        "medium": AUTUMN_PALETTE["warning"],  # Harvest gold - caution
        "low": AUTUMN_PALETTE["secondary"],  # Amber gold - minor issues
        "info": AUTUMN_PALETTE["success"],  # Forest green - informational
        "safe": AUTUMN_PALETTE["success"],  # Forest green - all clear
    }


# =============================================================================
# CSS INJECTION FUNCTIONS
# =============================================================================


def inject_theme() -> None:
    """
    Main theme injection function.

    Injects the complete autumn theme CSS via st.markdown, including:
    - Google Fonts (Crimson Pro for headers, JetBrains Mono for code)
    - Base theme colors and variables
    - Typography settings
    - Component styling (buttons, inputs, cards, tables)
    - Custom scrollbar styling

    This function should be called once at app initialization.
    """
    # Import Google Fonts
    fonts_css = """
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Crimson+Pro:wght@400;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    """

    # CSS Variables and Base Theme
    theme_css = f"""
    <style>
        /* ===== CSS VARIABLES ===== */
        :root {{
            --vh-background: {AUTUMN_PALETTE['background']};
            --vh-surface: {AUTUMN_PALETTE['surface']};
            --vh-primary: {AUTUMN_PALETTE['primary']};
            --vh-secondary: {AUTUMN_PALETTE['secondary']};
            --vh-highlight: {AUTUMN_PALETTE['highlight']};
            --vh-text-primary: {AUTUMN_PALETTE['text_primary']};
            --vh-text-secondary: {AUTUMN_PALETTE['text_secondary']};
            --vh-success: {AUTUMN_PALETTE['success']};
            --vh-warning: {AUTUMN_PALETTE['warning']};
            --vh-danger: {AUTUMN_PALETTE['danger']};
            --vh-border: {AUTUMN_PALETTE['border']};
            --vh-muted: {AUTUMN_PALETTE['muted']};
            --vh-hover: {AUTUMN_PALETTE['hover']};
            --vh-code-bg: {AUTUMN_PALETTE['code_background']};
        }}

        /* ===== GLOBAL STYLES ===== */
        .stApp {{
            background-color: var(--vh-background);
            color: var(--vh-text-primary);
        }}

        /* Typography - Crimson Pro for elegant headers */
        h1, h2, h3, h4, h5, h6 {{
            font-family: 'Crimson Pro', Georgia, serif;
            color: var(--vh-text-primary);
            font-weight: 600;
            letter-spacing: 0.02em;
        }}

        /* Code - JetBrains Mono for technical readability */
        code, pre, .stCodeBlock {{
            font-family: 'JetBrains Mono', 'Consolas', monospace;
            background-color: var(--vh-code-bg);
        }}

        /* ===== COMPONENT STYLES ===== */
        
        /* Buttons - Burnt orange for primary actions */
        .stButton > button {{
            background-color: var(--vh-primary);
            color: var(--vh-text-primary);
            border: 1px solid var(--vh-border);
            border-radius: 6px;
            font-family: 'Crimson Pro', Georgia, serif;
            font-weight: 600;
            transition: all 0.2s ease;
        }}
        .stButton > button:hover {{
            background-color: var(--vh-highlight);
            border-color: var(--vh-primary);
            transform: translateY(-1px);
        }}

        /* Input fields - Dark walnut surface */
        .stTextInput > div > div,
        .stTextArea > div > div,
        .stSelectbox > div > div,
        .stNumberInput > div > div {{
            background-color: var(--vh-surface);
            border: 1px solid var(--vh-border);
            border-radius: 6px;
            color: var(--vh-text-primary);
        }}
        .stTextInput > div > div:focus-within,
        .stTextArea > div > div:focus-within {{
            border-color: var(--vh-primary);
            box-shadow: 0 0 0 2px rgba(224, 123, 57, 0.2);
        }}

        /* Cards - Elevated surface with subtle shadow */
        .stCard, div[data-testid="stMetric"], 
        div[data-testid="stExpander"], .streamlit-expanderHeader {{
            background-color: var(--vh-surface);
            border: 1px solid var(--vh-border);
            border-radius: 8px;
            padding: 16px;
            color: var(--vh-text-primary);
        }}

        /* Dataframes/Tables */
        .stDataFrame {{
            border: 1px solid var(--vh-border);
            border-radius: 8px;
        }}
        [data-testid="stDataFrame"] {{
            background-color: var(--vh-surface);
        }}

        /* Metrics - Amber gold for emphasis */
        [data-testid="stMetricValue"] {{
            color: var(--vh-secondary);
            font-family: 'Crimson Pro', Georgia, serif;
        }}
        [data-testid="stMetricLabel"] {{
            color: var(--vh-text-secondary);
        }}

        /* Tabs */
        .stTabs [data-baseweb="tab-list"] {{
            gap: 8px;
        }}
        .stTabs [data-baseweb="tab"] {{
            background-color: transparent;
            border: 1px solid var(--vh-border);
            border-radius: 6px 6px 0 0;
            color: var(--vh-text-secondary);
            font-family: 'Crimson Pro', Georgia, serif;
        }}
        .stTabs [aria-selected="true"] {{
            background-color: var(--vh-surface);
            border-bottom-color: var(--vh-primary);
            color: var(--vh-primary);
        }}

        /* Sidebar - Darker surface for contrast */
        [data-testid="stSidebar"] {{
            background-color: {AUTUMN_PALETTE['background']};
            border-right: 1px solid var(--vh-border);
        }}

        /* Dividers */
        hr {{
            border-color: var(--vh-border);
        }}

        /* Progress bars */
        .stProgress > div > div > div {{
            background-color: var(--vh-primary);
        }}

        /* Alerts/Messages */
        .stAlert {{
            border-radius: 6px;
            border-left: 4px solid;
        }}
        
        /* Success messages - Forest green */
        .stSuccess {{
            background-color: rgba(90, 138, 60, 0.15);
            border-left-color: var(--vh-success);
        }}
        
        /* Warning messages - Harvest gold */
        .stWarning {{
            background-color: rgba(212, 160, 23, 0.15);
            border-left-color: var(--vh-warning);
        }}
        
        /* Error messages - Deep red */
        .stError {{
            background-color: rgba(192, 57, 43, 0.15);
            border-left-color: var(--vh-danger);
        }}

        /* Info messages - Burnt orange */
        .stInfo {{
            background-color: rgba(224, 123, 57, 0.15);
            border-left-color: var(--vh-primary);
        }}

        /* Custom scrollbar - Dark bark theme */
        ::-webkit-scrollbar {{
            width: 10px;
            height: 10px;
        }}
        ::-webkit-scrollbar-track {{
            background: var(--vh-background);
        }}
        ::-webkit-scrollbar-thumb {{
            background: var(--vh-border);
            border-radius: 5px;
        }}
        ::-webkit-scrollbar-thumb:hover {{
            background: var(--vh-muted);
        }}

        /* Links - Burnt orange for visibility */
        a {{
            color: var(--vh-primary);
            text-decoration: none;
        }}
        a:hover {{
            color: var(--vh-secondary);
            text-decoration: underline;
        }}

        /* Custom header gradient effect */
        .vh-gradient-header {{
            background: linear-gradient(135deg, 
                {AUTUMN_PALETTE['surface']} 0%, 
                {AUTUMN_PALETTE['highlight']} 50%, 
                {AUTUMN_PALETTE['primary']} 100%);
            padding: 20px 24px;
            border-radius: 12px;
            border: 1px solid var(--vh-border);
            margin-bottom: 24px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
        }}
        
        .vh-gradient-header h1, 
        .vh-gradient-header h2 {{
            margin: 0;
            padding: 0;
            font-family: 'Crimson Pro', Georgia, serif;
            color: var(--vh-text-primary);
            text-shadow: 1px 1px 2px rgba(0, 0, 0, 0.3);
        }}
    </style>
    """

    # Inject fonts first, then theme
    st.markdown(fonts_css, unsafe_allow_html=True)
    st.markdown(theme_css, unsafe_allow_html=True)


def apply_custom_styling() -> None:
    """
    Applies additional custom styling beyond the base theme.

    Includes:
    - Custom animations for emphasis
    - Additional utility classes
    - Print-friendly styles

    Called after inject_theme() for extended styling.
    """
    custom_css = """
    <style>
        /* ===== ANIMATIONS ===== */
        @keyframes vh-pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.7; }
        }
        
        @keyframes vh-glow {
            0%, 100% { box-shadow: 0 0 5px var(--vh-primary); }
            50% { box-shadow: 0 0 20px var(--vh-primary), 0 0 30px var(--vh-secondary); }
        }
        
        /* Pulse animation for critical alerts */
        .vh-critical {{
            animation: vh-pulse 2s ease-in-out infinite;
            border-left: 4px solid var(--vh-danger);
        }}
        
        /* Glow effect for important metrics */
        .vh-highlight-metric {{
            animation: vh-glow 3s ease-in-out infinite;
        }}
        
        /* ===== UTILITY CLASSES ===== */
        .vh-text-success { color: var(--vh-success); }
        .vh-text-warning { color: var(--vh-warning); }
        .vh-text-danger { color: var(--vh-danger); }
        .vh-text-muted { color: var(--vh-text-secondary); }
        
        .vh-bg-surface { background-color: var(--vh-surface); }
        .vh-bg-hover { background-color: var(--vh-hover); }
        
        .vh-border-accent { border-left: 3px solid var(--vh-primary); }
        .vh-border-warning { border-left: 3px solid var(--vh-warning); }
        .vh-border-danger { border-left: 3px solid var(--vh-danger); }
        
        /* ===== SEVERITY BADGES ===== */
        .vh-badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        
        .vh-badge-critical {{
            background-color: var(--vh-danger);
            color: white;
        }}
        
        .vh-badge-high {{
            background-color: var(--vh-highlight);
            color: white;
        }}
        
        .vh-badge-medium {{
            background-color: var(--vh-warning);
            color: var(--vh-background);
        }}
        
        .vh-badge-low {{
            background-color: var(--vh-secondary);
            color: var(--vh-background);
        }}
        
        .vh-badge-info {{
            background-color: var(--vh-success);
            color: white;
        }}

        /* ===== PRINT STYLES ===== */
        @media print {
            .stButton, .stSidebar {{
                display: none !important;
            }}
            .stApp {{
                background-color: white !important;
                color: black !important;
            }}
        }
    </style>
    """
    st.markdown(custom_css, unsafe_allow_html=True)


def apply_card_styling() -> str:
    """
    Returns CSS string for card/styled box styling.

    Provides a reusable CSS block for creating themed cards
    with the autumn color palette.

    Returns:
        CSS string for card styling that can be used in st.markdown.
    """
    return f"""
    <style>
        .vh-card {{
            background-color: {AUTUMN_PALETTE['surface']};
            border: 1px solid {AUTUMN_PALETTE['border']};
            border-radius: 10px;
            padding: 20px;
            margin: 12px 0;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.2);
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }}
        
        .vh-card:hover {{
            transform: translateY(-2px);
            box-shadow: 0 4px 16px rgba(0, 0, 0, 0.3);
            border-color: {AUTUMN_PALETTE['primary']};
        }}
        
        .vh-card-header {{
            font-family: 'Crimson Pro', Georgia, serif;
            font-size: 1.25rem;
            font-weight: 600;
            color: {AUTUMN_PALETTE['text_primary']};
            margin-bottom: 12px;
            padding-bottom: 8px;
            border-bottom: 1px solid {AUTUMN_PALETTE['border']};
        }}
        
        .vh-card-content {{
            color: {AUTUMN_PALETTE['text_secondary']};
            line-height: 1.6;
        }}
    </style>
    """


# =============================================================================
# GRADIENT HEADER FUNCTIONS
# =============================================================================


def create_gradient_header(title: str, subtitle: Optional[str] = None) -> None:
    """
    Creates a styled gradient header with the autumn theme.

    Args:
        title: The main title text to display in the header.
        subtitle: Optional subtitle text for additional context.

    Example:
        >>> create_gradient_header("Secrets Detection Results", "Scan completed in 2.3s")
    """
    if subtitle:
        header_html = f"""
        <div class="vh-gradient-header">
            <h1>{title}</h1>
            <p style="margin: 8px 0 0 0; color: var(--vh-text-secondary); font-size: 0.9rem;">
                {subtitle}
            </p>
        </div>
        """
    else:
        header_html = f"""
        <div class="vh-gradient-header">
            <h1>{title}</h1>
        </div>
        """

    st.markdown(header_html, unsafe_allow_html=True)


def create_horizontal_gradient() -> str:
    """
    Returns CSS for a horizontal autumn gradient.

    Useful for creating decorative gradient backgrounds or borders.

    Returns:
        CSS linear-gradient string.
    """
    return f"linear-gradient(90deg, {AUTUMN_PALETTE['surface']}, {AUTUMN_PALETTE['highlight']}, {AUTUMN_PALETTE['primary']})"


# =============================================================================
# PLOTLY CHART HELPER FUNCTIONS
# =============================================================================


def get_plotly_color_sequence() -> list:
    """
    Returns an ordered list of autumn colors suitable for Plotly charts.

    The sequence is designed to provide good contrast between data points
    while maintaining visual harmony with the overall theme.

    Returns:
        List of hex color codes in display order.
    """
    return [
        AUTUMN_PALETTE["primary"],  # Burnt orange - primary data
        AUTUMN_PALETTE["secondary"],  # Amber gold - secondary data
        AUTUMN_PALETTE["highlight"],  # Deep crimson - accent
        AUTUMN_PALETTE["success"],  # Forest green - positive
        AUTUMN_PALETTE["warning"],  # Harvest gold - neutral
        AUTUMN_PALETTE["danger"],  # Deep red - negative
        AUTUMN_PALETTE["muted"],  # Muted brown - background
    ]


def get_plotly_template() -> Dict[str, Any]:
    """
    Returns a complete Plotly template dictionary for autumn-themed charts.

    Includes:
    - Background colors
    - Font settings (Crimson Pro, JetBrains Mono)
    - Grid colors
    - Axis colors
    - Color sequence

    Returns:
        Dict suitable for passing to plotly graph objects.
    """
    return {
        "layout": {
            "paper_bgcolor": AUTUMN_PALETTE["surface"],
            "plot_bgcolor": AUTUMN_PALETTE["background"],
            "font": {
                "family": "Crimson Pro, Georgia, serif",
                "color": AUTUMN_PALETTE["text_primary"],
            },
            "xaxis": {
                "gridcolor": AUTUMN_PALETTE["border"],
                "linecolor": AUTUMN_PALETTE["border"],
                "tickcolor": AUTUMN_PALETTE["text_secondary"],
                "titlefont": {
                    "family": "Crimson Pro, Georgia, serif",
                    "size": 14,
                    "color": AUTUMN_PALETTE["text_primary"],
                },
            },
            "yaxis": {
                "gridcolor": AUTUMN_PALETTE["border"],
                "linecolor": AUTUMN_PALETTE["border"],
                "tickcolor": AUTUMN_PALETTE["text_secondary"],
                "titlefont": {
                    "family": "Crimson Pro, Georgia, serif",
                    "size": 14,
                    "color": AUTUMN_PALETTE["text_primary"],
                },
            },
            "colorway": get_plotly_color_sequence(),
        }
    }


def get_chart_color(color_key: str) -> str:
    """
    Returns a specific theme color for use in charts.

    Args:
        color_key: Key name from the color palette (e.g., 'primary', 'danger').

    Returns:
        Hex color code string.

    Raises:
        KeyError: If color_key is not found in the palette.
    """
    if color_key not in AUTUMN_PALETTE:
        raise KeyError(
            f"Color '{color_key}' not found in theme palette. "
            f"Available keys: {list(AUTUMN_PALETTE.keys())}"
        )
    return AUTUMN_PALETTE[color_key]


# =============================================================================
# SEVERITY DISPLAY HELPER
# =============================================================================


def get_severity_badge_css(severity: str) -> str:
    """
    Returns HTML/CSS for a severity badge with appropriate coloring.

    Args:
        severity: Severity level ('critical', 'high', 'medium', 'low', 'info').

    Returns:
        HTML string containing the styled badge.
    """
    severity_lower = severity.lower()
    colors = get_severity_colors()

    # Default to info if severity not recognized
    bg_color = colors.get(severity_lower, colors["info"])

    # Calculate text color based on background brightness
    # (simple heuristic: use dark text on light backgrounds)
    text_color = (
        AUTUMN_PALETTE["background"]
        if severity_lower in ["medium", "low"]
        else "#ffffff"
    )

    return f"""
    <span style="
        background-color: {bg_color};
        color: {text_color};
        padding: 4px 12px;
        border-radius: 12px;
        font-size: 12px;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    ">{severity}</span>
    """


# =============================================================================
# THEME INITIALIZATION
# =============================================================================


def initialize_theme() -> None:
    """
    Convenience function to initialize the complete theme.

    Calls inject_theme() and apply_custom_styling() to set up
    the full autumn theme system.

    Call this once at the beginning of your Streamlit app.
    """
    inject_theme()
    apply_custom_styling()
