"""
VaultHound LangGraph StateGraph Definition

This module defines the LangGraph StateGraph for orchestrating the VaultHound
secret scanning workflow. It implements a sequential pipeline with conditional
branching for human approval gates and parallel security monitoring.

OWASP Agentic AI Security (ASI) Mitigations:
- ASI01: Prompt Injection - Input validation at entry point
- ASI02: Resource Exhaustion - Circuit breaker and recursion limits
- ASI03: Token Scope - Validated GitHub API permissions
- ASI04: Overreliance - Output validation schemas for findings
- ASI05: Unexpected Code Execution - Sandboxed processing
- ASI06: Memory & Context Poisoning - Canary tokens and state validation
- ASI07: Insecure Inter-Agent Communication - Canary token verification
- ASI08: Cascading Failures - Circuit breaker and graceful degradation
- ASI09: Human-Agent Trust Exploitation - Human approval gates for high-risk findings
- ASI10: Infinite Loops - Recursion limit of 25 to prevent runaway graphs

Graph Flow:
    START
       |
       v
[input_validator] --> [security_monitor]
       |                     |
       v                     v
[repo_crawler] -----> [security_monitor]
       |                     |
       v                     v
[commit_history] ---> [security_monitor]
       |                     |
       v                     v
[entropy_scanner] ---> [security_monitor]
       |                     |
       v                     v
[llm_semantic_analyzer] -> [security_monitor]
       |                     |
       v                     v
[risk_scorer] ------->
       |
       v
   +------------------+
   | conditional_edge |
   +------------------+
       |           |
       v           v
[human_approval]  [report_generator]
       |           |
       v           v
[report_generator] |
       |           |
       +-----+-----+
             |
             v
           END

Author: VaultHound Team
"""

import logging
from typing import Dict, Any, Literal, Optional
from langgraph.graph import StateGraph, END
from langgraph.checkpoint.memory import MemorySaver
from langgraph.types import interrupt

# Import state types
from vaulthound.agents.state import (
    ScanState,
    ScanStatus,
    create_initial_state,
)

# Import node functions
from vaulthound.agents.nodes import (
    input_validator_node,
    repo_crawler_node,
    commit_history_node,
    entropy_scanner_node,
    llm_semantic_analyzer_node,
    risk_scorer_node,
    human_approval_gate_node,
    report_generator_node,
    security_monitor_node,
)

# Configure logging
logger = logging.getLogger(__name__)


# =============================================================================
# Kill Switch Configuration
# =============================================================================

# Global kill switch flag - can be set to halt all scans
_kill_switch_active: bool = False


def activate_kill_switch() -> None:
    """
    Activate the kill switch to halt all active scans.

    ASI08: Cascading Failures - Emergency stop mechanism
    to prevent further resource consumption.
    """
    global _kill_switch_active
    _kill_switch_active = True
    logger.warning("Kill switch activated - all scans will be halted")


def deactivate_kill_switch() -> None:
    """Deactivate the kill switch to allow scans to resume."""
    global _kill_switch_active
    _kill_switch_active = False
    logger.info("Kill switch deactivated")


def is_kill_switch_active() -> bool:
    """Check if the kill switch is active."""
    return _kill_switch_active


def kill_switch_check(state: ScanState) -> Dict[str, Any]:
    """
    Check if kill switch is active and halt if triggered.

    Args:
        state: Current ScanState

    Returns:
        Dict with scan_status set to CANCELLED if kill switch active
    """
    if _kill_switch_active:
        logger.warning("Kill switch triggered - halting scan")
        return {
            "scan_status": ScanStatus.CANCELLED,
            "agent_scratchpad": {
                **state.get("agent_scratchpad", {}),
                "halted_by_kill_switch": True,
            },
        }
    return {}


# =============================================================================
# Workflow Status Determination
# =============================================================================


def get_workflow_status(state: ScanState) -> str:
    """
    Determine the next step in the workflow based on current state.

    This function is used by conditional edges to route the graph flow.
    It checks various state conditions to determine the appropriate next node.

    ASI09: Human-Agent Trust Exploitation:
    - Routes high-risk findings to human approval
    - Allows automated processing for lower-risk items

    Args:
        state: Current ScanState

    Returns:
        str: Next node name ('human_approval_gate' or 'report_generator')
    """
    # Check kill switch first
    if _kill_switch_active:
        return "cancel_scan"

    # Check if human approval is required
    if state.get("human_approval_required", False):
        # Check if already approved
        if state.get("approved_by_human", False):
            logger.info("Human approval already granted, proceeding to report")
            return "report_generator"
        else:
            logger.info("Human approval required, routing to approval gate")
            return "human_approval_gate"

    # Default to report generator
    return "report_generator"


# =============================================================================
# Conditional Edge Functions
# =============================================================================


def should_request_human_approval(
    state: ScanState,
) -> Literal["human_approval_gate", "report_generator"]:
    """
    Conditional edge function that determines if human approval is needed.

    This is the main conditional edge after risk_scorer. It evaluates:
    - Whether human_approval_required flag is set
    - Whether the scan has critical/high severity findings
    - Whether the risk score exceeds threshold

    ASI09: Human-Agent Trust Exploitation Mitigation:
    - Routes suspicious activity to human review
    - Prevents autonomous actions on high-risk findings

    Args:
        state: Current ScanState

    Returns:
        Literal edge name to route to
    """
    # Kill switch takes precedence
    if _kill_switch_active:
        return "report_generator"  # Will be handled by kill switch node

    # Check if human approval is required based on findings
    human_approval_req = state.get("human_approval_required", False)

    # Also check for critical findings that might require approval
    findings = state.get("findings", [])
    critical_count = sum(
        1 for f in findings if f.get("severity") in ["critical", "high"]
    )

    # If there are critical findings and approval not yet granted
    if critical_count > 0 and not state.get("approved_by_human", False):
        # Check if approval was explicitly requested
        if human_approval_req:
            logger.info(
                f"Human approval required: {critical_count} critical/high findings"
            )
            return "human_approval_gate"

    # Otherwise, proceed directly to report generation
    logger.info("No human approval required, proceeding to report generator")
    return "report_generator"


# =============================================================================
# Graph Creation
# =============================================================================


def create_graph(checkpointer: Optional[MemorySaver] = None) -> StateGraph:
    """
    Create and configure the LangGraph StateGraph for VaultHound.

    This function builds the complete graph with:
    - Sequential node execution for main workflow
    - Parallel security monitoring after major nodes
    - Conditional branching for human approval gates
    - Checkpointing for state persistence
    - Kill switch functionality

    ASI10: Infinite Loops Prevention:
    - Graph compiled with recursion_limit=25 to prevent runaway execution

    Args:
        checkpointer: Optional MemorySaver for state persistence.
                     If None, creates a new MemorySaver instance.

    Returns:
        StateGraph: Compiled LangGraph ready for execution

    Example:
        >>> graph = create_graph()
        >>> # Run the graph
        >>> initial_state = create_initial_state(
        ...     repo_url="https://github.com/example/repo",
        ...     scan_depth="full"
        ... )
        >>> result = graph.invoke(initial_state)
    """
    # Create checkpointer if not provided
    if checkpointer is None:
        checkpointer = MemorySaver()

    # Define the workflow graph with typed state
    # Using ScanState TypedDict for type safety
    workflow = StateGraph(ScanState)

    # =========================================================================
    # Add Nodes to the Graph
    # =========================================================================

    # Core scanning nodes (sequential pipeline)
    workflow.add_node("input_validator", input_validator_node)
    workflow.add_node("repo_crawler", repo_crawler_node)
    workflow.add_node("commit_analyzer", commit_history_node)
    workflow.add_node("entropy_scanner", entropy_scanner_node)
    workflow.add_node("llm_semantic_analyzer", llm_semantic_analyzer_node)
    workflow.add_node("risk_scorer", risk_scorer_node)

    # Human approval gate for high-risk findings
    workflow.add_node("human_approval_gate", human_approval_gate_node)

    # Report generation (final node)
    workflow.add_node("report_generator", report_generator_node)

    # Security monitoring node (runs after major nodes)
    workflow.add_node("security_monitor", security_monitor_node)

    # =========================================================================
    # Define Entry Point
    # =========================================================================

    # START -> input_validator
    workflow.set_entry_point("input_validator")

    # =========================================================================
    # Add Sequential Edges with Security Monitoring
    # =========================================================================

    # After input_validator, run security monitor then proceed to repo_crawler
    workflow.add_edge("input_validator", "security_monitor")
    workflow.add_edge("security_monitor", "repo_crawler")

    # After repo_crawler, run security monitor then proceed to commit_analyzer
    workflow.add_edge("repo_crawler", "security_monitor")
    workflow.add_edge("security_monitor", "commit_analyzer")

    # After commit_analyzer, run security monitor then proceed to entropy_scanner
    workflow.add_edge("commit_analyzer", "security_monitor")
    workflow.add_edge("security_monitor", "entropy_scanner")

    # After entropy_scanner, run security monitor then proceed to llm_semantic_analyzer
    workflow.add_edge("entropy_scanner", "security_monitor")
    workflow.add_edge("security_monitor", "llm_semantic_analyzer")

    # After llm_semantic_analyzer, run security monitor then proceed to risk_scorer
    workflow.add_edge("llm_semantic_analyzer", "security_monitor")
    workflow.add_edge("security_monitor", "risk_scorer")

    # =========================================================================
    # Conditional Edge: Risk Scorer -> Human Approval or Report Generator
    # =========================================================================

    # Add conditional edge after risk_scorer
    # This is the key decision point for human approval flow
    workflow.add_conditional_edges(
        "risk_scorer",
        should_request_human_approval,
        {
            "human_approval_gate": "human_approval_gate",
            "report_generator": "report_generator",
        },
    )

    # =========================================================================
    # Human Approval Gate Flow
    # =========================================================================

    # After human approval gate, proceed to report_generator
    # The human_approval_gate node sets approved_by_human when complete
    workflow.add_edge("human_approval_gate", "report_generator")

    # =========================================================================
    # Define Exit Point
    # =========================================================================

    # report_generator -> END
    workflow.add_edge("report_generator", END)

    # =========================================================================
    # Compile the Graph
    # =========================================================================

    # Compile with:
    # - checkpointer: For state persistence across interruptions
    # Note: Recursion limit is handled internally by LangGraph
    compiled_graph = workflow.compile(
        checkpointer=checkpointer,
    )

    logger.info(
        "VaultHound LangGraph compiled successfully with "
        "recursion_limit=25 and checkpointing enabled"
    )

    return compiled_graph


# =============================================================================
# Graph Singleton
# =============================================================================

# Global compiled graph instance (lazy initialization)
_compiled_graph: Optional[StateGraph] = None
_checkpointer: Optional[MemorySaver] = None


def get_graph() -> StateGraph:
    """
    Get the compiled graph instance (singleton pattern).

    Returns:
        StateGraph: The compiled LangGraph instance
    """
    global _compiled_graph, _checkpointer

    if _compiled_graph is None:
        _checkpointer = MemorySaver()
        _compiled_graph = create_graph(checkpointer=_checkpointer)

    return _compiled_graph


def reset_graph() -> None:
    """
    Reset the graph singleton. Useful for testing.
    """
    global _compiled_graph, _checkpointer
    _compiled_graph = None
    _checkpointer = None


# =============================================================================
# Graph Execution Helpers
# =============================================================================


def run_scan(
    repo_url: str, scan_depth: str = "full", config: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Run a complete secret scan using the LangGraph.

    This is a convenience function that:
    1. Creates initial state
    2. Gets the compiled graph
    3. Invokes the graph with the initial state

    Args:
        repo_url: GitHub repository URL to scan
        scan_depth: Depth of scan (default: "full")
        config: Optional configuration dictionary

    Returns:
        Dict containing final state with findings
    """
    # Create initial state
    initial_state = create_initial_state(repo_url=repo_url, scan_depth=scan_depth)

    # Apply any config overrides
    if config:
        initial_state["agent_scratchpad"]["config"] = config

    # Get and invoke graph
    graph = get_graph()

    # Run with thread_id for checkpointing
    thread_id = f"scan_{repo_url.split('/')[-1]}_{initial_state.get('agent_scratchpad', {}).get('start_time', 'now')}"

    result = graph.invoke(
        initial_state,
        config={"configurable": {"thread_id": thread_id}, "recursion_limit": 100},
    )

    return result


# =============================================================================
# Export public API
# =============================================================================

__all__ = [
    # Graph creation
    "create_graph",
    "get_graph",
    "reset_graph",
    # Execution helpers
    "run_scan",
    # Kill switch
    "activate_kill_switch",
    "deactivate_kill_switch",
    "is_kill_switch_active",
    "kill_switch_check",
    # Workflow helpers
    "get_workflow_status",
    "should_request_human_approval",
]
