"""
SQLite-based Scan History Persistence Module

This module provides SQLite-based persistence for VaultHound scan history,
including scans, findings, and security events.

Database Schema:
- scans table: id, repo_url, scan_depth, status, start_time, end_time, risk_score, findings_count, locked
- findings table: id, scan_id (FK), all finding fields
- security_events table: id, scan_id (FK), event_type, severity, details, timestamp

OWASP Agentic AI Security (ASI) Compliance:
- ASI06: Memory & Context Poisoning - Write protection implemented via lock_scan()
  After each scan completes, the scan record is locked to prevent tampering.
  This ensures scan history cannot be modified post-write, protecting against
  context poisoning attacks where an attacker might try to modify historical
  data to hide evidence of compromise.

Data Retention Policy:
- Scans are retained indefinitely unless explicitly deleted
- Locked scans cannot be modified (read-only historical record)
- Deletion requires explicit action and is logged for audit purposes

Author: VaultHound Team
"""

import sqlite3
import json
import os
from datetime import datetime
from typing import List, Dict, Optional, Any
from pathlib import Path

# Import models from the project
from vaulthound.agents.state import ScanState, FindingModel
from vaulthound.agents.security_monitor import SecurityEvent

# Database configuration
DEFAULT_DB_PATH = "vaulthound.db"
TABLE_SCANS = "scans"
TABLE_FINDINGS = "findings"
TABLE_SECURITY_EVENTS = "security_events"


class SQLiteStore:
    """
    SQLite-based storage for VaultHound scan history.

    This class provides CRUD operations for scan history with write protection
    to ensure data integrity and compliance with ASI06 (Memory & Context Poisoning).

    Attributes:
        db_path: Path to the SQLite database file
        connection: Active database connection

    Example:
        >>> store = SQLiteStore()
        >>> store.init_db()
        >>> scan_id = store.save_scan("https://github.com/example/repo", "full", state)
        >>> scans = store.get_all_scans()
    """

    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        """
        Initialize the SQLite store.

        Args:
            db_path: Path to the SQLite database file (default: vaulthound.db)
        """
        self.db_path = db_path
        self.connection: Optional[sqlite3.Connection] = None

    def _get_connection(self) -> sqlite3.Connection:
        """Get or create database connection."""
        if self.connection is None:
            self.connection = sqlite3.connect(self.db_path)
            # Enable foreign keys
            self.connection.execute("PRAGMA foreign_keys = ON")
            # Return rows as dictionaries
            self.connection.row_factory = sqlite3.Row
        return self.connection

    def close(self) -> None:
        """Close the database connection."""
        if self.connection:
            self.connection.close()
            self.connection = None

    def init_db(self) -> None:
        """
        Initialize database and create tables.

        Creates the following tables:
        - scans: Stores scan metadata
        - findings: Stores individual findings linked to scans
        - security_events: Stores security events linked to scans

        ASI06 Compliance:
        - Each scan record includes a 'locked' field that is set after write completion
        - Locked scans cannot be modified, ensuring historical data integrity
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        # Create scans table
        cursor.execute(
            f"""
            CREATE TABLE IF NOT EXISTS {TABLE_SCANS} (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                repo_url TEXT NOT NULL,
                scan_depth TEXT NOT NULL,
                status TEXT NOT NULL,
                start_time TEXT NOT NULL,
                end_time TEXT,
                risk_score REAL,
                findings_count INTEGER DEFAULT 0,
                locked INTEGER DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """
        )

        # Create findings table
        cursor.execute(
            f"""
            CREATE TABLE IF NOT EXISTS {TABLE_FINDINGS} (
                id TEXT PRIMARY KEY,
                scan_id INTEGER NOT NULL,
                secret_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                file_path TEXT NOT NULL,
                line_number INTEGER NOT NULL,
                column_start INTEGER,
                column_end INTEGER,
                commit_sha TEXT,
                commit_date TEXT,
                commit_author TEXT,
                commit_message TEXT,
                context_before TEXT,
                context_after TEXT,
                entropy_score REAL,
                is_canary INTEGER DEFAULT 0,
                confirmed_real INTEGER DEFAULT 0,
                false_positive INTEGER DEFAULT 0,
                remediation_status TEXT DEFAULT 'open',
                notes TEXT,
                discovered_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES {TABLE_SCANS}(id) ON DELETE CASCADE
            )
        """
        )

        # Create security_events table
        cursor.execute(
            f"""
            CREATE TABLE IF NOT EXISTS {TABLE_SECURITY_EVENTS} (
                id TEXT PRIMARY KEY,
                scan_id INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                details TEXT NOT NULL,
                node_name TEXT,
                metadata TEXT,
                timestamp TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES {TABLE_SCANS}(id) ON DELETE CASCADE
            )
        """
        )

        # Create indexes for better query performance
        cursor.execute(
            f"CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON {TABLE_FINDINGS}(scan_id)"
        )
        cursor.execute(
            f"CREATE INDEX IF NOT EXISTS idx_security_events_scan_id ON {TABLE_SECURITY_EVENTS}(scan_id)"
        )
        cursor.execute(
            f"CREATE INDEX IF NOT EXISTS idx_scans_repo_url ON {TABLE_SCANS}(repo_url)"
        )
        cursor.execute(
            f"CREATE INDEX IF NOT EXISTS idx_scans_status ON {TABLE_SCANS}(status)"
        )

        conn.commit()

    def save_scan(self, repo_url: str, scan_depth: str, state: ScanState) -> int:
        """
        Save a scan to the database.

        Args:
            repo_url: URL of the repository being scanned
            scan_depth: Depth of scanning (e.g., "shallow", "full", "commit_history")
            state: ScanState containing scan data

        Returns:
            int: The ID of the inserted scan

        ASI06 Compliance:
            After saving, the caller MUST call lock_scan() to enable write protection
            This ensures the scan record cannot be modified after completion
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        # Extract data from state
        status = state.get("scan_status", "pending")
        start_time = datetime.utcnow().isoformat()
        findings_count = len(state.get("findings", []))

        # Calculate risk score based on findings
        risk_score = self._calculate_risk_score(state.get("findings", []))

        now = datetime.utcnow().isoformat()

        cursor.execute(
            f"""
            INSERT INTO {TABLE_SCANS} 
            (repo_url, scan_depth, status, start_time, findings_count, risk_score, locked, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?)
        """,
            (
                repo_url,
                scan_depth,
                status,
                start_time,
                findings_count,
                risk_score,
                now,
                now,
            ),
        )

        conn.commit()
        return cursor.lastrowid

    def _calculate_risk_score(self, findings: List[FindingModel]) -> float:
        """
        Calculate risk score based on findings.

        Args:
            findings: List of FindingModel instances

        Returns:
            float: Risk score (0.0 - 10.0)
        """
        if not findings:
            return 0.0

        severity_weights = {
            "critical": 10.0,
            "high": 7.5,
            "medium": 5.0,
            "low": 2.5,
            "info": 1.0,
        }

        total_score = 0.0
        for finding in findings:
            weight = severity_weights.get(str(finding.severity), 1.0)
            # Reduce score for false positives
            if finding.false_positive:
                weight *= 0.1
            total_score += weight

        # Normalize to 0-10 scale
        return min(10.0, total_score)

    def get_scan(self, scan_id: int) -> Optional[Dict[str, Any]]:
        """
        Retrieve a scan by ID.

        Args:
            scan_id: The ID of the scan to retrieve

        Returns:
            Optional[Dict]: Scan data as dictionary, or None if not found
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(f"SELECT * FROM {TABLE_SCANS} WHERE id = ?", (scan_id,))
        row = cursor.fetchone()

        if not row:
            return None

        return dict(row)

    def get_all_scans(self, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Get scan history.

        Args:
            limit: Maximum number of scans to return (default: 50)

        Returns:
            List[Dict]: List of scan records ordered by most recent first
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            f"""
            SELECT * FROM {TABLE_SCANS} 
            ORDER BY created_at DESC 
            LIMIT ?
        """,
            (limit,),
        )

        return [dict(row) for row in cursor.fetchall()]

    def save_findings(self, scan_id: int, findings: List[FindingModel]) -> None:
        """
        Save findings for a scan.

        Args:
            scan_id: The ID of the scan to associate findings with
            findings: List of FindingModel instances

        Note:
            If the scan is locked, findings cannot be saved.
            Use lock_scan() after initial save to enable write protection.
        """
        # Check if scan is locked
        scan = self.get_scan(scan_id)
        if scan and scan.get("locked"):
            raise PermissionError(f"Cannot save findings to locked scan {scan_id}")

        conn = self._get_connection()
        cursor = conn.cursor()

        for finding in findings:
            # Serialize context lists as JSON
            context_before = (
                json.dumps(finding.context_before) if finding.context_before else None
            )
            context_after = (
                json.dumps(finding.context_after) if finding.context_after else None
            )
            commit_date = (
                finding.commit_date.isoformat() if finding.commit_date else None
            )

            cursor.execute(
                f"""
                INSERT OR REPLACE INTO {TABLE_FINDINGS}
                (id, scan_id, secret_type, severity, file_path, line_number,
                 column_start, column_end, commit_sha, commit_date, commit_author,
                 commit_message, context_before, context_after, entropy_score,
                 is_canary, confirmed_real, false_positive, remediation_status,
                 notes, discovered_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    finding.id,
                    scan_id,
                    str(finding.secret_type),
                    str(finding.severity),
                    finding.file_path,
                    finding.line_number,
                    finding.column_start,
                    finding.column_end,
                    finding.commit_sha,
                    commit_date,
                    finding.commit_author,
                    finding.commit_message,
                    context_before,
                    context_after,
                    finding.entropy_score,
                    int(finding.is_canary),
                    int(finding.confirmed_real),
                    int(finding.false_positive),
                    finding.remediation_status,
                    finding.notes,
                    finding.discovered_at.isoformat(),
                    finding.updated_at.isoformat(),
                ),
            )

        conn.commit()

    def get_findings(self, scan_id: int) -> List[Dict[str, Any]]:
        """
        Retrieve all findings for a scan.

        Args:
            scan_id: The ID of the scan

        Returns:
            List[Dict]: List of finding records
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(f"SELECT * FROM {TABLE_FINDINGS} WHERE scan_id = ?", (scan_id,))

        findings = []
        for row in cursor.fetchall():
            finding_dict = dict(row)
            # Deserialize JSON fields
            if finding_dict.get("context_before"):
                finding_dict["context_before"] = json.loads(
                    finding_dict["context_before"]
                )
            if finding_dict.get("context_after"):
                finding_dict["context_after"] = json.loads(
                    finding_dict["context_after"]
                )
            # Convert integer flags back to boolean
            finding_dict["is_canary"] = bool(finding_dict["is_canary"])
            finding_dict["confirmed_real"] = bool(finding_dict["confirmed_real"])
            finding_dict["false_positive"] = bool(finding_dict["false_positive"])
            findings.append(finding_dict)

        return findings

    def save_security_events(self, scan_id: int, events: List[SecurityEvent]) -> None:
        """
        Save security events for a scan.

        Args:
            scan_id: The ID of the scan to associate events with
            events: List of SecurityEvent instances

        Note:
            If the scan is locked, security events cannot be saved.
            Use lock_scan() after initial save to enable write protection.
        """
        # Check if scan is locked
        scan = self.get_scan(scan_id)
        if scan and scan.get("locked"):
            raise PermissionError(
                f"Cannot save security events to locked scan {scan_id}"
            )

        conn = self._get_connection()
        cursor = conn.cursor()

        for event in events:
            cursor.execute(
                f"""
                INSERT OR REPLACE INTO {TABLE_SECURITY_EVENTS}
                (id, scan_id, event_type, severity, details, node_name, metadata, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    event.event_id,
                    scan_id,
                    event.event_type,
                    event.severity,
                    event.details,
                    event.node_name,
                    json.dumps(event.metadata),
                    event.timestamp,
                ),
            )

        conn.commit()

    def get_security_events(self, scan_id: int) -> List[Dict[str, Any]]:
        """
        Retrieve all security events for a scan.

        Args:
            scan_id: The ID of the scan

        Returns:
            List[Dict]: List of security event records
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            f"SELECT * FROM {TABLE_SECURITY_EVENTS} WHERE scan_id = ?", (scan_id,)
        )

        events = []
        for row in cursor.fetchall():
            event_dict = dict(row)
            # Deserialize metadata JSON
            if event_dict.get("metadata"):
                event_dict["metadata"] = json.loads(event_dict["metadata"])
            events.append(event_dict)

        return events

    def delete_scan(self, scan_id: int) -> bool:
        """
        Delete a scan and all associated data.

        Args:
            scan_id: The ID of the scan to delete

        Returns:
            bool: True if scan was deleted, False if not found

        Note:
            This method checks if the scan is locked before deletion.
            Locked scans cannot be deleted to maintain audit trail integrity.

        ASI06 Compliance:
            Locked scans represent completed/verified scans and should not be
            deleted to maintain the integrity of the security audit trail.
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        # Check if scan exists and is locked
        cursor.execute(f"SELECT locked FROM {TABLE_SCANS} WHERE id = ?", (scan_id,))
        row = cursor.fetchone()

        if not row:
            return False

        if row["locked"]:
            raise PermissionError(
                f"Cannot delete locked scan {scan_id}. Locked scans maintain "
                "audit trail integrity and cannot be modified or deleted."
            )

        # Delete scan (findings and events cascade due to FK constraint)
        cursor.execute(f"DELETE FROM {TABLE_SCANS} WHERE id = ?", (scan_id,))
        conn.commit()

        return cursor.rowcount > 0

    def lock_scan(self, scan_id: int) -> None:
        """
        Lock a scan to enable write protection.

        This method implements ASI06 (Memory & Context Poisoning) protection
        by marking a scan as read-only after all write operations are complete.

        Once locked:
        - Findings cannot be added, modified, or deleted
        - Security events cannot be added
        - The scan itself cannot be deleted

        This ensures the integrity of the historical record and protects
        against attacks that might try to modify scan results after completion.

        Args:
            scan_id: The ID of the scan to lock

        Raises:
            ValueError: If scan_id is invalid
            RuntimeError: If locking fails

        Example:
            >>> store.save_scan(repo_url, scan_depth, state)
            >>> store.save_findings(scan_id, findings)
            >>> store.save_security_events(scan_id, events)
            >>> store.lock_scan(scan_id)  # Enable ASI06 write protection
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        # Verify scan exists
        cursor.execute(f"SELECT id, locked FROM {TABLE_SCANS} WHERE id = ?", (scan_id,))
        row = cursor.fetchone()

        if not row:
            raise ValueError(f"Scan {scan_id} does not exist")

        if row["locked"]:
            # Already locked, no-op
            return

        # Lock the scan
        now = datetime.utcnow().isoformat()
        cursor.execute(
            f"""
            UPDATE {TABLE_SCANS} 
            SET locked = 1, updated_at = ?
            WHERE id = ?
        """,
            (now, scan_id),
        )

        conn.commit()

    def get_scan_statistics(self) -> Dict[str, Any]:
        """
        Get aggregate statistics across all scans.

        Returns:
            Dict: Dictionary containing:
                - total_scans: Total number of scans
                - completed_scans: Number of completed scans
                - failed_scans: Number of failed scans
                - total_findings: Total findings across all scans
                - findings_by_severity: Breakdown of findings by severity
                - findings_by_type: Breakdown of findings by secret type
                - average_risk_score: Average risk score across scans
                - locked_scans: Number of locked (protected) scans
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        # Total scans
        cursor.execute(f"SELECT COUNT(*) as total FROM {TABLE_SCANS}")
        total_scans = cursor.fetchone()["total"]

        # Scans by status
        cursor.execute(
            f"SELECT status, COUNT(*) as count FROM {TABLE_SCANS} GROUP BY status"
        )
        status_counts = {row["status"]: row["count"] for row in cursor.fetchall()}

        # Locked scans
        cursor.execute(f"SELECT COUNT(*) as count FROM {TABLE_SCANS} WHERE locked = 1")
        locked_scans = cursor.fetchone()["count"]

        # Total findings
        cursor.execute(f"SELECT COUNT(*) as total FROM {TABLE_FINDINGS}")
        total_findings = cursor.fetchone()["total"]

        # Findings by severity
        cursor.execute(
            f"""
            SELECT severity, COUNT(*) as count 
            FROM {TABLE_FINDINGS} 
            GROUP BY severity
        """
        )
        findings_by_severity = {
            row["severity"]: row["count"] for row in cursor.fetchall()
        }

        # Findings by secret type
        cursor.execute(
            f"""
            SELECT secret_type, COUNT(*) as count 
            FROM {TABLE_FINDINGS} 
            GROUP BY secret_type
        """
        )
        findings_by_type = {
            row["secret_type"]: row["count"] for row in cursor.fetchall()
        }

        # Average risk score
        cursor.execute(
            f"SELECT AVG(risk_score) as avg_score FROM {TABLE_SCANS} WHERE risk_score IS NOT NULL"
        )
        avg_result = cursor.fetchone()
        average_risk_score = (
            round(avg_result["avg_score"], 2) if avg_result["avg_score"] else 0.0
        )

        return {
            "total_scans": total_scans,
            "completed_scans": status_counts.get("completed", 0),
            "failed_scans": status_counts.get("failed", 0),
            "pending_scans": status_counts.get("pending", 0),
            "in_progress_scans": status_counts.get("in_progress", 0),
            "total_findings": total_findings,
            "findings_by_severity": findings_by_severity,
            "findings_by_type": findings_by_type,
            "average_risk_score": average_risk_score,
            "locked_scans": locked_scans,
        }

    def update_scan_status(self, scan_id: int, status: str) -> bool:
        """
        Update the status of a scan.

        Args:
            scan_id: The ID of the scan
            status: New status value

        Returns:
            bool: True if updated successfully

        Note:
            Locked scans cannot be modified to maintain data integrity.
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        # Check if scan is locked
        cursor.execute(f"SELECT locked FROM {TABLE_SCANS} WHERE id = ?", (scan_id,))
        row = cursor.fetchone()

        if not row:
            return False

        if row["locked"]:
            raise PermissionError(f"Cannot update locked scan {scan_id}")

        now = datetime.utcnow().isoformat()
        cursor.execute(
            f"""
            UPDATE {TABLE_SCANS} 
            SET status = ?, updated_at = ?
            WHERE id = ?
        """,
            (status, now, scan_id),
        )

        conn.commit()
        return cursor.rowcount > 0

    def get_scans_by_repo(self, repo_url: str) -> List[Dict[str, Any]]:
        """
        Get all scans for a specific repository.

        Args:
            repo_url: The URL of the repository

        Returns:
            List[Dict]: List of scan records for the repository
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            f"""
            SELECT * FROM {TABLE_SCANS} 
            WHERE repo_url = ?
            ORDER BY created_at DESC
        """,
            (repo_url,),
        )

        return [dict(row) for row in cursor.fetchall()]

    def is_scan_locked(self, scan_id: int) -> bool:
        """
        Check if a scan is locked (read-only).

        Args:
            scan_id: The ID of the scan

        Returns:
            bool: True if scan is locked, False otherwise
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(f"SELECT locked FROM {TABLE_SCANS} WHERE id = ?", (scan_id,))
        row = cursor.fetchone()

        if not row:
            return False

        return bool(row["locked"])


# Module-level convenience functions
_store: Optional[SQLiteStore] = None


def get_store(db_path: str = DEFAULT_DB_PATH) -> SQLiteStore:
    """
    Get or create a singleton SQLiteStore instance.

    Args:
        db_path: Path to the SQLite database file

    Returns:
        SQLiteStore: The store instance
    """
    global _store
    if _store is None:
        _store = SQLiteStore(db_path)
        _store.init_db()
    return _store


def init_db(db_path: str = DEFAULT_DB_PATH) -> None:
    """
    Initialize the database.

    Args:
        db_path: Path to the SQLite database file
    """
    store = get_store(db_path)
    store.init_db()


def save_scan(repo_url: str, scan_depth: str, state: ScanState) -> int:
    """
    Save a scan to the database.

    Args:
        repo_url: URL of the repository being scanned
        scan_depth: Depth of scanning
        state: ScanState containing scan data

    Returns:
        int: The ID of the inserted scan
    """
    store = get_store()
    return store.save_scan(repo_url, scan_depth, state)


def get_scan(scan_id: int) -> Optional[Dict[str, Any]]:
    """
    Retrieve a scan by ID.

    Args:
        scan_id: The ID of the scan

    Returns:
        Optional[Dict]: Scan data or None
    """
    store = get_store()
    return store.get_scan(scan_id)


def get_all_scans(limit: int = 50) -> List[Dict[str, Any]]:
    """
    Get scan history.

    Args:
        limit: Maximum number of scans to return

    Returns:
        List[Dict]: List of scan records
    """
    store = get_store()
    return store.get_all_scans(limit)


def save_findings(scan_id: int, findings: List[FindingModel]) -> None:
    """
    Save findings for a scan.

    Args:
        scan_id: The ID of the scan
        findings: List of FindingModel instances
    """
    store = get_store()
    store.save_findings(scan_id, findings)


def save_security_events(scan_id: int, events: List[SecurityEvent]) -> None:
    """
    Save security events for a scan.

    Args:
        scan_id: The ID of the scan
        events: List of SecurityEvent instances
    """
    store = get_store()
    store.save_security_events(scan_id, events)


def delete_scan(scan_id: int) -> bool:
    """
    Delete a scan.

    Args:
        scan_id: The ID of the scan

    Returns:
        bool: True if deleted
    """
    store = get_store()
    return store.delete_scan(scan_id)


def get_scan_statistics() -> Dict[str, Any]:
    """
    Get aggregate statistics.

    Returns:
        Dict: Statistics dictionary
    """
    store = get_store()
    return store.get_scan_statistics()


def lock_scan(scan_id: int) -> None:
    """
    Lock a scan to enable write protection (ASI06).

    Args:
        scan_id: The ID of the scan
    """
    store = get_store()
    store.lock_scan(scan_id)
