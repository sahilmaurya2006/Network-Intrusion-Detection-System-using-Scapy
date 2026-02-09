# nids/database/alert_store.py
"""
Alert persistence module.
Stores alerts in SQLite database with retention policies.
"""

import sqlite3
import json
import logging
from typing import Optional, List, Dict, Any
from pathlib import Path
from datetime import datetime, timedelta
import threading

from nids.core.rules import DetectionAlert

logger = logging.getLogger(__name__)


class AlertDatabase:
    """
    SQLite-based alert storage.
    
    Features:
    - Thread-safe operations
    - Structured alert storage
    - Query capabilities
    - Data retention policies
    - Full-text search support
    """
    
    def __init__(self, db_path: str):
        """
        Initialize alert database.
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()
        
        self._initialize_database()
        logger.info(f"Alert database initialized: {db_path}")
    
    def _initialize_database(self) -> None:
        """Create database tables if they don't exist."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Alerts table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS alerts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        rule_name TEXT NOT NULL,
                        rule_type TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        timestamp REAL NOT NULL,
                        src_ip TEXT,
                        dst_ip TEXT,
                        src_port INTEGER,
                        dst_port INTEGER,
                        message TEXT,
                        packet_count INTEGER,
                        threshold INTEGER,
                        matched_value INTEGER,
                        additional_info TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY(rule_name) REFERENCES rules(name)
                    )
                ''')
                
                # Rules metadata table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS rules (
                        name TEXT PRIMARY KEY,
                        rule_type TEXT,
                        severity TEXT,
                        description TEXT,
                        enabled BOOLEAN DEFAULT 1
                    )
                ''')
                
                # Statistics table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS alert_stats (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        hour TIMESTAMP NOT NULL UNIQUE,
                        total_alerts INTEGER,
                        critical_alerts INTEGER,
                        high_alerts INTEGER,
                        medium_alerts INTEGER,
                        low_alerts INTEGER
                    )
                ''')
                
                # Create indices for faster queries
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON alerts(timestamp)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_severity ON alerts(severity)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_src_ip ON alerts(src_ip)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_rule_name ON alerts(rule_name)')
                
                conn.commit()
        
        except Exception as e:
            logger.error(f"Error initializing database: {e}")
            raise
    
    def store_alert(self, alert: DetectionAlert) -> int:
        """
        Store alert in database.
        
        Args:
            alert: DetectionAlert object
            
        Returns:
            Alert ID
        """
        try:
            with self.lock:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    
                    # Insert alert
                    cursor.execute('''
                        INSERT INTO alerts
                        (rule_name, rule_type, severity, timestamp, src_ip, dst_ip,
                         src_port, dst_port, message, packet_count, threshold,
                         matched_value, additional_info)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        alert.rule_name,
                        alert.rule_type,
                        alert.severity,
                        alert.timestamp,
                        alert.src_ip,
                        alert.dst_ip,
                        alert.src_port,
                        alert.dst_port,
                        alert.message,
                        alert.packet_count,
                        alert.threshold,
                        alert.matched_value,
                        json.dumps(alert.additional_info) if alert.additional_info else None
                    ))
                    
                    conn.commit()
                    return cursor.lastrowid
        
        except Exception as e:
            logger.error(f"Error storing alert: {e}")
            raise
    
    def get_alerts(
        self,
        limit: int = 100,
        offset: int = 0,
        order_by: str = 'timestamp DESC'
    ) -> List[Dict[str, Any]]:
        """
        Retrieve alerts from database.
        
        Args:
            limit: Maximum number of alerts
            offset: Number of alerts to skip
            order_by: SQL ORDER BY clause
            
        Returns:
            List of alert dictionaries
        """
        try:
            with self.lock:
                with sqlite3.connect(self.db_path) as conn:
                    conn.row_factory = sqlite3.Row
                    cursor = conn.cursor()
                    
                    cursor.execute(f'''
                        SELECT * FROM alerts
                        ORDER BY {order_by}
                        LIMIT ? OFFSET ?
                    ''', (limit, offset))
                    
                    rows = cursor.fetchall()
                    alerts = []
                    
                    for row in rows:
                        alert_dict = dict(row)
                        # Parse JSON additional_info
                        if alert_dict['additional_info']:
                            alert_dict['additional_info'] = json.loads(alert_dict['additional_info'])
                        alerts.append(alert_dict)
                    
                    return alerts
        
        except Exception as e:
            logger.error(f"Error retrieving alerts: {e}")
            return []
    
    def get_alerts_by_severity(self, severity: str, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get alerts by severity level.
        
        Args:
            severity: Severity level
            limit: Maximum number of alerts
            
        Returns:
            List of alert dictionaries
        """
        try:
            with self.lock:
                with sqlite3.connect(self.db_path) as conn:
                    conn.row_factory = sqlite3.Row
                    cursor = conn.cursor()
                    
                    cursor.execute('''
                        SELECT * FROM alerts
                        WHERE severity = ?
                        ORDER BY timestamp DESC
                        LIMIT ?
                    ''', (severity, limit))
                    
                    return [dict(row) for row in cursor.fetchall()]
        
        except Exception as e:
            logger.error(f"Error querying by severity: {e}")
            return []
    
    def get_alerts_by_source_ip(self, src_ip: str, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get alerts from source IP.
        
        Args:
            src_ip: Source IP address
            limit: Maximum number of alerts
            
        Returns:
            List of alert dictionaries
        """
        try:
            with self.lock:
                with sqlite3.connect(self.db_path) as conn:
                    conn.row_factory = sqlite3.Row
                    cursor = conn.cursor()
                    
                    cursor.execute('''
                        SELECT * FROM alerts
                        WHERE src_ip = ?
                        ORDER BY timestamp DESC
                        LIMIT ?
                    ''', (src_ip, limit))
                    
                    return [dict(row) for row in cursor.fetchall()]
        
        except Exception as e:
            logger.error(f"Error querying by source IP: {e}")
            return []
    
    def get_alerts_by_rule(self, rule_name: str, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get alerts by rule name.
        
        Args:
            rule_name: Rule name
            limit: Maximum number of alerts
            
        Returns:
            List of alert dictionaries
        """
        try:
            with self.lock:
                with sqlite3.connect(self.db_path) as conn:
                    conn.row_factory = sqlite3.Row
                    cursor = conn.cursor()
                    
                    cursor.execute('''
                        SELECT * FROM alerts
                        WHERE rule_name = ?
                        ORDER BY timestamp DESC
                        LIMIT ?
                    ''', (rule_name, limit))
                    
                    return [dict(row) for row in cursor.fetchall()]
        
        except Exception as e:
            logger.error(f"Error querying by rule: {e}")
            return []
    
    def get_statistics(self, hours: int = 24) -> Dict[str, Any]:
        """
        Get alert statistics for last N hours.
        
        Args:
            hours: Number of hours to analyze
            
        Returns:
            Dictionary with statistics
        """
        try:
            with self.lock:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    
                    # Get timestamp threshold
                    threshold_time = datetime.now() - timedelta(hours=hours)
                    threshold_timestamp = threshold_time.timestamp()
                    
                    # Total alerts
                    cursor.execute(
                        'SELECT COUNT(*) as total FROM alerts WHERE timestamp > ?',
                        (threshold_timestamp,)
                    )
                    total = cursor.fetchone()[0]
                    
                    # Alerts by severity
                    cursor.execute('''
                        SELECT severity, COUNT(*) as count
                        FROM alerts
                        WHERE timestamp > ?
                        GROUP BY severity
                    ''', (threshold_timestamp,))
                    
                    severity_counts = {}
                    for row in cursor.fetchall():
                        severity_counts[row[0]] = row[1]
                    
                    # Alerts by rule
                    cursor.execute('''
                        SELECT rule_name, COUNT(*) as count
                        FROM alerts
                        WHERE timestamp > ?
                        GROUP BY rule_name
                        ORDER BY count DESC
                        LIMIT 10
                    ''', (threshold_timestamp,))
                    
                    top_rules = {row[0]: row[1] for row in cursor.fetchall()}
                    
                    # Top source IPs
                    cursor.execute('''
                        SELECT src_ip, COUNT(*) as count
                        FROM alerts
                        WHERE timestamp > ? AND src_ip IS NOT NULL
                        GROUP BY src_ip
                        ORDER BY count DESC
                        LIMIT 10
                    ''', (threshold_timestamp,))
                    
                    top_ips = {row[0]: row[1] for row in cursor.fetchall()}
                    
                    return {
                        'total_alerts': total,
                        'severity_distribution': severity_counts,
                        'top_rules': top_rules,
                        'top_source_ips': top_ips,
                        'time_period_hours': hours
                    }
        
        except Exception as e:
            logger.error(f"Error getting statistics: {e}")
            return {}
    
    def cleanup_old_alerts(self, days: int = 90) -> int:
        """
        Delete alerts older than specified days.
        
        Args:
            days: Delete alerts older than this many days
            
        Returns:
            Number of deleted alerts
        """
        try:
            with self.lock:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    
                    # Calculate cutoff time
                    cutoff_time = datetime.now() - timedelta(days=days)
                    cutoff_timestamp = cutoff_time.timestamp()
                    
                    # Delete old alerts
                    cursor.execute(
                        'DELETE FROM alerts WHERE timestamp < ?',
                        (cutoff_timestamp,)
                    )
                    
                    conn.commit()
                    deleted = cursor.rowcount
                    
                    logger.info(f"Deleted {deleted} alerts older than {days} days")
                    return deleted
        
        except Exception as e:
            logger.error(f"Error cleaning up alerts: {e}")
            return 0
    
    def get_total_alerts(self) -> int:
        """Get total number of alerts in database."""
        try:
            with self.lock:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute('SELECT COUNT(*) FROM alerts')
                    return cursor.fetchone()[0]
        except Exception as e:
            logger.error(f"Error getting alert count: {e}")
            return 0
