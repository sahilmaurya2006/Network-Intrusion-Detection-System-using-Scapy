# nids/dashboard/api_output.py
"""
Dashboard API output module.
Generates JSON output for web dashboard integration.
Real-time metrics, alert data, and system statistics.
"""

import json
import time
from typing import Dict, Any, List, Optional
from datetime import datetime
import logging

from nids.core.analyzer import PacketAnalyzer
from nids.database.alert_store import AlertDatabase

logger = logging.getLogger(__name__)


class DashboardAPI:
    """
    Dashboard API output generator.
    
    Generates structured JSON for web UI integration.
    Features:
    - Real-time metrics
    - Alert data
    - System health status
    - Historical statistics
    - Threat intelligence summaries
    """
    
    def __init__(self, analyzer: PacketAnalyzer, database: Optional[AlertDatabase] = None):
        """
        Initialize dashboard API.
        
        Args:
            analyzer: PacketAnalyzer instance
            database: Optional AlertDatabase instance
        """
        self.analyzer = analyzer
        self.database = database
        self.last_update = time.time()
    
    def get_system_status(self) -> Dict[str, Any]:
        """
        Get overall system status.
        
        Returns:
            JSON-serializable dict with system status
        """
        analyzer_stats = self.analyzer.get_stats()
        
        return {
            'timestamp': datetime.now().isoformat(),
            'status': 'healthy' if self.analyzer.is_healthy() else 'degraded',
            'system': {
                'uptime_seconds': analyzer_stats.get('uptime_seconds', 0),
                'packets_analyzed': analyzer_stats.get('packets_analyzed', 0),
                'alerts_generated': analyzer_stats.get('alerts_generated', 0),
                'analysis_cycles': analyzer_stats.get('analysis_cycles', 0),
            },
            'sniffer': {
                'packets_captured': analyzer_stats.get('sniffer', {}).get('packets_captured', 0),
                'packets_dropped': analyzer_stats.get('sniffer', {}).get('packets_dropped', 0),
                'packets_per_second': analyzer_stats.get('sniffer', {}).get('packets_per_second', 0),
            },
            'alerts': analyzer_stats.get('alerts', {}),
        }
    
    def get_recent_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Get recent alerts.
        
        Args:
            limit: Maximum number of alerts
            
        Returns:
            List of alert dicts
        """
        alerts = self.analyzer.get_alerts(limit=limit)
        return [self._serialize_alert(alert) for alert in alerts]
    
    def get_critical_alerts(self, limit: int = 20) -> List[Dict[str, Any]]:
        """
        Get critical severity alerts.
        
        Args:
            limit: Maximum number of alerts
            
        Returns:
            List of alert dicts
        """
        alerts = self.analyzer.get_alerts_by_severity('CRITICAL')[:limit]
        return [self._serialize_alert(alert) for alert in alerts]
    
    def get_top_threats(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get top threat actors (source IPs).
        
        Args:
            limit: Maximum number of threats
            
        Returns:
            List of threat summaries
        """
        ip_counts: Dict[str, int] = {}
        ip_details: Dict[str, Dict[str, Any]] = {}
        
        for alert in self.analyzer.alerts_history:
            if not alert.src_ip:
                continue
            
            ip_counts[alert.src_ip] = ip_counts.get(alert.src_ip, 0) + 1
            
            if alert.src_ip not in ip_details:
                ip_details[alert.src_ip] = {
                    'ip': alert.src_ip,
                    'rules': set(),
                    'severities': set(),
                    'last_seen': alert.timestamp,
                }
            
            ip_details[alert.src_ip]['rules'].add(alert.rule_name)
            ip_details[alert.src_ip]['severities'].add(alert.severity)
            ip_details[alert.src_ip]['last_seen'] = max(
                ip_details[alert.src_ip]['last_seen'],
                alert.timestamp
            )
        
        # Sort by count and return
        top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:limit]
        
        threats = []
        for ip, count in top_ips:
            details = ip_details[ip]
            threat_level = self._calculate_threat_level(
                count,
                details['severities']
            )
            
            threats.append({
                'source_ip': ip,
                'alert_count': count,
                'threat_level': threat_level,
                'rules_triggered': list(details['rules']),
                'severities': list(details['severities']),
                'last_seen': datetime.fromtimestamp(details['last_seen']).isoformat(),
            })
        
        return threats
    
    def get_detection_rules_status(self) -> Dict[str, Any]:
        """
        Get status of all detection rules.
        
        Returns:
            Dict with rule status information
        """
        rules_status = {}
        
        for rule_name in self.analyzer.rule_engine.get_enabled_rules():
            rule = self.analyzer.rule_engine.rules[rule_name]
            
            # Count alerts for this rule
            rule_alerts = self.analyzer.get_alerts()
            alerts_count = sum(1 for a in rule_alerts if a.rule_name == rule_name)
            
            rules_status[rule_name] = {
                'name': rule.name,
                'type': rule.rule_type,
                'severity': rule.severity,
                'enabled': rule.enabled,
                'description': rule.description,
                'alerts_this_session': alerts_count,
            }
        
        return rules_status
    
    def get_alert_timeline(self, minutes: int = 60, bucket_size: int = 5) -> Dict[str, Any]:
        """
        Get alert timeline for last N minutes.
        
        Args:
            minutes: Time period in minutes
            bucket_size: Bucket size in minutes
            
        Returns:
            Timeline data for charting
        """
        current_time = time.time()
        start_time = current_time - (minutes * 60)
        
        # Initialize buckets
        buckets: Dict[int, Dict[str, int]] = {}
        for i in range(0, minutes, bucket_size):
            bucket_time = int((current_time - (i * 60)) / (bucket_size * 60))
            buckets[bucket_time] = {
                'CRITICAL': 0,
                'HIGH': 0,
                'MEDIUM': 0,
                'LOW': 0,
                'timestamp': current_time - (i * 60)
            }
        
        # Count alerts in buckets
        for alert in self.analyzer.alerts_history:
            if alert.timestamp < start_time:
                continue
            
            bucket_time = int(alert.timestamp / (bucket_size * 60))
            if bucket_time in buckets:
                buckets[bucket_time][alert.severity] = buckets[bucket_time].get(alert.severity, 0) + 1
        
        # Format for response
        timeline = []
        for bucket_time in sorted(buckets.keys()):
            bucket = buckets[bucket_time]
            timeline.append({
                'timestamp': datetime.fromtimestamp(bucket['timestamp']).isoformat(),
                'critical': bucket.get('CRITICAL', 0),
                'high': bucket.get('HIGH', 0),
                'medium': bucket.get('MEDIUM', 0),
                'low': bucket.get('LOW', 0),
            })
        
        return {
            'period_minutes': minutes,
            'bucket_size_minutes': bucket_size,
            'timeline': timeline
        }
    
    def get_full_dashboard(self) -> Dict[str, Any]:
        """
        Get complete dashboard data.
        
        Returns:
            Complete dashboard JSON
        """
        return {
            'timestamp': datetime.now().isoformat(),
            'system_status': self.get_system_status(),
            'recent_alerts': self.get_recent_alerts(limit=20),
            'critical_alerts': self.get_critical_alerts(limit=10),
            'top_threats': self.get_top_threats(limit=10),
            'detection_rules': self.get_detection_rules_status(),
            'alert_timeline': self.get_alert_timeline(minutes=60),
        }
    
    def get_database_stats(self) -> Optional[Dict[str, Any]]:
        """
        Get statistics from database if available.
        
        Returns:
            Dictionary with DB statistics or None
        """
        if not self.database:
            return None
        
        stats = self.database.get_statistics(hours=24)
        stats['total_in_database'] = self.database.get_total_alerts()
        return stats
    
    def export_alerts_csv(self, alerts: Optional[List[Any]] = None) -> str:
        """
        Export alerts as CSV.
        
        Args:
            alerts: List of alerts (if None, uses recent alerts)
            
        Returns:
            CSV formatted string
        """
        if alerts is None:
            alerts = self.analyzer.get_alerts()
        
        csv_lines = [
            "timestamp,rule_name,severity,source_ip,dest_ip,src_port,dst_port,message,packet_count"
        ]
        
        for alert in alerts:
            timestamp = datetime.fromtimestamp(alert.timestamp).isoformat()
            csv_lines.append(
                f'{timestamp},"{alert.rule_name}",{alert.severity},'
                f'{alert.src_ip},{alert.dst_ip},{alert.src_port},{alert.dst_port},'
                f'"{alert.message}",{alert.packet_count}'
            )
        
        return "\n".join(csv_lines)
    
    def to_json(self, data: Dict[str, Any], pretty: bool = False) -> str:
        """
        Convert data to JSON string.
        
        Args:
            data: Data dictionary
            pretty: Whether to pretty-print
            
        Returns:
            JSON string
        """
        if pretty:
            return json.dumps(data, indent=2, default=str)
        return json.dumps(data, default=str)
    
    @staticmethod
    def _serialize_alert(alert: Any) -> Dict[str, Any]:
        """Convert alert to JSON-serializable dict."""
        return {
            'rule_name': alert.rule_name,
            'rule_type': alert.rule_type,
            'severity': alert.severity,
            'timestamp': datetime.fromtimestamp(alert.timestamp).isoformat(),
            'source_ip': alert.src_ip,
            'dest_ip': alert.dst_ip,
            'source_port': alert.src_port,
            'dest_port': alert.dst_port,
            'message': alert.message,
            'packet_count': alert.packet_count,
            'threshold': alert.threshold,
            'matched_value': alert.matched_value,
            'additional_info': alert.additional_info or {},
        }
    
    @staticmethod
    def _calculate_threat_level(alert_count: int, severities: set) -> str:
        """
        Calculate threat level based on alerts and severities.
        
        Args:
            alert_count: Number of alerts from source
            severities: Set of severity levels
            
        Returns:
            Threat level (LOW, MEDIUM, HIGH, CRITICAL)
        """
        has_critical = 'CRITICAL' in severities
        has_high = 'HIGH' in severities
        
        if has_critical and alert_count >= 5:
            return 'CRITICAL'
        elif has_critical or (has_high and alert_count >= 10):
            return 'HIGH'
        elif has_high or alert_count >= 15:
            return 'MEDIUM'
        else:
            return 'LOW'
