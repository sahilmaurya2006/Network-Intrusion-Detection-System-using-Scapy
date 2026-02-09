# nids/alerts/console.py
"""
Console alert handler.
Displays alerts in the console with colored output.
"""

import logging
from typing import Optional
from nids.core.rules import DetectionAlert
from nids.alerts.alert_base import AlertHandler

logger = logging.getLogger(__name__)

# ANSI color codes
class Colors:
    """ANSI color codes for terminal output."""
    CRITICAL = '\033[91m'  # Bright Red
    HIGH = '\033[93m'      # Bright Yellow
    MEDIUM = '\033[94m'    # Bright Blue
    LOW = '\033[92m'       # Bright Green
    RESET = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class ConsoleAlertHandler(AlertHandler):
    """
    Console alert handler.
    
    Features:
    - Real-time alert display
    - Color-coded severity levels
    - Detailed alert information
    - Configurable verbosity
    """
    
    def __init__(
        self,
        enabled: bool = True,
        show_details: bool = True,
        color_output: bool = True
    ):
        """
        Initialize console alert handler.
        
        Args:
            enabled: Whether handler is active
            show_details: Whether to show detailed alert info
            color_output: Whether to use colored output
        """
        super().__init__(enabled)
        self.show_details = show_details
        self.color_output = color_output
    
    def handle_alert(self, alert: DetectionAlert) -> bool:
        """
        Display alert in console.
        
        Args:
            alert: DetectionAlert object
            
        Returns:
            True if successfully displayed
        """
        try:
            output = self._format_alert(alert)
            print(output)
            logger.warning(f"Alert: {alert.rule_name} - {alert.message}")
            return True
        except Exception as e:
            logger.error(f"Error displaying console alert: {e}")
            return False
    
    def _format_alert(self, alert: DetectionAlert) -> str:
        """
        Format alert with colors and styling.
        
        Args:
            alert: DetectionAlert object
            
        Returns:
            Formatted alert string
        """
        color = self._get_severity_color(alert.severity)
        reset = Colors.RESET if self.color_output else ""
        
        lines = []
        lines.append("")  # Blank line for spacing
        
        # Header
        header = f"{'=' * 80}"
        lines.append(f"{color}{header}{reset}")
        
        # Alert title
        title = f"⚠️  {alert.severity} ALERT: {alert.rule_name}"
        lines.append(f"{color}{Colors.BOLD}{title}{reset}")
        
        # Main message
        lines.append(f"{color}{alert.message}{reset}")
        
        # Basic information
        lines.append(f"\n{Colors.BOLD}Basic Information:{reset}")
        lines.append(f"  Rule Type:     {alert.rule_type}")
        lines.append(f"  Timestamp:     {self._format_timestamp(alert.timestamp)}")
        
        # Network information
        if alert.src_ip or alert.dst_ip:
            lines.append(f"\n{Colors.BOLD}Network Details:{reset}")
            if alert.src_ip:
                lines.append(f"  Source IP:     {alert.src_ip}")
            if alert.src_port:
                lines.append(f"  Source Port:   {alert.src_port}")
            if alert.dst_ip:
                lines.append(f"  Dest IP:       {alert.dst_ip}")
            if alert.dst_port:
                lines.append(f"  Dest Port:     {alert.dst_port}")
        
        # Detection statistics
        lines.append(f"\n{Colors.BOLD}Detection Statistics:{reset}")
        lines.append(f"  Threshold:     {alert.threshold}")
        lines.append(f"  Matched Value: {color}{alert.matched_value}{reset}")
        lines.append(f"  Packet Count:  {alert.packet_count}")
        
        # Additional information
        if alert.additional_info and self.show_details:
            lines.append(f"\n{Colors.BOLD}Additional Details:{reset}")
            for key, value in alert.additional_info.items():
                if isinstance(value, (list, dict)):
                    lines.append(f"  {key}:")
                    if isinstance(value, list):
                        for item in value[:5]:  # Limit to 5 items
                            lines.append(f"    - {item}")
                        if len(value) > 5:
                            lines.append(f"    ... and {len(value) - 5} more")
                    else:
                        for k, v in list(value.items())[:5]:
                            lines.append(f"    {k}: {v}")
                else:
                    lines.append(f"  {key}: {value}")
        
        # Footer
        footer = f"{'=' * 80}"
        lines.append(f"{color}{footer}{reset}")
        
        return "\n".join(lines)
    
    @staticmethod
    def _get_severity_color(severity: str) -> str:
        """
        Get color code for severity level.
        
        Args:
            severity: Severity level
            
        Returns:
            ANSI color code
        """
        color_map = {
            'CRITICAL': Colors.CRITICAL,
            'HIGH': Colors.HIGH,
            'MEDIUM': Colors.MEDIUM,
            'LOW': Colors.LOW,
        }
        return color_map.get(severity, Colors.RESET)
    
    @staticmethod
    def _format_timestamp(timestamp: float) -> str:
        """
        Format timestamp as readable string.
        
        Args:
            timestamp: Unix timestamp
            
        Returns:
            Formatted timestamp
        """
        from datetime import datetime
        return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
