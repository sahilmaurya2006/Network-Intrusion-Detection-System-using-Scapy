# nids/alerts/alert_base.py
"""
Base alert handler classes.
Abstract interfaces for different alert delivery methods.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any
import logging
from nids.core.rules import DetectionAlert

logger = logging.getLogger(__name__)


class AlertHandler(ABC):
    """
    Abstract base class for alert handlers.
    All alert methods inherit from this.
    """
    
    def __init__(self, enabled: bool = True):
        """
        Initialize alert handler.
        
        Args:
            enabled: Whether this handler is active
        """
        self.enabled = enabled
        self.alerts_sent = 0
        self.alerts_failed = 0
    
    @abstractmethod
    def handle_alert(self, alert: DetectionAlert) -> bool:
        """
        Send/handle an alert.
        
        Args:
            alert: DetectionAlert object
            
        Returns:
            True if alert was handled successfully, False otherwise
        """
        pass
    
    def format_alert(self, alert: DetectionAlert) -> str:
        """
        Format alert into readable string.
        
        Args:
            alert: DetectionAlert object
            
        Returns:
            Formatted alert string
        """
        return (
            f"[{alert.severity}] {alert.rule_name} - {alert.message}\n"
            f"  Source IP: {alert.src_ip}, Dest IP: {alert.dst_ip}\n"
            f"  Time: {alert.timestamp}\n"
            f"  Details: Threshold={alert.threshold}, Matched={alert.matched_value}"
        )
    
    def get_stats(self) -> Dict[str, int]:
        """
        Get handler statistics.
        
        Returns:
            Dictionary with stats
        """
        return {
            'alerts_sent': self.alerts_sent,
            'alerts_failed': self.alerts_failed,
            'success_rate': (
                100 * self.alerts_sent / (self.alerts_sent + self.alerts_failed)
                if (self.alerts_sent + self.alerts_failed) > 0 else 0
            )
        }


class AlertManager:
    """
    Manages multiple alert handlers.
    Routes alerts to appropriate handlers.
    """
    
    def __init__(self):
        """Initialize alert manager."""
        self.handlers: Dict[str, AlertHandler] = {}
    
    def register_handler(self, name: str, handler: AlertHandler) -> None:
        """
        Register an alert handler.
        
        Args:
            name: Handler name
            handler: AlertHandler instance
        """
        self.handlers[name] = handler
        logger.debug(f"Registered alert handler: {name}")
    
    def handle_alert(self, alert: DetectionAlert) -> None:
        """
        Route alert to all registered handlers.
        
        Args:
            alert: DetectionAlert object
        """
        for name, handler in self.handlers.items():
            if not handler.enabled:
                continue
            
            try:
                success = handler.handle_alert(alert)
                if success:
                    handler.alerts_sent += 1
                else:
                    handler.alerts_failed += 1
            except Exception as e:
                logger.error(f"Error in handler {name}: {e}")
                handler.alerts_failed += 1
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get statistics from all handlers.
        
        Returns:
            Dictionary with per-handler statistics
        """
        return {
            name: handler.get_stats()
            for name, handler in self.handlers.items()
        }
