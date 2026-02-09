# nids/core/analyzer.py
"""
Packet analyzer module.
Orchestrates packet capture, rule evaluation, and alert generation.
Main intelligence component of the NIDS system.
"""

import time
import threading
from typing import Optional, List, Dict, Any, Callable
from collections import deque
import logging

from nids.core.sniffer import PacketSniffer, PacketInfo
from nids.core.rules import RuleEngine, DetectionAlert
from nids.utils.logging_utils import setup_logger

logger = setup_logger(__name__)


class PacketAnalyzer:
    """
    Main packet analyzer.
    
    Responsibilities:
    - Coordinate packet capture and analysis
    - Evaluate packets against detection rules
    - Generate and manage alerts
    - Maintain analysis statistics
    """
    
    def __init__(
        self,
        sniffer: PacketSniffer,
        rule_engine: RuleEngine,
        alert_batch_size: int = 100,
        analysis_interval: float = 1.0
    ):
        """
        Initialize packet analyzer.
        
        Args:
            sniffer: PacketSniffer instance
            rule_engine: RuleEngine instance
            alert_batch_size: Number of packets to analyze per batch
            analysis_interval: Time between analysis cycles (seconds)
        """
        self.sniffer = sniffer
        self.rule_engine = rule_engine
        self.alert_batch_size = alert_batch_size
        self.analysis_interval = analysis_interval
        
        self.is_running = False
        self.analyzer_thread: Optional[threading.Thread] = None
        
        self.alert_callbacks: List[Callable[[DetectionAlert], None]] = []
        self.alerts_history: deque = deque(maxlen=1000)  # Keep last 1000 alerts
        
        self.stats = {
            'packets_analyzed': 0,
            'alerts_generated': 0,
            'analysis_cycles': 0,
            'start_time': None,
            'last_analysis_time': None,
        }
    
    def add_alert_callback(self, callback: Callable[[DetectionAlert], None]) -> None:
        """
        Register callback for alerts.
        
        Args:
            callback: Function called when alert is generated
        """
        self.alert_callbacks.append(callback)
        logger.debug(f"Registered alert callback: {callback.__name__}")
    
    def start(self) -> None:
        """
        Start packet analyzer.
        Runs in separate thread.
        """
        if self.is_running:
            logger.warning("Analyzer already running")
            return
        
        self.is_running = True
        self.stats['start_time'] = time.time()
        
        # Start sniffer first
        self.sniffer.start()
        
        # Start analyzer in separate thread
        self.analyzer_thread = threading.Thread(
            target=self._analysis_loop,
            daemon=True,
            name="PacketAnalyzerThread"
        )
        self.analyzer_thread.start()
        logger.info("Packet analyzer started")
    
    def _analysis_loop(self) -> None:
        """
        Main analysis loop.
        Continuously fetches packets and evaluates against rules.
        """
        try:
            while self.is_running:
                try:
                    self._analyze_batch()
                    time.sleep(self.analysis_interval)
                except Exception as e:
                    logger.error(f"Error in analysis cycle: {e}")
                    time.sleep(self.analysis_interval)
        
        except KeyboardInterrupt:
            logger.info("Analysis loop interrupted")
        except Exception as e:
            logger.error(f"Fatal error in analysis loop: {e}")
        finally:
            self.is_running = False
    
    def _analyze_batch(self) -> None:
        """
        Analyze a batch of captured packets.
        Fetches packets from sniffer queue and evaluates against rules.
        """
        # Get packets from sniffer
        packets = self.sniffer.flush_queue()
        if not packets:
            return
        
        self.stats['packets_analyzed'] += len(packets)
        self.stats['analysis_cycles'] += 1
        self.stats['last_analysis_time'] = time.time()
        
        # Evaluate packets against rules
        try:
            alerts = self.rule_engine.evaluate(packets)
            
            # Process detected alerts
            for alert in alerts:
                self._handle_alert(alert)
        
        except Exception as e:
            logger.error(f"Error evaluating rules: {e}")
    
    def _handle_alert(self, alert: DetectionAlert) -> None:
        """
        Handle generated alert.
        Stores alert and calls registered callbacks.
        
        Args:
            alert: DetectionAlert object
        """
        # Store in history
        self.alerts_history.append(alert)
        self.stats['alerts_generated'] += 1
        
        # Call registered callbacks
        for callback in self.alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                logger.error(f"Error in alert callback: {e}")
    
    def stop(self) -> None:
        """
        Stop packet analyzer.
        Also stops the sniffer.
        """
        if not self.is_running:
            logger.warning("Analyzer not running")
            return
        
        self.is_running = False
        
        # Stop sniffer
        self.sniffer.stop()
        
        # Wait for analyzer thread
        if self.analyzer_thread:
            self.analyzer_thread.join(timeout=5)
        
        logger.info("Packet analyzer stopped")
    
    def get_alerts(self, limit: Optional[int] = None) -> List[DetectionAlert]:
        """
        Get recent alerts.
        
        Args:
            limit: Maximum number of alerts to return (None = all)
            
        Returns:
            List of DetectionAlert objects
        """
        alerts = list(self.alerts_history)
        if limit:
            alerts = alerts[-limit:]
        return alerts
    
    def clear_alerts(self) -> None:
        """Clear alert history."""
        self.alerts_history.clear()
    
    def get_alerts_by_type(self, alert_type: str) -> List[DetectionAlert]:
        """
        Get alerts of specific type.
        
        Args:
            alert_type: Rule type to filter by
            
        Returns:
            List of matching alerts
        """
        return [a for a in self.alerts_history if a.rule_type == alert_type]
    
    def get_alerts_by_severity(self, severity: str) -> List[DetectionAlert]:
        """
        Get alerts of specific severity.
        
        Args:
            severity: Severity level (LOW, MEDIUM, HIGH, CRITICAL)
            
        Returns:
            List of matching alerts
        """
        return [a for a in self.alerts_history if a.severity == severity]
    
    def get_alerts_by_source_ip(self, src_ip: str) -> List[DetectionAlert]:
        """
        Get alerts from specific source IP.
        
        Args:
            src_ip: Source IP address
            
        Returns:
            List of matching alerts
        """
        return [a for a in self.alerts_history if a.src_ip == src_ip]
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get analyzer statistics.
        
        Returns:
            Dictionary with analyzer statistics
        """
        stats = self.stats.copy()
        
        if stats['start_time']:
            stats['uptime_seconds'] = time.time() - stats['start_time']
            if stats['packets_analyzed'] > 0:
                stats['packets_per_second'] = (
                    stats['packets_analyzed'] / stats['uptime_seconds']
                )
        
        # Include sniffer stats
        stats['sniffer'] = self.sniffer.get_stats()
        
        # Alert statistics
        stats['alerts'] = {
            'total': len(self.alerts_history),
            'by_severity': {
                'CRITICAL': len(self.get_alerts_by_severity('CRITICAL')),
                'HIGH': len(self.get_alerts_by_severity('HIGH')),
                'MEDIUM': len(self.get_alerts_by_severity('MEDIUM')),
                'LOW': len(self.get_alerts_by_severity('LOW')),
            }
        }
        
        return stats
    
    def is_healthy(self) -> bool:
        """
        Check if analyzer is operating normally.
        
        Returns:
            True if analyzer is running and processing packets
        """
        if not self.is_running:
            return False
        
        # Check if packets are being processed
        if self.stats['packets_analyzed'] == 0:
            return False
        
        # Check if analyzer thread is alive
        if self.analyzer_thread and not self.analyzer_thread.is_alive():
            return False
        
        return True
