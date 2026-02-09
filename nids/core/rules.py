# nids/core/rules.py
"""
Detection rules engine.
Defines and manages all intrusion detection rules with configurable thresholds.
Implements rule evaluation and condition checking.
"""

from typing import Optional, List, Dict, Any, Callable, Set, Tuple
from dataclasses import dataclass, field
from abc import ABC, abstractmethod
import time
from collections import defaultdict
import logging

from nids.utils.validators import RangeTracker, InputValidator

logger = logging.getLogger(__name__)


@dataclass
class DetectionAlert:
    """
    Represents a detected intrusion alert.
    Contains all relevant information about the detected attack.
    """
    rule_name: str
    rule_type: str
    severity: str
    timestamp: float
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    message: str = ""
    packet_count: int = 0
    threshold: int = 0
    matched_value: int = 0
    additional_info: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert alert to dictionary."""
        return {
            'rule_name': self.rule_name,
            'rule_type': self.rule_type,
            'severity': self.severity,
            'timestamp': self.timestamp,
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'message': self.message,
            'packet_count': self.packet_count,
            'threshold': self.threshold,
            'matched_value': self.matched_value,
            'additional_info': self.additional_info,
        }


class DetectionRule(ABC):
    """
    Abstract base class for detection rules.
    All specific rules inherit from this.
    """
    
    def __init__(
        self,
        name: str,
        rule_type: str,
        severity: str,
        enabled: bool = True,
        description: str = ""
    ):
        """
        Initialize detection rule.
        
        Args:
            name: Rule name (e.g., "ICMP_FLOOD")
            rule_type: Type of rule (e.g., "PROTOCOL_FLOOD")
            severity: Severity level (LOW, MEDIUM, HIGH, CRITICAL)
            enabled: Whether rule is active
            description: Rule description
        """
        self.name = name
        self.rule_type = rule_type
        self.severity = severity
        self.enabled = enabled
        self.description = description
    
    @abstractmethod
    def evaluate(self, packets: List[Any]) -> List[DetectionAlert]:
        """
        Evaluate packets against rule.
        
        Args:
            packets: List of packets to analyze
            
        Returns:
            List of DetectionAlert objects if rule matched
        """
        pass


class ICMPFloodRule(DetectionRule):
    """
    Detects ICMP Flood attacks.
    Triggered when ICMP packet rate exceeds threshold.
    """
    
    def __init__(self, threshold: int = 100, time_window: int = 10):
        """
        Initialize ICMP flood rule.
        
        Args:
            threshold: ICMP packets per time window
            time_window: Time window in seconds
        """
        super().__init__(
            name="ICMP_FLOOD",
            rule_type="PROTOCOL_FLOOD",
            severity="HIGH",
            description="Detects abnormally high ICMP packet rates"
        )
        self.threshold = threshold
        self.time_window = time_window
        self.trackers: Dict[str, RangeTracker] = defaultdict(
            lambda: RangeTracker(time_window)
        )
    
    def evaluate(self, packets: List[Any]) -> List[DetectionAlert]:
        """
        Evaluate ICMP flood condition.
        
        Args:
            packets: List of PacketInfo objects
            
        Returns:
            List of DetectionAlert objects
        """
        alerts = []
        current_time = time.time()
        
        for packet in packets:
            if packet.protocol != "ICMP":
                continue
            
            src_ip = packet.src_ip or "unknown"
            
            # Track ICMP packets from source
            self.trackers[src_ip].add_event(current_time)
            
            # Check threshold
            count = self.trackers[src_ip].get_count(current_time)
            if count >= self.threshold:
                alerts.append(DetectionAlert(
                    rule_name=self.name,
                    rule_type=self.rule_type,
                    severity=self.severity,
                    timestamp=current_time,
                    src_ip=src_ip,
                    dst_ip=packet.dst_ip,
                    message=f"ICMP flood detected: {count} packets in {self.time_window}s",
                    packet_count=count,
                    threshold=self.threshold,
                    matched_value=count,
                ))
        
        return alerts


class TCPSYNScanRule(DetectionRule):
    """
    Detects TCP SYN port scanning.
    Triggered when large number of unique ports are scanned from single source.
    """
    
    def __init__(self, threshold: int = 50, time_window: int = 30):
        """
        Initialize TCP SYN scan rule.
        
        Args:
            threshold: Unique destination ports threshold
            time_window: Time window in seconds
        """
        super().__init__(
            name="TCP_SYN_SCAN",
            rule_type="PORT_SCAN",
            severity="HIGH",
            description="Detects TCP SYN scanning activity"
        )
        self.threshold = threshold
        self.time_window = time_window
        self.source_ports: Dict[str, Dict[str, Any]] = defaultdict(
            lambda: {'ports': set(), 'last_update': time.time()}
        )
    
    def evaluate(self, packets: List[Any]) -> List[DetectionAlert]:
        """
        Evaluate TCP SYN scan condition.
        
        Args:
            packets: List of PacketInfo objects
            
        Returns:
            List of DetectionAlert objects
        """
        alerts = []
        current_time = time.time()
        
        for packet in packets:
            if packet.protocol != "TCP" or "SYN" not in (packet.flags or ""):
                continue
            
            src_ip = packet.src_ip or "unknown"
            
            # Initialize tracker for source if needed
            if src_ip not in self.source_ports:
                self.source_ports[src_ip] = {
                    'ports': set(),
                    'last_update': current_time,
                    'start_time': current_time
                }
            
            # Clean up old entries (outside time window)
            source_info = self.source_ports[src_ip]
            if current_time - source_info['last_update'] > self.time_window:
                source_info['ports'].clear()
                source_info['start_time'] = current_time
            
            # Add destination port
            destination_port = packet.dst_port
            if destination_port:
                source_info['ports'].add(destination_port)
                source_info['last_update'] = current_time
            
            # Check threshold
            unique_ports = len(source_info['ports'])
            if unique_ports >= self.threshold:
                alerts.append(DetectionAlert(
                    rule_name=self.name,
                    rule_type=self.rule_type,
                    severity=self.severity,
                    timestamp=current_time,
                    src_ip=src_ip,
                    message=f"TCP SYN scan detected: {unique_ports} unique ports scanned",
                    packet_count=unique_ports,
                    threshold=self.threshold,
                    matched_value=unique_ports,
                    additional_info={'ports': list(source_info['ports'])}
                ))
        
        return alerts


class BruteForceRule(DetectionRule):
    """
    Detects brute-force login attempts.
    Triggered by excessive connection attempts to known service ports.
    """
    
    # Common service ports for login attempts
    BRUTE_FORCE_PORTS = {22, 23, 3389, 3306, 5432, 5984, 6379, 8080}
    
    def __init__(self, threshold: int = 5, time_window: int = 60):
        """
        Initialize brute-force rule.
        
        Args:
            threshold: Connection attempts threshold
            time_window: Time window in seconds
        """
        super().__init__(
            name="BRUTE_FORCE",
            rule_type="LOGIN_ATTACK",
            severity="CRITICAL",
            description="Detects excessive connection attempts (brute-force)"
        )
        self.threshold = threshold
        self.time_window = time_window
        self.connection_attempts: Dict[str, Dict[str, Any]] = defaultdict(
            lambda: {
                'connections': [],
                'last_cleanup': time.time()
            }
        )
    
    def evaluate(self, packets: List[Any]) -> List[DetectionAlert]:
        """
        Evaluate brute-force condition.
        
        Args:
            packets: List of PacketInfo objects
            
        Returns:
            List of DetectionAlert objects
        """
        alerts = []
        current_time = time.time()
        
        for packet in packets:
            if packet.protocol != "TCP":
                continue
            
            # Check if destination port is a service port
            dst_port = packet.dst_port
            if dst_port not in self.BRUTE_FORCE_PORTS:
                continue
            
            src_ip = packet.src_ip or "unknown"
            key = f"{src_ip}:{dst_port}"
            
            # Track connection attempt
            connection_data = self.connection_attempts[key]
            connection_data['connections'].append(current_time)
            
            # Clean up old attempts
            if current_time - connection_data['last_cleanup'] > self.time_window:
                connection_data['connections'] = [
                    t for t in connection_data['connections']
                    if current_time - t < self.time_window
                ]
                connection_data['last_cleanup'] = current_time
            
            # Check threshold
            attempt_count = len(connection_data['connections'])
            if attempt_count >= self.threshold:
                service_name = self._get_service_name(dst_port)
                alerts.append(DetectionAlert(
                    rule_name=self.name,
                    rule_type=self.rule_type,
                    severity=self.severity,
                    timestamp=current_time,
                    src_ip=src_ip,
                    dst_port=dst_port,
                    message=f"Brute-force attack on {service_name}: "
                           f"{attempt_count} attempts in {self.time_window}s",
                    packet_count=attempt_count,
                    threshold=self.threshold,
                    matched_value=attempt_count,
                    additional_info={'service': service_name}
                ))
        
        return alerts
    
    @staticmethod
    def _get_service_name(port: int) -> str:
        """Get service name for port."""
        services = {
            22: "SSH",
            23: "Telnet",
            3389: "RDP",
            3306: "MySQL",
            5432: "PostgreSQL",
            5984: "CouchDB",
            6379: "Redis",
            8080: "HTTP-Alt"
        }
        return services.get(port, f"Unknown({port})")


class ARPSpoofingRule(DetectionRule):
    """
    Detects ARP spoofing and gratuitous ARP floods.
    Triggered by duplicate ARP replies from different MAC addresses.
    """
    
    def __init__(self, threshold: int = 10, time_window: int = 30):
        """
        Initialize ARP spoofing rule.
        
        Args:
            threshold: Duplicate ARP replies threshold
            time_window: Time window in seconds
        """
        super().__init__(
            name="ARP_SPOOFING",
            rule_type="ARP_ATTACK",
            severity="CRITICAL",
            description="Detects ARP spoofing and gratuitous ARP floods"
        )
        self.threshold = threshold
        self.time_window = time_window
        self.arp_responses: Dict[str, Dict[str, Any]] = defaultdict(
            lambda: {
                'macs': defaultdict(list),
                'last_cleanup': time.time()
            }
        )
    
    def evaluate(self, packets: List[Any]) -> List[DetectionAlert]:
        """
        Evaluate ARP spoofing condition.
        
        Args:
            packets: List of PacketInfo objects
            
        Returns:
            List of DetectionAlert objects
        """
        alerts = []
        current_time = time.time()
        
        for packet in packets:
            if not packet.is_arp or packet.arp_operation != "REPLY":
                continue
            
            # Track ARP replies by target IP and source MAC
            target_ip = packet.src_ip  # In ARP reply, source is the replier
            src_mac = packet.src_mac
            
            if not target_ip or not src_mac:
                continue
            
            arp_data = self.arp_responses[target_ip]
            arp_data['macs'][src_mac].append(current_time)
            
            # Clean up old entries
            if current_time - arp_data['last_cleanup'] > self.time_window:
                arp_data['macs'] = defaultdict(
                    list,
                    {
                        mac: [t for t in times if current_time - t < self.time_window]
                        for mac, times in arp_data['macs'].items()
                        if times
                    }
                )
                # Remove empty entries
                arp_data['macs'] = defaultdict(
                    list,
                    {k: v for k, v in arp_data['macs'].items() if v}
                )
                arp_data['last_cleanup'] = current_time
            
            # Check if multiple MACs are replying for same IP
            unique_macs = len(arp_data['macs'])
            if unique_macs >= 2:
                total_responses = sum(len(times) for times in arp_data['macs'].values())
                if total_responses >= self.threshold:
                    alerts.append(DetectionAlert(
                        rule_name=self.name,
                        rule_type=self.rule_type,
                        severity=self.severity,
                        timestamp=current_time,
                        src_ip=target_ip,
                        message=f"ARP spoofing detected: {unique_macs} MACs "
                               f"claiming IP {target_ip} "
                               f"({total_responses} replies)",
                        packet_count=total_responses,
                        threshold=self.threshold,
                        matched_value=unique_macs,
                        additional_info={'mac_addresses': list(arp_data['macs'].keys())}
                    ))
        
        return alerts


class RuleEngine:
    """
    Detection rule engine.
    Manages and evaluates all detection rules against packet streams.
    """
    
    def __init__(self):
        """Initialize rule engine."""
        self.rules: Dict[str, DetectionRule] = {}
    
    def register_rule(self, rule: DetectionRule) -> None:
        """
        Register a detection rule.
        
        Args:
            rule: DetectionRule instance
        """
        self.rules[rule.name] = rule
        logger.debug(f"Registered rule: {rule.name}")
    
    def create_default_rules(self, config: Dict[str, Any]) -> None:
        """
        Create default detection rules from configuration.
        
        Args:
            config: Configuration dictionary for detection rules
        """
        # ICMP Flood Rule
        icmp_config = config.get('icmp_flood', {})
        if icmp_config.get('enabled', True):
            self.register_rule(ICMPFloodRule(
                threshold=icmp_config.get('threshold', 100),
                time_window=icmp_config.get('time_window', 10)
            ))
        
        # TCP SYN Scan Rule
        syn_config = config.get('tcp_syn_scan', {})
        if syn_config.get('enabled', True):
            self.register_rule(TCPSYNScanRule(
                threshold=syn_config.get('threshold', 50),
                time_window=syn_config.get('time_window', 30)
            ))
        
        # Brute Force Rule
        bf_config = config.get('brute_force', {})
        if bf_config.get('enabled', True):
            self.register_rule(BruteForceRule(
                threshold=bf_config.get('threshold', 5),
                time_window=bf_config.get('time_window', 60)
            ))
        
        # ARP Spoofing Rule
        arp_config = config.get('arp_spoofing', {})
        if arp_config.get('enabled', True):
            self.register_rule(ARPSpoofingRule(
                threshold=arp_config.get('threshold', 10),
                time_window=arp_config.get('time_window', 30)
            ))
        
        logger.info(f"Created {len(self.rules)} detection rules")
    
    def evaluate(self, packets: List[Any]) -> List[DetectionAlert]:
        """
        Evaluate packets against all enabled rules.
        
        Args:
            packets: List of packets to analyze
            
        Returns:
            List of DetectionAlert objects from all rules
        """
        all_alerts = []
        
        for rule in self.rules.values():
            if not rule.enabled:
                continue
            
            try:
                alerts = rule.evaluate(packets)
                all_alerts.extend(alerts)
            except Exception as e:
                logger.error(f"Error evaluating rule {rule.name}: {e}")
        
        return all_alerts
    
    def get_enabled_rules(self) -> List[str]:
        """Get list of enabled rule names."""
        return [name for name, rule in self.rules.items() if rule.enabled]
    
    def enable_rule(self, rule_name: str) -> None:
        """Enable a specific rule."""
        if rule_name in self.rules:
            self.rules[rule_name].enabled = True
    
    def disable_rule(self, rule_name: str) -> None:
        """Disable a specific rule."""
        if rule_name in self.rules:
            self.rules[rule_name].enabled = False
