# nids/utils/validators.py
"""
Input validation module.
Provides functions for validating network-related inputs.
Implements security best practices for input sanitization.
"""

import re
import ipaddress
from typing import Optional, List, Tuple
import logging

logger = logging.getLogger(__name__)


class InputValidator:
    """
    Validates network and system inputs.
    
    Provides secure validation for:
    - IP addresses (IPv4 and IPv6)
    - Ports
    - MAC addresses
    - Protocol types
    - Email addresses
    """
    
    # IP address patterns
    IPV4_PATTERN = re.compile(
        r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    )
    
    # MAC address pattern
    MAC_PATTERN = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
    
    # Email pattern
    EMAIL_PATTERN = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    
    @staticmethod
    def validate_ip(ip_address: str, allow_ipv6: bool = True) -> bool:
        """
        Validate IP address.
        
        Args:
            ip_address: IP address string to validate
            allow_ipv6: Whether to allow IPv6 addresses
            
        Returns:
            True if valid, False otherwise
        """
        try:
            addr = ipaddress.ip_address(ip_address)
            if isinstance(addr, ipaddress.IPv6Address) and not allow_ipv6:
                return False
            return True
        except ValueError:
            return False
    
    @staticmethod
    def validate_port(port: int, min_port: int = 0, max_port: int = 65535) -> bool:
        """
        Validate port number.
        
        Args:
            port: Port number to validate
            min_port: Minimum allowed port
            max_port: Maximum allowed port
            
        Returns:
            True if valid, False otherwise
        """
        try:
            port_int = int(port)
            return min_port <= port_int <= max_port
        except (ValueError, TypeError):
            return False
    
    @staticmethod
    def validate_mac(mac_address: str) -> bool:
        """
        Validate MAC address.
        
        Args:
            mac_address: MAC address string (format: XX:XX:XX:XX:XX:XX)
            
        Returns:
            True if valid, False otherwise
        """
        return InputValidator.MAC_PATTERN.match(mac_address) is not None
    
    @staticmethod
    def validate_protocol(protocol: str) -> bool:
        """
        Validate protocol name.
        
        Args:
            protocol: Protocol name (tcp, udp, icmp, arp, etc.)
            
        Returns:
            True if valid, False otherwise
        """
        valid_protocols = {'tcp', 'udp', 'icmp', 'arp', 'ipv6', 'igmp', 'igmp'}
        return protocol.lower() in valid_protocols
    
    @staticmethod
    def validate_email(email: str) -> bool:
        """
        Validate email address.
        
        Args:
            email: Email address to validate
            
        Returns:
            True if valid, False otherwise
        """
        if not email or len(email) > 254:
            return False
        return InputValidator.EMAIL_PATTERN.match(email) is not None
    
    @staticmethod
    def sanitize_string(text: str, max_length: int = 256, allow_special: bool = False) -> str:
        """
        Sanitize string input.
        
        Args:
            text: String to sanitize
            max_length: Maximum allowed length
            allow_special: Whether to allow special characters
            
        Returns:
            Sanitized string
        """
        if not text:
            return ""
        
        # Truncate to max length
        text = text[:max_length]
        
        # Remove null bytes
        text = text.replace('\x00', '')
        
        if not allow_special:
            # Allow only alphanumeric, spaces, and basic punctuation
            text = re.sub(r'[^a-zA-Z0-9\s\-_.@]', '', text)
        
        return text
    
    @staticmethod
    def is_ip_in_range(ip_address: str, cidr_range: str) -> bool:
        """
        Check if IP address is within CIDR range.
        
        Args:
            ip_address: IP address to check
            cidr_range: CIDR range (e.g., "192.168.0.0/16")
            
        Returns:
            True if IP is in range, False otherwise
        """
        try:
            addr = ipaddress.ip_address(ip_address)
            network = ipaddress.ip_network(cidr_range, strict=False)
            return addr in network
        except ValueError:
            return False


class RangeTracker:
    """
    Tracks and counts events within a sliding time window.
    Used for threshold-based detection.
    """
    
    def __init__(self, time_window: int):
        """
        Initialize range tracker.
        
        Args:
            time_window: Time window in seconds
        """
        self.time_window = time_window
        self.events: List[float] = []
    
    def add_event(self, timestamp: float) -> None:
        """
        Add an event timestamp.
        
        Args:
            timestamp: Event timestamp (seconds since epoch)
        """
        self.events.append(timestamp)
        self._cleanup_old_events(timestamp)
    
    def _cleanup_old_events(self, current_time: float) -> None:
        """Remove events older than time window."""
        cutoff_time = current_time - self.time_window
        self.events = [t for t in self.events if t > cutoff_time]
    
    def get_count(self, current_time: float) -> int:
        """
        Get count of events in current time window.
        
        Args:
            current_time: Current timestamp
            
        Returns:
            Count of events in time window
        """
        self._cleanup_old_events(current_time)
        return len(self.events)
    
    def reset(self) -> None:
        """Clear all events."""
        self.events.clear()
