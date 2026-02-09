# nids/core/sniffer.py
"""
Packet sniffer module.
Captures and processes network packets in real-time using Scapy.
Supports multi-interface monitoring and efficient packet filtering.
"""

import threading
import time
from typing import Optional, Callable, List, Dict, Any
from dataclasses import dataclass
from datetime import datetime
import logging

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Raw
except ImportError:
    raise ImportError("Scapy not installed. Run: pip install scapy")

from nids.utils.validators import InputValidator, RangeTracker
from nids.utils.logging_utils import setup_logger

logger = setup_logger(__name__)


@dataclass
class PacketInfo:
    """
    Structured packet information.
    Extracts and stores relevant packet data for analysis.
    """
    timestamp: float
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    protocol: str = "UNKNOWN"
    payload_size: int = 0
    flags: str = ""
    sequence_number: Optional[int] = None
    acknowledgment_number: Optional[int] = None
    is_arp: bool = False
    arp_operation: Optional[str] = None
    raw_packet: Optional[Any] = None


class PacketSniffer:
    """
    Real-time packet sniffer using Scapy.
    
    Features:
    - Multi-interface monitoring
    - Efficient packet filtering (BPF)
    - Thread-safe operation
    - Packet queuing and batch processing
    - Callback support for packet processing
    """
    
    def __init__(
        self,
        interfaces: Optional[List[str]] = None,
        packet_filter: str = "",
        max_packet_size: int = 65535,
        timeout: int = 2000,
        use_threading: bool = True
    ):
        """
        Initialize packet sniffer.
        
        Args:
            interfaces: List of interfaces to sniff on. If None, uses all.
            packet_filter: BPF filter (e.g., "tcp port 80")
            max_packet_size: Maximum packet size to capture
            timeout: Packet capture timeout in milliseconds
            use_threading: Whether to run sniffer in separate thread
        """
        self.interfaces = interfaces or [None]  # None = all interfaces
        self.packet_filter = packet_filter
        self.max_packet_size = max_packet_size
        self.timeout = timeout
        self.use_threading = use_threading
        
        self.is_running = False
        self.sniffer_thread: Optional[threading.Thread] = None
        self.packet_callbacks: List[Callable[[PacketInfo], None]] = []
        self.packet_queue: List[PacketInfo] = []
        self.queue_lock = threading.Lock()
        
        self.stats = {
            'packets_captured': 0,
            'packets_dropped': 0,
            'packets_processed': 0,
            'start_time': None,
            'last_packet_time': None,
        }
    
    def add_callback(self, callback: Callable[[PacketInfo], None]) -> None:
        """
        Register callback function for packet processing.
        
        Args:
            callback: Function to call for each packet
        """
        self.packet_callbacks.append(callback)
        logger.debug(f"Registered packet callback: {callback.__name__}")
    
    def _parse_packet(self, packet: Any) -> Optional[PacketInfo]:
        """
        Parse Scapy packet into PacketInfo structure.
        
        Args:
            packet: Scapy packet object
            
        Returns:
            PacketInfo object or None if parsing failed
        """
        try:
            packet_info = PacketInfo(
                timestamp=time.time(),
                raw_packet=packet
            )
            
            # MAC addresses
            try:
                packet_info.src_mac = packet.src
                packet_info.dst_mac = packet.dst
            except (AttributeError, IndexError):
                pass
            
            # ARP Spoofing Detection
            if ARP in packet:
                arp_layer = packet[ARP]
                packet_info.is_arp = True
                packet_info.src_ip = arp_layer.psrc
                packet_info.dst_ip = arp_layer.pdst
                packet_info.src_mac = arp_layer.hwsrc
                packet_info.dst_mac = arp_layer.hwdst
                packet_info.protocol = "ARP"
                
                if arp_layer.op == 1:
                    packet_info.arp_operation = "REQUEST"
                elif arp_layer.op == 2:
                    packet_info.arp_operation = "REPLY"
                else:
                    packet_info.arp_operation = f"UNKNOWN({arp_layer.op})"
                
                return packet_info
            
            # IP Layer Processing
            if IP in packet:
                ip_layer = packet[IP]
                packet_info.src_ip = ip_layer.src
                packet_info.dst_ip = ip_layer.dst
                
                # Validate IPs
                if not InputValidator.validate_ip(packet_info.src_ip):
                    return None
                if not InputValidator.validate_ip(packet_info.dst_ip):
                    return None
                
                # TCP Processing
                if TCP in packet:
                    tcp_layer = packet[TCP]
                    packet_info.src_port = tcp_layer.sport
                    packet_info.dst_port = tcp_layer.dport
                    packet_info.protocol = "TCP"
                    packet_info.sequence_number = tcp_layer.seq
                    packet_info.acknowledgment_number = tcp_layer.ack
                    
                    # TCP Flags
                    flags = []
                    if tcp_layer.flags.F:
                        flags.append("FIN")
                    if tcp_layer.flags.S:
                        flags.append("SYN")
                    if tcp_layer.flags.R:
                        flags.append("RST")
                    if tcp_layer.flags.P:
                        flags.append("PSH")
                    if tcp_layer.flags.A:
                        flags.append("ACK")
                    if tcp_layer.flags.U:
                        flags.append("URG")
                    packet_info.flags = ",".join(flags)
                
                # UDP Processing
                elif UDP in packet:
                    udp_layer = packet[UDP]
                    packet_info.src_port = udp_layer.sport
                    packet_info.dst_port = udp_layer.dport
                    packet_info.protocol = "UDP"
                
                # ICMP Processing
                elif ICMP in packet:
                    icmp_layer = packet[ICMP]
                    packet_info.protocol = "ICMP"
                    # icmp_layer.type gives ICMP type (8=Echo Request, 0=Echo Reply, etc.)
                
                # Get payload size
                if Raw in packet:
                    raw_layer = packet[Raw]
                    packet_info.payload_size = len(raw_layer.load)
            
            return packet_info
        
        except Exception as e:
            logger.debug(f"Error parsing packet: {e}")
            return None
    
    def _packet_handler(self, packet: Any) -> None:
        """
        Internal packet handler called by Scapy sniff.
        Parses packets and calls registered callbacks.
        
        Args:
            packet: Scapy packet object
        """
        try:
            packet_info = self._parse_packet(packet)
            if packet_info is None:
                return
            
            # Update statistics
            self.stats['packets_captured'] += 1
            self.stats['last_packet_time'] = time.time()
            
            # Queue packet
            with self.queue_lock:
                self.packet_queue.append(packet_info)
            
            # Call registered callbacks
            for callback in self.packet_callbacks:
                try:
                    callback(packet_info)
                except Exception as e:
                    logger.error(f"Error in packet callback: {e}")
        
        except Exception as e:
            logger.error(f"Error in packet handler: {e}")
            self.stats['packets_dropped'] += 1
    
    def start(self) -> None:
        """
        Start packet sniffer.
        Runs in separate thread if use_threading is True.
        """
        if self.is_running:
            logger.warning("Sniffer already running")
            return
        
        self.is_running = True
        self.stats['start_time'] = time.time()
        
        if self.use_threading:
            self.sniffer_thread = threading.Thread(target=self._sniff_loop, daemon=True)
            self.sniffer_thread.start()
            logger.info("Packet sniffer started in background thread")
        else:
            self._sniff_loop()
    
    def _sniff_loop(self) -> None:
        """
        Main sniffer loop.
        Captures packets continuously from each interface.
        """
        try:
            for interface in self.interfaces:
                if not self.is_running:
                    break
                
                interface_name = interface or "all interfaces"
                logger.info(f"Starting packet capture on {interface_name}")
                
                try:
                    sniff(
                        prn=self._packet_handler,
                        iface=interface,
                        filter=self.packet_filter,
                        store=False,
                        timeout=self.timeout / 1000,  # Convert ms to seconds
                        stop_filter=lambda x: not self.is_running,
                    )
                except PermissionError as e:
                    logger.error(
                        f"Permission denied for sniffer. "
                        f"Try running with administrator privileges: {e}"
                    )
                    self.is_running = False
                    break
                except Exception as e:
                    logger.error(f"Error capturing packets on {interface_name}: {e}")
        
        except Exception as e:
            logger.error(f"Fatal error in sniffer loop: {e}")
            self.is_running = False
    
    def stop(self) -> None:
        """Stop packet sniffer."""
        if not self.is_running:
            logger.warning("Sniffer not running")
            return
        
        self.is_running = False
        
        if self.sniffer_thread and self.use_threading:
            self.sniffer_thread.join(timeout=5)
        
        logger.info("Packet sniffer stopped")
    
    def get_queued_packets(self, max_count: Optional[int] = None) -> List[PacketInfo]:
        """
        Retrieve queued packets (non-destructive for now).
        
        Args:
            max_count: Maximum packets to return (None = all)
            
        Returns:
            List of PacketInfo objects
        """
        with self.queue_lock:
            packets = self.packet_queue[:max_count]
        return packets
    
    def flush_queue(self) -> List[PacketInfo]:
        """
        Retrieve and clear packet queue.
        
        Returns:
            List of PacketInfo objects
        """
        with self.queue_lock:
            packets = self.packet_queue.copy()
            self.packet_queue.clear()
        
        self.stats['packets_processed'] += len(packets)
        return packets
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get sniffer statistics.
        
        Returns:
            Dictionary with sniffer statistics
        """
        stats = self.stats.copy()
        if stats['start_time']:
            stats['uptime_seconds'] = time.time() - stats['start_time']
            if stats['packets_captured'] > 0:
                stats['packets_per_second'] = (
                    stats['packets_captured'] / stats['uptime_seconds']
                )
        return stats
    
    def reset_stats(self) -> None:
        """Reset statistics counters."""
        self.stats = {
            'packets_captured': 0,
            'packets_dropped': 0,
            'packets_processed': 0,
            'start_time': time.time() if self.is_running else None,
            'last_packet_time': None,
        }
