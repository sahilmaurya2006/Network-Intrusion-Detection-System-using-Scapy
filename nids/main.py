# nids/main.py
"""
NIDS Main Application.
Production-ready Network Intrusion Detection System.

Usage:
    python main.py                      # Use default config
    python main.py --config custom.yaml # Use custom config
    python main.py --help              # Show help
"""

import argparse
import sys
import time
import signal
import logging
from pathlib import Path
from typing import Optional

from nids.utils.config_loader import ConfigLoader
from nids.utils.logging_utils import StructuredLogger
from nids.core.sniffer import PacketSniffer
from nids.core.rules import RuleEngine
from nids.core.analyzer import PacketAnalyzer
from nids.alerts.alert_base import AlertManager
from nids.alerts.console import ConsoleAlertHandler
from nids.alerts.email_alert import EmailAlertHandler
from nids.database.alert_store import AlertDatabase
from nids.dashboard.api_output import DashboardAPI


class NISSApplication:
    """
    Main NIDS application class.
    Orchestrates all system components.
    """
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize NIDS application.
        
        Args:
            config_path: Path to configuration file
        """
        self.config_path = config_path
        self.config = None
        self.logger = None
        self.sniffer = None
        self.rule_engine = None
        self.analyzer = None
        self.alert_manager = None
        self.database = None
        self.dashboard = None
        
        self._initialize()
    
    def _initialize(self) -> None:
        """Initialize all components."""
        # Load configuration
        try:
            self.config = ConfigLoader(self.config_path)
            self.config.validate()
            print("[*] Configuration loaded successfully")
        except Exception as e:
            print(f"[!] Configuration error: {e}")
            sys.exit(1)
        
        # Setup logging
        log_dir = Path(self.config.get('logging.file.path', './logs'))
        log_file = log_dir / self.config.get('logging.file.filename', 'nids_alerts.json')
        
        self.logger = StructuredLogger(
            name='NIDS',
            log_file=log_file,
            log_level=self.config.get('system.log_level', 'INFO'),
            console_output=True
        )
        self.logger.info("NIDS Application initializing...")
        
        try:
            # Initialize packet sniffer
            sniffer_config = self.config.get_section('sniffer')
            self.sniffer = PacketSniffer(
                interfaces=sniffer_config.get('interfaces') or None,
                packet_filter=sniffer_config.get('filter', ''),
                max_packet_size=sniffer_config.get('max_packet_size', 65535),
                timeout=sniffer_config.get('packet_timeout', 2000),
                use_threading=sniffer_config.get('use_threading', True)
            )
            self.logger.info("Packet sniffer initialized")
            
            # Initialize rule engine
            self.rule_engine = RuleEngine()
            detection_config = self.config.get_section('detection')
            self.rule_engine.create_default_rules(detection_config)
            self.logger.info("Rule engine initialized with detection rules")
            
            # Initialize analyzer
            self.analyzer = PacketAnalyzer(
                sniffer=self.sniffer,
                rule_engine=self.rule_engine,
                alert_batch_size=100,
                analysis_interval=1.0
            )
            self.logger.info("Packet analyzer initialized")
            
            # Initialize alert manager
            self.alert_manager = AlertManager()
            self._setup_alert_handlers()
            self.logger.info("Alert manager initialized with handlers")
            
            # Register alert callback
            self.analyzer.add_alert_callback(self.alert_manager.handle_alert)
            
            # Initialize database if enabled
            if self.config.get('logging.database.enabled', False):
                db_type = self.config.get('logging.database.type', 'sqlite')
                if db_type == 'sqlite':
                    db_path = self.config.get(
                        'logging.database.connection.sqlite.db_path',
                        './logs/nids.db'
                    )
                    self.database = AlertDatabase(db_path)
                    # Register database callback
                    self.analyzer.add_alert_callback(self.database.store_alert)
                    self.logger.info("Alert database initialized")
            
            # Initialize dashboard API
            self.dashboard = DashboardAPI(self.analyzer, self.database)
            self.logger.info("Dashboard API initialized")
            
            print("[+] All components initialized successfully")
            self.logger.info("NIDS Application initialized successfully")
        
        except Exception as e:
            print(f"[!] Initialization error: {e}")
            self.logger.error(f"Initialization error: {e}")
            sys.exit(1)
    
    def _setup_alert_handlers(self) -> None:
        """Setup alert handlers based on configuration."""
        alerting_config = self.config.get_section('alerting')
        
        # Console alert handler
        console_config = alerting_config.get('console', {})
        console_handler = ConsoleAlertHandler(
            enabled=console_config.get('enabled', True),
            show_details=console_config.get('show_details', True),
            color_output=console_config.get('color_output', True)
        )
        self.alert_manager.register_handler('console', console_handler)
        
        # Email alert handler
        email_config = alerting_config.get('email', {})
        if email_config.get('enabled', False):
            try:
                email_handler = EmailAlertHandler(
                    smtp_server=email_config.get('smtp_server', 'smtp.gmail.com'),
                    smtp_port=email_config.get('smtp_port', 587),
                    sender_email=email_config.get('sender_email', ''),
                    sender_password=email_config.get('sender_password', ''),
                    recipients=email_config.get('recipients', []),
                    use_tls=email_config.get('use_tls', True),
                    enabled=True,
                    alert_severity_threshold=email_config.get('alert_severity_threshold', 'HIGH')
                )
                self.alert_manager.register_handler('email', email_handler)
                self.logger.info("Email alert handler registered")
            except Exception as e:
                self.logger.error(f"Failed to setup email alerts: {e}")
    
    def start(self) -> None:
        """Start the NIDS application."""
        print("[*] Starting NIDS...")
        print(f"[*] Monitoring {len(self.sniffer.interfaces)} interface(s)")
        print(f"[*] {len(self.rule_engine.rules)} detection rules active")
        
        try:
            self.analyzer.start()
            self.logger.info("NIDS Application started")
            
            # Setup signal handlers
            signal.signal(signal.SIGINT, self._handle_signal)
            signal.signal(signal.SIGTERM, self._handle_signal)
            
            # Main loop - print statistics periodically
            stats_interval = 30  # Print stats every 30 seconds
            last_stats_time = time.time()
            
            while True:
                time.sleep(1)
                
                # Print statistics periodically
                if time.time() - last_stats_time >= stats_interval:
                    self._print_stats()
                    last_stats_time = time.time()
        
        except KeyboardInterrupt:
            print("\n[*] Keyboard interrupt received")
            self.stop()
        except Exception as e:
            print(f"[!] Application error: {e}")
            self.logger.error(f"Application error: {e}")
            self.stop()
            sys.exit(1)
    
    def _print_stats(self) -> None:
        """Print system statistics."""
        stats = self.analyzer.get_stats()
        
        print("\n" + "=" * 80)
        print(f"[*] NIDS Statistics - {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 80)
        
        print(f"  System Status: {'HEALTHY' if self.analyzer.is_healthy() else 'DEGRADED'}")
        print(f"  Uptime: {stats.get('uptime_seconds', 0):.1f}s")
        print(f"  Packets Captured: {stats['sniffer'].get('packets_captured', 0)}")
        print(f"  Packets Analyzed: {stats.get('packets_analyzed', 0)}")
        print(f"  Packets/Second: {stats['sniffer'].get('packets_per_second', 0):.2f}")
        print(f"  Total Alerts: {stats['alerts'].get('total', 0)}")
        print(f"    - CRITICAL: {stats['alerts'].get('by_severity', {}).get('CRITICAL', 0)}")
        print(f"    - HIGH: {stats['alerts'].get('by_severity', {}).get('HIGH', 0)}")
        print(f"    - MEDIUM: {stats['alerts'].get('by_severity', {}).get('MEDIUM', 0)}")
        print(f"    - LOW: {stats['alerts'].get('by_severity', {}).get('LOW', 0)}")
        
        if self.database:
            db_stats = self.database.get_statistics(hours=1)
            print(f"  Alerts in Database (1h): {len(db_stats.get('top_rules', {}))}")
        
        print("=" * 80)
    
    def _handle_signal(self, signum, frame) -> None:
        """Handle shutdown signals."""
        print(f"\n[*] Received signal {signum}")
        self.stop()
    
    def stop(self) -> None:
        """Stop the NIDS application."""
        print("[*] Shutting down NIDS...")
        
        if self.analyzer:
            self.analyzer.stop()
        
        self.logger.info("NIDS Application stopped")
        print("[+] NIDS shutdown complete")
    
    def show_dashboard(self) -> None:
        """Display dashboard in console."""
        if not self.dashboard:
            print("[!] Dashboard not initialized")
            return
        
        dashboard_data = self.dashboard.get_full_dashboard()
        json_output = self.dashboard.to_json(dashboard_data, pretty=True)
        print(json_output)
    
    def export_alerts_csv(self, output_file: str) -> None:
        """
        Export recent alerts to CSV file.
        
        Args:
            output_file: Output file path
        """
        if not self.dashboard:
            print("[!] Dashboard not initialized")
            return
        
        csv_data = self.dashboard.export_alerts_csv()
        
        with open(output_file, 'w') as f:
            f.write(csv_data)
        
        print(f"[+] Alerts exported to {output_file}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Network Intrusion Detection System (NIDS)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                           # Run with default config
  python main.py --config custom.yaml     # Run with custom config
  python main.py --dashboard              # Show dashboard
  python main.py --export alerts.csv      # Export alerts to CSV
        """
    )
    
    parser.add_argument(
        '--config',
        type=str,
        default=None,
        help='Path to configuration file'
    )
    parser.add_argument(
        '--dashboard',
        action='store_true',
        help='Display dashboard (one-time)'
    )
    parser.add_argument(
        '--export',
        type=str,
        default=None,
        help='Export alerts to CSV file'
    )
    parser.add_argument(
        '--version',
        action='version',
        version='%(prog)s 1.0.0'
    )
    
    args = parser.parse_args()
    
    # Initialize application
    app = NISSApplication(config_path=args.config)
    
    # Handle special modes
    if args.dashboard:
        app.show_dashboard()
        sys.exit(0)
    
    if args.export:
        app.export_alerts_csv(args.export)
        app.stop()
        sys.exit(0)
    
    # Start normal operation
    try:
        app.start()
    except Exception as e:
        print(f"[!] Fatal error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
