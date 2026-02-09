# nids/alerts/email_alert.py
"""
Email alert handler.
Sends alerts via SMTP (Gmail, Office365, custom SMTP servers).
"""

import smtplib
import logging
import os
from typing import Optional, List
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

from nids.core.rules import DetectionAlert
from nids.alerts.alert_base import AlertHandler

logger = logging.getLogger(__name__)


class EmailAlertHandler(AlertHandler):
    """
    Email alert handler.
    
    Features:
    - SMTP/TLS support
    - Multiple recipients
    - HTML formatted emails
    - Graceful error handling
    - Optional alert batching
    """
    
    def __init__(
        self,
        smtp_server: str,
        smtp_port: int = 587,
        sender_email: str = "",
        sender_password: str = "",
        recipients: Optional[List[str]] = None,
        use_tls: bool = True,
        enabled: bool = False,
        alert_severity_threshold: str = "HIGH"
    ):
        """
        Initialize email alert handler.
        
        Args:
            smtp_server: SMTP server address
            smtp_port: SMTP port
            sender_email: Sender email address
            sender_password: Sender password (use env vars for security!)
            recipients: List of recipient email addresses
            use_tls: Whether to use TLS encryption
            enabled: Whether handler is active
            alert_severity_threshold: Only send emails for this severity or higher
        """
        super().__init__(enabled)
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.sender_email = sender_email
        self.sender_password = sender_password
        self.recipients = recipients or []
        self.use_tls = use_tls
        self.severity_order = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        self.alert_severity_threshold = alert_severity_threshold
        self.min_severity_index = self.severity_order.index(alert_severity_threshold)
        
        # Validate configuration
        if self.enabled:
            self._validate_config()
    
    def _validate_config(self) -> None:
        """
        Validate email configuration.
        
        Raises:
            ValueError: If configuration is invalid
        """
        if not self.smtp_server:
            raise ValueError("SMTP server not configured")
        if not self.sender_email:
            raise ValueError("Sender email not configured")
        if not self.sender_password:
            raise ValueError("Sender password not configured")
        if not self.recipients:
            raise ValueError("No recipients configured")
    
    def handle_alert(self, alert: DetectionAlert) -> bool:
        """
        Send alert via email.
        
        Args:
            alert: DetectionAlert object
            
        Returns:
            True if email sent successfully
        """
        # Check severity threshold
        try:
            alert_index = self.severity_order.index(alert.severity)
            if alert_index < self.min_severity_index:
                logger.debug(
                    f"Alert severity {alert.severity} below threshold "
                    f"{self.alert_severity_threshold}"
                )
                return True  # Don't count as failure
        except ValueError:
            logger.warning(f"Unknown alert severity: {alert.severity}")
            return False
        
        try:
            # Create email message
            msg = self._create_email_message(alert)
            
            # Send email
            self._send_email(msg)
            
            logger.info(f"Alert email sent for {alert.rule_name}")
            return True
        
        except Exception as e:
            logger.error(f"Failed to send alert email: {e}")
            return False
    
    def _create_email_message(self, alert: DetectionAlert) -> MIMEMultipart:
        """
        Create formatted email message.
        
        Args:
            alert: DetectionAlert object
            
        Returns:
            MIMEMultipart message object
        """
        msg = MIMEMultipart('alternative')
        msg['Subject'] = f"[NIDS ALERT] {alert.severity}: {alert.rule_name}"
        msg['From'] = self.sender_email
        msg['To'] = ", ".join(self.recipients)
        msg['Date'] = datetime.now().strftime('%a, %d %b %Y %H:%M:%S %z')
        
        # Create plain text version
        text_body = self._format_text_email(alert)
        
        # Create HTML version
        html_body = self._format_html_email(alert)
        
        # Attach both versions
        msg.attach(MIMEText(text_body, 'plain'))
        msg.attach(MIMEText(html_body, 'html'))
        
        return msg
    
    def _format_text_email(self, alert: DetectionAlert) -> str:
        """Format alert as plain text email."""
        lines = [
            f"Network Intrusion Detection System Alert",
            f"Severity: {alert.severity}",
            f"Rule: {alert.rule_name}",
            f"Type: {alert.rule_type}",
            f"",
            f"Message:",
            f"  {alert.message}",
            f"",
            f"Network Details:",
            f"  Source IP: {alert.src_ip}",
            f"  Dest IP: {alert.dst_ip}",
        ]
        
        if alert.src_port:
            lines.append(f"  Source Port: {alert.src_port}")
        if alert.dst_port:
            lines.append(f"  Dest Port: {alert.dst_port}")
        
        lines.extend([
            f"",
            f"Detection Statistics:",
            f"  Threshold: {alert.threshold}",
            f"  Matched Value: {alert.matched_value}",
            f"  Packet Count: {alert.packet_count}",
            f"",
            f"Timestamp: {datetime.fromtimestamp(alert.timestamp).isoformat()}",
            f"",
            f"Alert ID: {id(alert)}",
        ])
        
        if alert.additional_info:
            lines.append(f"")
            lines.append(f"Additional Information:")
            for key, value in alert.additional_info.items():
                lines.append(f"  {key}: {value}")
        
        return "\n".join(lines)
    
    def _format_html_email(self, alert: DetectionAlert) -> str:
        """Format alert as HTML email."""
        severity_color = {
            'CRITICAL': '#FF0000',
            'HIGH': '#FF9900',
            'MEDIUM': '#0066FF',
            'LOW': '#00AA00',
        }.get(alert.severity, '#000000')
        
        html = f"""
        <html>
            <head>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; }}
                    .alert-container {{ border: 2px solid {severity_color}; padding: 15px; border-radius: 5px; }}
                    .alert-header {{ background-color: {severity_color}; color: white; padding: 10px; margin: -15px -15px 15px -15px; border-radius: 3px 3px 0 0; }}
                    .severity {{ font-size: 18px; font-weight: bold; }}
                    .section-title {{ font-weight: bold; margin-top: 15px; margin-bottom: 5px; color: {severity_color}; }}
                    .info-row {{ margin: 5px 0; padding: 5px; }}
                    .label {{ font-weight: bold; color: #333; }}
                    .details {{ background-color: #f5f5f5; padding: 10px; border-radius: 3px; margin-top: 10px; }}
                    code {{ background-color: #f0f0f0; padding: 2px 5px; border-radius: 3px; }}
                </style>
            </head>
            <body>
                <div class="alert-container">
                    <div class="alert-header">
                        <span class="severity">⚠️  {alert.severity}: {alert.rule_name}</span>
                    </div>
                    
                    <div class="info-row">
                        <p>{alert.message}</p>
                    </div>
                    
                    <div class="section-title">Network Details:</div>
                    <div class="info-row">
                        <span class="label">Source IP:</span> <code>{alert.src_ip}</code>
                    </div>
                    <div class="info-row">
                        <span class="label">Destination IP:</span> <code>{alert.dst_ip}</code>
                    </div>
                    {f'<div class="info-row"><span class="label">Source Port:</span> {alert.src_port}</div>' if alert.src_port else ''}
                    {f'<div class="info-row"><span class="label">Dest Port:</span> {alert.dst_port}</div>' if alert.dst_port else ''}
                    
                    <div class="section-title">Detection Statistics:</div>
                    <div class="details">
                        <div class="info-row">
                            <span class="label">Alert Type:</span> {alert.rule_type}
                        </div>
                        <div class="info-row">
                            <span class="label">Threshold:</span> {alert.threshold}
                        </div>
                        <div class="info-row">
                            <span class="label">Matched Value:</span> <strong>{alert.matched_value}</strong>
                        </div>
                        <div class="info-row">
                            <span class="label">Packet Count:</span> {alert.packet_count}
                        </div>
                    </div>
                    
                    <div class="info-row">
                        <span class="label">Time:</span> {datetime.fromtimestamp(alert.timestamp).isoformat()}
                    </div>
                    
                    {self._format_html_additional_info(alert.additional_info) if alert.additional_info else ''}
                </div>
            </body>
        </html>
        """
        return html
    
    @staticmethod
    def _format_html_additional_info(info: dict) -> str:
        """Format additional info as HTML."""
        if not info:
            return ""
        
        lines = ['<div class="section-title">Additional Information:</div>']
        for key, value in info.items():
            if isinstance(value, list):
                lines.append(f'<div class="info-row"><span class="label">{key}:</span>')
                for item in value[:5]:
                    lines.append(f'  • {item}<br>')
                if len(value) > 5:
                    lines.append(f'  ... and {len(value) - 5} more<br>')
                lines.append('</div>')
            else:
                lines.append(f'<div class="info-row"><span class="label">{key}:</span> {value}</div>')
        
        return "\n".join(lines)
    
    def _send_email(self, msg: MIMEMultipart) -> None:
        """
        Send email via SMTP.
        
        Args:
            msg: MIMEMultipart message object
            
        Raises:
            smtplib.SMTPException: If email sending fails
        """
        try:
            # Create SMTP connection
            if self.use_tls:
                server = smtplib.SMTP(self.smtp_server, self.smtp_port)
                server.starttls()
            else:
                server = smtplib.SMTP_SSL(self.smtp_server, self.smtp_port)
            
            # Login
            server.login(self.sender_email, self.sender_password)
            
            # Send email
            server.send_message(msg)
            
            # Cleanup
            server.quit()
        
        except smtplib.SMTPAuthenticationError as e:
            raise ValueError(f"SMTP authentication failed: {e}")
        except smtplib.SMTPException as e:
            raise RuntimeError(f"SMTP error: {e}")
