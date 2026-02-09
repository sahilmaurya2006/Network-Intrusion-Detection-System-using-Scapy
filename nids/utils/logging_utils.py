# nids/utils/logging_utils.py
"""
Logging configuration module.
Sets up structured logging with JSON output support.
"""

import logging
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any


class JSONFormatter(logging.Formatter):
    """
    Custom JSON formatter for structured logging.
    Converts log records to JSON format for easy parsing and analysis.
    """
    
    def format(self, record: logging.LogRecord) -> str:
        """
        Format log record as JSON.
        
        Args:
            record: Log record to format
            
        Returns:
            JSON formatted log message
        """
        log_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
        }
        
        # Add exception information if present
        if record.exc_info:
            log_data['exception'] = self.formatException(record.exc_info)
        
        # Add custom fields if present
        if hasattr(record, 'extra_fields'):
            log_data.update(record.extra_fields)
        
        return json.dumps(log_data)


class StructuredLogger:
    """
    Structured logging utility for NIDS alerts and events.
    Provides consistent logging across the application.
    """
    
    def __init__(
        self,
        name: str,
        log_file: Optional[Path] = None,
        log_level: str = "INFO",
        console_output: bool = True
    ):
        """
        Initialize structured logger.
        
        Args:
            name: Logger name
            log_file: Path to log file (if None, only console output)
            log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            console_output: Whether to output to console
        """
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, log_level.upper()))
        
        # Remove default handlers
        self.logger.handlers = []
        
        # Console handler
        if console_output:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setFormatter(
                logging.Formatter(
                    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
                )
            )
            self.logger.addHandler(console_handler)
        
        # File handler (JSON format)
        if log_file:
            log_file.parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(JSONFormatter())
            self.logger.addHandler(file_handler)
    
    def log_alert(
        self,
        alert_type: str,
        severity: str,
        message: str,
        source_ip: Optional[str] = None,
        dest_ip: Optional[str] = None,
        **kwargs
    ) -> None:
        """
        Log a security alert with structured data.
        
        Args:
            alert_type: Type of alert (e.g., "ICMP_FLOOD", "SYN_SCAN")
            severity: Alert severity (LOW, MEDIUM, HIGH, CRITICAL)
            message: Alert message
            source_ip: Source IP address
            dest_ip: Destination IP address
            **kwargs: Additional custom fields
        """
        extra_data = {
            'alert_type': alert_type,
            'severity': severity,
            'source_ip': source_ip,
            'dest_ip': dest_ip,
        }
        extra_data.update(kwargs)
        
        record = self.logger.makeRecord(
            self.logger.name,
            logging.WARNING,
            "(unknown file)",
            0,
            message,
            (),
            None,
            func=None
        )
        record.extra_fields = extra_data
        self.logger.handle(record)
    
    def info(self, message: str, **kwargs) -> None:
        """Log info message with extra fields."""
        record = self.logger.makeRecord(
            self.logger.name,
            logging.INFO,
            "(unknown file)",
            0,
            message,
            (),
            None,
            func=None
        )
        if kwargs:
            record.extra_fields = kwargs
        self.logger.handle(record)
    
    def error(self, message: str, **kwargs) -> None:
        """Log error message with extra fields."""
        record = self.logger.makeRecord(
            self.logger.name,
            logging.ERROR,
            "(unknown file)",
            0,
            message,
            (),
            None,
            func=None
        )
        if kwargs:
            record.extra_fields = kwargs
        self.logger.handle(record)
    
    def debug(self, message: str, **kwargs) -> None:
        """Log debug message with extra fields."""
        record = self.logger.makeRecord(
            self.logger.name,
            logging.DEBUG,
            "(unknown file)",
            0,
            message,
            (),
            None,
            func=None
        )
        if kwargs:
            record.extra_fields = kwargs
        self.logger.handle(record)


def setup_logger(
    name: str,
    log_file: Optional[Path] = None,
    log_level: str = "INFO"
) -> logging.Logger:
    """
    Quick setup function for standard logger.
    
    Args:
        name: Logger name
        log_file: Optional log file path
        log_level: Logging level
        
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, log_level.upper()))
    
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    
    return logger
