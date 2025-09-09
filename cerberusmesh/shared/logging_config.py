"""
CerberusMesh Logging Configuration

Centralized logging setup with support for multiple handlers:
- Console logging for development
- File logging with rotation
- Optional ELK stack integration
"""

import os
import logging
import logging.handlers
from pathlib import Path
from typing import Dict, Any

def setup_logging(
    log_level: str = "INFO",
    log_file: str = "logs/cerberusmesh.log",
    max_bytes: int = 10 * 1024 * 1024,  # 10MB
    backup_count: int = 5,
    elk_enabled: bool = False,
    elk_host: str = "localhost",
    elk_port: int = 9200
) -> logging.Logger:
    """Setup comprehensive logging configuration.

    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Path to log file
        max_bytes: Maximum log file size before rotation
        backup_count: Number of backup files to keep
        elk_enabled: Whether to enable ELK stack logging
        elk_host: ELK stack host
        elk_port: ELK stack port

    Returns:
        Configured logger instance
    """

    # Create logs directory if it doesn't exist
    log_path = Path(log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    # Create logger
    logger = logging.getLogger('cerberusmesh')
    logger.setLevel(getattr(logging, log_level.upper()))

    # Remove existing handlers to avoid duplicates
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)

    # Create formatters
    detailed_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
    )

    simple_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s'
    )

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(simple_formatter)
    logger.addHandler(console_handler)

    # File handler with rotation
    file_handler = logging.handlers.RotatingFileHandler(
        log_file,
        maxBytes=max_bytes,
        backupCount=backup_count
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(detailed_formatter)
    logger.addHandler(file_handler)

    # Security-specific logger for sensitive events
    security_logger = logging.getLogger(SECURITY_LOGGER_NAME)
    security_file = log_path.parent / 'security.log'
    security_handler = logging.handlers.RotatingFileHandler(
        str(security_file),
        maxBytes=max_bytes,
        backupCount=backup_count
    )
    security_handler.setLevel(logging.WARNING)
    security_handler.setFormatter(detailed_formatter)
    security_logger.addHandler(security_handler)
    security_logger.propagate = False

    # ELK stack handler (optional)
    if elk_enabled:
        try:
            from elasticsearch import Elasticsearch
            from logging.handlers import QueueHandler
            import queue

            # Create ELK handler
            elk_handler = logging.handlers.QueueHandler(queue.Queue())
            elk_handler.setLevel(logging.INFO)
            logger.addHandler(elk_handler)

            # Note: In production, you'd want to properly configure
            # the Elasticsearch handler with proper formatting
            logger.info(f"ELK logging enabled for {elk_host}:{elk_port}")

        except ImportError:
            logger.warning("Elasticsearch not available for ELK logging")

    # Log startup message
    logger.info("CerberusMesh logging initialized")
    logger.info(f"Log level: {log_level}")
    logger.info(f"Log file: {log_file}")

    return logger

SECURITY_LOGGER_NAME = 'cerberusmesh.security'

def get_security_logger() -> logging.Logger:
    """Get the security-specific logger."""
    return logging.getLogger(SECURITY_LOGGER_NAME)

def log_security_event(
    event_type: str,
    message: str,
    source_ip: str = None,
    user_agent: str = None,
    **kwargs
):
    """Log a security event with structured data."""
    security_logger = get_security_logger()

    # Build structured log message
    log_data = {
        'event_type': event_type,
        'message': message,
        'source_ip': source_ip,
        'user_agent': user_agent,
        **kwargs
    }

    # Remove None values
    log_data = {k: v for k, v in log_data.items() if v is not None}

    security_logger.warning(f"SECURITY EVENT: {log_data}")

class SecurityFilter(logging.Filter):
    """Filter for security-related log messages."""

    def filter(self, record):
        # Add custom filtering logic here
        # For example, filter out sensitive information
        if hasattr(record, 'msg') and 'password' in str(record.msg).lower():
            record.msg = "[FILTERED SENSITIVE DATA]"
        return True

# Add security filter to all loggers
security_filter = SecurityFilter()
logging.getLogger('cerberusmesh').addFilter(security_filter)
logging.getLogger('cerberusmesh.security').addFilter(security_filter)
