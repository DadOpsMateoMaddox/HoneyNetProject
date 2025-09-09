"""
CerberusMesh Configuration Management

This module handles all configuration loading from environment variables
and .env files, providing secure secrets management.
"""

import os
from pathlib import Path
from typing import Dict, Any, Optional
from dotenv import load_dotenv
import logging

logger = logging.getLogger(__name__)

class ConfigManager:
    """Centralized configuration management with secure secrets handling."""

    def __init__(self, env_file: Optional[str] = None):
        """Initialize configuration manager.

        Args:
            env_file: Path to .env file (defaults to .env in project root)
        """
        self.env_file = env_file or Path(__file__).parent.parent / '.env'
        self._load_environment()

    def _load_environment(self):
        """Load environment variables from .env file if it exists."""
        if self.env_file.exists():
            load_dotenv(self.env_file)
            logger.info(f"Loaded environment from {self.env_file}")
        else:
            logger.warning(f"Environment file {self.env_file} not found")

    def get_aws_config(self) -> Dict[str, str]:
        """Get AWS configuration with validation."""
        config = {
            'aws_access_key_id': os.getenv('AWS_ACCESS_KEY_ID'),
            'aws_secret_access_key': os.getenv('AWS_SECRET_ACCESS_KEY'),
            'aws_default_region': os.getenv('AWS_DEFAULT_REGION', 'us-east-1'),
            'aws_session_token': os.getenv('AWS_SESSION_TOKEN')
        }

        # Validate required AWS credentials
        if not config['aws_access_key_id'] or not config['aws_secret_access_key']:
            raise ValueError("AWS credentials not found. Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY")

        return {k: v for k, v in config.items() if v is not None}

    def get_openai_config(self) -> Dict[str, str]:
        """Get OpenAI configuration."""
        api_key = os.getenv('OPENAI_API_KEY')
        if not api_key:
            raise ValueError("OpenAI API key not found. Set OPENAI_API_KEY")

        return {
            'api_key': api_key,
            'model': os.getenv('OPENAI_MODEL', 'gpt-4'),
            'max_tokens': int(os.getenv('OPENAI_MAX_TOKENS', '1000'))
        }

    def get_redis_config(self) -> Dict[str, Any]:
        """Get Redis configuration."""
        return {
            'host': os.getenv('REDIS_HOST', 'localhost'),
            'port': int(os.getenv('REDIS_PORT', '6379')),
            'db': int(os.getenv('REDIS_DB', '0')),
            'password': os.getenv('REDIS_PASSWORD'),
            'ssl': os.getenv('REDIS_SSL', 'false').lower() == 'true'
        }

    def get_database_config(self) -> Dict[str, str]:
        """Get database configuration."""
        return {
            'url': os.getenv('DATABASE_URL', 'sqlite:///data/cerberusmesh.db'),
            'pool_size': int(os.getenv('DB_POOL_SIZE', '10')),
            'max_overflow': int(os.getenv('DB_MAX_OVERFLOW', '20'))
        }

    def get_security_config(self) -> Dict[str, Any]:
        """Get security-related configuration."""
        return {
            'encryption_key': os.getenv('ENCRYPTION_KEY'),
            'jwt_secret': os.getenv('JWT_SECRET'),
            'api_key': os.getenv('API_KEY'),
            'allowed_ips': os.getenv('ALLOWED_IPS', '').split(',') if os.getenv('ALLOWED_IPS') else [],
            'rate_limit': int(os.getenv('RATE_LIMIT', '100'))
        }

    def get_monitoring_config(self) -> Dict[str, Any]:
        """Get monitoring and logging configuration."""
        return {
            'log_level': os.getenv('LOG_LEVEL', 'INFO'),
            'log_file': os.getenv('LOG_FILE', 'logs/cerberusmesh.log'),
            'metrics_enabled': os.getenv('METRICS_ENABLED', 'true').lower() == 'true',
            'prometheus_port': int(os.getenv('PROMETHEUS_PORT', '9090'))
        }

    def get_all_config(self) -> Dict[str, Any]:
        """Get complete configuration dictionary."""
        return {
            'aws': self.get_aws_config(),
            'openai': self.get_openai_config(),
            'redis': self.get_redis_config(),
            'database': self.get_database_config(),
            'security': self.get_security_config(),
            'monitoring': self.get_monitoring_config(),
            'environment': os.getenv('CERBERUSMESH_ENV', 'development'),
            'debug': os.getenv('DEBUG', 'false').lower() == 'true'
        }

# Global configuration instance
config_manager = ConfigManager()

def get_config() -> Dict[str, Any]:
    """Get the global configuration."""
    return config_manager.get_all_config()

def validate_config(config: Dict[str, Any]) -> bool:
    """Validate configuration completeness."""
    required_keys = ['aws', 'openai', 'redis', 'database']

    for key in required_keys:
        if key not in config:
            logger.error(f"Missing required configuration section: {key}")
            return False

    # Validate AWS
    aws_config = config.get('aws', {})
    if not aws_config.get('aws_access_key_id') or not aws_config.get('aws_secret_access_key'):
        logger.error("AWS credentials missing")
        return False

    # Validate OpenAI
    openai_config = config.get('openai', {})
    if not openai_config.get('api_key'):
        logger.error("OpenAI API key missing")
        return False

    logger.info("Configuration validation successful")
    return True
