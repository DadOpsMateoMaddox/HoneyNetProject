#!/usr/bin/env python3
"""
CerberusMesh Integrations Package

This package provides optional integrations for:
- Splunk SIEM integration
- Nessus vulnerability scanner integration  
- SQL database support (MariaDB, PostgreSQL, MySQL)
- Grafana-style dashboard UI
"""

from .splunk_integration import SplunkIntegration
from .nessus_integration import NessusIntegration
from .database_integration import DatabaseIntegration
from .grafana_ui import GrafanaUIIntegration

__all__ = [
    'SplunkIntegration',
    'NessusIntegration', 
    'DatabaseIntegration',
    'GrafanaUIIntegration'
]

# Integration registry with configuration examples
AVAILABLE_INTEGRATIONS = {
    'splunk': {
        'class': SplunkIntegration,
        'description': 'Splunk SIEM integration with HEC forwarding and SPL queries',
        'config_example': {
            'hec_url': 'https://splunk.example.com:8088/services/collector',
            'hec_token': 'your-hec-token-here',
            'index': 'cerberusmesh',
            'verify_ssl': True,
            'batch_size': 100,
            'flush_interval': 30
        }
    },
    'nessus': {
        'class': NessusIntegration,
        'description': 'Nessus vulnerability scanner integration with automated scanning',
        'config_example': {
            'server_url': 'https://nessus.example.com:8834',
            'access_key': 'your-access-key',
            'secret_key': 'your-secret-key',
            'verify_ssl': True,
            'scan_templates': ['basic', 'discovery', 'web_app'],
            'auto_scan_interval': 3600
        }
    },
    'database': {
        'class': DatabaseIntegration,
        'description': 'Multi-database support for MariaDB, PostgreSQL, MySQL, SQLite',
        'config_examples': {
            'mysql': {
                'db_type': 'mysql',
                'host': 'mysql.example.com',
                'port': 3306,
                'database': 'cerberusmesh',
                'username': 'cerberus',
                'password': 'secure_password',
                'ssl_enabled': True,
                'pool_size': 10
            },
            'postgresql': {
                'db_type': 'postgresql',
                'host': 'postgres.example.com',
                'port': 5432,
                'database': 'cerberusmesh',
                'username': 'cerberus',
                'password': 'secure_password',
                'ssl_enabled': True,
                'pool_size': 10
            },
            'sqlite': {
                'db_type': 'sqlite',
                'sqlite_path': '/var/lib/cerberusmesh/cerberusmesh.db'
            }
        }
    },
    'grafana_ui': {
        'class': GrafanaUIIntegration,
        'description': 'Grafana-style dashboard UI with real-time monitoring',
        'config_example': {
            'host': '0.0.0.0',
            'port': 3000,
            'enable_websocket': True,
            'refresh_interval': 5,
            'theme': 'dark',
            'enable_alerts': True
        }
    }
}

def get_integration(integration_name: str, config: dict = None):
    """Factory function to create integration instances."""
    if integration_name not in AVAILABLE_INTEGRATIONS:
        raise ValueError(f"Unknown integration: {integration_name}")
    
    integration_info = AVAILABLE_INTEGRATIONS[integration_name]
    return integration_info['class'](config or {})

def list_integrations():
    """List all available integrations."""
    return {name: info['description'] for name, info in AVAILABLE_INTEGRATIONS.items()}

def get_config_example(integration_name: str):
    """Get configuration example for an integration."""
    if integration_name not in AVAILABLE_INTEGRATIONS:
        return None
    
    integration_info = AVAILABLE_INTEGRATIONS[integration_name]
    return integration_info.get('config_example') or integration_info.get('config_examples')
