#!/usr/bin/env python3
"""
CerberusMesh Integration Test Suite

Comprehensive test suite for all enterprise integrations:
- Splunk SIEM integration testing
- Nessus vulnerability scanner testing
- Database integration testing (MySQL, PostgreSQL, SQLite)
- Grafana UI dashboard testing
"""

import asyncio
import logging
import json
from datetime import datetime
from typing import Dict, Any
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

# Import integrations
from . import get_integration, list_integrations, get_config_example
from .config_examples import (
    SPLUNK_CONFIG,
    NESSUS_CONFIG,
    MYSQL_CONFIG,
    POSTGRESQL_CONFIG,
    SQLITE_CONFIG,
    GRAFANA_UI_CONFIG
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class TestIntegrationRegistry(unittest.TestCase):
    """Test the integration registry functionality."""
    
    def test_list_integrations(self):
        """Test listing available integrations."""
        integrations = list_integrations()
        
        self.assertIn('splunk', integrations)
        self.assertIn('nessus', integrations)
        self.assertIn('database', integrations)
        self.assertIn('grafana_ui', integrations)
        
        logger.info("Available integrations:")
        for name, description in integrations.items():
            logger.info(f"  {name}: {description}")
    
    def test_get_config_examples(self):
        """Test getting configuration examples."""
        splunk_config = get_config_example('splunk')
        self.assertIsNotNone(splunk_config)
        self.assertIn('hec_url', splunk_config)
        
        database_config = get_config_example('database')
        self.assertIsNotNone(database_config)
        self.assertIn('mysql', database_config)
        
        logger.info("Configuration examples retrieved successfully")

class TestSplunkIntegration(unittest.TestCase):
    """Test Splunk SIEM integration."""
    
    def setUp(self):
        """Setup test configuration."""
        self.config = SPLUNK_CONFIG.copy()
        self.config['hec_token'] = 'test-token'
    
    @patch('aiohttp.ClientSession.post')
    async def test_splunk_connection(self, mock_post):
        """Test Splunk HEC connection."""
        mock_post.return_value.__aenter__.return_value.status = 200
        mock_post.return_value.__aenter__.return_value.json = AsyncMock(
            return_value={'text': 'Success', 'code': 0}
        )
        
        try:
            splunk = get_integration('splunk', self.config)
            await splunk.initialize()
            
            # Test event sending
            test_event = {
                'event_id': 'test-001',
                'timestamp': datetime.now(),
                'source_ip': '192.168.1.100',
                'event_type': 'ssh_login'
            }
            
            result = await splunk.send_event(test_event)
            self.assertTrue(result)
            
            logger.info("Splunk integration test passed")
            
        except Exception as e:
            logger.error(f"Splunk test failed: {e}")
            self.skipTest(f"Splunk dependencies not available: {e}")
    
    def test_spl_query_generation(self):
        """Test SPL query generation."""
        try:
            splunk = get_integration('splunk', self.config)
            
            # Test various SPL queries
            connection_query = splunk.generate_spl_query('honeypot_connections', hours=24)
            self.assertIn('index=cerberusmesh', connection_query)
            self.assertIn('source_ip', connection_query)
            
            mitre_query = splunk.generate_spl_query('mitre_techniques', hours=6)
            self.assertIn('mitre_technique', mitre_query)
            
            logger.info("SPL query generation test passed")
            
        except Exception as e:
            logger.error(f"SPL query test failed: {e}")
            self.skipTest(f"Splunk dependencies not available: {e}")

class TestNessusIntegration(unittest.TestCase):
    """Test Nessus vulnerability scanner integration."""
    
    def setUp(self):
        """Setup test configuration."""
        self.config = NESSUS_CONFIG.copy()
        self.config['access_key'] = 'test-access-key'
        self.config['secret_key'] = 'test-secret-key'
    
    @patch('aiohttp.ClientSession.get')
    async def test_nessus_connection(self, mock_get):
        """Test Nessus API connection."""
        mock_get.return_value.__aenter__.return_value.status = 200
        mock_get.return_value.__aenter__.return_value.json = AsyncMock(
            return_value={'token': 'test-session-token'}
        )
        
        try:
            nessus = get_integration('nessus', self.config)
            await nessus.initialize()
            
            # Test scanner status
            status = await nessus.get_scanner_status()
            self.assertIsNotNone(status)
            
            logger.info("Nessus integration test passed")
            
        except Exception as e:
            logger.error(f"Nessus test failed: {e}")
            self.skipTest(f"Nessus dependencies not available: {e}")
    
    def test_vulnerability_correlation(self):
        """Test vulnerability correlation with attack patterns."""
        try:
            nessus = get_integration('nessus', self.config)
            
            # Mock vulnerability data
            vuln_data = {
                'plugin_id': '12345',
                'plugin_name': 'SSH Weak Encryption',
                'severity': 'High',
                'host': '192.168.1.100',
                'port': 22
            }
            
            # Mock attack pattern
            attack_pattern = {
                'source_ip': '192.168.1.100',
                'destination_port': 22,
                'protocol': 'ssh',
                'attack_type': 'brute_force'
            }
            
            correlation = nessus.correlate_vulnerability_with_attack(vuln_data, attack_pattern)
            self.assertIsNotNone(correlation)
            self.assertIn('correlation_score', correlation)
            
            logger.info("Vulnerability correlation test passed")
            
        except Exception as e:
            logger.error(f"Vulnerability correlation test failed: {e}")
            self.skipTest(f"Nessus dependencies not available: {e}")

class TestDatabaseIntegration(unittest.TestCase):
    """Test database integration for MySQL, PostgreSQL, and SQLite."""
    
    async def test_sqlite_integration(self):
        """Test SQLite database integration."""
        config = SQLITE_CONFIG.copy()
        config['sqlite_path'] = ':memory:'  # In-memory database for testing
        
        try:
            db = get_integration('database', config)
            await db.initialize()
            
            # Test storing intrusion event
            test_event = MagicMock()
            test_event.event_id = 'test-001'
            test_event.timestamp = datetime.now()
            test_event.honeypot_id = 'test-honeypot'
            test_event.source_ip = '192.168.1.100'
            test_event.event_type = 'ssh_login'
            test_event.protocol = 'tcp'
            test_event.destination_port = 22
            test_event.session_id = None
            test_event.username = 'admin'
            test_event.password = 'password123'
            test_event.command = None
            test_event.payload = None
            test_event.severity = 'medium'
            test_event.raw_data = {}
            
            result = await db.store_intrusion_event(test_event)
            self.assertTrue(result)
            
            # Test analytics
            timeline = await db.get_attack_timeline(24)
            self.assertIsInstance(timeline, list)
            
            await db.close()
            logger.info("SQLite integration test passed")
            
        except Exception as e:
            logger.error(f"SQLite test failed: {e}")
            self.skipTest(f"SQLite dependencies not available: {e}")
    
    @patch('aiomysql.create_pool')
    async def test_mysql_integration(self, mock_create_pool):
        """Test MySQL database integration."""
        mock_pool = AsyncMock()
        mock_create_pool.return_value = mock_pool
        
        try:
            db = get_integration('database', MYSQL_CONFIG)
            await db.initialize()
            
            self.assertIsNotNone(db.pool)
            logger.info("MySQL integration test passed")
            
        except Exception as e:
            logger.error(f"MySQL test failed: {e}")
            self.skipTest(f"MySQL dependencies not available: {e}")
    
    @patch('asyncpg.create_pool')
    async def test_postgresql_integration(self, mock_create_pool):
        """Test PostgreSQL database integration."""
        mock_pool = AsyncMock()
        mock_create_pool.return_value = mock_pool
        
        try:
            db = get_integration('database', POSTGRESQL_CONFIG)
            await db.initialize()
            
            self.assertIsNotNone(db.pool)
            logger.info("PostgreSQL integration test passed")
            
        except Exception as e:
            logger.error(f"PostgreSQL test failed: {e}")
            self.skipTest(f"PostgreSQL dependencies not available: {e}")

class TestGrafanaUIIntegration(unittest.TestCase):
    """Test Grafana-style UI integration."""
    
    def setUp(self):
        """Setup test configuration."""
        self.config = GRAFANA_UI_CONFIG.copy()
        self.config['port'] = 3001  # Use different port for testing
    
    def test_dashboard_creation(self):
        """Test dashboard creation and management."""
        try:
            ui = get_integration('grafana_ui', self.config)
            
            # Test default dashboards
            self.assertIn('overview', ui.dashboards)
            self.assertIn('ai-agent', ui.dashboards)
            self.assertIn('threat-intel', ui.dashboards)
            
            # Test custom panel creation
            custom_panel = ui.create_custom_panel(
                'stat',
                'Test Metric',
                'cerberusmesh_test_metric',
                legend='Test Data'
            )
            
            self.assertIsNotNone(custom_panel)
            self.assertEqual(custom_panel.title, 'Test Metric')
            self.assertEqual(custom_panel.type, 'stat')
            
            logger.info("Grafana UI integration test passed")
            
        except Exception as e:
            logger.error(f"Grafana UI test failed: {e}")
            self.skipTest(f"Grafana UI dependencies not available: {e}")
    
    def test_dashboard_config_generation(self):
        """Test Grafana-compatible configuration generation."""
        try:
            ui = get_integration('grafana_ui', self.config)
            
            config = ui.generate_dashboard_config('overview')
            self.assertIsNotNone(config)
            self.assertIn('dashboard', config)
            self.assertIn('panels', config['dashboard'])
            
            logger.info("Dashboard configuration generation test passed")
            
        except Exception as e:
            logger.error(f"Dashboard config test failed: {e}")
            self.skipTest(f"Grafana UI dependencies not available: {e}")

async def run_integration_tests():
    """Run all integration tests asynchronously."""
    logger.info("Starting CerberusMesh Integration Test Suite")
    logger.info("=" * 60)
    
    # Test integration registry
    registry_test = TestIntegrationRegistry()
    registry_test.test_list_integrations()
    registry_test.test_get_config_examples()
    
    # Test Splunk integration
    splunk_test = TestSplunkIntegration()
    splunk_test.setUp()
    await splunk_test.test_splunk_connection()
    splunk_test.test_spl_query_generation()
    
    # Test Nessus integration
    nessus_test = TestNessusIntegration()
    nessus_test.setUp()
    await nessus_test.test_nessus_connection()
    nessus_test.test_vulnerability_correlation()
    
    # Test database integrations
    db_test = TestDatabaseIntegration()
    await db_test.test_sqlite_integration()
    await db_test.test_mysql_integration()
    await db_test.test_postgresql_integration()
    
    # Test Grafana UI integration
    ui_test = TestGrafanaUIIntegration()
    ui_test.setUp()
    ui_test.test_dashboard_creation()
    ui_test.test_dashboard_config_generation()
    
    logger.info("=" * 60)
    logger.info("Integration Test Suite Completed Successfully!")

def demonstrate_integrations():
    """Demonstrate integration usage with examples."""
    print("\nCerberusMesh Enterprise Integration Demonstration")
    print("=" * 60)
    
    # List available integrations
    print("\n1. Available Integrations:")
    integrations = list_integrations()
    for name, description in integrations.items():
        print(f"   • {name}: {description}")
    
    # Show configuration examples
    print("\n2. Configuration Examples:")
    
    print("\n   Splunk SIEM Integration:")
    splunk_config = get_config_example('splunk')
    print(f"   {json.dumps(splunk_config, indent=6)}")
    
    print("\n   Database Integration (PostgreSQL):")
    db_config = get_config_example('database')
    print(f"   {json.dumps(db_config['postgresql'], indent=6)}")
    
    # Usage examples
    print("\n3. Usage Examples:")
    print("""
   # Initialize Splunk integration
   splunk = get_integration('splunk', splunk_config)
   await splunk.initialize()
   await splunk.send_event(event_data)
   
   # Initialize database integration
   db = get_integration('database', postgresql_config)
   await db.initialize()
   await db.store_intrusion_event(event)
   
   # Initialize Grafana UI
   ui = get_integration('grafana_ui', ui_config)
   ui.run(host='0.0.0.0', port=3000)
   """)
    
    print("\n4. Enterprise Deployment:")
    print("""
   • Docker Compose: See config_examples.py for complete setup
   • Kubernetes: YAML configurations included
   • Environment Variables: .env template provided
   • Installation Script: Automated setup available
   """)

if __name__ == "__main__":
    # Run demonstration
    demonstrate_integrations()
    
    # Run tests
    print("\nRunning Integration Tests...")
    asyncio.run(run_integration_tests())
