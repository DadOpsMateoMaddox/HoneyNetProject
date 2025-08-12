#!/usr/bin/env python3
"""
CerberusMesh Cerberus Agent - Internal AI Watchdog Agent

This module implements an intelligent monitoring agent that:
- Watches for new intrusion events from honeypots
- Enriches events with MITRE ATT&CK context
- Uses GPT-4 to analyze suspicious behavior
- Makes autonomous defensive decisions
- Manages honeypot lifecycle and deception tactics
"""

import asyncio
import json
import logging
import os
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
import hashlib
import uuid

import redis
import boto3
import openai
from openai import OpenAI
from tqdm import tqdm
import schedule
from dotenv import load_dotenv

# Import shared modules
import sys
sys.path.append(str(Path(__file__).parent.parent))
from shared.mitre_mapper import MitreMapper, AttackMapping
from controller.main import HoneypotController

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('cerberus_agent.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class IntrusionEvent:
    """Structure for honeypot intrusion events."""
    event_id: str
    timestamp: datetime
    honeypot_id: str
    source_ip: str
    event_type: str
    protocol: str
    destination_port: int
    session_id: str
    username: Optional[str] = None
    password: Optional[str] = None
    command: Optional[str] = None
    payload: Optional[str] = None
    severity: str = "medium"
    raw_data: Optional[Dict[str, Any]] = None

@dataclass
class AgentDecision:
    """Structure for agent decisions and actions."""
    decision_id: str
    timestamp: datetime
    event_id: str
    decision_type: str  # rotate_key, launch_decoy, insert_trap, escalate, ignore
    confidence: float
    reasoning: str
    mitre_techniques: List[str]
    action_taken: bool
    result: Optional[str] = None
    execution_time: Optional[float] = None

@dataclass
class ThreatContext:
    """Enhanced threat context with MITRE and LLM analysis."""
    event: IntrusionEvent
    mitre_mapping: AttackMapping
    llm_analysis: Dict[str, Any]
    threat_score: float
    behavioral_patterns: List[str]
    recommendations: List[str]

class CerberusAgent:
    """Main Cerberus Agent - AI-powered honeypot watchdog."""
    
    def __init__(self, config: Optional[Dict] = None):
        """Initialize the Cerberus Agent."""
        self.config = config or self._load_config()
        
        # Initialize components
        self._init_clients()
        self._init_cache()
        self._init_components()
        
        # Agent state
        self.is_running = False
        self.event_queue = asyncio.Queue()
        self.decision_history = []
        self.threat_patterns = {}
        
        # Decision quotas and circuit breakers  
        self.decision_quotas = {
            "rotate_key": {"hourly": 5, "daily": 20},
            "launch_decoy": {"hourly": 3, "daily": 10}, 
            "insert_trap": {"hourly": 10, "daily": 50},
            "escalate": {"hourly": 5, "daily": 15}
        }
        
        # Per-CIDR quotas (max actions per /24 network per hour)
        self.cidr_quotas = {
            "rotate_key": 2,
            "launch_decoy": 1,
            "insert_trap": 5,
            "escalate": 3
        }
        
        # Performance metrics
        self.events_processed = 0
        self.decisions_made = 0
        self.actions_executed = 0
        
        logger.info("Cerberus Agent initialized successfully")
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from environment and defaults."""
        return {
            # LLM Configuration
            "openai_api_key": os.getenv("OPENAI_API_KEY"),
            "llm_model": os.getenv("CERBERUS_LLM_MODEL", "gpt-4"),
            "llm_temperature": float(os.getenv("CERBERUS_LLM_TEMP", "0.2")),
            
            # AWS Configuration
            "aws_region": os.getenv("AWS_DEFAULT_REGION", "us-east-1"),
            
            # Redis Configuration
            "redis_host": os.getenv("REDIS_HOST", "localhost"),
            "redis_port": int(os.getenv("REDIS_PORT", "6379")),
            "redis_db": int(os.getenv("REDIS_DB", "1")),
            
            # Agent Behavior
            "decision_threshold": float(os.getenv("CERBERUS_THRESHOLD", "0.7")),
            "max_events_per_minute": int(os.getenv("CERBERUS_MAX_EVENTS", "100")),
            "auto_action_enabled": os.getenv("CERBERUS_AUTO_ACTION", "true").lower() == "true",
            "decoy_launch_threshold": float(os.getenv("CERBERUS_DECOY_THRESHOLD", "0.8")),
            
            # Monitoring
            "event_sources": ["cowrie", "ssh", "web", "telnet"],
            "monitoring_interval": int(os.getenv("CERBERUS_MONITOR_INTERVAL", "5")),
            "cache_ttl": int(os.getenv("CERBERUS_CACHE_TTL", "3600")),
        }
    
    def _init_clients(self):
        """Initialize external service clients."""
        # OpenAI client
        if not self.config["openai_api_key"]:
            logger.warning("OpenAI API key not configured - LLM analysis disabled")
            self.llm_client = None
        else:
            self.llm_client = OpenAI(api_key=self.config["openai_api_key"])
        
        # AWS clients
        try:
            self.ec2_client = boto3.client('ec2', region_name=self.config["aws_region"])
            self.cloudwatch_client = boto3.client('cloudwatch', region_name=self.config["aws_region"])
            logger.info("AWS clients initialized")
        except Exception as e:
            logger.error(f"Failed to initialize AWS clients: {e}")
            self.ec2_client = None
            self.cloudwatch_client = None
    
    def _init_cache(self):
        """Initialize Redis cache connection."""
        try:
            self.redis_client = redis.Redis(
                host=self.config["redis_host"],
                port=self.config["redis_port"],
                db=self.config["redis_db"],
                decode_responses=True
            )
            # Test connection
            self.redis_client.ping()
            logger.info("Redis cache initialized")
        except Exception as e:
            logger.warning(f"Redis not available: {e} - using in-memory cache")
            self.redis_client = None
            self._memory_cache = {}
    
    def _init_components(self):
        """Initialize internal components."""
        # MITRE mapper for attack pattern analysis
        self.mitre_mapper = MitreMapper()
        
        # Honeypot controller for infrastructure management
        try:
            self.honeypot_controller = HoneypotController()
        except Exception as e:
            logger.warning(f"Controller unavailable: {e}")
            self.honeypot_controller = None
        
        # Threat pattern database
        self.threat_patterns = self._load_threat_patterns()
    
    def _load_threat_patterns(self) -> Dict[str, Any]:
        """Load known threat patterns from cache or defaults."""
        patterns = self._get_cached_data("threat_patterns")
        if patterns:
            return patterns
        
        # Default threat patterns
        default_patterns = {
            "brute_force": {
                "indicators": ["repeated_login_failures", "dictionary_passwords"],
                "threshold": 10,
                "response": "rotate_key"
            },
            "port_scanning": {
                "indicators": ["multiple_ports", "rapid_connections"],
                "threshold": 20,
                "response": "launch_decoy"
            },
            "command_injection": {
                "indicators": ["shell_metacharacters", "privilege_escalation"],
                "threshold": 1,
                "response": "insert_trap"
            },
            "persistent_attacker": {
                "indicators": ["long_session", "multiple_commands"],
                "threshold": 5,
                "response": "escalate"
            }
        }
        
        self._cache_data("threat_patterns", default_patterns)
        return default_patterns
    
    async def start_monitoring(self):
        """Start the main monitoring loop."""
        logger.info("Starting Cerberus Agent monitoring...")
        self.is_running = True
        
        # Start background tasks
        monitor_task = asyncio.create_task(self._monitor_events())
        process_task = asyncio.create_task(self._process_event_queue())
        metrics_task = asyncio.create_task(self._update_metrics())
        
        try:
            await asyncio.gather(monitor_task, process_task, metrics_task)
        except asyncio.CancelledError:
            logger.info("Monitoring tasks cancelled")
        except Exception as e:
            logger.error(f"Monitoring error: {e}")
        finally:
            self.is_running = False
    
    async def stop_monitoring(self):
        """Stop the monitoring loop."""
        logger.info("Stopping Cerberus Agent...")
        self.is_running = False
    
    async def _monitor_events(self):
        """Monitor for new intrusion events from various sources."""
        logger.info("Event monitoring started")
        
        while self.is_running:
            try:
                # Monitor Cowrie logs
                cowrie_events = await self._check_cowrie_events()
                for event in cowrie_events:
                    await self.event_queue.put(event)
                
                # Monitor CloudWatch logs
                if self.cloudwatch_client:
                    cw_events = await self._check_cloudwatch_events()
                    for event in cw_events:
                        await self.event_queue.put(event)
                
                # Monitor controller notifications
                if self.honeypot_controller:
                    controller_events = await self._check_controller_events()
                    for event in controller_events:
                        await self.event_queue.put(event)
                
                # Sleep before next check
                await asyncio.sleep(self.config["monitoring_interval"])
                
            except Exception as e:
                logger.error(f"Event monitoring error: {e}")
                await asyncio.sleep(5)
    
    async def _process_event_queue(self):
        """Process events from the queue and make decisions."""
        logger.info("Event processing started")
        
        while self.is_running:
            try:
                # Get event from queue (with timeout)
                try:
                    event = await asyncio.wait_for(
                        self.event_queue.get(), 
                        timeout=1.0
                    )
                except asyncio.TimeoutError:
                    continue
                
                # Process the event
                start_time = time.time()
                decision = await self._analyze_and_decide(event)
                processing_time = time.time() - start_time
                
                if decision:
                    decision.execution_time = processing_time
                    self.decision_history.append(decision)
                    
                    # Execute action if auto-action is enabled
                    if self.config["auto_action_enabled"] and decision.confidence >= self.config["decision_threshold"]:
                        await self._execute_decision(decision)
                    
                    # Cache decision
                    self._cache_decision(decision)
                
                self.events_processed += 1
                
            except Exception as e:
                logger.error(f"Event processing error: {e}")
                await asyncio.sleep(1)
    
    async def _analyze_and_decide(self, event: IntrusionEvent) -> Optional[AgentDecision]:
        """Analyze event and make a decision using MITRE + LLM."""
        logger.info(f"Analyzing event {event.event_id} from {event.source_ip}")
        
        try:
            # Step 1: MITRE ATT&CK context enrichment
            mitre_context = await self._enrich_with_mitre(event)
            
            # Step 2: LLM analysis for behavioral interpretation
            llm_analysis = await self._analyze_with_llm(event, mitre_context)
            
            # Step 3: Create threat context
            threat_context = ThreatContext(
                event=event,
                mitre_mapping=mitre_context,
                llm_analysis=llm_analysis,
                threat_score=llm_analysis.get("threat_score", 0.5),
                behavioral_patterns=llm_analysis.get("patterns", []),
                recommendations=llm_analysis.get("recommendations", [])
            )
            
            # Step 4: Make decision based on threat context
            decision = await self._make_decision(threat_context)
            
            logger.info(f"Decision made: {decision.decision_type} (confidence: {decision.confidence:.2f})")
            return decision
            
        except Exception as e:
            logger.error(f"Analysis failed for event {event.event_id}: {e}")
            return None
    
    async def _enrich_with_mitre(self, event: IntrusionEvent) -> AttackMapping:
        """Enrich event with MITRE ATT&CK context."""
        try:
            # Determine attack patterns from event
            attack_patterns = []
            
            if event.event_type == "login_attempt":
                if event.username and event.password:
                    attack_patterns.append("brute_force")
                    attack_patterns.append("credential_stuffing")
            
            elif event.event_type == "command_execution":
                if event.command:
                    attack_patterns.append("command_execution")
                    if any(cmd in event.command.lower() for cmd in ['wget', 'curl', 'nc', 'bash']):
                        attack_patterns.append("persistence")
            
            elif event.event_type == "port_scan":
                attack_patterns.append("port_scan")
                attack_patterns.append("network_scan")
            
            elif event.event_type == "file_upload":
                attack_patterns.append("data_exfiltration")
                attack_patterns.append("backdoor_installation")
            
            # Create attack mapping
            mapping = self.mitre_mapper.create_attack_mapping(
                ioc_value=event.source_ip,
                ioc_type="ip",
                attack_patterns=attack_patterns,
                context={
                    "port": event.destination_port,
                    "protocol": event.protocol,
                    "event_type": event.event_type
                }
            )
            
            return mapping
            
        except Exception as e:
            logger.error(f"MITRE enrichment failed: {e}")
            # Return empty mapping as fallback
            return AttackMapping(
                ioc_value=event.source_ip,
                ioc_type="ip",
                attack_pattern="unknown",
                confidence_score=0.1,
                mapped_techniques=[],
                kill_chain_phase="Unknown",
                timestamp=datetime.now()
            )
    
    async def _analyze_with_llm(self, event: IntrusionEvent, mitre_context: AttackMapping) -> Dict[str, Any]:
        """Enhanced LLM analysis using structured function calling."""
        if not self.llm_client:
            logger.warning("LLM client not available - using fallback analysis")
            return self._fallback_analysis(event)
        
        try:
            # Sanitize inputs to prevent prompt injection
            sanitized_event = self._sanitize_event_data(event)
            
            # Create structured messages
            messages = self._create_analysis_messages(sanitized_event, mitre_context)
            
            # Get function schema for structured output
            function_schema = self._get_analysis_function_schema()
            
            # Call GPT-4 with function calling for guaranteed JSON structure
            response = self.llm_client.chat.completions.create(
                model="gpt-4-1106-preview",  # Function calling supported model
                messages=messages,
                functions=[function_schema],
                function_call={"name": "analyze_threat_event"},
                temperature=0.3,  # Lower temperature for consistent analysis
                max_tokens=800,
                timeout=30
            )
            
            # Parse function call response
            function_call = response.choices[0].message.function_call
            if function_call and function_call.name == "analyze_threat_event":
                analysis_data = json.loads(function_call.arguments)
                return self._validate_analysis_response(analysis_data)
            else:
                logger.warning("No function call in response, falling back")
                return self._fallback_analysis(sanitized_event)
            
        except Exception as e:
            logger.error(f"LLM analysis failed: {e}")
            return self._fallback_analysis(event)
    
    def _sanitize_event_data(self, event: IntrusionEvent) -> IntrusionEvent:
        """Sanitize event data to prevent prompt injection attacks."""
        # Create a copy to avoid modifying original
        sanitized = IntrusionEvent(
            event_id=event.event_id,
            timestamp=event.timestamp,
            honeypot_id=event.honeypot_id,
            source_ip=event.source_ip,
            event_type=event.event_type,
            protocol=event.protocol,
            destination_port=event.destination_port,
            session_id=event.session_id,
            severity=event.severity
        )
        
        # Sanitize text fields to prevent injection
        def sanitize_text(text: Optional[str], max_length: int = 200) -> Optional[str]:
            if not text:
                return None
            # Remove potential prompt injection patterns
            text = text.replace('"""', '').replace("'''", '').replace('\\n', ' ')
            text = text.replace('{', '').replace('}', '').replace('`', '')
            # Limit length to prevent token exhaustion
            return text[:max_length] if len(text) > max_length else text
        
        sanitized.username = sanitize_text(event.username, 50)
        sanitized.password = sanitize_text(event.password, 50)  
        sanitized.command = sanitize_text(event.command, 100)
        sanitized.payload = sanitize_text(event.payload, 300)
        
        # Sanitize raw_data
        if event.raw_data:
            sanitized.raw_data = {k: str(v)[:100] for k, v in event.raw_data.items() 
                                 if isinstance(v, (str, int, float, bool))}
        
        return sanitized
    
    def _create_analysis_messages(self, event: IntrusionEvent, mitre_context: AttackMapping) -> List[Dict[str, str]]:
        """Create structured messages for GPT analysis."""
        
        system_prompt = """You are a cybersecurity threat analyst for CerberusMesh honeypot platform. 
Analyze honeypot intrusion events and provide structured threat assessments using the provided function.

Guidelines:
- Assess threat scores based on technique sophistication and potential impact
- Consider MITRE ATT&CK context for accurate technique classification  
- Recommend appropriate defensive actions based on threat level
- Provide concise but informative reasoning
- Maintain high confidence when patterns are clear, lower when ambiguous"""

        event_prompt = f"""Analyze this honeypot intrusion event:

**Event Details:**
- ID: {event.event_id}
- Timestamp: {event.timestamp}
- Source IP: {event.source_ip}
- Type: {event.event_type}
- Protocol: {event.protocol}
- Port: {event.destination_port}
- Session: {event.session_id}

**Interaction Data:**
- Username: {event.username or 'N/A'}
- Password: {event.password or 'N/A'}
- Command: {event.command or 'N/A'}
- Payload: {event.payload or 'N/A'}

**MITRE Context:**
- Attack Pattern: {mitre_context.attack_pattern}
- Kill Chain: {mitre_context.kill_chain_phase}
- Confidence: {mitre_context.confidence_score:.2f}
- Techniques: {[f"{t.technique_id}: {t.name}" for t in mitre_context.mapped_techniques[:2]]}

**Raw Data:**
{json.dumps(event.raw_data or {}, indent=2)[:500]}"""

        return [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": event_prompt}
        ]
    
    def _get_analysis_function_schema(self) -> Dict[str, Any]:
        """Define function schema for structured LLM responses."""
        return {
            "name": "analyze_threat_event",
            "description": "Analyze honeypot intrusion event and provide structured threat assessment",
            "parameters": {
                "type": "object", 
                "properties": {
                    "threat_score": {
                        "type": "number",
                        "minimum": 0.0,
                        "maximum": 1.0,
                        "description": "Threat level from 0.0 (benign) to 1.0 (critical)"
                    },
                    "severity": {
                        "type": "string",
                        "enum": ["low", "medium", "high", "critical"],
                        "description": "Threat severity classification"
                    },
                    "behavioral_patterns": {
                        "type": "array",
                        "items": {"type": "string"},
                        "maxItems": 8,
                        "description": "Observed behavioral patterns"
                    },
                    "attack_sophistication": {
                        "type": "string", 
                        "enum": ["basic", "intermediate", "advanced", "expert"],
                        "description": "Attack sophistication level"
                    },
                    "likely_objectives": {
                        "type": "array",
                        "items": {"type": "string"},
                        "maxItems": 5,
                        "description": "Probable attacker objectives"
                    },
                    "recommended_action": {
                        "type": "string",
                        "enum": ["monitor", "rotate_key", "launch_decoy", "insert_trap", "escalate", "block_ip"],
                        "description": "Recommended defensive action"
                    },
                    "confidence": {
                        "type": "number",
                        "minimum": 0.0,
                        "maximum": 1.0,
                        "description": "Analysis confidence level"
                    },
                    "reasoning": {
                        "type": "string",
                        "maxLength": 400,
                        "description": "Analysis reasoning and justification"
                    },
                    "indicators_of_compromise": {
                        "type": "array",
                        "items": {"type": "string"},
                        "maxItems": 8,
                        "description": "Observable indicators of compromise"
                    },
                    "next_likely_actions": {
                        "type": "array",
                        "items": {"type": "string"},
                        "maxItems": 5,
                        "description": "Predicted next attacker actions"
                    }
                },
                "required": [
                    "threat_score", "severity", "behavioral_patterns",
                    "attack_sophistication", "likely_objectives", 
                    "recommended_action", "confidence", "reasoning"
                ]
            }
        }
    
    def _validate_analysis_response(self, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate and normalize analysis response from function calling."""
        try:
            # Ensure required fields with fallbacks
            normalized = {
                "threat_score": max(0.0, min(1.0, float(analysis_data.get("threat_score", 0.5)))),
                "severity": analysis_data.get("severity", "medium"),
                "patterns": analysis_data.get("behavioral_patterns", []),
                "sophistication": analysis_data.get("attack_sophistication", "basic"),
                "objectives": analysis_data.get("likely_objectives", []),
                "recommended_action": analysis_data.get("recommended_action", "monitor"),
                "confidence": max(0.0, min(1.0, float(analysis_data.get("confidence", 0.5)))),
                "reasoning": analysis_data.get("reasoning", "No reasoning provided"),
                "iocs": analysis_data.get("indicators_of_compromise", []),
                "next_actions": analysis_data.get("next_likely_actions", []),
                "recommendations": [analysis_data.get("recommended_action", "monitor")]
            }
            
            # Validate enum values
            valid_severities = ["low", "medium", "high", "critical"]
            if normalized["severity"] not in valid_severities:
                normalized["severity"] = "medium"
                
            valid_sophistication = ["basic", "intermediate", "advanced", "expert"]
            if normalized["sophistication"] not in valid_sophistication:
                normalized["sophistication"] = "basic"
                
            valid_actions = ["monitor", "rotate_key", "launch_decoy", "insert_trap", "escalate", "block_ip"]
            if normalized["recommended_action"] not in valid_actions:
                normalized["recommended_action"] = "monitor"
            
            return normalized
            
        except Exception as e:
            logger.error(f"Failed to validate analysis response: {e}")
            return self._fallback_analysis_response()
    
    def _build_analysis_prompt(self, event: IntrusionEvent, mitre_context: AttackMapping) -> str:
        """Build analysis prompt for GPT-4."""
        prompt = f"""
Analyze this honeypot intrusion event:

EVENT DETAILS:
- Event ID: {event.event_id}
- Timestamp: {event.timestamp}
- Source IP: {event.source_ip}
- Event Type: {event.event_type}
- Protocol: {event.protocol}
- Port: {event.destination_port}
- Session: {event.session_id}
"""
        
        if event.username:
            prompt += f"- Username: {event.username}\n"
        if event.password:
            prompt += f"- Password: {event.password}\n"
        if event.command:
            prompt += f"- Command: {event.command}\n"
        
        prompt += f"""
MITRE ATT&CK CONTEXT:
- Attack Pattern: {mitre_context.attack_pattern}
- Kill Chain Phase: {mitre_context.kill_chain_phase}
- Confidence: {mitre_context.confidence_score:.2f}
- Techniques: {[t.technique_id + ': ' + t.name for t in mitre_context.mapped_techniques[:3]]}

ANALYSIS REQUIREMENTS:
Provide a JSON response with:
{{
    "threat_score": [0.0-1.0],
    "severity": ["low", "medium", "high", "critical"],
    "behavioral_patterns": ["pattern1", "pattern2"],
    "attack_sophistication": "description",
    "likely_objectives": ["objective1", "objective2"],
    "recommended_action": "action_type",
    "confidence": [0.0-1.0],
    "reasoning": "detailed explanation",
    "indicators_of_compromise": ["ioc1", "ioc2"],
    "next_likely_actions": ["action1", "action2"]
}}

Focus on:
1. Attack sophistication and automation level
2. Persistence indicators and lateral movement potential
3. Data exfiltration or destruction capabilities
4. Recommended defensive actions
"""
        
        return prompt
    
    def _parse_llm_response(self, response_text: str) -> Dict[str, Any]:
        """Parse and validate LLM response."""
        try:
            # Extract JSON from response
            start_idx = response_text.find('{')
            end_idx = response_text.rfind('}') + 1
            
            if start_idx == -1 or end_idx == 0:
                raise ValueError("No JSON found in response")
            
            json_text = response_text[start_idx:end_idx]
            parsed = json.loads(json_text)
            
            # Validate and normalize
            return {
                "threat_score": float(parsed.get("threat_score", 0.5)),
                "severity": parsed.get("severity", "medium"),
                "patterns": parsed.get("behavioral_patterns", []),
                "sophistication": parsed.get("attack_sophistication", "unknown"),
                "objectives": parsed.get("likely_objectives", []),
                "recommended_action": parsed.get("recommended_action", "monitor"),
                "confidence": float(parsed.get("confidence", 0.5)),
                "reasoning": parsed.get("reasoning", "No reasoning provided"),
                "iocs": parsed.get("indicators_of_compromise", []),
                "next_actions": parsed.get("next_likely_actions", []),
                "recommendations": [parsed.get("recommended_action", "monitor")]
            }
            
        except Exception as e:
            logger.error(f"Failed to parse LLM response: {e}")
            return self._fallback_analysis_response()
    
    def _fallback_analysis(self, event: IntrusionEvent) -> Dict[str, Any]:
        """Fallback analysis when LLM is unavailable."""
        # Rule-based analysis
        threat_score = 0.3  # Default baseline
        patterns = []
        
        # Analyze based on event type
        if event.event_type == "login_attempt":
            threat_score = 0.6
            patterns.append("credential_attack")
            
        elif event.event_type == "command_execution":
            threat_score = 0.8
            patterns.append("post_exploitation")
            
        elif event.event_type == "file_upload":
            threat_score = 0.9
            patterns.append("data_exfiltration")
        
        return {
            "threat_score": threat_score,
            "severity": "medium",
            "patterns": patterns,
            "sophistication": "automated",
            "objectives": ["reconnaissance"],
            "recommended_action": "monitor",
            "confidence": 0.6,
            "reasoning": "Rule-based fallback analysis",
            "iocs": [event.source_ip],
            "next_actions": ["continued_probing"],
            "recommendations": ["monitor"]
        }
    
    def _fallback_analysis_response(self) -> Dict[str, Any]:
        """Default response when analysis fails."""
        return {
            "threat_score": 0.5,
            "severity": "medium",
            "patterns": ["unknown"],
            "sophistication": "unknown",
            "objectives": ["unknown"],
            "recommended_action": "monitor",
            "confidence": 0.3,
            "reasoning": "Analysis failed - using defaults",
            "iocs": [],
            "next_actions": [],
            "recommendations": ["monitor"]
        }
    
    def _check_decision_quota(self, action_type: str, source_ip: str) -> bool:
        """Check if decision action is within quota limits."""
        try:
            current_time = datetime.now()
            hour_key = f"quota:{action_type}:hourly:{current_time.strftime('%Y%m%d%H')}"
            day_key = f"quota:{action_type}:daily:{current_time.strftime('%Y%m%d')}"
            
            # Extract /24 network from source IP
            cidr_24 = ".".join(source_ip.split(".")[:3]) + ".0/24"
            cidr_key = f"quota:{action_type}:cidr24:{cidr_24}:{current_time.strftime('%Y%m%d%H')}"
            
            # Check global quotas
            if action_type in self.decision_quotas:
                hourly_count = int(self.redis_client.get(hour_key) or 0)
                daily_count = int(self.redis_client.get(day_key) or 0)
                
                if hourly_count >= self.decision_quotas[action_type]["hourly"]:
                    logger.warning(f"Hourly quota exceeded for {action_type}: {hourly_count}")
                    return False
                    
                if daily_count >= self.decision_quotas[action_type]["daily"]:
                    logger.warning(f"Daily quota exceeded for {action_type}: {daily_count}")
                    return False
            
            # Check per-CIDR quotas
            if action_type in self.cidr_quotas:
                cidr_count = int(self.redis_client.get(cidr_key) or 0)
                if cidr_count >= self.cidr_quotas[action_type]:
                    logger.warning(f"CIDR quota exceeded for {action_type} from {cidr_24}: {cidr_count}")
                    return False
            
            return True
            
        except Exception as e:
            logger.error(f"Error checking quota for {action_type}: {e}")
            # Fail safe - allow action if quota check fails
            return True
    
    def _increment_decision_quota(self, action_type: str, source_ip: str) -> None:
        """Increment quota counters for executed action."""
        try:
            current_time = datetime.now()
            hour_key = f"quota:{action_type}:hourly:{current_time.strftime('%Y%m%d%H')}"
            day_key = f"quota:{action_type}:daily:{current_time.strftime('%Y%m%d')}"
            
            # Extract /24 network from source IP
            cidr_24 = ".".join(source_ip.split(".")[:3]) + ".0/24"
            cidr_key = f"quota:{action_type}:cidr24:{cidr_24}:{current_time.strftime('%Y%m%d%H')}"
            
            # Increment counters with expiration
            pipe = self.redis_client.pipeline()
            pipe.incr(hour_key)
            pipe.expire(hour_key, 3600)  # 1 hour
            pipe.incr(day_key)  
            pipe.expire(day_key, 86400)  # 24 hours
            pipe.incr(cidr_key)
            pipe.expire(cidr_key, 3600)  # 1 hour
            pipe.execute()
            
            logger.info(f"Incremented quota counters for {action_type} from {source_ip}")
            
        except Exception as e:
            logger.error(f"Error incrementing quota for {action_type}: {e}")
    
    def _get_quota_status(self) -> Dict[str, Dict[str, int]]:
        """Get current quota usage for monitoring."""
        quota_status = {}
        current_time = datetime.now()
        
        try:
            for action_type in self.decision_quotas:
                hour_key = f"quota:{action_type}:hourly:{current_time.strftime('%Y%m%d%H')}"
                day_key = f"quota:{action_type}:daily:{current_time.strftime('%Y%m%d')}"
                
                hourly_used = int(self.redis_client.get(hour_key) or 0)
                daily_used = int(self.redis_client.get(day_key) or 0)
                
                quota_status[action_type] = {
                    "hourly_used": hourly_used,
                    "hourly_limit": self.decision_quotas[action_type]["hourly"],
                    "daily_used": daily_used,
                    "daily_limit": self.decision_quotas[action_type]["daily"],
                    "hourly_remaining": max(0, self.decision_quotas[action_type]["hourly"] - hourly_used),
                    "daily_remaining": max(0, self.decision_quotas[action_type]["daily"] - daily_used)
                }
                
        except Exception as e:
            logger.error(f"Error getting quota status: {e}")
            
        return quota_status

    async def _make_decision(self, threat_context: ThreatContext) -> AgentDecision:
        """Make decision based on threat context."""
        event = threat_context.event
        analysis = threat_context.llm_analysis
        
        # Decision logic based on threat score and patterns
        decision_type = "monitor"  # Default
        confidence = analysis["confidence"]
        
        threat_score = threat_context.threat_score
        recommended_action = analysis["recommended_action"]
        
        # Decision matrix
        if threat_score >= 0.9 or "data_exfiltration" in threat_context.behavioral_patterns:
            decision_type = "escalate"
            confidence = min(confidence + 0.1, 1.0)
            
        elif threat_score >= 0.8 or "post_exploitation" in threat_context.behavioral_patterns:
            decision_type = "insert_trap"
            confidence = min(confidence + 0.05, 1.0)
            
        elif threat_score >= 0.7 or "credential_attack" in threat_context.behavioral_patterns:
            decision_type = "rotate_key"
            
        elif threat_score >= 0.6 or self._detect_spike_pattern(event.source_ip):
            decision_type = "launch_decoy"
        
        # Override with LLM recommendation if confidence is high
        if analysis["confidence"] >= 0.8 and recommended_action in ["rotate_key", "launch_decoy", "insert_trap", "escalate"]:
            decision_type = recommended_action
        
        # Check quota limits before allowing action
        if decision_type != "monitor" and not self._check_decision_quota(decision_type, event.source_ip):
            logger.warning(f"Quota exceeded for {decision_type} from {event.source_ip}, defaulting to monitor")
            decision_type = "monitor"
            confidence = max(confidence - 0.2, 0.1)
            reasoning_suffix = " (quota exceeded)"
        else:
            reasoning_suffix = ""
        
        # Build reasoning
        reasoning = f"Threat score: {threat_score:.2f}, "
        reasoning += f"Patterns: {threat_context.behavioral_patterns}, "
        reasoning += f"LLM recommendation: {recommended_action}, "
        reasoning += f"MITRE phase: {threat_context.mitre_mapping.kill_chain_phase}"
        reasoning += reasoning_suffix
        
        decision = AgentDecision(
            decision_id=str(uuid.uuid4()),
            timestamp=datetime.now(),
            event_id=event.event_id,
            decision_type=decision_type,
            confidence=confidence,
            reasoning=reasoning,
            mitre_techniques=[t.technique_id for t in threat_context.mitre_mapping.mapped_techniques],
            action_taken=False
        )
        
        return decision
    
    def _detect_spike_pattern(self, source_ip: str) -> bool:
        """Detect if there's an attack spike from this IP."""
        try:
            # Check cached event count for this IP
            cache_key = f"ip_events:{source_ip}"
            count = self._get_cached_data(cache_key) or 0
            
            # Consider it a spike if more than 10 events in last hour
            return count > 10
            
        except Exception:
            return False
    
    async def _execute_decision(self, decision: AgentDecision):
        """Execute the decided action."""
        logger.info(f"Executing decision: {decision.decision_type}")
        
        try:
            result = None
            
            if decision.decision_type == "rotate_key":
                result = await self._rotate_ssh_key(decision)
                
            elif decision.decision_type == "launch_decoy":
                result = await self._launch_decoy_honeypot(decision)
                
            elif decision.decision_type == "insert_trap":
                result = await self._insert_session_trap(decision)
                
            elif decision.decision_type == "escalate":
                result = await self._escalate_threat(decision)
                
            elif decision.decision_type == "monitor":
                result = await self._enhance_monitoring(decision)
            
            # Update decision with result
            decision.action_taken = True
            decision.result = result
            self.actions_executed += 1
            
            # Increment quota counters for executed actions
            if decision.decision_type != "monitor":
                # Get source IP from the event in decision history
                source_ip = "unknown"
                for event_data in self.decision_history:
                    if hasattr(event_data, 'event_id') and event_data.event_id == decision.event_id:
                        source_ip = event_data.source_ip
                        break
                if source_ip != "unknown":
                    self._increment_decision_quota(decision.decision_type, source_ip)
            
            logger.info(f"Action executed successfully: {result}")
            
        except Exception as e:
            logger.error(f"Failed to execute decision {decision.decision_id}: {e}")
            decision.result = f"Execution failed: {str(e)}"
    
    async def _rotate_ssh_key(self, decision: AgentDecision) -> str:
        """Rotate SSH key for affected honeypot."""
        if not self.honeypot_controller:
            return "Controller unavailable"
        
        try:
            # Generate new key pair
            key_name = f"cerberusmesh-key-{int(time.time())}"
            key_name, key_file = self.honeypot_controller.create_keypair(key_name)
            
            # Tag instances for key rotation (would need implementation in controller)
            logger.info(f"SSH key rotated: {key_name}")
            return f"New key created: {key_name}"
            
        except Exception as e:
            return f"Key rotation failed: {str(e)}"
    
    async def _launch_decoy_honeypot(self, decision: AgentDecision) -> str:
        """Launch additional decoy honeypot."""
        if not self.honeypot_controller:
            return "Controller unavailable"
        
        try:
            # Launch single decoy instance
            instances = self.honeypot_controller.launch_honeypots(
                count=1,
                tags={"Purpose": "Decoy", "TriggeredBy": decision.event_id}
            )
            
            if instances:
                instance_id = instances[0]["aws_instance_id"]
                logger.info(f"Decoy honeypot launched: {instance_id}")
                return f"Decoy launched: {instance_id}"
            else:
                return "Decoy launch failed"
                
        except Exception as e:
            return f"Decoy launch failed: {str(e)}"
    
    async def _insert_session_trap(self, decision: AgentDecision) -> str:
        """Insert deceptive content into active session."""
        try:
            # This would require integration with Cowrie's session management
            # For now, we'll create a trap response file
            
            trap_content = {
                "timestamp": datetime.now().isoformat(),
                "decision_id": decision.decision_id,
                "trap_type": "fake_sensitive_file",
                "content": [
                    "# Fake sensitive configuration",
                    "admin_password=definitely_not_the_real_password",
                    "database_host=127.0.0.1",
                    "api_key=fake_key_12345"
                ]
            }
            
            # Save trap content for Cowrie to use
            trap_file = Path("/tmp/cowrie_trap.json")
            with open(trap_file, 'w') as f:
                json.dump(trap_content, f, indent=2)
            
            logger.info("Session trap inserted")
            return "Deceptive content trap inserted"
            
        except Exception as e:
            return f"Trap insertion failed: {str(e)}"
    
    async def _escalate_threat(self, decision: AgentDecision) -> str:
        """Escalate high-priority threat."""
        try:
            # Send alert to monitoring systems
            alert_data = {
                "severity": "HIGH",
                "decision_id": decision.decision_id,
                "event_id": decision.event_id,
                "timestamp": datetime.now().isoformat(),
                "reasoning": decision.reasoning,
                "mitre_techniques": decision.mitre_techniques
            }
            
            # Cache high-priority alert
            self._cache_data(f"alert:{decision.decision_id}", alert_data, ttl=86400)
            
            # Would integrate with SIEM/SOAR platforms
            logger.warning(f"THREAT ESCALATED: {decision.reasoning}")
            return "Threat escalated to security team"
            
        except Exception as e:
            return f"Escalation failed: {str(e)}"
    
    async def _enhance_monitoring(self, decision: AgentDecision) -> str:
        """Enhance monitoring for ongoing threats."""
        try:
            # Increase monitoring frequency for this event type
            enhanced_config = {
                "event_type": decision.event_id.split("-")[0],  # Extract event type
                "enhanced_until": (datetime.now() + timedelta(hours=1)).isoformat(),
                "monitoring_interval": 1  # Increase to every second
            }
            
            self._cache_data("enhanced_monitoring", enhanced_config, ttl=3600)
            
            logger.info("Enhanced monitoring activated")
            return "Monitoring enhanced for 1 hour"
            
        except Exception as e:
            return f"Monitoring enhancement failed: {str(e)}"
    
    async def _check_cowrie_events(self) -> List[IntrusionEvent]:
        """Check for new Cowrie events."""
        events = []
        
        try:
            # Mock implementation - would read from Cowrie JSON logs
            cowrie_log_path = Path("/opt/cowrie/var/log/cowrie/cowrie.json")
            
            if cowrie_log_path.exists():
                # Read last few lines (simplified)
                with open(cowrie_log_path, 'r') as f:
                    lines = f.readlines()[-10:]  # Get last 10 lines
                
                for line in lines:
                    try:
                        log_entry = json.loads(line)
                        event = self._parse_cowrie_event(log_entry)
                        if event:
                            events.append(event)
                    except json.JSONDecodeError:
                        continue
            
        except Exception as e:
            logger.debug(f"Cowrie event check failed: {e}")
        
        return events
    
    def _parse_cowrie_event(self, log_entry: Dict) -> Optional[IntrusionEvent]:
        """Parse Cowrie log entry into IntrusionEvent."""
        try:
            event_id = log_entry.get("eventid", "")
            
            if event_id in ["cowrie.login.success", "cowrie.login.failed"]:
                return IntrusionEvent(
                    event_id=str(uuid.uuid4()),
                    timestamp=datetime.fromisoformat(log_entry["timestamp"]),
                    honeypot_id=log_entry.get("sensor", "unknown"),
                    source_ip=log_entry.get("src_ip", "unknown"),
                    event_type="login_attempt",
                    protocol="ssh",
                    destination_port=log_entry.get("dst_port", 22),
                    session_id=log_entry.get("session", ""),
                    username=log_entry.get("username"),
                    password=log_entry.get("password"),
                    raw_data=log_entry
                )
            
            elif event_id == "cowrie.command.input":
                return IntrusionEvent(
                    event_id=str(uuid.uuid4()),
                    timestamp=datetime.fromisoformat(log_entry["timestamp"]),
                    honeypot_id=log_entry.get("sensor", "unknown"),
                    source_ip=log_entry.get("src_ip", "unknown"),
                    event_type="command_execution",
                    protocol="ssh",
                    destination_port=22,
                    session_id=log_entry.get("session", ""),
                    command=log_entry.get("input"),
                    raw_data=log_entry
                )
            
        except Exception as e:
            logger.debug(f"Failed to parse Cowrie event: {e}")
        
        return None
    
    async def _check_cloudwatch_events(self) -> List[IntrusionEvent]:
        """Check CloudWatch logs for events."""
        events = []
        
        # Placeholder for CloudWatch integration
        # Would query log groups for honeypot events
        
        return events
    
    async def _check_controller_events(self) -> List[IntrusionEvent]:
        """Check controller for infrastructure events."""
        events = []
        
        # Placeholder for controller integration
        # Would check for instance state changes, etc.
        
        return events
    
    async def _update_metrics(self):
        """Update agent performance metrics."""
        while self.is_running:
            try:
                metrics = {
                    "events_processed": self.events_processed,
                    "decisions_made": self.decisions_made,
                    "actions_executed": self.actions_executed,
                    "queue_size": self.event_queue.qsize(),
                    "timestamp": datetime.now().isoformat()
                }
                
                self._cache_data("agent_metrics", metrics, ttl=300)
                
                # Log metrics every 5 minutes
                if self.events_processed % 100 == 0:
                    logger.info(f"Agent metrics: {metrics}")
                
                await asyncio.sleep(60)  # Update every minute
                
            except Exception as e:
                logger.error(f"Metrics update failed: {e}")
                await asyncio.sleep(60)
    
    def _cache_data(self, key: str, data: Any, ttl: int = None):
        """Cache data in Redis or memory."""
        try:
            if self.redis_client:
                serialized = json.dumps(data, default=str)
                if ttl:
                    self.redis_client.setex(key, ttl, serialized)
                else:
                    self.redis_client.set(key, serialized)
            else:
                # Use memory cache
                self._memory_cache[key] = {
                    "data": data,
                    "expires": datetime.now() + timedelta(seconds=ttl or self.config["cache_ttl"])
                }
        except Exception as e:
            logger.debug(f"Cache write failed: {e}")
    
    def _get_cached_data(self, key: str) -> Any:
        """Get data from cache."""
        try:
            if self.redis_client:
                data = self.redis_client.get(key)
                if data:
                    return json.loads(data)
            else:
                # Check memory cache
                cached = self._memory_cache.get(key)
                if cached and cached["expires"] > datetime.now():
                    return cached["data"]
        except Exception as e:
            logger.debug(f"Cache read failed: {e}")
        
        return None
    
    def _cache_decision(self, decision: AgentDecision):
        """Cache decision for history and analysis."""
        decision_data = asdict(decision)
        cache_key = f"decision:{decision.decision_id}"
        self._cache_data(cache_key, decision_data, ttl=86400)  # 24 hours
    
    def get_agent_status(self) -> Dict[str, Any]:
        """Get current agent status."""
        return {
            "is_running": self.is_running,
            "events_processed": self.events_processed,
            "decisions_made": self.decisions_made,
            "actions_executed": self.actions_executed,
            "queue_size": self.event_queue.qsize() if hasattr(self.event_queue, 'qsize') else 0,
            "config": self.config,
            "components": {
                "llm_client": self.llm_client is not None,
                "redis_client": self.redis_client is not None,
                "ec2_client": self.ec2_client is not None,
                "honeypot_controller": self.honeypot_controller is not None
            }
        }
    
    def get_recent_decisions(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent decisions made by the agent."""
        recent = self.decision_history[-limit:] if self.decision_history else []
        return [asdict(decision) for decision in recent]

async def main():
    """Main entry point for the Cerberus Agent."""
    logger.info("Starting Cerberus Agent...")
    
    # Initialize agent
    agent = CerberusAgent()
    
    # Start monitoring
    try:
        await agent.start_monitoring()
    except KeyboardInterrupt:
        logger.info("Received interrupt signal")
        await agent.stop_monitoring()
    except Exception as e:
        logger.error(f"Agent failed: {e}")
    finally:
        logger.info("Cerberus Agent stopped")

if __name__ == "__main__":
    asyncio.run(main())
