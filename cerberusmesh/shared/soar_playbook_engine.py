#!/usr/bin/env python3
"""
CerberusMesh SOAR Playbook Engine - Distributed security orchestration and automated response.

This module provides:
- YAML-based playbook definitions
- Parallel execution engine
- Integration with external SIEM/SOAR platforms
- Comprehensive audit logging
- Dynamic playbook generation based on threat intelligence

Integrates with: Splunk SOAR, QRadar, Cortex XSOAR, custom SIEM platforms
"""

import asyncio
import json
import logging
import yaml
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, asdict, field
from pathlib import Path
from enum import Enum
import uuid
import time

import aiohttp
import aiokafka
import jinja2
from jinja2 import Template

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('soar_playbook_engine.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class PlaybookStatus(Enum):
    """Playbook execution status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"

class ActionType(Enum):
    """Types of automated actions."""
    HTTP_REQUEST = "http_request"
    SIEM_ALERT = "siem_alert"
    BLOCK_IP = "block_ip"
    THREAT_INTEL_UPDATE = "threat_intel_update"
    EMAIL_NOTIFICATION = "email_notification"
    SLACK_MESSAGE = "slack_message"
    CUSTOM_SCRIPT = "custom_script"
    AWS_ACTION = "aws_action"
    CONTAINMENT = "containment"

@dataclass
class PlaybookAction:
    """Individual action within a playbook."""
    
    action_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    action_type: ActionType = ActionType.HTTP_REQUEST
    name: str = ""
    description: str = ""
    
    # Action configuration
    config: Dict[str, Any] = field(default_factory=dict)
    timeout: int = 300  # 5 minutes default
    retry_count: int = 3
    retry_delay: int = 5
    
    # Conditional execution
    condition: Optional[str] = None  # Jinja2 template condition
    depends_on: List[str] = field(default_factory=list)  # Action dependencies
    
    # Execution tracking
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    status: PlaybookStatus = PlaybookStatus.PENDING
    result: Dict[str, Any] = field(default_factory=dict)
    error_message: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return asdict(self)

@dataclass
class SOARPlaybook:
    """SOAR playbook definition and execution state."""
    
    playbook_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    description: str = ""
    version: str = "1.0"
    
    # Trigger configuration
    trigger_conditions: Dict[str, Any] = field(default_factory=dict)
    threat_level_threshold: int = 1  # Minimum threat level to trigger
    
    # Playbook structure
    actions: List[PlaybookAction] = field(default_factory=list)
    parallel_execution: bool = False
    max_execution_time: int = 3600  # 1 hour default
    
    # Metadata
    author: str = "CerberusMesh"
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    tags: List[str] = field(default_factory=list)
    
    # Execution state
    execution_id: Optional[str] = None
    status: PlaybookStatus = PlaybookStatus.PENDING
    session_context: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return asdict(self)

class SOARPlaybookEngine:
    """SOAR playbook execution engine with enterprise integrations."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the SOAR engine with configuration."""
        self.config = config
        
        # Playbook storage
        self.playbooks: Dict[str, SOARPlaybook] = {}
        self.active_executions: Dict[str, SOARPlaybook] = {}
        
        # Template engine for dynamic content
        self.jinja_env = jinja2.Environment(
            loader=jinja2.DictLoader({}),
            autoescape=True
        )
        
        # Integration clients
        self.kafka_producer = None
        self.http_session = None
        
        # Action handlers
        self.action_handlers: Dict[ActionType, Callable] = {
            ActionType.HTTP_REQUEST: self._execute_http_request,
            ActionType.SIEM_ALERT: self._execute_siem_alert,
            ActionType.BLOCK_IP: self._execute_block_ip,
            ActionType.THREAT_INTEL_UPDATE: self._execute_threat_intel_update,
            ActionType.EMAIL_NOTIFICATION: self._execute_email_notification,
            ActionType.SLACK_MESSAGE: self._execute_slack_message,
            ActionType.CUSTOM_SCRIPT: self._execute_custom_script,
            ActionType.AWS_ACTION: self._execute_aws_action,
            ActionType.CONTAINMENT: self._execute_containment
        }
        
        # Execution metrics
        self.metrics = {
            'playbooks_loaded': 0,
            'executions_started': 0,
            'executions_completed': 0,
            'executions_failed': 0,
            'actions_executed': 0,
            'total_execution_time': 0.0
        }
    
    async def initialize(self):
        """Initialize the SOAR engine."""
        logger.info("Initializing SOAR Playbook Engine...")
        
        # Initialize Kafka producer
        self.kafka_producer = aiokafka.AIOKafkaProducer(
            bootstrap_servers=self.config.get('kafka_servers', 'localhost:9092'),
            value_serializer=lambda x: json.dumps(x, default=str).encode('utf-8')
        )
        await self.kafka_producer.start()
        
        # Initialize HTTP session
        self.http_session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=300)
        )
        
        # Load default playbooks
        await self._load_default_playbooks()
        
        logger.info("SOAR Playbook Engine initialized successfully")
    
    async def _load_default_playbooks(self):
        """Load default SOAR playbooks."""
        
        # Incident Response Playbook
        incident_response = SOARPlaybook(
            name="Advanced Threat Incident Response",
            description="Comprehensive incident response for high-severity threats",
            threat_level_threshold=3,
            parallel_execution=True,
            actions=[
                PlaybookAction(
                    action_type=ActionType.SIEM_ALERT,
                    name="Create SIEM Incident",
                    description="Create high-priority incident in SIEM",
                    config={
                        'severity': 'high',
                        'category': 'advanced_threat',
                        'template': 'incident_template_v2'
                    }
                ),
                PlaybookAction(
                    action_type=ActionType.THREAT_INTEL_UPDATE,
                    name="Update Threat Intelligence",
                    description="Add IOCs to threat intelligence platform",
                    config={
                        'platforms': ['splunk', 'misp', 'threatconnect'],
                        'confidence': 'high',
                        'tlp': 'amber'
                    }
                ),
                PlaybookAction(
                    action_type=ActionType.BLOCK_IP,
                    name="Network Containment",
                    description="Block malicious IPs across security stack",
                    config={
                        'duration': 86400,
                        'scope': ['firewall', 'proxy', 'honeypots'],
                        'notification': True
                    }
                ),
                PlaybookAction(
                    action_type=ActionType.EMAIL_NOTIFICATION,
                    name="SOC Team Alert",
                    description="Notify SOC team of critical threat",
                    config={
                        'recipients': ['soc-team@company.com'],
                        'priority': 'urgent',
                        'template': 'critical_threat_notification'
                    },
                    depends_on=['Create SIEM Incident']
                ),
                PlaybookAction(
                    action_type=ActionType.CUSTOM_SCRIPT,
                    name="Forensic Data Collection",
                    description="Collect forensic artifacts for analysis",
                    config={
                        'script_path': '/opt/cerberus/scripts/collect_forensics.py',
                        'args': ['--session-id', '{{ session.session_id }}'],
                        'environment': 'forensics'
                    },
                    timeout=1800  # 30 minutes
                )
            ],
            tags=['incident_response', 'high_severity', 'automated']
        )
        
        # APT Detection Playbook
        apt_detection = SOARPlaybook(
            name="APT Campaign Detection",
            description="Advanced Persistent Threat detection and response",
            threat_level_threshold=4,
            parallel_execution=False,  # Sequential for APT analysis
            actions=[
                PlaybookAction(
                    action_type=ActionType.THREAT_INTEL_UPDATE,
                    name="APT Intelligence Query",
                    description="Query threat intelligence for APT indicators",
                    config={
                        'query_type': 'apt_campaign',
                        'indicators': ['{{ session.iocs_extracted }}'],
                        'lookback_days': 90
                    }
                ),
                PlaybookAction(
                    action_type=ActionType.CUSTOM_SCRIPT,
                    name="MITRE ATT&CK Analysis",
                    description="Deep MITRE ATT&CK technique analysis",
                    config={
                        'script_path': '/opt/cerberus/scripts/mitre_analysis.py',
                        'args': ['--techniques', '{{ session.mitre_techniques | join(",") }}'],
                        'output_format': 'json'
                    },
                    depends_on=['APT Intelligence Query']
                ),
                PlaybookAction(
                    action_type=ActionType.HTTP_REQUEST,
                    name="Executive Notification",
                    description="Send executive alert for potential APT",
                    config={
                        'method': 'POST',
                        'url': 'https://internal-api.company.com/executive-alerts',
                        'headers': {'Authorization': 'Bearer {{ executive_api_token }}'},
                        'payload': {
                            'alert_type': 'apt_detection',
                            'severity': 'critical',
                            'session_id': '{{ session.session_id }}',
                            'threat_actor': '{{ apt_analysis.threat_actor }}',
                            'confidence': '{{ apt_analysis.confidence }}'
                        }
                    },
                    condition='{{ apt_analysis.confidence > 0.8 }}',
                    depends_on=['MITRE ATT&CK Analysis']
                )
            ],
            tags=['apt', 'advanced_threat', 'executive_notification']
        )
        
        # Malware Analysis Playbook
        malware_analysis = SOARPlaybook(
            name="Automated Malware Analysis",
            description="Comprehensive malware analysis and sandboxing",
            threat_level_threshold=2,
            parallel_execution=True,
            actions=[
                PlaybookAction(
                    action_type=ActionType.HTTP_REQUEST,
                    name="Submit to Sandbox",
                    description="Submit malware samples to analysis sandbox",
                    config={
                        'method': 'POST',
                        'url': 'https://sandbox-api.company.com/submit',
                        'files': ['{{ session.malware_hashes }}'],
                        'analysis_timeout': 1800
                    },
                    condition='{{ session.malware_hashes | length > 0 }}'
                ),
                PlaybookAction(
                    action_type=ActionType.THREAT_INTEL_UPDATE,
                    name="Hash Intelligence Lookup",
                    description="Query threat intelligence for known malware hashes",
                    config={
                        'hash_types': ['md5', 'sha1', 'sha256'],
                        'sources': ['virustotal', 'reversing_labs', 'hybrid_analysis']
                    }
                ),
                PlaybookAction(
                    action_type=ActionType.SLACK_MESSAGE,
                    name="Malware Team Notification",
                    description="Notify malware analysis team",
                    config={
                        'channel': '#malware-analysis',
                        'message': 'New malware detected in session {{ session.session_id }}. Hashes: {{ session.malware_hashes | join(", ") }}',
                        'attachments': [{
                            'title': 'Session Details',
                            'fields': [
                                {'title': 'Source IP', 'value': '{{ session.source_ip }}'},
                                {'title': 'Threat Level', 'value': '{{ session.threat_level.name }}'},
                                {'title': 'CVSS Score', 'value': '{{ session.cvss_score }}'}
                            ]
                        }]
                    },
                    depends_on=['Submit to Sandbox']
                )
            ],
            tags=['malware', 'analysis', 'sandbox']
        )
        
        # Store default playbooks
        self.playbooks[incident_response.playbook_id] = incident_response
        self.playbooks[apt_detection.playbook_id] = apt_detection
        self.playbooks[malware_analysis.playbook_id] = malware_analysis
        
        self.metrics['playbooks_loaded'] = len(self.playbooks)
        logger.info(f"Loaded {len(self.playbooks)} default playbooks")
    
    async def load_playbook_from_yaml(self, yaml_content: str) -> SOARPlaybook:
        """Load a playbook from YAML definition."""
        try:
            playbook_data = yaml.safe_load(yaml_content)
            
            # Convert actions
            actions = []
            for action_data in playbook_data.get('actions', []):
                action = PlaybookAction(
                    action_type=ActionType(action_data['action_type']),
                    name=action_data['name'],
                    description=action_data.get('description', ''),
                    config=action_data.get('config', {}),
                    timeout=action_data.get('timeout', 300),
                    retry_count=action_data.get('retry_count', 3),
                    condition=action_data.get('condition'),
                    depends_on=action_data.get('depends_on', [])
                )
                actions.append(action)
            
            # Create playbook
            playbook = SOARPlaybook(
                name=playbook_data['name'],
                description=playbook_data.get('description', ''),
                version=playbook_data.get('version', '1.0'),
                trigger_conditions=playbook_data.get('trigger_conditions', {}),
                threat_level_threshold=playbook_data.get('threat_level_threshold', 1),
                actions=actions,
                parallel_execution=playbook_data.get('parallel_execution', False),
                max_execution_time=playbook_data.get('max_execution_time', 3600),
                tags=playbook_data.get('tags', [])
            )
            
            self.playbooks[playbook.playbook_id] = playbook
            self.metrics['playbooks_loaded'] += 1
            
            logger.info(f"Loaded playbook: {playbook.name}")
            return playbook
            
        except Exception as e:
            logger.error(f"Failed to load playbook from YAML: {e}")
            raise
    
    async def execute_playbook(self, playbook_id: str, session_context: Dict[str, Any]) -> str:
        """
        Execute a SOAR playbook with the given session context.
        
        Args:
            playbook_id: ID of the playbook to execute
            session_context: Adversary session data for context
            
        Returns:
            str: Execution ID for tracking
        """
        if playbook_id not in self.playbooks:
            raise ValueError(f"Playbook {playbook_id} not found")
        
        # Clone playbook for execution
        playbook = self.playbooks[playbook_id]
        execution = SOARPlaybook(**asdict(playbook))
        execution.execution_id = str(uuid.uuid4())
        execution.session_context = session_context
        execution.status = PlaybookStatus.RUNNING
        
        # Store active execution
        self.active_executions[execution.execution_id] = execution
        
        logger.info(f"Starting execution of playbook '{playbook.name}' (ID: {execution.execution_id})")
        
        # Start execution asynchronously
        asyncio.create_task(self._execute_playbook_actions(execution))
        
        self.metrics['executions_started'] += 1
        
        return execution.execution_id
    
    async def _execute_playbook_actions(self, playbook: SOARPlaybook):
        """Execute all actions in a playbook."""
        start_time = time.time()
        
        try:
            # Prepare Jinja2 context
            template_context = {
                'session': playbook.session_context,
                'playbook': playbook.to_dict(),
                'execution_id': playbook.execution_id,
                'timestamp': datetime.utcnow().isoformat()
            }
            
            if playbook.parallel_execution:
                # Execute actions in parallel (respecting dependencies)
                await self._execute_actions_parallel(playbook, template_context)
            else:
                # Execute actions sequentially
                await self._execute_actions_sequential(playbook, template_context)
            
            playbook.status = PlaybookStatus.COMPLETED
            self.metrics['executions_completed'] += 1
            
        except asyncio.TimeoutError:
            playbook.status = PlaybookStatus.TIMEOUT
            logger.error(f"Playbook {playbook.execution_id} timed out")
            
        except Exception as e:
            playbook.status = PlaybookStatus.FAILED
            logger.error(f"Playbook {playbook.execution_id} failed: {e}")
            self.metrics['executions_failed'] += 1
            
        finally:
            execution_time = time.time() - start_time
            self.metrics['total_execution_time'] += execution_time
            
            # Send completion event
            await self._send_execution_event(playbook, 'completed', {
                'execution_time': execution_time,
                'actions_executed': len([a for a in playbook.actions if a.status == PlaybookStatus.COMPLETED])
            })
            
            # Clean up
            if playbook.execution_id in self.active_executions:
                del self.active_executions[playbook.execution_id]
            
            logger.info(f"Playbook {playbook.execution_id} completed with status: {playbook.status.value}")
    
    async def _execute_actions_sequential(self, playbook: SOARPlaybook, context: Dict[str, Any]):
        """Execute actions sequentially."""
        for action in playbook.actions:
            # Check condition
            if not await self._evaluate_action_condition(action, context):
                logger.info(f"Skipping action {action.name} - condition not met")
                continue
            
            # Execute action
            await self._execute_single_action(action, context)
            
            # Update context with action results
            context[f'action_{action.action_id}_result'] = action.result
    
    async def _execute_actions_parallel(self, playbook: SOARPlaybook, context: Dict[str, Any]):
        """Execute actions in parallel, respecting dependencies."""
        
        # Build dependency graph
        dependency_graph = {}
        for action in playbook.actions:
            dependency_graph[action.action_id] = action.depends_on
        
        # Track completed actions
        completed_actions = set()
        
        # Execute actions in dependency order
        while len(completed_actions) < len(playbook.actions):
            # Find actions ready to execute
            ready_actions = []
            for action in playbook.actions:
                if (action.action_id not in completed_actions and 
                    all(dep in completed_actions for dep in dependency_graph[action.action_id])):
                    ready_actions.append(action)
            
            if not ready_actions:
                logger.error("Circular dependency detected in playbook actions")
                break
            
            # Execute ready actions in parallel
            tasks = []
            for action in ready_actions:
                if await self._evaluate_action_condition(action, context):
                    task = asyncio.create_task(self._execute_single_action(action, context))
                    tasks.append((action, task))
                else:
                    # Mark as completed (skipped)
                    completed_actions.add(action.action_id)
            
            # Wait for completion
            if tasks:
                await asyncio.gather(*[task for _, task in tasks], return_exceptions=True)
                
                # Update completed actions and context
                for action, _ in tasks:
                    completed_actions.add(action.action_id)
                    context[f'action_{action.action_id}_result'] = action.result
    
    async def _execute_single_action(self, action: PlaybookAction, context: Dict[str, Any]):
        """Execute a single playbook action."""
        logger.info(f"Executing action: {action.name}")
        action.started_at = datetime.utcnow()
        action.status = PlaybookStatus.RUNNING
        
        try:
            # Render templates in action config
            rendered_config = await self._render_action_config(action.config, context)
            action.config = rendered_config
            
            # Execute action with retries
            for attempt in range(action.retry_count + 1):
                try:
                    # Get action handler
                    handler = self.action_handlers.get(action.action_type)
                    if not handler:
                        raise ValueError(f"No handler for action type: {action.action_type}")
                    
                    # Execute with timeout
                    result = await asyncio.wait_for(
                        handler(action, context),
                        timeout=action.timeout
                    )
                    
                    action.result = result
                    action.status = PlaybookStatus.COMPLETED
                    break
                    
                except Exception as e:
                    if attempt < action.retry_count:
                        logger.warning(f"Action {action.name} failed (attempt {attempt + 1}), retrying: {e}")
                        await asyncio.sleep(action.retry_delay)
                    else:
                        raise e
            
        except Exception as e:
            action.status = PlaybookStatus.FAILED
            action.error_message = str(e)
            logger.error(f"Action {action.name} failed: {e}")
            
        finally:
            action.completed_at = datetime.utcnow()
            self.metrics['actions_executed'] += 1
            
            # Send action event
            await self._send_action_event(action, context)
    
    async def _evaluate_action_condition(self, action: PlaybookAction, context: Dict[str, Any]) -> bool:
        """Evaluate action condition using Jinja2."""
        if not action.condition:
            return True
        
        try:
            template = self.jinja_env.from_string(action.condition)
            result = template.render(context)
            return result.lower() in ('true', '1', 'yes', 'on')
        except Exception as e:
            logger.error(f"Failed to evaluate condition for action {action.name}: {e}")
            return False
    
    async def _render_action_config(self, config: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Render Jinja2 templates in action configuration."""
        def render_value(value):
            if isinstance(value, str):
                try:
                    template = self.jinja_env.from_string(value)
                    return template.render(context)
                except:
                    return value
            elif isinstance(value, dict):
                return {k: render_value(v) for k, v in value.items()}
            elif isinstance(value, list):
                return [render_value(item) for item in value]
            else:
                return value
        
        return render_value(config)
    
    # Action Handlers
    
    async def _execute_http_request(self, action: PlaybookAction, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute HTTP request action."""
        config = action.config
        
        async with self.http_session.request(
            method=config.get('method', 'GET'),
            url=config['url'],
            headers=config.get('headers', {}),
            json=config.get('payload'),
            params=config.get('params')
        ) as response:
            result = {
                'status_code': response.status,
                'headers': dict(response.headers),
                'body': await response.text()
            }
            
            if response.status >= 400:
                raise Exception(f"HTTP request failed with status {response.status}")
            
            return result
    
    async def _execute_siem_alert(self, action: PlaybookAction, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute SIEM alert action."""
        config = action.config
        session = context['session']
        
        # Create SIEM alert payload
        alert_payload = {
            'alert_id': str(uuid.uuid4()),
            'severity': config.get('severity', 'medium'),
            'category': config.get('category', 'security_incident'),
            'title': f"CerberusMesh Threat Detection - {session['source_ip']}",
            'description': f"Threat detected in session {session['session_id']}",
            'source_ip': session['source_ip'],
            'threat_level': session.get('threat_level', {}).get('name', 'unknown'),
            'cvss_score': session.get('cvss_score', 0),
            'mitre_techniques': session.get('mitre_techniques', []),
            'timestamp': datetime.utcnow().isoformat(),
            'source_system': 'cerberusmesh'
        }
        
        # Send to Kafka for SIEM consumption
        await self.kafka_producer.send('cerberus.siem.alert', alert_payload)
        
        return {'alert_id': alert_payload['alert_id'], 'status': 'sent'}
    
    async def _execute_block_ip(self, action: PlaybookAction, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute IP blocking action."""
        config = action.config
        session = context['session']
        
        block_request = {
            'action': 'block_ip',
            'ip_address': session['source_ip'],
            'duration': config.get('duration', 3600),
            'scope': config.get('scope', ['firewall']),
            'reason': f"Automated block from playbook {context['playbook']['name']}",
            'session_id': session['session_id'],
            'timestamp': datetime.utcnow().isoformat()
        }
        
        # Send to security orchestration platform
        await self.kafka_producer.send('cerberus.security.block_request', block_request)
        
        return {'block_id': str(uuid.uuid4()), 'ip_address': session['source_ip'], 'status': 'requested'}
    
    async def _execute_threat_intel_update(self, action: PlaybookAction, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute threat intelligence update action."""
        config = action.config
        session = context['session']
        
        intel_updates = []
        for ioc in session.get('iocs_extracted', []):
            intel_entry = {
                'ioc_type': ioc.get('type'),
                'ioc_value': ioc.get('value'),
                'confidence': config.get('confidence', 'medium'),
                'tlp': config.get('tlp', 'white'),
                'source': 'cerberusmesh_honeypot',
                'first_seen': session.get('created_at'),
                'threat_level': session.get('threat_level', {}).get('name'),
                'context': f"Observed in honeypot session {session['session_id']}"
            }
            intel_updates.append(intel_entry)
        
        # Send to threat intelligence platform
        await self.kafka_producer.send('cerberus.threat_intel.update', {
            'updates': intel_updates,
            'platforms': config.get('platforms', ['splunk']),
            'timestamp': datetime.utcnow().isoformat()
        })
        
        return {'updates_count': len(intel_updates), 'status': 'sent'}
    
    async def _execute_email_notification(self, action: PlaybookAction, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute email notification action."""
        config = action.config
        session = context['session']
        
        email_payload = {
            'to': config['recipients'],
            'subject': f"CerberusMesh Security Alert - {session['source_ip']}",
            'template': config.get('template', 'default_alert'),
            'priority': config.get('priority', 'normal'),
            'data': {
                'session': session,
                'threat_level': session.get('threat_level', {}).get('name'),
                'cvss_score': session.get('cvss_score'),
                'source_ip': session['source_ip'],
                'timestamp': datetime.utcnow().isoformat()
            }
        }
        
        # Send to email service
        await self.kafka_producer.send('cerberus.notification.email', email_payload)
        
        return {'message_id': str(uuid.uuid4()), 'recipients': len(config['recipients']), 'status': 'queued'}
    
    async def _execute_slack_message(self, action: PlaybookAction, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute Slack message action."""
        config = action.config
        
        # Slack webhook URL should be in config
        webhook_url = self.config.get('slack_webhook_url')
        if not webhook_url:
            raise Exception("Slack webhook URL not configured")
        
        payload = {
            'channel': config.get('channel', '#security'),
            'text': config['message'],
            'attachments': config.get('attachments', [])
        }
        
        async with self.http_session.post(webhook_url, json=payload) as response:
            if response.status != 200:
                raise Exception(f"Slack message failed with status {response.status}")
        
        return {'status': 'sent', 'channel': config.get('channel')}
    
    async def _execute_custom_script(self, action: PlaybookAction, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute custom script action."""
        config = action.config
        
        # For security, only allow scripts from approved directory
        script_path = config['script_path']
        approved_dir = self.config.get('approved_scripts_dir', '/opt/cerberus/scripts/')
        
        if not script_path.startswith(approved_dir):
            raise Exception(f"Script not in approved directory: {script_path}")
        
        # Execute script asynchronously
        import subprocess
        result = await asyncio.create_subprocess_exec(
            'python3', script_path, *config.get('args', []),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await result.communicate()
        
        return {
            'return_code': result.returncode,
            'stdout': stdout.decode(),
            'stderr': stderr.decode(),
            'script_path': script_path
        }
    
    async def _execute_aws_action(self, action: PlaybookAction, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute AWS action."""
        config = action.config
        
        # AWS actions would integrate with boto3
        # This is a placeholder for AWS integrations
        aws_action = {
            'service': config.get('service', 'ec2'),
            'action': config.get('action'),
            'parameters': config.get('parameters', {}),
            'region': config.get('region', 'us-east-1')
        }
        
        # Send to AWS orchestration service
        await self.kafka_producer.send('cerberus.aws.action', aws_action)
        
        return {'action_id': str(uuid.uuid4()), 'status': 'requested'}
    
    async def _execute_containment(self, action: PlaybookAction, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute containment action."""
        config = action.config
        session = context['session']
        
        containment_actions = []
        
        # Network containment
        if 'network' in config.get('scope', []):
            containment_actions.append({
                'type': 'network_isolation',
                'ip_address': session['source_ip'],
                'duration': config.get('duration', 3600)
            })
        
        # Honeypot containment
        if 'honeypot' in config.get('scope', []):
            containment_actions.append({
                'type': 'honeypot_isolation',
                'honeypot_id': session['honeypot_id'],
                'action': 'quarantine'
            })
        
        # Send containment requests
        for containment_action in containment_actions:
            await self.kafka_producer.send('cerberus.containment.action', containment_action)
        
        return {'actions': containment_actions, 'status': 'initiated'}
    
    async def _send_execution_event(self, playbook: SOARPlaybook, event_type: str, data: Dict[str, Any]):
        """Send playbook execution event."""
        event = {
            'event_type': f'playbook.{event_type}',
            'execution_id': playbook.execution_id,
            'playbook_name': playbook.name,
            'status': playbook.status.value,
            'data': data,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        await self.kafka_producer.send('cerberus.playbook.events', event)
    
    async def _send_action_event(self, action: PlaybookAction, context: Dict[str, Any]):
        """Send action execution event."""
        event = {
            'event_type': 'action.completed',
            'action_id': action.action_id,
            'action_name': action.name,
            'action_type': action.action_type.value,
            'status': action.status.value,
            'execution_time': (action.completed_at - action.started_at).total_seconds() if action.completed_at and action.started_at else 0,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        await self.kafka_producer.send('cerberus.action.events', event)
    
    def get_execution_status(self, execution_id: str) -> Optional[Dict[str, Any]]:
        """Get execution status."""
        if execution_id in self.active_executions:
            playbook = self.active_executions[execution_id]
            return {
                'execution_id': execution_id,
                'playbook_name': playbook.name,
                'status': playbook.status.value,
                'actions': [
                    {
                        'name': action.name,
                        'status': action.status.value,
                        'started_at': action.started_at.isoformat() if action.started_at else None,
                        'completed_at': action.completed_at.isoformat() if action.completed_at else None
                    }
                    for action in playbook.actions
                ]
            }
        return None
    
    def list_playbooks(self) -> List[Dict[str, Any]]:
        """List all available playbooks."""
        return [
            {
                'playbook_id': playbook_id,
                'name': playbook.name,
                'description': playbook.description,
                'threat_level_threshold': playbook.threat_level_threshold,
                'actions_count': len(playbook.actions),
                'tags': playbook.tags
            }
            for playbook_id, playbook in self.playbooks.items()
        ]
    
    async def get_metrics(self) -> Dict[str, Any]:
        """Get SOAR engine metrics."""
        return {
            **self.metrics,
            'active_executions': len(self.active_executions),
            'total_playbooks': len(self.playbooks),
            'avg_execution_time': self.metrics['total_execution_time'] / max(self.metrics['executions_completed'], 1)
        }
    
    async def shutdown(self):
        """Graceful shutdown of the SOAR engine."""
        logger.info("Shutting down SOAR Playbook Engine...")
        
        # Cancel active executions
        for execution_id in list(self.active_executions.keys()):
            execution = self.active_executions[execution_id]
            execution.status = PlaybookStatus.CANCELLED
            del self.active_executions[execution_id]
        
        # Close HTTP session
        if self.http_session:
            await self.http_session.close()
        
        # Close Kafka producer
        if self.kafka_producer:
            await self.kafka_producer.stop()
        
        logger.info("SOAR Playbook Engine shutdown complete")

# Example YAML playbook configuration
EXAMPLE_PLAYBOOK_YAML = """
name: "Custom Incident Response"
description: "Custom incident response playbook for specific threat types"
version: "1.0"
threat_level_threshold: 2
parallel_execution: true
max_execution_time: 1800

trigger_conditions:
  mitre_techniques:
    - "T1059"  # Command and Scripting Interpreter
    - "T1190"  # Exploit Public-Facing Application

actions:
  - action_type: "siem_alert"
    name: "Create High Priority Alert"
    description: "Create high priority alert in SIEM"
    config:
      severity: "high"
      category: "targeted_attack"
    
  - action_type: "block_ip"
    name: "Block Attacker IP"
    description: "Block the attacking IP address"
    config:
      duration: 86400
      scope: ["firewall", "proxy"]
    
  - action_type: "threat_intel_update"
    name: "Update Threat Intelligence"
    description: "Add IOCs to threat intel platforms"
    config:
      platforms: ["splunk", "misp"]
      confidence: "high"
    depends_on: ["Create High Priority Alert"]
    
  - action_type: "email_notification"
    name: "Notify Security Team"
    description: "Send email notification to security team"
    config:
      recipients: ["security-team@company.com"]
      template: "incident_notification"
      priority: "urgent"
    condition: "{{ session.cvss_score > 7.0 }}"

tags:
  - "incident_response"
  - "automated"
  - "high_priority"
"""

if __name__ == "__main__":
    
    # Configuration
    config = {
        'kafka_servers': 'localhost:9092',
        'slack_webhook_url': 'https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK',
        'approved_scripts_dir': '/opt/cerberus/scripts/'
    }
    
    async def main():
        """Main execution function."""
        
        # Initialize SOAR engine
        soar_engine = SOARPlaybookEngine(config)
        await soar_engine.initialize()
        
        # Load custom playbook from YAML
        custom_playbook = await soar_engine.load_playbook_from_yaml(EXAMPLE_PLAYBOOK_YAML)
        
        # Example session context (from adversary session manager)
        session_context = {
            'session_id': 'session_12345',
            'source_ip': '192.168.1.100',
            'threat_level': {'name': 'HIGH', 'value': 3},
            'cvss_score': 8.5,
            'mitre_techniques': ['T1059.003', 'T1190'],
            'iocs_extracted': [
                {'type': 'ip', 'value': '192.168.1.100'},
                {'type': 'domain', 'value': 'malicious-site.com'}
            ],
            'honeypot_id': 'honey-ssh-01',
            'created_at': datetime.utcnow().isoformat()
        }
        
        # Execute playbook
        execution_id = await soar_engine.execute_playbook(custom_playbook.playbook_id, session_context)
        
        # Monitor execution
        await asyncio.sleep(10)  # Allow execution to complete
        
        # Get execution status
        status = soar_engine.get_execution_status(execution_id)
        print("Execution Status:", json.dumps(status, indent=2))
        
        # Get metrics
        metrics = await soar_engine.get_metrics()
        print("SOAR Metrics:", json.dumps(metrics, indent=2))
        
        # Graceful shutdown
        await soar_engine.shutdown()
    
    # Run the example
    asyncio.run(main())
