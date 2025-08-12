#!/usr/bin/env python3
"""
CerberusMesh Splunk Integration

Provides comprehensive Splunk SIEM integration including:
- Real-time event forwarding to Splunk
- SPL query generation for threat hunting
- Custom dashboards and alerts
- Automated incident response workflows
"""

import json
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
import asyncio
import aiohttp
import hashlib
import base64

logger = logging.getLogger(__name__)

@dataclass
class SplunkEvent:
    """Structure for Splunk event data."""
    time: float
    host: str
    source: str
    sourcetype: str
    index: str
    event: Dict[str, Any]

@dataclass
class SplunkAlert:
    """Structure for Splunk alert configuration."""
    name: str
    search: str
    cron_schedule: str
    actions: List[str]
    severity: str

class SplunkIntegration:
    """Splunk SIEM integration for CerberusMesh."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize Splunk integration."""
        self.config = config
        self.splunk_host = config.get("splunk_host", "localhost")
        self.splunk_port = config.get("splunk_port", 8088)
        self.hec_token = config.get("hec_token")
        self.index = config.get("index", "cerberusmesh")
        self.verify_ssl = config.get("verify_ssl", True)
        
        # SPL templates for common queries
        self.spl_templates = self._init_spl_templates()
        
        # Setup HTTP session
        self.session = None
        
        if not self.hec_token:
            logger.warning("Splunk HEC token not provided - integration disabled")
            
    async def initialize(self):
        """Initialize async components."""
        connector = aiohttp.TCPConnector(verify_ssl=self.verify_ssl)
        self.session = aiohttp.ClientSession(connector=connector)
        
    async def close(self):
        """Close async components."""
        if self.session:
            await self.session.close()
    
    def _init_spl_templates(self) -> Dict[str, str]:
        """Initialize SPL query templates for threat hunting."""
        return {
            "honeypot_connections": '''
index={index} sourcetype="cerberusmesh:session"
| eval connection_time=strftime(_time, "%Y-%m-%d %H:%M:%S")
| stats count by src_ip, honeypot_id, protocol, dest_port
| sort -count
| head 100
''',
            
            "suspicious_commands": '''
index={index} sourcetype="cerberusmesh:command" 
| search command IN ("wget", "curl", "nc", "ncat", "python", "perl", "bash", "/bin/sh")
| eval cmd_category=case(
    match(command, "wget|curl"), "download",
    match(command, "nc|ncat"), "network",
    match(command, "python|perl"), "script",
    match(command, "bash|sh"), "shell",
    1==1, "other"
)
| stats count by src_ip, cmd_category, command
| sort -count
''',
            
            "credential_attacks": '''
index={index} sourcetype="cerberusmesh:auth"
| eval auth_result=if(success="true", "success", "failure")
| stats count by src_ip, username, auth_result
| where count > 5
| sort -count
''',
            
            "file_transfers": '''
index={index} sourcetype="cerberusmesh:file"
| eval file_size_mb=round(file_size/1024/1024, 2)
| stats sum(file_size_mb) as total_mb, count by src_ip, direction
| sort -total_mb
''',
            
            "geographic_analysis": '''
index={index} sourcetype="cerberusmesh:session"
| iplocation src_ip
| stats count by Country, Region, City, src_ip
| geostats count by Country
''',
            
            "attack_timeline": '''
index={index} sourcetype="cerberusmesh:*"
| eval hour=strftime(_time, "%H")
| stats count by hour, event_type
| chart count over hour by event_type
''',
            
            "mitre_techniques": '''
index={index} sourcetype="cerberusmesh:mitre"
| stats count by technique_id, technique_name, tactic
| sort -count
| head 20
''',
            
            "threat_scores": '''
index={index} sourcetype="cerberusmesh:threat"
| eval threat_level=case(
    threat_score >= 0.8, "critical",
    threat_score >= 0.6, "high", 
    threat_score >= 0.4, "medium",
    1==1, "low"
)
| stats count by threat_level, src_ip
| sort -count
''',
            
            "agent_decisions": '''
index={index} sourcetype="cerberusmesh:decision"
| stats count by decision_type, confidence_range=case(
    confidence >= 0.8, "high",
    confidence >= 0.6, "medium",
    1==1, "low"
)
| chart count over decision_type by confidence_range
''',
            
            "anomaly_detection": '''
index={index} sourcetype="cerberusmesh:session"
| bucket _time span=1h
| stats dc(src_ip) as unique_ips, count as total_connections by _time
| eval connections_per_ip=round(total_connections/unique_ips, 2)
| where connections_per_ip > 10 OR unique_ips > 100
| sort -_time
'''
        }
    
    async def send_event(self, event_data: Dict[str, Any], sourcetype: str = "cerberusmesh:generic") -> bool:
        """Send single event to Splunk HEC."""
        if not self.hec_token or not self.session:
            return False
            
        try:
            splunk_event = SplunkEvent(
                time=time.time(),
                host=event_data.get("honeypot_id", "cerberusmesh"),
                source="cerberusmesh",
                sourcetype=sourcetype,
                index=self.index,
                event=event_data
            )
            
            url = f"https://{self.splunk_host}:{self.splunk_port}/services/collector/event"
            headers = {
                "Authorization": f"Splunk {self.hec_token}",
                "Content-Type": "application/json"
            }
            
            async with self.session.post(url, headers=headers, json=asdict(splunk_event)) as response:
                if response.status == 200:
                    logger.debug(f"Event sent to Splunk: {sourcetype}")
                    return True
                else:
                    logger.error(f"Splunk HEC error: {response.status} - {await response.text()}")
                    return False
                    
        except Exception as e:
            logger.error(f"Failed to send event to Splunk: {e}")
            return False
    
    async def send_batch_events(self, events: List[Dict[str, Any]], sourcetype: str = "cerberusmesh:batch") -> bool:
        """Send multiple events to Splunk in batch."""
        if not self.hec_token or not self.session:
            return False
            
        try:
            # Prepare batch payload
            batch_data = []
            for event_data in events:
                splunk_event = {
                    "time": time.time(),
                    "host": event_data.get("honeypot_id", "cerberusmesh"),
                    "source": "cerberusmesh",
                    "sourcetype": sourcetype,
                    "index": self.index,
                    "event": event_data
                }
                batch_data.append(splunk_event)
            
            # Send to HEC
            url = f"https://{self.splunk_host}:{self.splunk_port}/services/collector/event"
            headers = {
                "Authorization": f"Splunk {self.hec_token}",
                "Content-Type": "application/json"
            }
            
            # Send as newline-delimited JSON
            payload = "\n".join([json.dumps(event) for event in batch_data])
            
            async with self.session.post(url, headers=headers, data=payload) as response:
                if response.status == 200:
                    logger.info(f"Batch of {len(events)} events sent to Splunk")
                    return True
                else:
                    logger.error(f"Splunk batch error: {response.status}")
                    return False
                    
        except Exception as e:
            logger.error(f"Failed to send batch to Splunk: {e}")
            return False
    
    def generate_spl_query(self, template_name: str, **kwargs) -> str:
        """Generate SPL query from template."""
        if template_name not in self.spl_templates:
            raise ValueError(f"Unknown SPL template: {template_name}")
        
        # Set default values
        kwargs.setdefault("index", self.index)
        kwargs.setdefault("time_range", "last 24h")
        
        return self.spl_templates[template_name].format(**kwargs).strip()
    
    def create_custom_spl(self, base_template: str, filters: Dict[str, Any]) -> str:
        """Create custom SPL query with additional filters."""
        spl = base_template.format(index=self.index)
        
        # Add filters
        for field, value in filters.items():
            if isinstance(value, list):
                value_str = " OR ".join([f'"{v}"' for v in value])
                spl += f'\n| search {field} IN ({value_str})'
            else:
                spl += f'\n| search {field}="{value}"'
        
        return spl
    
    async def execute_search(self, spl_query: str, max_results: int = 1000) -> Dict[str, Any]:
        """Execute SPL search and return results (requires Splunk REST API access)."""
        # Note: This requires additional Splunk REST API credentials
        # Implementation would depend on specific Splunk setup
        logger.info(f"Would execute SPL: {spl_query[:100]}...")
        return {"message": "SPL execution requires Splunk REST API setup"}
    
    def create_alert_config(self, name: str, spl_query: str, schedule: str = "*/15 * * * *") -> SplunkAlert:
        """Create Splunk alert configuration."""
        return SplunkAlert(
            name=f"CerberusMesh - {name}",
            search=spl_query,
            cron_schedule=schedule,
            actions=["email", "webhook"],
            severity="medium"
        )
    
    def get_dashboard_panels(self) -> List[Dict[str, Any]]:
        """Generate Splunk dashboard panel configurations."""
        return [
            {
                "title": "Connection Activity",
                "type": "chart",
                "search": self.generate_spl_query("honeypot_connections"),
                "visualization": "column_chart"
            },
            {
                "title": "Threat Score Distribution", 
                "type": "chart",
                "search": self.generate_spl_query("threat_scores"),
                "visualization": "pie_chart"
            },
            {
                "title": "MITRE Techniques",
                "type": "table",
                "search": self.generate_spl_query("mitre_techniques"),
                "visualization": "statistics"
            },
            {
                "title": "Geographic Analysis",
                "type": "map",
                "search": self.generate_spl_query("geographic_analysis"),
                "visualization": "cluster_map"
            }
        ]
    
    # CerberusMesh-specific event formatters
    def format_intrusion_event(self, event) -> Dict[str, Any]:
        """Format intrusion event for Splunk."""
        return {
            "event_id": event.event_id,
            "timestamp": event.timestamp.isoformat(),
            "honeypot_id": event.honeypot_id,
            "src_ip": event.source_ip,
            "event_type": event.event_type,
            "protocol": event.protocol,
            "dest_port": event.destination_port,
            "session_id": event.session_id,
            "username": event.username,
            "password": event.password,
            "command": event.command,
            "payload_size": len(event.payload or ""),
            "severity": event.severity
        }
    
    def format_decision_event(self, decision) -> Dict[str, Any]:
        """Format agent decision for Splunk."""
        return {
            "decision_id": decision.decision_id,
            "timestamp": decision.timestamp.isoformat(),
            "event_id": decision.event_id,
            "decision_type": decision.decision_type,
            "confidence": decision.confidence,
            "reasoning": decision.reasoning,
            "mitre_techniques": decision.mitre_techniques,
            "action_taken": decision.action_taken,
            "result": decision.result,
            "execution_time": decision.execution_time
        }
    
    def format_threat_context(self, threat_context) -> Dict[str, Any]:
        """Format threat context for Splunk."""
        return {
            "event_id": threat_context.event.event_id,
            "timestamp": threat_context.event.timestamp.isoformat(),
            "src_ip": threat_context.event.source_ip,
            "threat_score": threat_context.threat_score,
            "behavioral_patterns": threat_context.behavioral_patterns,
            "mitre_technique": threat_context.mitre_mapping.technique,
            "mitre_tactic": threat_context.mitre_mapping.tactic,
            "kill_chain_phase": threat_context.mitre_mapping.kill_chain_phase,
            "llm_reasoning": threat_context.llm_analysis.get("reasoning", ""),
            "recommendations": threat_context.recommendations
        }
