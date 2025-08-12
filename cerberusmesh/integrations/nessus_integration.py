#!/usr/bin/env python3
"""
CerberusMesh Nessus Integration

Provides vulnerability scanning integration including:
- Automated scanning of honeypot infrastructure
- Vulnerability correlation with attack patterns
- Security posture monitoring
- Compliance reporting
"""

import json
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
import asyncio
import aiohttp
import base64

logger = logging.getLogger(__name__)

@dataclass
class NessusTarget:
    """Target for Nessus scanning."""
    name: str
    targets: List[str]  # IP addresses or hostnames
    policy_id: str
    scan_frequency: str  # cron expression

@dataclass
class NessusVulnerability:
    """Nessus vulnerability finding."""
    plugin_id: str
    plugin_name: str
    severity: str
    cvss_score: float
    cve_list: List[str]
    host: str
    port: int
    protocol: str
    description: str
    solution: str
    first_found: datetime
    last_found: datetime

@dataclass
class NessusScanResult:
    """Complete scan result."""
    scan_id: str
    scan_name: str
    status: str
    start_time: datetime
    end_time: Optional[datetime]
    targets: List[str]
    vulnerabilities: List[NessusVulnerability]
    summary: Dict[str, int]

class NessusIntegration:
    """Nessus vulnerability scanner integration."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize Nessus integration."""
        self.config = config
        self.nessus_host = config.get("nessus_host", "localhost")
        self.nessus_port = config.get("nessus_port", 8834)
        self.access_key = config.get("access_key")
        self.secret_key = config.get("secret_key")
        self.verify_ssl = config.get("verify_ssl", True)
        
        # Scan policies
        self.scan_policies = {
            "honeypot_baseline": {
                "name": "CerberusMesh Honeypot Baseline",
                "description": "Security baseline scan for honeypot infrastructure",
                "template": "basic"
            },
            "honeypot_deep": {
                "name": "CerberusMesh Deep Scan", 
                "description": "Comprehensive vulnerability assessment",
                "template": "advanced"
            },
            "compliance_check": {
                "name": "CerberusMesh Compliance",
                "description": "Compliance and configuration audit",
                "template": "policy_compliance"
            }
        }
        
        self.session = None
        self.token = None
        
        if not self.access_key or not self.secret_key:
            logger.warning("Nessus API keys not provided - integration disabled")
    
    async def initialize(self):
        """Initialize async components and authenticate."""
        connector = aiohttp.TCPConnector(verify_ssl=self.verify_ssl)
        self.session = aiohttp.ClientSession(connector=connector)
        
        if self.access_key and self.secret_key:
            await self._authenticate()
    
    async def close(self):
        """Close async components."""
        if self.session:
            await self.session.close()
    
    async def _authenticate(self) -> bool:
        """Authenticate with Nessus API."""
        try:
            url = f"https://{self.nessus_host}:{self.nessus_port}/session"
            auth_data = {
                "username": self.access_key,
                "password": self.secret_key
            }
            
            async with self.session.post(url, json=auth_data) as response:
                if response.status == 200:
                    data = await response.json()
                    self.token = data.get("token")
                    logger.info("Successfully authenticated with Nessus")
                    return True
                else:
                    logger.error(f"Nessus authentication failed: {response.status}")
                    return False
                    
        except Exception as e:
            logger.error(f"Nessus authentication error: {e}")
            return False
    
    async def _make_request(self, method: str, endpoint: str, data: Dict = None) -> Optional[Dict]:
        """Make authenticated request to Nessus API."""
        if not self.token:
            logger.error("Not authenticated with Nessus")
            return None
            
        try:
            url = f"https://{self.nessus_host}:{self.nessus_port}{endpoint}"
            headers = {"X-API-Token": self.token}
            
            async with self.session.request(method, url, headers=headers, json=data) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    logger.error(f"Nessus API error: {response.status} - {await response.text()}")
                    return None
                    
        except Exception as e:
            logger.error(f"Nessus request error: {e}")
            return None
    
    async def create_scan_policy(self, policy_name: str, template_uuid: str = None) -> Optional[str]:
        """Create custom scan policy."""
        if policy_name not in self.scan_policies:
            logger.error(f"Unknown policy: {policy_name}")
            return None
            
        policy_config = self.scan_policies[policy_name]
        
        # Get available templates if not specified
        if not template_uuid:
            templates = await self._make_request("GET", "/editor/policy/templates")
            if templates:
                # Find template by name
                for template in templates.get("templates", []):
                    if template.get("name", "").lower() == policy_config["template"]:
                        template_uuid = template.get("uuid")
                        break
        
        if not template_uuid:
            logger.error(f"Could not find template for policy: {policy_name}")
            return None
        
        # Create policy
        policy_data = {
            "uuid": template_uuid,
            "settings": {
                "name": policy_config["name"],
                "description": policy_config["description"],
                "text_targets": "",
                "launch": "ONETIME",
                "enabled": "true",
                "scanner_id": "1"
            }
        }
        
        result = await self._make_request("POST", "/policies", policy_data)
        if result:
            policy_id = result.get("policy", {}).get("id")
            logger.info(f"Created scan policy: {policy_config['name']} (ID: {policy_id})")
            return policy_id
        
        return None
    
    async def create_scan(self, name: str, targets: List[str], policy_id: str) -> Optional[str]:
        """Create new vulnerability scan."""
        scan_data = {
            "uuid": policy_id,
            "settings": {
                "name": name,
                "description": f"CerberusMesh scan: {name}",
                "text_targets": ",".join(targets),
                "launch": "ONETIME",
                "enabled": "true"
            }
        }
        
        result = await self._make_request("POST", "/scans", scan_data)
        if result:
            scan_id = result.get("scan", {}).get("id")
            logger.info(f"Created scan: {name} (ID: {scan_id})")
            return scan_id
        
        return None
    
    async def launch_scan(self, scan_id: str) -> bool:
        """Launch vulnerability scan."""
        result = await self._make_request("POST", f"/scans/{scan_id}/launch")
        if result:
            logger.info(f"Launched scan: {scan_id}")
            return True
        return False
    
    async def get_scan_status(self, scan_id: str) -> Optional[str]:
        """Get scan status."""
        result = await self._make_request("GET", f"/scans/{scan_id}")
        if result:
            return result.get("info", {}).get("status")
        return None
    
    async def get_scan_results(self, scan_id: str) -> Optional[NessusScanResult]:
        """Get detailed scan results."""
        result = await self._make_request("GET", f"/scans/{scan_id}")
        if not result:
            return None
        
        scan_info = result.get("info", {})
        vulnerabilities = []
        
        # Process vulnerability findings
        for vuln in result.get("vulnerabilities", []):
            vulnerability = NessusVulnerability(
                plugin_id=str(vuln.get("plugin_id", "")),
                plugin_name=vuln.get("plugin_name", ""),
                severity=self._severity_map(vuln.get("severity", 0)),
                cvss_score=float(vuln.get("cvss_base_score", 0.0)),
                cve_list=vuln.get("cve", []),
                host=vuln.get("hostname", ""),
                port=vuln.get("port", 0),
                protocol=vuln.get("protocol", ""),
                description=vuln.get("description", ""),
                solution=vuln.get("solution", ""),
                first_found=datetime.fromtimestamp(vuln.get("first_found", time.time())),
                last_found=datetime.fromtimestamp(vuln.get("last_found", time.time()))
            )
            vulnerabilities.append(vulnerability)
        
        # Create summary
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for vuln in vulnerabilities:
            severity_counts[vuln.severity] += 1
        
        return NessusScanResult(
            scan_id=scan_id,
            scan_name=scan_info.get("name", ""),
            status=scan_info.get("status", ""),
            start_time=datetime.fromtimestamp(scan_info.get("timestamp", time.time())),
            end_time=datetime.fromtimestamp(scan_info.get("scan_end", time.time())) if scan_info.get("scan_end") else None,
            targets=scan_info.get("targets", "").split(","),
            vulnerabilities=vulnerabilities,
            summary=severity_counts
        )
    
    def _severity_map(self, nessus_severity: int) -> str:
        """Map Nessus severity numbers to strings."""
        severity_map = {
            0: "info",
            1: "low", 
            2: "medium",
            3: "high",
            4: "critical"
        }
        return severity_map.get(nessus_severity, "info")
    
    async def scan_honeypot_infrastructure(self, honeypot_ips: List[str]) -> List[NessusScanResult]:
        """Perform comprehensive vulnerability scan of honeypot infrastructure."""
        results = []
        
        # Create baseline scan
        baseline_policy = await self.create_scan_policy("honeypot_baseline")
        if baseline_policy:
            scan_id = await self.create_scan("Honeypot Baseline Scan", honeypot_ips, baseline_policy)
            if scan_id:
                await self.launch_scan(scan_id)
                
                # Wait for completion (with timeout)
                timeout = 3600  # 1 hour timeout
                start_time = time.time()
                
                while time.time() - start_time < timeout:
                    status = await self.get_scan_status(scan_id)
                    if status == "completed":
                        result = await self.get_scan_results(scan_id)
                        if result:
                            results.append(result)
                        break
                    elif status == "aborted" or status == "canceled":
                        logger.error(f"Scan {scan_id} was aborted")
                        break
                    
                    await asyncio.sleep(30)  # Check every 30 seconds
        
        return results
    
    async def correlate_with_attacks(self, vulnerabilities: List[NessusVulnerability], 
                                   attack_patterns: List[Dict]) -> List[Dict[str, Any]]:
        """Correlate vulnerabilities with observed attack patterns."""
        correlations = []
        
        for vuln in vulnerabilities:
            for pattern in attack_patterns:
                correlation_score = 0.0
                reasons = []
                
                # Check CVE matches
                pattern_cves = pattern.get("cves", [])
                vuln_cves = vuln.cve_list
                common_cves = set(pattern_cves).intersection(set(vuln_cves))
                if common_cves:
                    correlation_score += 0.8
                    reasons.append(f"CVE match: {', '.join(common_cves)}")
                
                # Check port/service matches
                if pattern.get("target_port") == vuln.port:
                    correlation_score += 0.3
                    reasons.append(f"Port match: {vuln.port}")
                
                # Check severity alignment
                attack_severity = pattern.get("severity", "medium")
                if attack_severity == vuln.severity:
                    correlation_score += 0.2
                    reasons.append(f"Severity match: {vuln.severity}")
                
                # Check MITRE technique overlap
                pattern_techniques = pattern.get("mitre_techniques", [])
                vuln_techniques = self._map_vuln_to_mitre(vuln)
                common_techniques = set(pattern_techniques).intersection(set(vuln_techniques))
                if common_techniques:
                    correlation_score += 0.4
                    reasons.append(f"MITRE technique match: {', '.join(common_techniques)}")
                
                # If correlation is significant, add to results
                if correlation_score >= 0.5:
                    correlations.append({
                        "vulnerability": vuln,
                        "attack_pattern": pattern,
                        "correlation_score": correlation_score,
                        "correlation_reasons": reasons,
                        "risk_amplification": correlation_score * vuln.cvss_score,
                        "recommended_actions": self._get_correlation_actions(vuln, pattern)
                    })
        
        return sorted(correlations, key=lambda x: x["risk_amplification"], reverse=True)
    
    def _map_vuln_to_mitre(self, vuln: NessusVulnerability) -> List[str]:
        """Map vulnerability to potential MITRE techniques."""
        # Simplified mapping - in production, use comprehensive CVE->MITRE database
        technique_map = {
            "ssh": ["T1021.004"],  # Remote Services: SSH
            "rdp": ["T1021.001"],  # Remote Services: Remote Desktop Protocol
            "web": ["T1190"],      # Exploit Public-Facing Application
            "ftp": ["T1021.002"],  # Remote Services: SMB/Windows Admin Shares
            "smtp": ["T1566"],     # Phishing
            "dns": ["T1071.004"]   # Application Layer Protocol: DNS
        }
        
        techniques = []
        service_name = vuln.plugin_name.lower()
        
        for service, techs in technique_map.items():
            if service in service_name:
                techniques.extend(techs)
        
        return techniques
    
    def _get_correlation_actions(self, vuln: NessusVulnerability, pattern: Dict) -> List[str]:
        """Get recommended actions for vulnerability-attack correlation."""
        actions = []
        
        if vuln.severity in ["critical", "high"]:
            actions.append("Immediate patching required")
            actions.append("Implement additional monitoring")
        
        if pattern.get("frequency", 0) > 10:
            actions.append("Deploy additional honeypots")
            actions.append("Enhance detection rules")
        
        if vuln.cvss_score >= 7.0:
            actions.append("Consider service isolation")
            actions.append("Implement compensating controls")
        
        return actions
    
    def generate_compliance_report(self, scan_results: List[NessusScanResult]) -> Dict[str, Any]:
        """Generate compliance report from scan results."""
        total_vulns = sum(len(result.vulnerabilities) for result in scan_results)
        critical_vulns = sum(result.summary.get("critical", 0) for result in scan_results)
        high_vulns = sum(result.summary.get("high", 0) for result in scan_results)
        
        compliance_score = max(0, 100 - (critical_vulns * 10 + high_vulns * 5))
        
        return {
            "scan_summary": {
                "total_scans": len(scan_results),
                "total_vulnerabilities": total_vulns,
                "critical_vulnerabilities": critical_vulns,
                "high_vulnerabilities": high_vulns,
                "compliance_score": compliance_score
            },
            "risk_assessment": {
                "overall_risk": "high" if critical_vulns > 0 else "medium" if high_vulns > 5 else "low",
                "critical_systems": [result.scan_name for result in scan_results if result.summary.get("critical", 0) > 0],
                "remediation_priority": self._prioritize_remediation(scan_results)
            },
            "recommendations": self._generate_recommendations(scan_results),
            "next_scan_date": (datetime.now() + timedelta(days=7)).isoformat()
        }
    
    def _prioritize_remediation(self, scan_results: List[NessusScanResult]) -> List[Dict[str, Any]]:
        """Prioritize vulnerability remediation."""
        priority_list = []
        
        for result in scan_results:
            for vuln in result.vulnerabilities:
                if vuln.severity in ["critical", "high"]:
                    priority_list.append({
                        "host": vuln.host,
                        "vulnerability": vuln.plugin_name,
                        "severity": vuln.severity,
                        "cvss_score": vuln.cvss_score,
                        "cve_list": vuln.cve_list,
                        "priority_score": vuln.cvss_score * (2 if vuln.severity == "critical" else 1)
                    })
        
        return sorted(priority_list, key=lambda x: x["priority_score"], reverse=True)[:20]
    
    def _generate_recommendations(self, scan_results: List[NessusScanResult]) -> List[str]:
        """Generate security recommendations."""
        recommendations = []
        
        total_critical = sum(result.summary.get("critical", 0) for result in scan_results)
        total_high = sum(result.summary.get("high", 0) for result in scan_results)
        
        if total_critical > 0:
            recommendations.append(f"Immediately address {total_critical} critical vulnerabilities")
            recommendations.append("Implement emergency patching procedures")
        
        if total_high > 5:
            recommendations.append(f"Prioritize remediation of {total_high} high-severity vulnerabilities")
            recommendations.append("Review security hardening procedures")
        
        recommendations.extend([
            "Implement regular vulnerability scanning schedule",
            "Establish vulnerability management process",
            "Consider implementing additional security controls",
            "Review and update incident response procedures"
        ])
        
        return recommendations
