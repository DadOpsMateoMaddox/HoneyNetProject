#!/usr/bin/env python3
"""
CerberusMesh MITRE ATT&CK Mapper - Maps IOCs and attack patterns to MITRE ATT&CK framework.

This module provides:
- IOC to MITRE technique mapping
- Attack pattern recognition
- Tactic and technique enrichment
- Enterprise matrix coverage analysis
"""

import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, asdict
from pathlib import Path
import re

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class MitreTechnique:
    """Structure for MITRE ATT&CK technique information."""
    technique_id: str
    name: str
    description: str
    tactic: str
    sub_techniques: List[str]
    platforms: List[str]
    data_sources: List[str]
    mitigations: List[str]
    detection_methods: List[str]

@dataclass
class AttackMapping:
    """Structure for attack pattern to MITRE mapping."""
    ioc_value: str
    ioc_type: str
    attack_pattern: str
    confidence_score: float
    mapped_techniques: List[MitreTechnique]
    kill_chain_phase: str
    timestamp: datetime

class MitreMapper:
    """Maps IOCs and attack patterns to MITRE ATT&CK techniques."""
    
    def __init__(self):
        """Initialize the MITRE mapper with technique database."""
        self.techniques_db = {}
        self.pattern_mappings = {}
        self.ioc_mappings = {}
        
        # Load MITRE data
        self._load_mitre_data()
        self._load_pattern_mappings()
        
        logger.info("MITRE mapper initialized")
    
    def _load_mitre_data(self):
        """Load MITRE ATT&CK technique data."""
        # Simplified MITRE technique database
        # In production, this would load from the official MITRE CTI repository
        self.techniques_db = {
            "T1110": MitreTechnique(
                technique_id="T1110",
                name="Brute Force",
                description="Adversaries may use brute force techniques to gain access to accounts",
                tactic="Credential Access",
                sub_techniques=["T1110.001", "T1110.002", "T1110.003", "T1110.004"],
                platforms=["Linux", "Windows", "macOS", "Network"],
                data_sources=["Authentication logs", "Application logs"],
                mitigations=["Account lockout", "Multi-factor authentication"],
                detection_methods=["Monitor authentication failures", "Unusual login patterns"]
            ),
            "T1110.001": MitreTechnique(
                technique_id="T1110.001",
                name="Password Guessing",
                description="Adversaries may use common passwords or dictionary attacks",
                tactic="Credential Access",
                sub_techniques=[],
                platforms=["Linux", "Windows", "macOS"],
                data_sources=["Authentication logs"],
                mitigations=["Strong password policy", "Account lockout"],
                detection_methods=["Monitor failed login attempts"]
            ),
            "T1110.002": MitreTechnique(
                technique_id="T1110.002",
                name="Password Cracking",
                description="Adversaries may crack password hashes to obtain plaintext passwords",
                tactic="Credential Access",
                sub_techniques=[],
                platforms=["Linux", "Windows", "macOS"],
                data_sources=["Authentication logs", "File monitoring"],
                mitigations=["Strong password policy", "Privileged account management"],
                detection_methods=["Monitor for hash dumping", "Unusual process execution"]
            ),
            "T1021": MitreTechnique(
                technique_id="T1021",
                name="Remote Services",
                description="Adversaries may use remote services to gain initial access",
                tactic="Lateral Movement",
                sub_techniques=["T1021.001", "T1021.002", "T1021.003", "T1021.004"],
                platforms=["Linux", "Windows", "macOS"],
                data_sources=["Network traffic", "Authentication logs"],
                mitigations=["Network segmentation", "Multi-factor authentication"],
                detection_methods=["Monitor network connections", "Authentication anomalies"]
            ),
            "T1021.004": MitreTechnique(
                technique_id="T1021.004",
                name="SSH",
                description="Adversaries may use SSH to laterally move between systems",
                tactic="Lateral Movement",
                sub_techniques=[],
                platforms=["Linux", "macOS", "Network"],
                data_sources=["Authentication logs", "Network traffic"],
                mitigations=["Disable unused services", "Multi-factor authentication"],
                detection_methods=["Monitor SSH connections", "Unusual login patterns"]
            ),
            "T1059": MitreTechnique(
                technique_id="T1059",
                name="Command and Scripting Interpreter",
                description="Adversaries may abuse command interpreters to execute commands",
                tactic="Execution",
                sub_techniques=["T1059.001", "T1059.002", "T1059.003", "T1059.004"],
                platforms=["Linux", "Windows", "macOS"],
                data_sources=["Process monitoring", "Command history"],
                mitigations=["Execution prevention", "Privileged account management"],
                detection_methods=["Monitor command execution", "Unusual process creation"]
            ),
            "T1059.004": MitreTechnique(
                technique_id="T1059.004",
                name="Unix Shell",
                description="Adversaries may abuse Unix shell commands and scripts",
                tactic="Execution",
                sub_techniques=[],
                platforms=["Linux", "macOS"],
                data_sources=["Process monitoring", "Command history"],
                mitigations=["Execution prevention", "Code signing"],
                detection_methods=["Monitor shell command execution"]
            ),
            "T1543": MitreTechnique(
                technique_id="T1543",
                name="Create or Modify System Process",
                description="Adversaries may create or modify system-level processes",
                tactic="Persistence",
                sub_techniques=["T1543.001", "T1543.002", "T1543.003"],
                platforms=["Linux", "Windows", "macOS"],
                data_sources=["Process monitoring", "File monitoring"],
                mitigations=["Privileged account management", "User account control"],
                detection_methods=["Monitor service creation", "File system changes"]
            ),
            "T1083": MitreTechnique(
                technique_id="T1083",
                name="File and Directory Discovery",
                description="Adversaries may enumerate files and directories",
                tactic="Discovery",
                sub_techniques=[],
                platforms=["Linux", "Windows", "macOS"],
                data_sources=["Process monitoring", "File monitoring"],
                mitigations=["User training"],
                detection_methods=["Monitor file access patterns", "Command line activity"]
            ),
            "T1046": MitreTechnique(
                technique_id="T1046",
                name="Network Service Scanning",
                description="Adversaries may attempt to get service information",
                tactic="Discovery",
                sub_techniques=[],
                platforms=["Linux", "Windows", "macOS", "Network"],
                data_sources=["Network traffic", "Packet capture"],
                mitigations=["Network intrusion prevention", "Network segmentation"],
                detection_methods=["Monitor network traffic", "Port scan detection"]
            ),
            "T1041": MitreTechnique(
                technique_id="T1041",
                name="Exfiltration Over C2 Channel",
                description="Adversaries may steal data by exfiltrating it over C2 channel",
                tactic="Exfiltration",
                sub_techniques=[],
                platforms=["Linux", "Windows", "macOS"],
                data_sources=["Network traffic", "File monitoring"],
                mitigations=["Data loss prevention", "Network intrusion prevention"],
                detection_methods=["Monitor network traffic", "Data flow analysis"]
            ),
            "T1505": MitreTechnique(
                technique_id="T1505",
                name="Server Software Component",
                description="Adversaries may abuse server software components",
                tactic="Persistence",
                sub_techniques=["T1505.001", "T1505.002", "T1505.003"],
                platforms=["Linux", "Windows", "Network"],
                data_sources=["File monitoring", "Web logs"],
                mitigations=["Privileged account management", "Code signing"],
                detection_methods=["Monitor file changes", "Web server logs"]
            )
        }
    
    def _load_pattern_mappings(self):
        """Load attack pattern to technique mappings."""
        self.pattern_mappings = {
            # Credential Access patterns
            "brute_force": ["T1110", "T1110.001"],
            "password_attack": ["T1110", "T1110.001", "T1110.002"],
            "credential_stuffing": ["T1110.004"],
            "dictionary_attack": ["T1110.001"],
            "login_attempt": ["T1110"],
            
            # Lateral Movement patterns
            "ssh_connection": ["T1021.004"],
            "remote_login": ["T1021"],
            "lateral_movement": ["T1021"],
            
            # Execution patterns
            "command_execution": ["T1059", "T1059.004"],
            "shell_command": ["T1059.004"],
            "script_execution": ["T1059"],
            "process_creation": ["T1059"],
            
            # Discovery patterns
            "port_scan": ["T1046"],
            "service_scan": ["T1046"],
            "network_scan": ["T1046"],
            "file_access": ["T1083"],
            "directory_enumeration": ["T1083"],
            "system_enumeration": ["T1083"],
            
            # Persistence patterns
            "service_creation": ["T1543"],
            "backdoor_installation": ["T1543"],
            "webshell": ["T1505.003"],
            
            # Exfiltration patterns
            "data_exfiltration": ["T1041"],
            "file_upload": ["T1041"],
            "data_theft": ["T1041"]
        }
        
        # IOC type to technique mappings
        self.ioc_mappings = {
            "ip": {
                "suspicious_geolocation": ["T1021", "T1046"],
                "known_malicious": ["T1071", "T1041"],
                "botnet_member": ["T1071", "T1041"],
                "tor_exit_node": ["T1090.003"]
            },
            "domain": {
                "suspicious_domain": ["T1071.001"],
                "dga_domain": ["T1071.001"],
                "phishing_domain": ["T1566.002"]
            },
            "hash": {
                "malware_hash": ["T1059", "T1105"],
                "backdoor_hash": ["T1543", "T1505"],
                "tool_hash": ["T1059", "T1083"]
            },
            "process": {
                "suspicious_process": ["T1059"],
                "system_process": ["T1543"],
                "persistence_process": ["T1543"]
            }
        }
    
    def map_attack_pattern(self, attack_pattern: str, confidence_threshold: float = 0.7) -> List[MitreTechnique]:
        """Map an attack pattern to MITRE techniques."""
        mapped_techniques = []
        
        # Normalize pattern
        pattern = attack_pattern.lower().strip()
        
        # Direct mapping
        if pattern in self.pattern_mappings:
            technique_ids = self.pattern_mappings[pattern]
            for technique_id in technique_ids:
                if technique_id in self.techniques_db:
                    mapped_techniques.append(self.techniques_db[technique_id])
        
        # Fuzzy matching for partial patterns
        else:
            for known_pattern, technique_ids in self.pattern_mappings.items():
                if self._pattern_similarity(pattern, known_pattern) >= confidence_threshold:
                    for technique_id in technique_ids:
                        if technique_id in self.techniques_db:
                            mapped_techniques.append(self.techniques_db[technique_id])
        
        # Remove duplicates while preserving order
        seen = set()
        unique_techniques = []
        for technique in mapped_techniques:
            if technique.technique_id not in seen:
                seen.add(technique.technique_id)
                unique_techniques.append(technique)
        
        return unique_techniques
    
    def map_ioc(self, ioc_type: str, ioc_value: str, context: Optional[Dict] = None) -> List[MitreTechnique]:
        """Map an IOC to MITRE techniques based on type and context."""
        mapped_techniques = []
        
        # Normalize IOC type
        ioc_type = ioc_type.lower().strip()
        
        if ioc_type in self.ioc_mappings:
            ioc_category_mappings = self.ioc_mappings[ioc_type]
            
            # Context-based mapping
            if context:
                for context_key, context_value in context.items():
                    context_pattern = f"{context_key}_{context_value}".lower()
                    
                    for category, technique_ids in ioc_category_mappings.items():
                        if category in context_pattern or context_pattern in category:
                            for technique_id in technique_ids:
                                if technique_id in self.techniques_db:
                                    mapped_techniques.append(self.techniques_db[technique_id])
            
            # Default mappings for IOC type
            if not mapped_techniques:
                # Use all available mappings for the IOC type
                all_technique_ids = []
                for technique_ids in ioc_category_mappings.values():
                    all_technique_ids.extend(technique_ids)
                
                for technique_id in set(all_technique_ids):
                    if technique_id in self.techniques_db:
                        mapped_techniques.append(self.techniques_db[technique_id])
        
        # Remove duplicates
        seen = set()
        unique_techniques = []
        for technique in mapped_techniques:
            if technique.technique_id not in seen:
                seen.add(technique.technique_id)
                unique_techniques.append(technique)
        
        return unique_techniques
    
    def create_attack_mapping(self, ioc_value: str, ioc_type: str, attack_patterns: List[str], 
                            context: Optional[Dict] = None) -> AttackMapping:
        """Create comprehensive attack mapping for an IOC."""
        
        all_techniques = []
        confidence_scores = []
        
        # Map attack patterns
        for pattern in attack_patterns:
            pattern_techniques = self.map_attack_pattern(pattern)
            all_techniques.extend(pattern_techniques)
            
            # Calculate confidence based on pattern specificity
            if pattern.lower() in self.pattern_mappings:
                confidence_scores.append(0.9)
            else:
                confidence_scores.append(0.6)
        
        # Map IOC
        ioc_techniques = self.map_ioc(ioc_type, ioc_value, context)
        all_techniques.extend(ioc_techniques)
        confidence_scores.extend([0.7] * len(ioc_techniques))
        
        # Remove duplicates and calculate overall confidence
        seen = set()
        unique_techniques = []
        for technique in all_techniques:
            if technique.technique_id not in seen:
                seen.add(technique.technique_id)
                unique_techniques.append(technique)
        
        overall_confidence = sum(confidence_scores) / len(confidence_scores) if confidence_scores else 0.0
        
        # Determine kill chain phase
        kill_chain_phase = self._determine_kill_chain_phase(unique_techniques, attack_patterns)
        
        return AttackMapping(
            ioc_value=ioc_value,
            ioc_type=ioc_type,
            attack_pattern=", ".join(attack_patterns),
            confidence_score=overall_confidence,
            mapped_techniques=unique_techniques,
            kill_chain_phase=kill_chain_phase,
            timestamp=datetime.now()
        )
    
    def _pattern_similarity(self, pattern1: str, pattern2: str) -> float:
        """Calculate similarity between two attack patterns."""
        # Simple token-based similarity
        tokens1 = set(re.findall(r'\w+', pattern1.lower()))
        tokens2 = set(re.findall(r'\w+', pattern2.lower()))
        
        if not tokens1 or not tokens2:
            return 0.0
        
        intersection = tokens1.intersection(tokens2)
        union = tokens1.union(tokens2)
        
        return len(intersection) / len(union)
    
    def _determine_kill_chain_phase(self, techniques: List[MitreTechnique], 
                                  attack_patterns: List[str]) -> str:
        """Determine the primary kill chain phase for the attack."""
        
        # Map tactics to kill chain phases
        tactic_to_phase = {
            "Initial Access": "Initial Access",
            "Execution": "Execution", 
            "Persistence": "Persistence",
            "Privilege Escalation": "Privilege Escalation",
            "Defense Evasion": "Defense Evasion",
            "Credential Access": "Credential Access",
            "Discovery": "Discovery",
            "Lateral Movement": "Lateral Movement",
            "Collection": "Collection",
            "Command and Control": "Command and Control",
            "Exfiltration": "Exfiltration",
            "Impact": "Impact"
        }
        
        # Count tactics
        tactic_counts = {}
        for technique in techniques:
            tactic = technique.tactic
            if tactic in tactic_to_phase:
                phase = tactic_to_phase[tactic]
                tactic_counts[phase] = tactic_counts.get(phase, 0) + 1
        
        # Return most common phase
        if tactic_counts:
            return max(tactic_counts, key=tactic_counts.get)
        
        # Fallback based on attack patterns
        pattern_str = " ".join(attack_patterns).lower()
        if any(keyword in pattern_str for keyword in ["brute", "login", "credential"]):
            return "Credential Access"
        elif any(keyword in pattern_str for keyword in ["scan", "enumeration", "discovery"]):
            return "Discovery"
        elif any(keyword in pattern_str for keyword in ["command", "execution", "shell"]):
            return "Execution"
        else:
            return "Unknown"
    
    def get_technique_by_id(self, technique_id: str) -> Optional[MitreTechnique]:
        """Get technique details by ID."""
        return self.techniques_db.get(technique_id)
    
    def get_techniques_by_tactic(self, tactic: str) -> List[MitreTechnique]:
        """Get all techniques for a specific tactic."""
        return [technique for technique in self.techniques_db.values() 
                if technique.tactic.lower() == tactic.lower()]
    
    def get_coverage_analysis(self, mappings: List[AttackMapping]) -> Dict[str, Any]:
        """Analyze MITRE coverage from attack mappings."""
        
        all_techniques = set()
        tactic_coverage = {}
        
        for mapping in mappings:
            for technique in mapping.mapped_techniques:
                all_techniques.add(technique.technique_id)
                tactic = technique.tactic
                if tactic not in tactic_coverage:
                    tactic_coverage[tactic] = set()
                tactic_coverage[tactic].add(technique.technique_id)
        
        # Convert sets to counts
        tactic_counts = {tactic: len(techniques) for tactic, techniques in tactic_coverage.items()}
        
        return {
            "total_techniques_observed": len(all_techniques),
            "total_mappings": len(mappings),
            "tactic_coverage": tactic_counts,
            "observed_techniques": sorted(list(all_techniques)),
            "coverage_percentage": (len(all_techniques) / len(self.techniques_db)) * 100,
            "analysis_timestamp": datetime.now().isoformat()
        }
    
    def export_mappings(self, mappings: List[AttackMapping], output_file: str):
        """Export mappings to JSON file."""
        export_data = {
            "mappings": [asdict(mapping) for mapping in mappings],
            "exported_at": datetime.now().isoformat(),
            "total_mappings": len(mappings)
        }
        
        with open(output_file, 'w') as f:
            json.dump(export_data, f, indent=2, default=str)
        
        logger.info(f"Exported {len(mappings)} mappings to {output_file}")

def main():
    """CLI interface for the MITRE mapper."""
    import argparse
    
    parser = argparse.ArgumentParser(description="CerberusMesh MITRE ATT&CK Mapper")
    parser.add_argument("action", choices=["map", "ioc", "technique", "tactics"], 
                       help="Action to perform")
    parser.add_argument("--pattern", 
                       help="Attack pattern to map")
    parser.add_argument("--ioc-type", 
                       help="IOC type (ip, domain, hash, etc.)")
    parser.add_argument("--ioc-value", 
                       help="IOC value")
    parser.add_argument("--technique-id", 
                       help="MITRE technique ID to lookup")
    parser.add_argument("--tactic", 
                       help="MITRE tactic to list techniques for")
    
    args = parser.parse_args()
    
    # Initialize mapper
    mapper = MitreMapper()
    
    # Execute action
    if args.action == "map":
        if not args.pattern:
            print("Error: --pattern required for mapping")
            return
        
        techniques = mapper.map_attack_pattern(args.pattern)
        print(f"Mapped techniques for pattern '{args.pattern}':")
        for technique in techniques:
            print(f"  - {technique.technique_id}: {technique.name} ({technique.tactic})")
    
    elif args.action == "ioc":
        if not args.ioc_type or not args.ioc_value:
            print("Error: --ioc-type and --ioc-value required")
            return
        
        techniques = mapper.map_ioc(args.ioc_type, args.ioc_value)
        print(f"Mapped techniques for IOC {args.ioc_type}:{args.ioc_value}:")
        for technique in techniques:
            print(f"  - {technique.technique_id}: {technique.name} ({technique.tactic})")
    
    elif args.action == "technique":
        if not args.technique_id:
            print("Error: --technique-id required")
            return
        
        technique = mapper.get_technique_by_id(args.technique_id)
        if technique:
            print(f"Technique Details:")
            print(f"  ID: {technique.technique_id}")
            print(f"  Name: {technique.name}")
            print(f"  Tactic: {technique.tactic}")
            print(f"  Description: {technique.description}")
            print(f"  Platforms: {', '.join(technique.platforms)}")
            print(f"  Data Sources: {', '.join(technique.data_sources)}")
        else:
            print(f"Technique {args.technique_id} not found")
    
    elif args.action == "tactics":
        if args.tactic:
            techniques = mapper.get_techniques_by_tactic(args.tactic)
            print(f"Techniques for tactic '{args.tactic}':")
            for technique in techniques:
                print(f"  - {technique.technique_id}: {technique.name}")
        else:
            # List all tactics
            tactics = set(technique.tactic for technique in mapper.techniques_db.values())
            print("Available tactics:")
            for tactic in sorted(tactics):
                print(f"  - {tactic}")

if __name__ == "__main__":
    main()
