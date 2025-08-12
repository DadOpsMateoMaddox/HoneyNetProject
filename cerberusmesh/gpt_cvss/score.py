#!/usr/bin/env python3
"""
CerberusMesh GPT CVSS Scorer - AI-powered threat analysis and CVSS scoring.

This module provides:
- GPT-4 powered IOC analysis
- CVSS v3.1 score generation
- Threat intelligence enrichment
- Automated remediation suggestions
"""

import json
import logging
import os
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from pathlib import Path
import requests
import openai
from enum import Enum

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('cvss_scorer.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class ThreatSeverity(Enum):
    """CVSS severity levels."""
    NONE = "None"
    LOW = "Low"
    MEDIUM = "Medium" 
    HIGH = "High"
    CRITICAL = "Critical"

@dataclass
class IOCMetadata:
    """Structure for Indicator of Compromise metadata."""
    ioc_type: str  # ip, domain, hash, process, etc.
    ioc_value: str
    source_honeypot: str
    first_seen: datetime
    last_seen: datetime
    occurrence_count: int
    associated_ports: List[int]
    protocols_used: List[str]
    attack_patterns: List[str]
    geolocation: Optional[Dict[str, str]] = None
    reputation_data: Optional[Dict[str, Any]] = None

@dataclass
class CVSSScore:
    """Structure for CVSS v3.1 scoring results."""
    base_score: float
    temporal_score: float
    environmental_score: float
    severity: ThreatSeverity
    vector_string: str
    
    # Individual metric scores
    attack_vector: str
    attack_complexity: str
    privileges_required: str
    user_interaction: str
    scope: str
    confidentiality_impact: str
    integrity_impact: str
    availability_impact: str
    
    # Analysis details
    justification: str
    confidence_level: float
    remediation_priority: str
    suggested_actions: List[str]
    mitre_techniques: List[str]

@dataclass
class ThreatAnalysis:
    """Complete threat analysis result."""
    ioc_metadata: IOCMetadata
    cvss_score: CVSSScore
    analysis_timestamp: datetime
    analyst_notes: str
    threat_actor_attribution: Optional[str] = None
    campaign_indicators: List[str] = None

class CVSSScorer:
    """GPT-4 powered CVSS scoring and threat analysis engine."""
    
    def __init__(self, api_key: Optional[str] = None):
        """Initialize the CVSS scorer with OpenAI API."""
        self.api_key = api_key or os.getenv('OPENAI_API_KEY')
        if not self.api_key:
            raise ValueError("OpenAI API key required. Set OPENAI_API_KEY environment variable.")
        
        # Initialize OpenAI client
        openai.api_key = self.api_key
        self.client = openai.OpenAI(api_key=self.api_key)
        
        # Analysis cache
        self.analysis_cache = {}
        self.cache_file = Path("cvss_analysis_cache.json")
        self._load_cache()
        
        logger.info("CVSS Scorer initialized with GPT-4")
    
    def _load_cache(self):
        """Load existing analysis cache."""
        try:
            if self.cache_file.exists():
                with open(self.cache_file, 'r') as f:
                    self.analysis_cache = json.load(f)
                logger.info(f"Loaded {len(self.analysis_cache)} cached analyses")
        except Exception as e:
            logger.warning(f"Could not load cache: {e}")
            self.analysis_cache = {}
    
    def _save_cache(self):
        """Save analysis cache to file."""
        try:
            with open(self.cache_file, 'w') as f:
                json.dump(self.analysis_cache, f, indent=2, default=str)
        except Exception as e:
            logger.error(f"Failed to save cache: {e}")
    
    def _build_analysis_prompt(self, ioc_metadata: IOCMetadata) -> str:
        """Build GPT-4 prompt for IOC analysis."""
        
        prompt = f"""You are a cybersecurity expert specializing in threat analysis and CVSS scoring. Analyze the following Indicator of Compromise (IOC) and provide a comprehensive assessment.

IOC DETAILS:
- Type: {ioc_metadata.ioc_type}
- Value: {ioc_metadata.ioc_value}
- Source: Honeypot {ioc_metadata.source_honeypot}
- First Seen: {ioc_metadata.first_seen}
- Last Seen: {ioc_metadata.last_seen}
- Occurrences: {ioc_metadata.occurrence_count}
- Associated Ports: {ioc_metadata.associated_ports}
- Protocols: {ioc_metadata.protocols_used}
- Attack Patterns: {ioc_metadata.attack_patterns}"""

        if ioc_metadata.geolocation:
            prompt += f"\n- Geolocation: {ioc_metadata.geolocation}"
        
        if ioc_metadata.reputation_data:
            prompt += f"\n- Reputation Data: {ioc_metadata.reputation_data}"

        prompt += """

ANALYSIS REQUIREMENTS:
Please provide a JSON response with the following structure:

{
  "cvss_analysis": {
    "base_score": [0.0-10.0],
    "severity": ["None", "Low", "Medium", "High", "Critical"],
    "attack_vector": ["Network", "Adjacent", "Local", "Physical"],
    "attack_complexity": ["Low", "High"],
    "privileges_required": ["None", "Low", "High"],
    "user_interaction": ["None", "Required"],
    "scope": ["Unchanged", "Changed"],
    "confidentiality_impact": ["None", "Low", "High"],
    "integrity_impact": ["None", "Low", "High"],
    "availability_impact": ["None", "Low", "High"],
    "vector_string": "CVSS:3.1/AV:X/AC:X/PR:X/UI:X/S:X/C:X/I:X/A:X"
  },
  "threat_assessment": {
    "justification": "Detailed explanation of the CVSS scoring rationale",
    "confidence_level": [0.0-1.0],
    "threat_actor_type": "description",
    "attack_sophistication": "description",
    "likely_objectives": ["objective1", "objective2"],
    "mitre_techniques": ["T1234", "T5678"]
  },
  "remediation": {
    "priority": ["Low", "Medium", "High", "Critical"],
    "immediate_actions": ["action1", "action2"],
    "long_term_actions": ["action1", "action2"],
    "monitoring_recommendations": ["recommendation1", "recommendation2"]
  }
}

SCORING GUIDELINES:
- Consider the honeypot context (attacker actively targeting the system)
- Factor in frequency and persistence of the IOC
- Assess potential for lateral movement and data exfiltration
- Evaluate evasion techniques and sophistication
- Consider impact on confidentiality, integrity, and availability

Provide accurate CVSS v3.1 scoring based on the specific IOC characteristics and honeypot context."""

        return prompt
    
    def _parse_gpt_response(self, response_text: str) -> Dict[str, Any]:
        """Parse and validate GPT-4 response."""
        try:
            # Extract JSON from response
            start_idx = response_text.find('{')
            end_idx = response_text.rfind('}') + 1
            
            if start_idx == -1 or end_idx == 0:
                raise ValueError("No JSON found in response")
            
            json_text = response_text[start_idx:end_idx]
            parsed = json.loads(json_text)
            
            # Validate required fields
            required_sections = ['cvss_analysis', 'threat_assessment', 'remediation']
            for section in required_sections:
                if section not in parsed:
                    raise ValueError(f"Missing required section: {section}")
            
            return parsed
            
        except Exception as e:
            logger.error(f"Failed to parse GPT response: {e}")
            logger.error(f"Response text: {response_text}")
            raise
    
    def _calculate_temporal_score(self, base_score: float, confidence: float) -> float:
        """Calculate temporal score based on exploit availability and confidence."""
        # Simplified temporal scoring
        # In production, this would consider exploit code maturity, remediation level, etc.
        exploit_code_maturity = 0.95  # Assume mature exploits for honeypot traffic
        remediation_level = 1.0  # No official fix available yet
        report_confidence = max(confidence, 0.8)  # High confidence for observed attacks
        
        temporal_score = base_score * exploit_code_maturity * remediation_level * report_confidence
        return round(temporal_score, 1)
    
    def _calculate_environmental_score(self, base_score: float, ioc_metadata: IOCMetadata) -> float:
        """Calculate environmental score based on organizational context."""
        # Simplified environmental scoring
        # In production, this would consider specific organizational requirements
        
        # Higher impact for frequent/persistent attacks
        frequency_multiplier = min(1.2, 1.0 + (ioc_metadata.occurrence_count / 100))
        
        # Higher impact for multiple ports/protocols
        diversity_multiplier = min(1.15, 1.0 + (len(ioc_metadata.associated_ports) / 20))
        
        environmental_score = base_score * frequency_multiplier * diversity_multiplier
        return round(min(environmental_score, 10.0), 1)
    
    def _determine_severity(self, score: float) -> ThreatSeverity:
        """Determine severity level from CVSS score."""
        if score == 0.0:
            return ThreatSeverity.NONE
        elif score < 4.0:
            return ThreatSeverity.LOW
        elif score < 7.0:
            return ThreatSeverity.MEDIUM
        elif score < 9.0:
            return ThreatSeverity.HIGH
        else:
            return ThreatSeverity.CRITICAL
    
    def analyze_ioc(self, ioc_metadata: IOCMetadata) -> ThreatAnalysis:
        """Perform complete threat analysis with GPT-4."""
        
        # Check cache first
        cache_key = f"{ioc_metadata.ioc_type}:{ioc_metadata.ioc_value}"
        if cache_key in self.analysis_cache:
            logger.info(f"Using cached analysis for {cache_key}")
            cached = self.analysis_cache[cache_key]
            return ThreatAnalysis(**cached)
        
        try:
            logger.info(f"Analyzing IOC: {ioc_metadata.ioc_value}")
            
            # Build prompt and get GPT-4 analysis
            prompt = self._build_analysis_prompt(ioc_metadata)
            
            response = self.client.chat.completions.create(
                model="gpt-4",
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert specializing in threat analysis and CVSS scoring. Provide accurate, detailed analysis in the requested JSON format."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.2,
                max_tokens=2000
            )
            
            response_text = response.choices[0].message.content
            parsed_response = self._parse_gpt_response(response_text)
            
            # Extract CVSS analysis
            cvss_data = parsed_response['cvss_analysis']
            threat_data = parsed_response['threat_assessment']
            remediation_data = parsed_response['remediation']
            
            # Calculate additional scores
            base_score = float(cvss_data['base_score'])
            temporal_score = self._calculate_temporal_score(base_score, threat_data['confidence_level'])
            environmental_score = self._calculate_environmental_score(base_score, ioc_metadata)
            
            # Create CVSS score object
            cvss_score = CVSSScore(
                base_score=base_score,
                temporal_score=temporal_score,
                environmental_score=environmental_score,
                severity=ThreatSeverity(cvss_data['severity']),
                vector_string=cvss_data['vector_string'],
                attack_vector=cvss_data['attack_vector'],
                attack_complexity=cvss_data['attack_complexity'],
                privileges_required=cvss_data['privileges_required'],
                user_interaction=cvss_data['user_interaction'],
                scope=cvss_data['scope'],
                confidentiality_impact=cvss_data['confidentiality_impact'],
                integrity_impact=cvss_data['integrity_impact'],
                availability_impact=cvss_data['availability_impact'],
                justification=threat_data['justification'],
                confidence_level=threat_data['confidence_level'],
                remediation_priority=remediation_data['priority'],
                suggested_actions=remediation_data['immediate_actions'] + remediation_data['long_term_actions'],
                mitre_techniques=threat_data.get('mitre_techniques', [])
            )
            
            # Create complete analysis
            analysis = ThreatAnalysis(
                ioc_metadata=ioc_metadata,
                cvss_score=cvss_score,
                analysis_timestamp=datetime.now(),
                analyst_notes=f"GPT-4 Analysis: {threat_data.get('attack_sophistication', 'N/A')}",
                threat_actor_attribution=threat_data.get('threat_actor_type'),
                campaign_indicators=threat_data.get('likely_objectives', [])
            )
            
            # Cache the result
            self.analysis_cache[cache_key] = asdict(analysis)
            self._save_cache()
            
            # Log the analysis
            self._log_analysis(analysis)
            
            return analysis
            
        except Exception as e:
            logger.error(f"Analysis failed for {ioc_metadata.ioc_value}: {e}")
            raise
    
    def _log_analysis(self, analysis: ThreatAnalysis):
        """Log analysis results."""
        logger.info(f"CVSS Analysis Complete:")
        logger.info(f"  IOC: {analysis.ioc_metadata.ioc_value}")
        logger.info(f"  Base Score: {analysis.cvss_score.base_score}")
        logger.info(f"  Severity: {analysis.cvss_score.severity.value}")
        logger.info(f"  Priority: {analysis.cvss_score.remediation_priority}")
        logger.info(f"  Confidence: {analysis.cvss_score.confidence_level:.2f}")
        
        # Save detailed report
        report_file = Path(f"cvss_reports/{analysis.ioc_metadata.ioc_value.replace('/', '_').replace(':', '_')}.json")
        report_file.parent.mkdir(exist_ok=True)
        
        with open(report_file, 'w') as f:
            report_data = asdict(analysis)
            json.dump(report_data, f, indent=2, default=str)
    
    def batch_analyze(self, ioc_list: List[IOCMetadata]) -> List[ThreatAnalysis]:
        """Analyze multiple IOCs in batch."""
        results = []
        
        for ioc in ioc_list:
            try:
                analysis = self.analyze_ioc(ioc)
                results.append(analysis)
            except Exception as e:
                logger.error(f"Failed to analyze {ioc.ioc_value}: {e}")
                continue
        
        logger.info(f"Batch analysis completed: {len(results)}/{len(ioc_list)} successful")
        return results
    
    def get_high_priority_threats(self, threshold: float = 7.0) -> List[ThreatAnalysis]:
        """Get all cached high-priority threats above threshold."""
        high_priority = []
        
        for cached_analysis in self.analysis_cache.values():
            if cached_analysis['cvss_score']['base_score'] >= threshold:
                high_priority.append(ThreatAnalysis(**cached_analysis))
        
        # Sort by score descending
        high_priority.sort(key=lambda x: x.cvss_score.base_score, reverse=True)
        return high_priority
    
    def generate_summary_report(self) -> Dict[str, Any]:
        """Generate summary report of all analyzed threats."""
        if not self.analysis_cache:
            return {"message": "No analyses available"}
        
        analyses = [ThreatAnalysis(**data) for data in self.analysis_cache.values()]
        
        # Calculate statistics
        scores = [a.cvss_score.base_score for a in analyses]
        severities = [a.cvss_score.severity.value for a in analyses]
        
        severity_counts = {}
        for sev in severities:
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        top_threats = sorted(analyses, key=lambda x: x.cvss_score.base_score, reverse=True)[:10]
        
        return {
            "total_analyses": len(analyses),
            "average_score": round(sum(scores) / len(scores), 2),
            "max_score": max(scores),
            "min_score": min(scores),
            "severity_distribution": severity_counts,
            "top_threats": [
                {
                    "ioc": threat.ioc_metadata.ioc_value,
                    "score": threat.cvss_score.base_score,
                    "severity": threat.cvss_score.severity.value,
                    "priority": threat.cvss_score.remediation_priority
                }
                for threat in top_threats
            ],
            "generated_at": datetime.now().isoformat()
        }

def create_sample_ioc(ioc_type: str, ioc_value: str, **kwargs) -> IOCMetadata:
    """Create sample IOC for testing."""
    return IOCMetadata(
        ioc_type=ioc_type,
        ioc_value=ioc_value,
        source_honeypot=kwargs.get('source_honeypot', 'honeypot-01'),
        first_seen=kwargs.get('first_seen', datetime.now()),
        last_seen=kwargs.get('last_seen', datetime.now()),
        occurrence_count=kwargs.get('occurrence_count', 1),
        associated_ports=kwargs.get('associated_ports', [22, 80]),
        protocols_used=kwargs.get('protocols_used', ['tcp']),
        attack_patterns=kwargs.get('attack_patterns', ['brute_force']),
        geolocation=kwargs.get('geolocation'),
        reputation_data=kwargs.get('reputation_data')
    )

def main():
    """CLI interface for the CVSS scorer."""
    import argparse
    
    parser = argparse.ArgumentParser(description="CerberusMesh GPT CVSS Scorer")
    parser.add_argument("action", choices=["analyze", "batch", "report", "threats"], 
                       help="Action to perform")
    parser.add_argument("--ioc-type", 
                       help="Type of IOC (ip, domain, hash, etc.)")
    parser.add_argument("--ioc-value", 
                       help="IOC value to analyze")
    parser.add_argument("--threshold", type=float, default=7.0,
                       help="Threat score threshold")
    parser.add_argument("--input-file", 
                       help="JSON file with IOC data for batch analysis")
    
    args = parser.parse_args()
    
    # Initialize scorer
    try:
        scorer = CVSSScorer()
    except ValueError as e:
        print(f"Error: {e}")
        return
    
    # Execute action
    if args.action == "analyze":
        if not args.ioc_type or not args.ioc_value:
            print("Error: --ioc-type and --ioc-value required for analysis")
            return
        
        ioc = create_sample_ioc(args.ioc_type, args.ioc_value)
        analysis = scorer.analyze_ioc(ioc)
        
        print(f"\nCVSS Analysis Results:")
        print(f"IOC: {analysis.ioc_metadata.ioc_value}")
        print(f"Base Score: {analysis.cvss_score.base_score}")
        print(f"Severity: {analysis.cvss_score.severity.value}")
        print(f"Vector: {analysis.cvss_score.vector_string}")
        print(f"Justification: {analysis.cvss_score.justification}")
        print(f"Remediation Priority: {analysis.cvss_score.remediation_priority}")
        print(f"Suggested Actions: {', '.join(analysis.cvss_score.suggested_actions)}")
    
    elif args.action == "report":
        report = scorer.generate_summary_report()
        print(json.dumps(report, indent=2))
    
    elif args.action == "threats":
        threats = scorer.get_high_priority_threats(args.threshold)
        print(f"High Priority Threats (Score >= {args.threshold}):")
        for threat in threats:
            print(f"  - {threat.ioc_metadata.ioc_value}: {threat.cvss_score.base_score} ({threat.cvss_score.severity.value})")

if __name__ == "__main__":
    main()
