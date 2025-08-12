#!/usr/bin/env python3
"""
CerberusMesh Traps Module

This module contains advanced deception and detection systems for the
CerberusMesh honeypot platform, including:

- AI-powered chatbot personas for real-time attacker engagement
- Cowrie honeypot integration engine for session monitoring
- Behavioral tripwire and anomaly detection system
"""

from .chatbot import CerberusPersona, CerberusPersonaManager
from .engage import CowrieSessionMonitor, EngagementEngine
from .tripwire import CerberusTripwire, TripwireEvent, BehaviorProfile

__version__ = "1.0.0"
__author__ = "CerberusMesh AI Security Team"

# Export main classes for easy import
__all__ = [
    # Chatbot classes
    "CerberusPersona",
    "CerberusPersonaManager",
    
    # Engagement classes  
    "CowrieSessionMonitor",
    "EngagementEngine",
    
    # Tripwire classes
    "CerberusTripwire", 
    "TripwireEvent",
    "BehaviorProfile",
]

# Module metadata
TRAPS_CONFIG = {
    "description": "Advanced AI-powered deception and detection traps",
    "capabilities": [
        "Multi-persona chatbot engagement",
        "Real-time session monitoring", 
        "Behavioral anomaly detection",
        "Automated tripwire triggers",
        "MITRE ATT&CK pattern recognition",
        "Session risk scoring"
    ],
    "integrations": [
        "Cowrie SSH honeypot",
        "OpenAI GPT-4 API",
        "Redis caching",
        "CerberusMesh controller"
    ]
}
