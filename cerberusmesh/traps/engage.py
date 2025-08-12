#!/usr/bin/env python3
"""
CerberusMesh Engagement Engine - Cowrie Integration

This module provides hooks and integration with Cowrie honeypot sessions
to enable real-time chatbot persona interactions with attackers.
"""

import asyncio
import json
import logging
import os
import random
import re
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from pathlib import Path
import uuid

import redis
from twisted.internet import reactor, task
from twisted.python import log
from dotenv import load_dotenv

# Import chatbot persona
from .chatbot import CerberusPersona, ChatMessage

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class CowrieSessionMonitor:
    """Monitor and engage with active Cowrie sessions."""
    
    def __init__(self, config: Optional[Dict] = None):
        """Initialize the session monitor."""
        self.config = config or self._load_config()
        self.chatbot = CerberusPersona(config)
        
        # Session tracking
        self.active_sessions: Dict[str, Dict] = {}
        self.engagement_rules: List[Dict] = []
        
        # Metrics
        self.sessions_monitored = 0
        self.engagements_triggered = 0
        self.responses_sent = 0
        
        # Redis for real-time coordination
        self._init_redis()
        
        # Load engagement rules
        self._load_engagement_rules()
        
        logger.info("CowrieSessionMonitor initialized")
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from environment."""
        return {
            # Cowrie Integration
            "cowrie_log_path": os.getenv("COWRIE_LOG_PATH", "/opt/cowrie/var/log/cowrie/cowrie.json"),
            "cowrie_output_path": os.getenv("COWRIE_OUTPUT_PATH", "/opt/cowrie/var/lib/cowrie/tty"),
            "engagement_enabled": os.getenv("CERBERUS_ENGAGEMENT", "true").lower() == "true",
            
            # Engagement Behavior
            "engagement_delay": float(os.getenv("CERBERUS_ENGAGE_DELAY", "3.0")),
            "engagement_probability": float(os.getenv("CERBERUS_ENGAGE_PROB", "0.8")),
            "session_timeout": int(os.getenv("CERBERUS_SESSION_TIMEOUT", "1800")),
            
            # Trigger Patterns
            "trigger_commands": [
                "ls", "ps", "whoami", "id", "uname", "cat", "grep", 
                "sudo", "su", "passwd", "crontab", "netstat", "ss"
            ],
            "escalation_commands": [
                "wget", "curl", "nc", "nmap", "python", "perl", "bash", 
                "sh", "chmod", "rm", "dd", "mount", "umount"
            ],
            
            # Redis Configuration
            "redis_host": os.getenv("REDIS_HOST", "localhost"),
            "redis_port": int(os.getenv("REDIS_PORT", "6379")),
            "redis_db": int(os.getenv("REDIS_DB", "3")),
        }
    
    def _init_redis(self):
        """Initialize Redis for session coordination."""
        try:
            self.redis_client = redis.Redis(
                host=self.config["redis_host"],
                port=self.config["redis_port"],
                db=self.config["redis_db"],
                decode_responses=True
            )
            self.redis_client.ping()
            logger.info("Redis initialized for engagement engine")
        except Exception as e:
            logger.warning(f"Redis not available: {e}")
            self.redis_client = None
    
    def _load_engagement_rules(self):
        """Load rules for when to engage with sessions."""
        self.engagement_rules = [
            {
                "name": "initial_reconnaissance",
                "triggers": ["ls", "pwd", "whoami", "id"],
                "persona": "junior_sysadmin",
                "delay_range": (2, 5),
                "probability": 0.7,
                "response_type": "helpful"
            },
            {
                "name": "privilege_escalation",
                "triggers": ["sudo", "su", "passwd"],
                "persona": "security_conscious", 
                "delay_range": (1, 3),
                "probability": 0.9,
                "response_type": "suspicious"
            },
            {
                "name": "file_exploration",
                "triggers": ["cat /etc/passwd", "cat /etc/shadow", "find /"],
                "persona": "panicking_intern",
                "delay_range": (0.5, 2),
                "probability": 0.8,
                "response_type": "panicked"
            },
            {
                "name": "network_tools",
                "triggers": ["netstat", "ss", "ifconfig", "nmap"],
                "persona": "sarcastic_engineer",
                "delay_range": (3, 8),
                "probability": 0.6,
                "response_type": "sarcastic"
            },
            {
                "name": "malicious_download",
                "triggers": ["wget http://", "curl -o", "python -c"],
                "persona": "junior_sysadmin",
                "delay_range": (1, 4),
                "probability": 0.95,
                "response_type": "confused"
            }
        ]
    
    async def start_monitoring(self):
        """Start monitoring Cowrie sessions."""
        if not self.config["engagement_enabled"]:
            logger.info("Engagement disabled in configuration")
            return
        
        logger.info("Starting Cowrie session monitoring...")
        
        # Start background tasks
        tasks = [
            asyncio.create_task(self._monitor_cowrie_logs()),
            asyncio.create_task(self._process_engagement_queue()),
            asyncio.create_task(self._cleanup_sessions()),
            asyncio.create_task(self._update_metrics())
        ]
        
        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            logger.info("Monitoring tasks cancelled")
            raise  # Re-raise the cancellation
        except Exception as e:
            logger.error(f"Monitoring error: {e}")
    
    async def _monitor_cowrie_logs(self):
        """Monitor Cowrie JSON logs for session events."""
        log_path = Path(self.config["cowrie_log_path"])
        
        if not log_path.exists():
            logger.warning(f"Cowrie log file not found: {log_path}")
            return
        
        logger.info(f"Monitoring Cowrie logs: {log_path}")
        
        # Track file position to only read new entries
        last_position = 0
        
        while True:
            try:
                with open(log_path, 'r') as f:
                    # Seek to last known position
                    f.seek(last_position)
                    
                    # Read new lines
                    new_lines = f.readlines()
                    last_position = f.tell()
                
                # Process new log entries
                for line in new_lines:
                    await self._process_cowrie_event(line.strip())
                
                # Sleep before next check
                await asyncio.sleep(0.5)
                
            except Exception as e:
                logger.error(f"Error monitoring Cowrie logs: {e}")
                await asyncio.sleep(5)
    
    async def _process_cowrie_event(self, log_line: str):
        """Process individual Cowrie log event."""
        if not log_line:
            return
        
        try:
            event = json.loads(log_line)
            event_id = event.get("eventid", "")
            
            # Handle different event types
            if event_id == "cowrie.session.connect":
                self._handle_session_connect(event)
            
            elif event_id == "cowrie.login.success":
                await self._handle_login_success(event)
            
            elif event_id == "cowrie.command.input":
                await self._handle_command_input(event)
            
            elif event_id in ["cowrie.session.closed", "cowrie.session.disconnect"]:
                await self._handle_session_close(event)
                
        except json.JSONDecodeError:
            logger.debug(f"Failed to parse log line: {log_line[:100]}...")
        except Exception as e:
            logger.error(f"Error processing Cowrie event: {e}")
    
    def _handle_session_connect(self, event: Dict):
        """Handle new session connection."""
        session_id = event.get("session", "")
        src_ip = event.get("src_ip", "unknown")
        
        if session_id:
            self.active_sessions[session_id] = {
                "session_id": session_id,
                "src_ip": src_ip,
                "start_time": datetime.now(),
                "last_activity": datetime.now(),
                "commands": [],
                "engaged": False,
                "persona": None,
                "login_attempts": 0
            }
            
            self.sessions_monitored += 1
            logger.info(f"New session tracked: {session_id} from {src_ip}")
    
    async def _handle_login_success(self, event: Dict):
        """Handle successful login to session."""
        session_id = event.get("session", "")
        username = event.get("username", "")
        
        if session_id in self.active_sessions:
            session_info = self.active_sessions[session_id]
            session_info["username"] = username
            session_info["login_time"] = datetime.now()
            session_info["last_activity"] = datetime.now()
            
            logger.info(f"Login success: {session_id} - user: {username}")
            
            # Consider engagement on successful login
            await self._consider_engagement(session_id, f"login as {username}")
    
    async def _handle_command_input(self, event: Dict):
        """Handle command input in session."""
        session_id = event.get("session", "")
        command = event.get("input", "")
        
        if session_id in self.active_sessions:
            session_info = self.active_sessions[session_id]
            session_info["commands"].append({
                "command": command,
                "timestamp": datetime.now()
            })
            session_info["last_activity"] = datetime.now()
            
            logger.debug(f"Command in {session_id}: {command}")
            
            # Check if this command should trigger engagement
            await self._consider_engagement(session_id, command)
    
    async def _handle_session_close(self, event: Dict):
        """Handle session closure."""
        session_id = event.get("session", "")
        
        if session_id in self.active_sessions:
            session_info = self.active_sessions[session_id]
            duration = (datetime.now() - session_info["start_time"]).total_seconds()
            
            logger.info(f"Session closed: {session_id} - Duration: {duration:.1f}s")
            
            # Log session summary
            await self._log_session_summary(session_info)
            
            # Clean up
            del self.active_sessions[session_id]
    
    async def _consider_engagement(self, session_id: str, trigger_input: str):
        """Determine if session should be engaged based on trigger."""
        if session_id not in self.active_sessions:
            return
        
        session_info = self.active_sessions[session_id]
        
        # Don't engage if already engaged
        if session_info["engaged"]:
            # But continue conversation if persona is active
            if session_info["persona"]:
                await self._continue_conversation(session_id, trigger_input)
            return
        
        # Find matching engagement rule
        matching_rule = None
        for rule in self.engagement_rules:
            for trigger in rule["triggers"]:
                if trigger.lower() in trigger_input.lower():
                    matching_rule = rule
                    break
            if matching_rule:
                break
        
        if not matching_rule:
            # Check for generic trigger commands
            for cmd in self.config["trigger_commands"]:
                if cmd.lower() in trigger_input.lower():
                    matching_rule = {
                        "name": "generic_command",
                        "persona": "junior_sysadmin",
                        "delay_range": (2, 6),
                        "probability": 0.5,
                        "response_type": "generic"
                    }
                    break
        
        if matching_rule and self._should_engage(matching_rule):
            await self._initiate_engagement(session_id, matching_rule, trigger_input)
    
    def _should_engage(self, rule: Dict) -> bool:
        """Determine if engagement should occur based on rule probability."""
        import random
        return random.random() < rule.get("probability", 0.5)
    
    async def _initiate_engagement(self, session_id: str, rule: Dict, trigger_input: str):
        """Initiate chatbot engagement with session."""
        session_info = self.active_sessions[session_id]
        persona_name = rule["persona"]
        
        logger.info(f"Initiating engagement: {session_id} - Rule: {rule['name']} - Persona: {persona_name}")
        
        # Mark session as engaged
        session_info["engaged"] = True
        session_info["persona"] = persona_name
        session_info["engagement_rule"] = rule["name"]
        session_info["engagement_time"] = datetime.now()
        
        # Start chatbot conversation
        await self.chatbot.start_conversation(session_id, persona_name)
        
        # Add artificial delay
        delay_range = rule.get("delay_range", (2, 5))
        delay = random.uniform(*delay_range)
        await asyncio.sleep(delay)
        
        # Generate initial response
        response = await self.chatbot.process_attacker_input(session_id, trigger_input)
        
        if response:
            await self._send_response_to_session(session_id, response)
            self.engagements_triggered += 1
    
    async def _continue_conversation(self, session_id: str, user_input: str):
        """Continue existing conversation with chatbot."""
        response = await self.chatbot.process_attacker_input(session_id, user_input)
        
        if response:
            await self._send_response_to_session(session_id, response)
    
    async def _send_response_to_session(self, session_id: str, response: str):
        """Send chatbot response to Cowrie session."""
        # Implementation for Cowrie session injection
        # This uses file-based communication that Cowrie can monitor
        # Real deployment would use Cowrie's twisted protocol hooks
        
        session_info = self.active_sessions.get(session_id, {})
        src_ip = session_info.get("src_ip", "unknown")
        
        logger.info(f"Response to {session_id} ({src_ip}): {response}")
        
        # Cache response for potential injection
        if self.redis_client:
            try:
                response_data = {
                    "session_id": session_id,
                    "response": response,
                    "timestamp": datetime.now().isoformat(),
                    "persona": session_info.get("persona", "unknown")
                }
                
                response_key = f"cowrie_response:{session_id}:{int(time.time())}"
                self.redis_client.setex(response_key, 300, json.dumps(response_data))
                
                # Also set latest response key
                latest_key = f"cowrie_latest_response:{session_id}"
                self.redis_client.setex(latest_key, 300, json.dumps(response_data))
                
            except Exception as e:
                logger.error(f"Failed to cache response: {e}")
        
        # Write to output file that Cowrie could potentially read
        self._write_response_to_output(session_id, response)
        
        self.responses_sent += 1
    
    def _write_response_to_output(self, session_id: str, response: str):
        """Write response to output file for potential Cowrie integration."""
        try:
            output_dir = Path("/tmp/cerberus_responses")
            output_dir.mkdir(exist_ok=True)
            
            output_file = output_dir / f"{session_id}_responses.txt"
            
            with open(output_file, 'a') as f:
                timestamp = datetime.now().isoformat()
                f.write(f"[{timestamp}] {response}\n")
                
        except Exception as e:
            logger.debug(f"Failed to write response to output: {e}")
    
    async def _process_engagement_queue(self):
        """Process queued engagement actions."""
        # This could handle delayed responses, follow-up messages, etc.
        while True:
            try:
                # Check for scheduled engagement actions
                await asyncio.sleep(1)
                
                # Process engagement queue for delayed responses and follow-ups
                # This handles persona behavior changes and timed interactions
                # Current implementation processes immediate responses
                # Extended features would include conversation scheduling
                
            except Exception as e:
                logger.error(f"Engagement queue processing error: {e}")
                await asyncio.sleep(5)
    
    async def _cleanup_sessions(self):
        """Clean up expired sessions."""
        while True:
            try:
                current_time = datetime.now()
                timeout_delta = timedelta(seconds=self.config["session_timeout"])
                
                expired_sessions = []
                for session_id, session_info in self.active_sessions.items():
                    if current_time - session_info["last_activity"] > timeout_delta:
                        expired_sessions.append(session_id)
                
                for session_id in expired_sessions:
                    logger.info(f"Cleaning up expired session: {session_id}")
                    await self._log_session_summary(self.active_sessions[session_id])
                    del self.active_sessions[session_id]
                
                # Also cleanup chatbot sessions
                self.chatbot.cleanup_expired_sessions()
                
                await asyncio.sleep(60)  # Check every minute
                
            except Exception as e:
                logger.error(f"Session cleanup error: {e}")
                await asyncio.sleep(60)
    
    async def _update_metrics(self):
        """Update engagement metrics."""
        while True:
            try:
                metrics = {
                    "sessions_monitored": self.sessions_monitored,
                    "engagements_triggered": self.engagements_triggered,
                    "responses_sent": self.responses_sent,
                    "active_sessions": len(self.active_sessions),
                    "timestamp": datetime.now().isoformat()
                }
                
                # Cache metrics
                if self.redis_client:
                    self.redis_client.setex("engagement_metrics", 300, json.dumps(metrics))
                
                logger.debug(f"Engagement metrics: {metrics}")
                await asyncio.sleep(60)
                
            except Exception as e:
                logger.error(f"Metrics update error: {e}")
                await asyncio.sleep(60)
    
    def _log_session_summary(self, session_info: Dict):
        """Log summary of session activity."""
        duration = (datetime.now() - session_info["start_time"]).total_seconds()
        
        summary = {
            "session_id": session_info["session_id"],
            "src_ip": session_info["src_ip"],
            "duration": duration,
            "commands_count": len(session_info["commands"]),
            "engaged": session_info["engaged"],
            "persona": session_info.get("persona"),
            "engagement_rule": session_info.get("engagement_rule"),
            "timestamp": datetime.now().isoformat()
        }
        
        logger.info(f"Session summary: {summary}")
        
        # Cache session summary
        if self.redis_client:
            try:
                summary_key = f"session_summary:{session_info['session_id']}"
                self.redis_client.setex(summary_key, 86400, json.dumps(summary))
            except Exception as e:
                logger.debug(f"Failed to cache session summary: {e}")
    
    def get_engagement_stats(self) -> Dict[str, Any]:
        """Get engagement statistics."""
        return {
            "sessions_monitored": self.sessions_monitored,
            "engagements_triggered": self.engagements_triggered,
            "responses_sent": self.responses_sent,
            "active_sessions": len(self.active_sessions),
            "engagement_rules": len(self.engagement_rules),
            "chatbot_stats": self.chatbot.get_chatbot_stats()
        }
    
    def get_active_sessions_info(self) -> List[Dict[str, Any]]:
        """Get information about currently active sessions."""
        sessions = []
        for session_id, session_info in self.active_sessions.items():
            sessions.append({
                "session_id": session_id,
                "src_ip": session_info["src_ip"],
                "start_time": session_info["start_time"].isoformat(),
                "last_activity": session_info["last_activity"].isoformat(),
                "commands_count": len(session_info["commands"]),
                "engaged": session_info["engaged"],
                "persona": session_info.get("persona")
            })
        return sessions

# Twisted integration for real-time Cowrie hooks
class CowrieEngagementProtocol:
    """Twisted protocol integration for real-time Cowrie session hooks."""
    
    def __init__(self, engagement_engine: CowrieSessionMonitor):
        """Initialize with engagement engine."""
        self.engagement_engine = engagement_engine
        self.session_hooks: Dict[str, Callable] = {}
    
    def register_session_hook(self, session_id: str, hook_func: Callable):
        """Register hook function for specific session."""
        self.session_hooks[session_id] = hook_func
        logger.debug(f"Registered hook for session: {session_id}")
    
    def unregister_session_hook(self, session_id: str):
        """Unregister hook for session."""
        if session_id in self.session_hooks:
            del self.session_hooks[session_id]
            logger.debug(f"Unregistered hook for session: {session_id}")
    
    async def inject_response(self, session_id: str, response: str):
        """Inject response into Cowrie session."""
        # Implementation for Cowrie session injection using hooks
        # Production deployment would integrate with Cowrie's transport layer
        
        hook_func = self.session_hooks.get(session_id)
        if hook_func:
            try:
                await hook_func(response)
            except Exception as e:
                logger.error(f"Hook execution failed for {session_id}: {e}")

# Cowrie Plugin Integration Framework
# class CerberusEngagementPlugin:
#     """Cowrie plugin for direct integration."""
#     
#     def __init__(self):
#         self.engagement_engine = CowrieSessionMonitor()
#     
#     def sessionOpened(self, session):
#         """Called when new session opens."""
#         pass
#     
#     def commandReceived(self, session, command):
#         """Called when command is received."""
#         pass
#     
#     def sessionClosed(self, session):
#         """Called when session closes."""
#         pass

async def main():
    """Main entry point for engagement engine."""
    logger.info("Starting CerberusMesh Engagement Engine...")
    
    # Initialize engagement monitor
    monitor = CowrieSessionMonitor()
    
    try:
        # Start monitoring
        await monitor.start_monitoring()
    except KeyboardInterrupt:
        logger.info("Received interrupt signal")
    except Exception as e:
        logger.error(f"Engagement engine failed: {e}")
    finally:
        logger.info("Engagement engine stopped")

if __name__ == "__main__":
    asyncio.run(main())
