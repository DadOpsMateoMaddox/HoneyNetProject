#!/usr/bin/env python3
"""
CerberusMesh Dashboard API - FastAPI backend for real-time honeypot monitoring.

This module provides:
- RESTful API endpoints for honeypot status
- Real-time event streaming
- CVSS score aggregation
- Attack statistics and visualization data
"""

import json
import logging
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from pathlib import Path
import asyncio
import sqlite3
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import uvicorn

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Pydantic models
class HoneypotStatus(BaseModel):
    """Model for honeypot status response."""
    honeypot_id: str
    status: str
    public_ip: str
    private_ip: str
    instance_type: str
    last_seen: datetime
    attack_count: int
    unique_attackers: int
    uptime_hours: float

class AttackEvent(BaseModel):
    """Model for attack event data."""
    timestamp: datetime
    source_ip: str
    destination_port: int
    protocol: str
    event_type: str
    honeypot_id: str
    session_id: str
    username: Optional[str] = None
    password: Optional[str] = None
    command: Optional[str] = None
    geolocation: Optional[Dict[str, str]] = None

class CVSSEvent(BaseModel):
    """Model for CVSS scoring events."""
    timestamp: datetime
    ioc_value: str
    ioc_type: str
    cvss_score: float
    severity: str
    justification: str
    remediation_priority: str
    honeypot_id: str

class StatsSummary(BaseModel):
    """Model for statistics summary."""
    total_attacks: int
    unique_attackers: int
    active_honeypots: int
    avg_cvss_score: float
    top_attack_types: Dict[str, int]
    attack_trend: List[Dict[str, Any]]
    geographic_distribution: Dict[str, int]

class ConnectionManager:
    """Manages WebSocket connections for real-time updates."""
    
    def __init__(self):
        self.active_connections: List[WebSocket] = []
    
    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"WebSocket connected. Total connections: {len(self.active_connections)}")
    
    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info(f"WebSocket disconnected. Total connections: {len(self.active_connections)}")
    
    async def send_personal_message(self, message: str, websocket: WebSocket):
        try:
            await websocket.send_text(message)
        except Exception as e:
            logger.error(f"Error sending message: {e}")
            self.disconnect(websocket)
    
    async def broadcast(self, message: str):
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception as e:
                logger.error(f"Error broadcasting to connection: {e}")
                disconnected.append(connection)
        
        # Remove disconnected connections
        for conn in disconnected:
            self.disconnect(conn)

class DataManager:
    """Manages data access and aggregation."""
    
    def __init__(self):
        self.db_path = Path("dashboard_data.db")
        self._init_database()
    
    def _init_database(self):
        """Initialize SQLite database for dashboard data."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS honeypot_status (
                    honeypot_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    public_ip TEXT,
                    private_ip TEXT,
                    instance_type TEXT,
                    last_seen TIMESTAMP,
                    attack_count INTEGER DEFAULT 0,
                    unique_attackers INTEGER DEFAULT 0,
                    uptime_hours REAL DEFAULT 0,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS attack_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP NOT NULL,
                    source_ip TEXT NOT NULL,
                    destination_port INTEGER,
                    protocol TEXT,
                    event_type TEXT,
                    honeypot_id TEXT,
                    session_id TEXT,
                    username TEXT,
                    password TEXT,
                    command TEXT,
                    geolocation_country TEXT,
                    geolocation_city TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cvss_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP NOT NULL,
                    ioc_value TEXT NOT NULL,
                    ioc_type TEXT,
                    cvss_score REAL,
                    severity TEXT,
                    justification TEXT,
                    remediation_priority TEXT,
                    honeypot_id TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            conn.execute("CREATE INDEX IF NOT EXISTS idx_attack_timestamp ON attack_events(timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_attack_source_ip ON attack_events(source_ip)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_cvss_timestamp ON cvss_events(timestamp)")
    
    def get_honeypot_status(self) -> List[HoneypotStatus]:
        """Get status of all honeypots."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("""
                SELECT * FROM honeypot_status 
                ORDER BY last_seen DESC
            """)
            
            results = []
            for row in cursor.fetchall():
                status = HoneypotStatus(
                    honeypot_id=row['honeypot_id'],
                    status=row['status'],
                    public_ip=row['public_ip'] or '',
                    private_ip=row['private_ip'] or '',
                    instance_type=row['instance_type'] or '',
                    last_seen=datetime.fromisoformat(row['last_seen']),
                    attack_count=row['attack_count'],
                    unique_attackers=row['unique_attackers'],
                    uptime_hours=row['uptime_hours']
                )
                results.append(status)
            
            return results
    
    def update_honeypot_status(self, honeypot_id: str, status_data: Dict[str, Any]):
        """Update honeypot status."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO honeypot_status 
                (honeypot_id, status, public_ip, private_ip, instance_type, 
                 last_seen, attack_count, unique_attackers, uptime_hours, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """, (
                honeypot_id,
                status_data.get('status', 'unknown'),
                status_data.get('public_ip'),
                status_data.get('private_ip'),
                status_data.get('instance_type'),
                status_data.get('last_seen', datetime.now()),
                status_data.get('attack_count', 0),
                status_data.get('unique_attackers', 0),
                status_data.get('uptime_hours', 0)
            ))
    
    def add_attack_event(self, event: AttackEvent):
        """Add new attack event."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO attack_events 
                (timestamp, source_ip, destination_port, protocol, event_type,
                 honeypot_id, session_id, username, password, command,
                 geolocation_country, geolocation_city)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event.timestamp,
                event.source_ip,
                event.destination_port,
                event.protocol,
                event.event_type,
                event.honeypot_id,
                event.session_id,
                event.username,
                event.password,
                event.command,
                event.geolocation.get('country') if event.geolocation else None,
                event.geolocation.get('city') if event.geolocation else None
            ))
    
    def add_cvss_event(self, event: CVSSEvent):
        """Add new CVSS event."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO cvss_events 
                (timestamp, ioc_value, ioc_type, cvss_score, severity,
                 justification, remediation_priority, honeypot_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event.timestamp,
                event.ioc_value,
                event.ioc_type,
                event.cvss_score,
                event.severity,
                event.justification,
                event.remediation_priority,
                event.honeypot_id
            ))
    
    def get_recent_attacks(self, hours: int = 24, limit: int = 100) -> List[AttackEvent]:
        """Get recent attack events."""
        since = datetime.now() - timedelta(hours=hours)
        
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("""
                SELECT * FROM attack_events 
                WHERE timestamp >= ?
                ORDER BY timestamp DESC
                LIMIT ?
            """, (since, limit))
            
            results = []
            for row in cursor.fetchall():
                geolocation = {}
                if row['geolocation_country']:
                    geolocation['country'] = row['geolocation_country']
                if row['geolocation_city']:
                    geolocation['city'] = row['geolocation_city']
                
                event = AttackEvent(
                    timestamp=datetime.fromisoformat(row['timestamp']),
                    source_ip=row['source_ip'],
                    destination_port=row['destination_port'],
                    protocol=row['protocol'],
                    event_type=row['event_type'],
                    honeypot_id=row['honeypot_id'],
                    session_id=row['session_id'],
                    username=row['username'],
                    password=row['password'],
                    command=row['command'],
                    geolocation=geolocation if geolocation else None
                )
                results.append(event)
            
            return results
    
    def get_recent_cvss_events(self, hours: int = 24, limit: int = 50) -> List[CVSSEvent]:
        """Get recent CVSS events."""
        since = datetime.now() - timedelta(hours=hours)
        
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("""
                SELECT * FROM cvss_events 
                WHERE timestamp >= ?
                ORDER BY cvss_score DESC, timestamp DESC
                LIMIT ?
            """, (since, limit))
            
            results = []
            for row in cursor.fetchall():
                event = CVSSEvent(
                    timestamp=datetime.fromisoformat(row['timestamp']),
                    ioc_value=row['ioc_value'],
                    ioc_type=row['ioc_type'],
                    cvss_score=row['cvss_score'],
                    severity=row['severity'],
                    justification=row['justification'],
                    remediation_priority=row['remediation_priority'],
                    honeypot_id=row['honeypot_id']
                )
                results.append(event)
            
            return results
    
    def get_statistics_summary(self) -> StatsSummary:
        """Get aggregated statistics."""
        with sqlite3.connect(self.db_path) as conn:
            # Total attacks in last 24 hours
            since_24h = datetime.now() - timedelta(hours=24)
            total_attacks = conn.execute(
                "SELECT COUNT(*) FROM attack_events WHERE timestamp >= ?", 
                (since_24h,)
            ).fetchone()[0]
            
            # Unique attackers in last 24 hours
            unique_attackers = conn.execute(
                "SELECT COUNT(DISTINCT source_ip) FROM attack_events WHERE timestamp >= ?", 
                (since_24h,)
            ).fetchone()[0]
            
            # Active honeypots
            active_honeypots = conn.execute(
                "SELECT COUNT(*) FROM honeypot_status WHERE status = 'running'"
            ).fetchone()[0]
            
            # Average CVSS score in last 24 hours
            avg_cvss = conn.execute(
                "SELECT AVG(cvss_score) FROM cvss_events WHERE timestamp >= ?", 
                (since_24h,)
            ).fetchone()[0] or 0.0
            
            # Top attack types
            cursor = conn.execute("""
                SELECT event_type, COUNT(*) as count 
                FROM attack_events 
                WHERE timestamp >= ?
                GROUP BY event_type 
                ORDER BY count DESC 
                LIMIT 10
            """, (since_24h,))
            top_attack_types = dict(cursor.fetchall())
            
            # Attack trend (hourly for last 24 hours)
            trend_data = []
            for i in range(24):
                hour_start = datetime.now() - timedelta(hours=i+1)
                hour_end = datetime.now() - timedelta(hours=i)
                
                count = conn.execute(
                    "SELECT COUNT(*) FROM attack_events WHERE timestamp BETWEEN ? AND ?",
                    (hour_start, hour_end)
                ).fetchone()[0]
                
                trend_data.append({
                    'hour': hour_start.strftime('%H:00'),
                    'attacks': count
                })
            
            trend_data.reverse()  # Chronological order
            
            # Geographic distribution
            cursor = conn.execute("""
                SELECT geolocation_country, COUNT(*) as count 
                FROM attack_events 
                WHERE timestamp >= ? AND geolocation_country IS NOT NULL
                GROUP BY geolocation_country 
                ORDER BY count DESC 
                LIMIT 10
            """, (since_24h,))
            geographic_distribution = dict(cursor.fetchall())
            
            return StatsSummary(
                total_attacks=total_attacks,
                unique_attackers=unique_attackers,
                active_honeypots=active_honeypots,
                avg_cvss_score=round(avg_cvss, 2),
                top_attack_types=top_attack_types,
                attack_trend=trend_data,
                geographic_distribution=geographic_distribution
            )

# Global instances
manager = ConnectionManager()
data_manager = DataManager()

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan management."""
    logger.info("Starting CerberusMesh Dashboard API")
    
    # Start background tasks
    asyncio.create_task(periodic_data_update())
    
    yield
    
    logger.info("Shutting down CerberusMesh Dashboard API")

# FastAPI app
app = FastAPI(
    title="CerberusMesh Dashboard API",
    description="Real-time honeypot monitoring and threat intelligence API",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API Routes

@app.get("/")
async def root():
    """API health check."""
    return {
        "message": "CerberusMesh Dashboard API",
        "version": "1.0.0",
        "status": "running",
        "timestamp": datetime.now()
    }

@app.get("/api/v1/status", response_model=List[HoneypotStatus])
async def get_honeypot_status():
    """Get status of all honeypots."""
    try:
        status_list = data_manager.get_honeypot_status()
        return status_list
    except Exception as e:
        logger.error(f"Error getting honeypot status: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/api/v1/status/{honeypot_id}")
async def update_honeypot_status(honeypot_id: str, status_data: Dict[str, Any]):
    """Update status for a specific honeypot."""
    try:
        data_manager.update_honeypot_status(honeypot_id, status_data)
        
        # Broadcast update to WebSocket clients
        await manager.broadcast(json.dumps({
            "type": "status_update",
            "honeypot_id": honeypot_id,
            "data": status_data,
            "timestamp": datetime.now().isoformat()
        }))
        
        return {"message": "Status updated successfully"}
    except Exception as e:
        logger.error(f"Error updating honeypot status: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/api/v1/attacks", response_model=List[AttackEvent])
async def get_recent_attacks(hours: int = 24, limit: int = 100):
    """Get recent attack events."""
    try:
        attacks = data_manager.get_recent_attacks(hours, limit)
        return attacks
    except Exception as e:
        logger.error(f"Error getting recent attacks: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/api/v1/attacks")
async def add_attack_event(event: AttackEvent):
    """Add a new attack event."""
    try:
        data_manager.add_attack_event(event)
        
        # Broadcast to WebSocket clients
        await manager.broadcast(json.dumps({
            "type": "attack_event",
            "data": event.dict(),
            "timestamp": datetime.now().isoformat()
        }, default=str))
        
        return {"message": "Attack event added successfully"}
    except Exception as e:
        logger.error(f"Error adding attack event: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/api/v1/cvss", response_model=List[CVSSEvent])
async def get_recent_cvss_events(hours: int = 24, limit: int = 50):
    """Get recent CVSS scoring events."""
    try:
        events = data_manager.get_recent_cvss_events(hours, limit)
        return events
    except Exception as e:
        logger.error(f"Error getting CVSS events: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/api/v1/cvss")
async def add_cvss_event(event: CVSSEvent):
    """Add a new CVSS scoring event."""
    try:
        data_manager.add_cvss_event(event)
        
        # Broadcast to WebSocket clients
        await manager.broadcast(json.dumps({
            "type": "cvss_event",
            "data": event.dict(),
            "timestamp": datetime.now().isoformat()
        }, default=str))
        
        return {"message": "CVSS event added successfully"}
    except Exception as e:
        logger.error(f"Error adding CVSS event: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/api/v1/statistics", response_model=StatsSummary)
async def get_statistics():
    """Get aggregated statistics summary."""
    try:
        stats = data_manager.get_statistics_summary()
        return stats
    except Exception as e:
        logger.error(f"Error getting statistics: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/api/v1/export/attacks")
async def export_attacks(hours: int = 24):
    """Export attack data as JSON."""
    try:
        attacks = data_manager.get_recent_attacks(hours, limit=1000)
        
        export_data = {
            "export_timestamp": datetime.now().isoformat(),
            "time_range_hours": hours,
            "total_events": len(attacks),
            "events": [attack.dict() for attack in attacks]
        }
        
        return JSONResponse(
            content=export_data,
            headers={
                "Content-Disposition": f"attachment; filename=cerberusmesh_attacks_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            }
        )
    except Exception as e:
        logger.error(f"Error exporting attacks: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time updates."""
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive and handle incoming messages
            data = await websocket.receive_text()
            
            # Echo back for testing
            await manager.send_personal_message(f"Echo: {data}", websocket)
            
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# Background Tasks

async def periodic_data_update():
    """Periodic task to update statistics and broadcast to clients."""
    while True:
        try:
            # Update statistics every 30 seconds
            await asyncio.sleep(30)
            
            stats = data_manager.get_statistics_summary()
            
            # Broadcast statistics update
            await manager.broadcast(json.dumps({
                "type": "statistics_update",
                "data": stats.dict(),
                "timestamp": datetime.now().isoformat()
            }))
            
        except Exception as e:
            logger.error(f"Error in periodic data update: {e}")
            await asyncio.sleep(5)

def load_sample_data():
    """Load sample data for testing (development only)."""
    if os.getenv("CERBERUSMESH_ENV") != "development":
        return
    
    logger.info("Loading sample data for development")
    
    # Sample honeypot status
    sample_honeypots = [
        {
            "honeypot_id": "honeypot-001",
            "status": "running",
            "public_ip": "1.2.3.4",
            "private_ip": "10.0.1.10",
            "instance_type": "t3.micro",
            "last_seen": datetime.now(),
            "attack_count": 125,
            "unique_attackers": 15,
            "uptime_hours": 48.5
        },
        {
            "honeypot_id": "honeypot-002", 
            "status": "running",
            "public_ip": "1.2.3.5",
            "private_ip": "10.0.1.11",
            "instance_type": "t3.micro",
            "last_seen": datetime.now(),
            "attack_count": 89,
            "unique_attackers": 12,
            "uptime_hours": 72.1
        }
    ]
    
    for honeypot in sample_honeypots:
        data_manager.update_honeypot_status(honeypot["honeypot_id"], honeypot)

if __name__ == "__main__":
    # Load sample data in development
    load_sample_data()
    
    # Run the server
    uvicorn.run(
        "api:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
