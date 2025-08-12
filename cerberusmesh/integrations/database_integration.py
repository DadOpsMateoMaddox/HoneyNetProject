#!/usr/bin/env python3
"""
CerberusMesh Database Integration

Provides comprehensive SQL database support including:
- MariaDB/MySQL integration
- PostgreSQL integration
- SQLite support (lightweight deployments)
- Custom schema management
- Data analytics and reporting
"""

import json
import logging
import asyncio
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union, Tuple
from dataclasses import dataclass, asdict
import hashlib
import uuid

class DatabaseDriverError(Exception):
    """Database driver not available error."""
    pass

# Database drivers
try:
    import aiomysql
    MYSQL_AVAILABLE = True
except ImportError:
    aiomysql = None
    MYSQL_AVAILABLE = False

try:
    import asyncpg
    POSTGRES_AVAILABLE = True
except ImportError:
    asyncpg = None
    POSTGRES_AVAILABLE = False

try:
    import aiosqlite
    SQLITE_AVAILABLE = True
except ImportError:
    aiosqlite = None
    SQLITE_AVAILABLE = False

logger = logging.getLogger(__name__)

@dataclass
class DatabaseConfig:
    """Database configuration."""
    db_type: str  # mysql, postgresql, sqlite
    host: str = "localhost"
    port: int = 3306
    database: str = "cerberusmesh"
    username: str = "cerberus"
    password: str = ""
    ssl_enabled: bool = True
    pool_size: int = 10
    sqlite_path: str = "cerberusmesh.db"

@dataclass
class QueryResult:
    """Database query result."""
    success: bool
    rows_affected: int
    data: List[Dict[str, Any]]
    execution_time: float
    error_message: Optional[str] = None

class DatabaseIntegration:
    """Multi-database integration for CerberusMesh."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize database integration."""
        self.config = DatabaseConfig(**config)
        self.pool = None
        self.connection = None
        
        # SQL schema definitions
        self.schemas = self._define_schemas()
        
        # Validate database type
        if self.config.db_type not in ["mysql", "postgresql", "sqlite"]:
            raise ValueError(f"Unsupported database type: {self.config.db_type}")
    
    def _define_schemas(self) -> Dict[str, str]:
        """Define database schemas for different DB types."""
        
        # MySQL/MariaDB schemas
        mysql_schemas = {
            "intrusion_events": '''
                CREATE TABLE IF NOT EXISTS intrusion_events (
                    id BIGINT AUTO_INCREMENT PRIMARY KEY,
                    event_id VARCHAR(64) UNIQUE NOT NULL,
                    timestamp DATETIME(6) NOT NULL,
                    honeypot_id VARCHAR(100) NOT NULL,
                    source_ip VARCHAR(45) NOT NULL,
                    event_type VARCHAR(50) NOT NULL,
                    protocol VARCHAR(10) NOT NULL,
                    destination_port INT NOT NULL,
                    session_id VARCHAR(100),
                    username VARCHAR(255),
                    password VARCHAR(255),
                    command TEXT,
                    payload LONGTEXT,
                    severity ENUM('low', 'medium', 'high', 'critical') DEFAULT 'medium',
                    raw_data JSON,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_timestamp (timestamp),
                    INDEX idx_source_ip (source_ip),
                    INDEX idx_event_type (event_type),
                    INDEX idx_honeypot_id (honeypot_id)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
            ''',
            
            "agent_decisions": '''
                CREATE TABLE IF NOT EXISTS agent_decisions (
                    id BIGINT AUTO_INCREMENT PRIMARY KEY,
                    decision_id VARCHAR(64) UNIQUE NOT NULL,
                    timestamp DATETIME(6) NOT NULL,
                    event_id VARCHAR(64) NOT NULL,
                    decision_type VARCHAR(50) NOT NULL,
                    confidence DECIMAL(3,2) NOT NULL,
                    reasoning TEXT,
                    mitre_techniques JSON,
                    action_taken BOOLEAN DEFAULT FALSE,
                    result TEXT,
                    execution_time DECIMAL(10,3),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (event_id) REFERENCES intrusion_events(event_id),
                    INDEX idx_timestamp (timestamp),
                    INDEX idx_decision_type (decision_type),
                    INDEX idx_event_id (event_id)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
            ''',
            
            "threat_intelligence": '''
                CREATE TABLE IF NOT EXISTS threat_intelligence (
                    id BIGINT AUTO_INCREMENT PRIMARY KEY,
                    indicator_id VARCHAR(64) UNIQUE NOT NULL,
                    indicator_type VARCHAR(50) NOT NULL,
                    indicator_value VARCHAR(500) NOT NULL,
                    threat_score DECIMAL(3,2) NOT NULL,
                    confidence DECIMAL(3,2) NOT NULL,
                    source VARCHAR(100) NOT NULL,
                    first_seen DATETIME(6) NOT NULL,
                    last_seen DATETIME(6) NOT NULL,
                    mitre_techniques JSON,
                    context JSON,
                    tags JSON,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    INDEX idx_indicator_type (indicator_type),
                    INDEX idx_indicator_value (indicator_value),
                    INDEX idx_threat_score (threat_score),
                    INDEX idx_first_seen (first_seen)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
            ''',
            
            "honeypot_metrics": '''
                CREATE TABLE IF NOT EXISTS honeypot_metrics (
                    id BIGINT AUTO_INCREMENT PRIMARY KEY,
                    metric_id VARCHAR(64) UNIQUE NOT NULL,
                    honeypot_id VARCHAR(100) NOT NULL,
                    metric_type VARCHAR(50) NOT NULL,
                    metric_name VARCHAR(100) NOT NULL,
                    metric_value DECIMAL(15,4) NOT NULL,
                    timestamp DATETIME(6) NOT NULL,
                    tags JSON,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_honeypot_id (honeypot_id),
                    INDEX idx_metric_type (metric_type),
                    INDEX idx_timestamp (timestamp)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
            ''',
            
            "vulnerability_scans": '''
                CREATE TABLE IF NOT EXISTS vulnerability_scans (
                    id BIGINT AUTO_INCREMENT PRIMARY KEY,
                    scan_id VARCHAR(64) UNIQUE NOT NULL,
                    scan_name VARCHAR(200) NOT NULL,
                    target_hosts JSON NOT NULL,
                    scan_status VARCHAR(50) NOT NULL,
                    start_time DATETIME(6) NOT NULL,
                    end_time DATETIME(6),
                    vulnerabilities_found INT DEFAULT 0,
                    critical_count INT DEFAULT 0,
                    high_count INT DEFAULT 0,
                    medium_count INT DEFAULT 0,
                    low_count INT DEFAULT 0,
                    scan_results JSON,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_scan_status (scan_status),
                    INDEX idx_start_time (start_time)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
            '''
        }
        
        # PostgreSQL schemas (similar structure with PostgreSQL-specific syntax)
        postgresql_schemas = {
            "intrusion_events": '''
                CREATE TABLE IF NOT EXISTS intrusion_events (
                    id BIGSERIAL PRIMARY KEY,
                    event_id VARCHAR(64) UNIQUE NOT NULL,
                    timestamp TIMESTAMPTZ NOT NULL,
                    honeypot_id VARCHAR(100) NOT NULL,
                    source_ip INET NOT NULL,
                    event_type VARCHAR(50) NOT NULL,
                    protocol VARCHAR(10) NOT NULL,
                    destination_port INTEGER NOT NULL,
                    session_id VARCHAR(100),
                    username VARCHAR(255),
                    password VARCHAR(255),
                    command TEXT,
                    payload TEXT,
                    severity VARCHAR(10) DEFAULT 'medium' CHECK (severity IN ('low', 'medium', 'high', 'critical')),
                    raw_data JSONB,
                    created_at TIMESTAMPTZ DEFAULT NOW()
                );
                CREATE INDEX IF NOT EXISTS idx_intrusion_timestamp ON intrusion_events(timestamp);
                CREATE INDEX IF NOT EXISTS idx_intrusion_source_ip ON intrusion_events(source_ip);
                CREATE INDEX IF NOT EXISTS idx_intrusion_event_type ON intrusion_events(event_type);
                CREATE INDEX IF NOT EXISTS idx_intrusion_honeypot_id ON intrusion_events(honeypot_id);
            ''',
            
            "agent_decisions": '''
                CREATE TABLE IF NOT EXISTS agent_decisions (
                    id BIGSERIAL PRIMARY KEY,
                    decision_id VARCHAR(64) UNIQUE NOT NULL,
                    timestamp TIMESTAMPTZ NOT NULL,
                    event_id VARCHAR(64) NOT NULL,
                    decision_type VARCHAR(50) NOT NULL,
                    confidence DECIMAL(3,2) NOT NULL,
                    reasoning TEXT,
                    mitre_techniques JSONB,
                    action_taken BOOLEAN DEFAULT FALSE,
                    result TEXT,
                    execution_time DECIMAL(10,3),
                    created_at TIMESTAMPTZ DEFAULT NOW(),
                    FOREIGN KEY (event_id) REFERENCES intrusion_events(event_id)
                );
                CREATE INDEX IF NOT EXISTS idx_decisions_timestamp ON agent_decisions(timestamp);
                CREATE INDEX IF NOT EXISTS idx_decisions_type ON agent_decisions(decision_type);
                CREATE INDEX IF NOT EXISTS idx_decisions_event_id ON agent_decisions(event_id);
            ''',
            
            "threat_intelligence": '''
                CREATE TABLE IF NOT EXISTS threat_intelligence (
                    id BIGSERIAL PRIMARY KEY,
                    indicator_id VARCHAR(64) UNIQUE NOT NULL,
                    indicator_type VARCHAR(50) NOT NULL,
                    indicator_value VARCHAR(500) NOT NULL,
                    threat_score DECIMAL(3,2) NOT NULL,
                    confidence DECIMAL(3,2) NOT NULL,
                    source VARCHAR(100) NOT NULL,
                    first_seen TIMESTAMPTZ NOT NULL,
                    last_seen TIMESTAMPTZ NOT NULL,
                    mitre_techniques JSONB,
                    context JSONB,
                    tags JSONB,
                    created_at TIMESTAMPTZ DEFAULT NOW(),
                    updated_at TIMESTAMPTZ DEFAULT NOW()
                );
                CREATE INDEX IF NOT EXISTS idx_threat_indicator_type ON threat_intelligence(indicator_type);
                CREATE INDEX IF NOT EXISTS idx_threat_indicator_value ON threat_intelligence(indicator_value);
                CREATE INDEX IF NOT EXISTS idx_threat_score ON threat_intelligence(threat_score);
            ''',
            
            "honeypot_metrics": '''
                CREATE TABLE IF NOT EXISTS honeypot_metrics (
                    id BIGSERIAL PRIMARY KEY,
                    metric_id VARCHAR(64) UNIQUE NOT NULL,
                    honeypot_id VARCHAR(100) NOT NULL,
                    metric_type VARCHAR(50) NOT NULL,
                    metric_name VARCHAR(100) NOT NULL,
                    metric_value DECIMAL(15,4) NOT NULL,
                    timestamp TIMESTAMPTZ NOT NULL,
                    tags JSONB,
                    created_at TIMESTAMPTZ DEFAULT NOW()
                );
                CREATE INDEX IF NOT EXISTS idx_metrics_honeypot_id ON honeypot_metrics(honeypot_id);
                CREATE INDEX IF NOT EXISTS idx_metrics_type ON honeypot_metrics(metric_type);
                CREATE INDEX IF NOT EXISTS idx_metrics_timestamp ON honeypot_metrics(timestamp);
            ''',
            
            "vulnerability_scans": '''
                CREATE TABLE IF NOT EXISTS vulnerability_scans (
                    id BIGSERIAL PRIMARY KEY,
                    scan_id VARCHAR(64) UNIQUE NOT NULL,
                    scan_name VARCHAR(200) NOT NULL,
                    target_hosts JSONB NOT NULL,
                    scan_status VARCHAR(50) NOT NULL,
                    start_time TIMESTAMPTZ NOT NULL,
                    end_time TIMESTAMPTZ,
                    vulnerabilities_found INTEGER DEFAULT 0,
                    critical_count INTEGER DEFAULT 0,
                    high_count INTEGER DEFAULT 0,
                    medium_count INTEGER DEFAULT 0,
                    low_count INTEGER DEFAULT 0,
                    scan_results JSONB,
                    created_at TIMESTAMPTZ DEFAULT NOW()
                );
                CREATE INDEX IF NOT EXISTS idx_scans_status ON vulnerability_scans(scan_status);
                CREATE INDEX IF NOT EXISTS idx_scans_start_time ON vulnerability_scans(start_time);
            '''
        }
        
        # SQLite schemas (simplified for lightweight deployments)
        sqlite_schemas = {
            "intrusion_events": '''
                CREATE TABLE IF NOT EXISTS intrusion_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT UNIQUE NOT NULL,
                    timestamp TEXT NOT NULL,
                    honeypot_id TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    protocol TEXT NOT NULL,
                    destination_port INTEGER NOT NULL,
                    session_id TEXT,
                    username TEXT,
                    password TEXT,
                    command TEXT,
                    payload TEXT,
                    severity TEXT DEFAULT 'medium',
                    raw_data TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                );
                CREATE INDEX IF NOT EXISTS idx_intrusion_timestamp ON intrusion_events(timestamp);
                CREATE INDEX IF NOT EXISTS idx_intrusion_source_ip ON intrusion_events(source_ip);
            ''',
            
            "agent_decisions": '''
                CREATE TABLE IF NOT EXISTS agent_decisions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    decision_id TEXT UNIQUE NOT NULL,
                    timestamp TEXT NOT NULL,
                    event_id TEXT NOT NULL,
                    decision_type TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    reasoning TEXT,
                    mitre_techniques TEXT,
                    action_taken INTEGER DEFAULT 0,
                    result TEXT,
                    execution_time REAL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (event_id) REFERENCES intrusion_events(event_id)
                );
                CREATE INDEX IF NOT EXISTS idx_decisions_timestamp ON agent_decisions(timestamp);
            ''',
            
            "threat_intelligence": '''
                CREATE TABLE IF NOT EXISTS threat_intelligence (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    indicator_id TEXT UNIQUE NOT NULL,
                    indicator_type TEXT NOT NULL,
                    indicator_value TEXT NOT NULL,
                    threat_score REAL NOT NULL,
                    confidence REAL NOT NULL,
                    source TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    mitre_techniques TEXT,
                    context TEXT,
                    tags TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                );
            ''',
            
            "honeypot_metrics": '''
                CREATE TABLE IF NOT EXISTS honeypot_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    metric_id TEXT UNIQUE NOT NULL,
                    honeypot_id TEXT NOT NULL,
                    metric_type TEXT NOT NULL,
                    metric_name TEXT NOT NULL,
                    metric_value REAL NOT NULL,
                    timestamp TEXT NOT NULL,
                    tags TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                );
            ''',
            
            "vulnerability_scans": '''
                CREATE TABLE IF NOT EXISTS vulnerability_scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT UNIQUE NOT NULL,
                    scan_name TEXT NOT NULL,
                    target_hosts TEXT NOT NULL,
                    scan_status TEXT NOT NULL,
                    start_time TEXT NOT NULL,
                    end_time TEXT,
                    vulnerabilities_found INTEGER DEFAULT 0,
                    critical_count INTEGER DEFAULT 0,
                    high_count INTEGER DEFAULT 0,
                    medium_count INTEGER DEFAULT 0,
                    low_count INTEGER DEFAULT 0,
                    scan_results TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                );
            '''
        }
        
        # Return appropriate schemas based on database type
        if self.config.db_type == "mysql":
            return mysql_schemas
        elif self.config.db_type == "postgresql":
            return postgresql_schemas
        else:  # sqlite
            return sqlite_schemas
    
    async def initialize(self) -> bool:
        """Initialize database connection and create tables."""
        try:
            if self.config.db_type == "mysql":
                await self._init_mysql()
            elif self.config.db_type == "postgresql":
                await self._init_postgresql()
            elif self.config.db_type == "sqlite":
                await self._init_sqlite()
            
            # Create tables
            await self._create_tables()
            
            logger.info(f"Database initialized: {self.config.db_type}")
            return True
            
        except Exception as e:
            logger.error(f"Database initialization failed: {e}")
            return False
    
    async def _init_mysql(self):
        """Initialize MySQL/MariaDB connection pool."""
        if not MYSQL_AVAILABLE:
            raise DatabaseDriverError("aiomysql not available")
        
        self.pool = await aiomysql.create_pool(
            host=self.config.host,
            port=self.config.port,
            user=self.config.username,
            password=self.config.password,
            db=self.config.database,
            minsize=1,
            maxsize=self.config.pool_size,
            charset='utf8mb4',
            autocommit=True
        )
    
    async def _init_postgresql(self):
        """Initialize PostgreSQL connection pool."""
        if not POSTGRES_AVAILABLE:
            raise DatabaseDriverError("asyncpg not available")
        
        self.pool = await asyncpg.create_pool(
            host=self.config.host,
            port=self.config.port,
            user=self.config.username,
            password=self.config.password,
            database=self.config.database,
            min_size=1,
            max_size=self.config.pool_size
        )
    
    async def _init_sqlite(self):
        """Initialize SQLite connection."""
        if not SQLITE_AVAILABLE:
            raise DatabaseDriverError("aiosqlite not available")
        
        self.connection = await aiosqlite.connect(self.config.sqlite_path)
        await self.connection.execute("PRAGMA foreign_keys = ON")
        await self.connection.commit()
    
    async def _create_tables(self):
        """Create database tables."""
        for table_name, schema in self.schemas.items():
            await self._execute_query(schema)
            logger.debug(f"Created table: {table_name}")
    
    async def _execute_query(self, query: str, params: Tuple = None) -> QueryResult:
        """Execute database query."""
        start_time = time.time()
        
        try:
            if self.config.db_type == "mysql":
                return await self._execute_mysql_query(query, params)
            elif self.config.db_type == "postgresql":
                return await self._execute_postgresql_query(query, params)
            elif self.config.db_type == "sqlite":
                return await self._execute_sqlite_query(query, params)
        except Exception as e:
            execution_time = time.time() - start_time
            logger.error(f"Query execution failed: {e}")
            return QueryResult(
                success=False,
                rows_affected=0,
                data=[],
                execution_time=execution_time,
                error_message=str(e)
            )
    
    async def _execute_mysql_query(self, query: str, params: Tuple = None) -> QueryResult:
        """Execute MySQL query."""
        start_time = time.time()
        
        async with self.pool.acquire() as conn:
            async with conn.cursor(aiomysql.DictCursor) as cursor:
                await cursor.execute(query, params)
                rows_affected = cursor.rowcount
                
                if query.strip().upper().startswith('SELECT'):
                    data = await cursor.fetchall()
                else:
                    data = []
                
                execution_time = time.time() - start_time
                return QueryResult(
                    success=True,
                    rows_affected=rows_affected,
                    data=data,
                    execution_time=execution_time
                )
    
    async def _execute_postgresql_query(self, query: str, params: Tuple = None) -> QueryResult:
        """Execute PostgreSQL query."""
        start_time = time.time()
        
        async with self.pool.acquire() as conn:
            if query.strip().upper().startswith('SELECT'):
                rows = await conn.fetch(query, *(params or ()))
                data = [dict(row) for row in rows]
                rows_affected = len(data)
            else:
                result = await conn.execute(query, *(params or ()))
                rows_affected = int(result.split()[-1]) if result else 0
                data = []
            
            execution_time = time.time() - start_time
            return QueryResult(
                success=True,
                rows_affected=rows_affected,
                data=data,
                execution_time=execution_time
            )
    
    async def _execute_sqlite_query(self, query: str, params: Tuple = None) -> QueryResult:
        """Execute SQLite query."""
        start_time = time.time()
        
        async with self.connection.cursor() as cursor:
            await cursor.execute(query, params or ())
            
            if query.strip().upper().startswith('SELECT'):
                rows = await cursor.fetchall()
                # Convert to dict format
                columns = [description[0] for description in cursor.description]
                data = [dict(zip(columns, row)) for row in rows]
                rows_affected = len(data)
            else:
                data = []
                rows_affected = cursor.rowcount
            
            await self.connection.commit()
            
            execution_time = time.time() - start_time
            return QueryResult(
                success=True,
                rows_affected=rows_affected,
                data=data,
                execution_time=execution_time
            )
    
    # High-level data access methods
    async def store_intrusion_event(self, event) -> bool:
        """Store intrusion event in database."""
        query = '''
            INSERT INTO intrusion_events 
            (event_id, timestamp, honeypot_id, source_ip, event_type, protocol, 
             destination_port, session_id, username, password, command, payload, 
             severity, raw_data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        '''
        
        params = (
            event.event_id,
            event.timestamp.isoformat(),
            event.honeypot_id,
            event.source_ip,
            event.event_type,
            event.protocol,
            event.destination_port,
            event.session_id,
            event.username,
            event.password,
            event.command,
            event.payload,
            event.severity,
            json.dumps(event.raw_data) if event.raw_data else None
        )
        
        result = await self._execute_query(query, params)
        return result.success
    
    async def store_agent_decision(self, decision) -> bool:
        """Store agent decision in database."""
        query = '''
            INSERT INTO agent_decisions 
            (decision_id, timestamp, event_id, decision_type, confidence, 
             reasoning, mitre_techniques, action_taken, result, execution_time)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        '''
        
        params = (
            decision.decision_id,
            decision.timestamp.isoformat(),
            decision.event_id,
            decision.decision_type,
            decision.confidence,
            decision.reasoning,
            json.dumps(decision.mitre_techniques),
            decision.action_taken,
            decision.result,
            decision.execution_time
        )
        
        result = await self._execute_query(query, params)
        return result.success
    
    async def get_attack_timeline(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get attack timeline for specified hours."""
        if self.config.db_type == "sqlite":
            query = '''
                SELECT 
                    DATE(timestamp) as date,
                    strftime('%H', timestamp) as hour,
                    event_type,
                    COUNT(*) as count,
                    COUNT(DISTINCT source_ip) as unique_ips
                FROM intrusion_events 
                WHERE datetime(timestamp) >= datetime('now', '-{} hours')
                GROUP BY date, hour, event_type
                ORDER BY date, hour
            '''.format(hours)
        else:
            query = '''
                SELECT 
                    DATE(timestamp) as date,
                    EXTRACT(HOUR FROM timestamp) as hour,
                    event_type,
                    COUNT(*) as count,
                    COUNT(DISTINCT source_ip) as unique_ips
                FROM intrusion_events 
                WHERE timestamp >= NOW() - INTERVAL {} HOUR
                GROUP BY date, hour, event_type
                ORDER BY date, hour
            '''.format(hours)
        
        result = await self._execute_query(query)
        return result.data if result.success else []
    
    async def get_top_attackers(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Get top attacking IP addresses."""
        query = '''
            SELECT 
                source_ip,
                COUNT(*) as total_events,
                COUNT(DISTINCT event_type) as event_types,
                COUNT(DISTINCT honeypot_id) as honeypots_hit,
                MIN(timestamp) as first_seen,
                MAX(timestamp) as last_seen,
                AVG(CASE WHEN severity = 'critical' THEN 4
                         WHEN severity = 'high' THEN 3
                         WHEN severity = 'medium' THEN 2
                         ELSE 1 END) as avg_severity
            FROM intrusion_events
            GROUP BY source_ip
            ORDER BY total_events DESC
            LIMIT ?
        '''
        
        result = await self._execute_query(query, (limit,))
        return result.data if result.success else []
    
    async def get_decision_effectiveness(self) -> Dict[str, Any]:
        """Analyze decision effectiveness."""
        query = '''
            SELECT 
                decision_type,
                COUNT(*) as total_decisions,
                SUM(CASE WHEN action_taken THEN 1 ELSE 0 END) as actions_taken,
                AVG(confidence) as avg_confidence,
                AVG(execution_time) as avg_execution_time
            FROM agent_decisions
            GROUP BY decision_type
            ORDER BY total_decisions DESC
        '''
        
        result = await self._execute_query(query)
        if result.success:
            effectiveness = {}
            for row in result.data:
                effectiveness[row['decision_type']] = {
                    'total_decisions': row['total_decisions'],
                    'action_rate': row['actions_taken'] / row['total_decisions'] if row['total_decisions'] > 0 else 0,
                    'avg_confidence': float(row['avg_confidence'] or 0),
                    'avg_execution_time': float(row['avg_execution_time'] or 0)
                }
            return effectiveness
        return {}
    
    async def close(self):
        """Close database connections."""
        try:
            if self.pool:
                if self.config.db_type == "mysql":
                    self.pool.close()
                    await self.pool.wait_closed()
                elif self.config.db_type == "postgresql":
                    await self.pool.close()
            elif self.connection:
                await self.connection.close()
            
            logger.info("Database connections closed")
        except Exception as e:
            logger.error(f"Error closing database: {e}")
    
    # Analytics and reporting methods
    async def generate_analytics_report(self, days: int = 7) -> Dict[str, Any]:
        """Generate comprehensive analytics report."""
        report = {
            "report_period": f"{days} days",
            "generated_at": datetime.now().isoformat(),
            "summary": {},
            "attack_trends": {},
            "decision_analysis": {},
            "threat_landscape": {}
        }
        
        # Summary statistics
        summary_query = '''
            SELECT 
                COUNT(*) as total_events,
                COUNT(DISTINCT source_ip) as unique_attackers,
                COUNT(DISTINCT honeypot_id) as active_honeypots,
                COUNT(DISTINCT session_id) as unique_sessions
            FROM intrusion_events
            WHERE timestamp >= datetime('now', '-{} days')
        '''.format(days) if self.config.db_type == "sqlite" else '''
            SELECT 
                COUNT(*) as total_events,
                COUNT(DISTINCT source_ip) as unique_attackers,
                COUNT(DISTINCT honeypot_id) as active_honeypots,
                COUNT(DISTINCT session_id) as unique_sessions
            FROM intrusion_events
            WHERE timestamp >= NOW() - INTERVAL {} DAY
        '''.format(days)
        
        summary_result = await self._execute_query(summary_query)
        if summary_result.success and summary_result.data:
            report["summary"] = summary_result.data[0]
        
        # Attack trends
        report["attack_trends"] = await self.get_attack_timeline(days * 24)
        
        # Decision analysis
        report["decision_analysis"] = await self.get_decision_effectiveness()
        
        # Top attackers
        report["threat_landscape"]["top_attackers"] = await self.get_top_attackers(10)
        
        return report
