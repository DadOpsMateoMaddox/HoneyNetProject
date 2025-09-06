# Troubleshooting Guide

## 🚨 Common Issues & Quick Fixes

### Docker & Container Issues

#### Issue: Containers Won't Start
**Symptoms**: `docker-compose up` fails, containers exit immediately

**Quick Diagnosis**:
```bash
# Check container logs
docker-compose logs cerberus-api
docker-compose logs cerberus-redis

# Check Docker system resources
docker system df
docker system prune -f  # Clean up if needed
```

**Common Causes & Solutions**:

1. **Port Already in Use**
   ```bash
   # Find process using port 8000
   netstat -ano | findstr :8000
   # Kill the process or change port in docker-compose.yml
   ```

2. **Environment Variables Missing**
   ```bash
   # Check .env file exists and has required variables
   cat .env | grep -E "(OPENAI_API_KEY|REDIS_URL)"
   
   # Copy from template if missing
   cp env_template.txt .env
   ```

3. **Docker Daemon Not Running**
   ```bash
   # On Windows/WSL
   sudo service docker start
   
   # Or restart Docker Desktop
   ```

#### Issue: API Returns 500 Internal Server Error
**Symptoms**: Dashboard shows connection errors, API endpoints return 500

**Diagnostic Steps**:
```bash
# Check API container logs
docker-compose logs cerberus-api --tail 50

# Test API health endpoint
curl http://localhost:8000/health

# Check Redis connectivity
docker exec -it cerberusmesh-redis redis-cli ping
```

**Common Solutions**:

1. **Redis Connection Failed**
   ```python
   # In dashboard/api.py, add connection retry
   import redis
   import time
   
   def get_redis_client():
       for attempt in range(5):
           try:
               client = redis.Redis(host='redis', port=6379, decode_responses=True)
               client.ping()
               return client
           except redis.ConnectionError:
               time.sleep(2)
       raise Exception("Could not connect to Redis")
   ```

2. **OpenAI API Key Invalid**
   ```bash
   # Test API key manually
   curl -H "Authorization: Bearer $OPENAI_API_KEY" \
        https://api.openai.com/v1/models
   
   # Response should list available models
   ```

3. **Memory/Resource Limits**
   ```yaml
   # Add to docker-compose.yml
   services:
     cerberus-api:
       mem_limit: 2g
       memswap_limit: 2g
   ```

### Performance Issues

#### Issue: Slow API Response Times
**Symptoms**: Dashboard takes >5 seconds to load, timeouts

**Performance Monitoring**:
```python
# Add timing middleware to FastAPI
import time
from fastapi import Request

@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(process_time)
    return response
```

**Common Bottlenecks**:

1. **GPT-4 API Timeout**
   ```python
   # Implement timeout and fallback
   async def analyze_with_timeout(event):
       try:
           response = await asyncio.wait_for(
               openai.ChatCompletion.acreate(...),
               timeout=5.0
           )
           return response
       except asyncio.TimeoutError:
           return {"analysis": "timeout_fallback", "confidence": 0.5}
   ```

2. **Database Connection Pool Exhausted**
   ```python
   # Increase connection pool size
   DATABASE_URL = "postgresql://user:pass@host/db?pool_size=20&max_overflow=30"
   ```

3. **Memory Leak in Event Processing**
   ```python
   # Add memory cleanup
   import gc
   
   def process_event_batch(events):
       results = []
       for event in events:
           result = process_single_event(event)
           results.append(result)
       
       # Force garbage collection
       gc.collect()
       return results
   ```

#### Issue: High CPU Usage
**Symptoms**: System becomes unresponsive, fans spinning at maximum

**CPU Profiling**:
```python
import cProfile
import pstats

def profile_cpu_usage():
    profiler = cProfile.Profile()
    profiler.enable()
    
    # Run problematic code
    process_events_for_analysis()
    
    profiler.disable()
    stats = pstats.Stats(profiler)
    stats.sort_stats('cumulative')
    stats.print_stats(10)  # Top 10 CPU consumers
```

**Optimization Strategies**:

1. **Reduce ML Model Complexity**
   ```python
   # Use simpler model for real-time analysis
   from sklearn.ensemble import IsolationForest
   
   # Instead of complex ensemble
   model = IsolationForest(
       n_estimators=50,  # Reduced from 100
       contamination=0.1,
       random_state=42,
       n_jobs=1  # Single thread for consistency
   )
   ```

2. **Implement Request Rate Limiting**
   ```python
   from slowapi import Limiter, _rate_limit_exceeded_handler
   from slowapi.util import get_remote_address
   
   limiter = Limiter(key_func=get_remote_address)
   app.state.limiter = limiter
   
   @app.get("/analyze")
   @limiter.limit("10/minute")  # Limit to 10 requests per minute
   async def analyze_event(request: Request):
       # Analysis code here
       pass
   ```

### AI & Machine Learning Issues

#### Issue: GPT-4 Responses Are Inconsistent
**Symptoms**: AI personas give contradictory information, break character

**Solution: Improve Prompt Engineering**
```python
class PersonaManager:
    def __init__(self):
        self.system_prompts = {
            "worried_admin": """
You are Jamie, a junior system administrator who started 3 months ago.
PERSONALITY: Nervous, eager to help, worried about making mistakes
KNOWLEDGE: Basic Linux commands, mentions being "still learning"
SPEECH PATTERN: Uses phrases like "I think...", "Let me double-check", "I'm still new but..."
NEVER: Give expert-level advice, be overly confident, break character
ALWAYS: Ask for confirmation, mention supervisor when unsure, apologize for delays
            """
        }
    
    def get_response(self, persona, user_input, context):
        messages = [
            {"role": "system", "content": self.system_prompts[persona]},
            {"role": "user", "content": f"Context: {context}\nUser says: {user_input}"}
        ]
        
        response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=messages,
            temperature=0.7,  # Some creativity but consistent
            max_tokens=150,   # Keep responses concise
            presence_penalty=0.6  # Avoid repetition
        )
        
        return response.choices[0].message.content
```

#### Issue: ML Model Gives Too Many False Positives
**Symptoms**: Normal activity flagged as attacks, alert fatigue

**Model Tuning Approach**:
```python
class AdaptiveAnomalyDetector:
    def __init__(self):
        self.model = IsolationForest(contamination=0.05)  # Start conservative
        self.feedback_buffer = []
        self.retrain_threshold = 1000
    
    def analyze_with_feedback(self, event):
        score = self.model.decision_function([event.features])[0]
        
        # Adjust threshold based on feedback
        threshold = self.calculate_adaptive_threshold()
        
        return {
            "anomaly_score": score,
            "is_anomaly": score < threshold,
            "confidence": abs(score - threshold) / threshold
        }
    
    def add_feedback(self, event, is_true_positive):
        """Security analyst provides feedback"""
        self.feedback_buffer.append({
            "features": event.features,
            "label": 1 if is_true_positive else 0,
            "timestamp": time.time()
        })
        
        if len(self.feedback_buffer) >= self.retrain_threshold:
            self.retrain_model()
    
    def retrain_model(self):
        """Retrain with human feedback"""
        # Extract features and labels from feedback
        X = [item["features"] for item in self.feedback_buffer]
        y = [item["label"] for item in self.feedback_buffer]
        
        # Train supervised model for confirmed attacks
        supervised_model = RandomForestClassifier()
        supervised_model.fit(X, y)
        
        # Combine with unsupervised detection
        self.ensemble_model = VotingClassifier([
            ("isolation_forest", self.model),
            ("supervised", supervised_model)
        ])
        
        # Clear feedback buffer
        self.feedback_buffer = []
```

### Database & Storage Issues

#### Issue: Database Growing Too Large
**Symptoms**: Disk space warnings, slow queries

**Storage Management Strategy**:
```python
import sqlite3
from datetime import datetime, timedelta

class DatabaseMaintenance:
    def __init__(self, db_path):
        self.db_path = db_path
    
    def cleanup_old_events(self, days_to_keep=30):
        """Remove events older than specified days"""
        cutoff_date = datetime.now() - timedelta(days=days_to_keep)
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Archive old events before deletion
            cursor.execute("""
                INSERT INTO events_archive 
                SELECT * FROM events 
                WHERE timestamp < ?
            """, (cutoff_date,))
            
            # Delete old events
            cursor.execute("DELETE FROM events WHERE timestamp < ?", (cutoff_date,))
            
            # Vacuum to reclaim space
            cursor.execute("VACUUM")
            
            conn.commit()
    
    def compress_old_data(self):
        """Compress detailed logs to summary statistics"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Create daily summaries
            cursor.execute("""
                INSERT OR REPLACE INTO daily_summary
                SELECT 
                    DATE(timestamp) as date,
                    source_ip,
                    COUNT(*) as event_count,
                    GROUP_CONCAT(DISTINCT mitre_technique) as techniques,
                    AVG(anomaly_score) as avg_score
                FROM events 
                WHERE timestamp < DATE('now', '-7 days')
                GROUP BY DATE(timestamp), source_ip
            """)
            
            # Remove detailed records after summarization
            cursor.execute("DELETE FROM events WHERE timestamp < DATE('now', '-7 days')")
            
            conn.commit()
```

#### Issue: Redis Memory Usage Too High
**Symptoms**: Redis container OOM kills, cache misses

**Redis Optimization**:
```python
import redis

class OptimizedRedisManager:
    def __init__(self):
        self.client = redis.Redis(
            host='localhost',
            port=6379,
            decode_responses=True,
            max_connections=10
        )
        
        # Configure Redis for memory efficiency
        self.client.config_set('maxmemory', '512mb')
        self.client.config_set('maxmemory-policy', 'allkeys-lru')
    
    def cache_with_compression(self, key, data, ttl=3600):
        """Cache data with compression"""
        import json
        import gzip
        
        # Serialize and compress
        json_data = json.dumps(data)
        compressed = gzip.compress(json_data.encode())
        
        # Store with TTL
        self.client.setex(f"compressed:{key}", ttl, compressed)
    
    def get_compressed(self, key):
        """Retrieve and decompress data"""
        import json
        import gzip
        
        compressed = self.client.get(f"compressed:{key}")
        if compressed:
            json_data = gzip.decompress(compressed).decode()
            return json.loads(json_data)
        return None
    
    def cleanup_expired_keys(self):
        """Manual cleanup of expired keys"""
        pattern = "session:*"
        for key in self.client.scan_iter(pattern):
            ttl = self.client.ttl(key)
            if ttl == -1:  # No expiration set
                self.client.expire(key, 3600)  # Set 1 hour TTL
```

## 🔧 Diagnostic Tools

### Health Check Script
```python
#!/usr/bin/env python3
"""
CerberusMesh Health Check Script
Usage: python health_check.py
"""

import requests
import redis
import sqlite3
import time
import sys

class HealthChecker:
    def __init__(self):
        self.api_url = "http://localhost:8000"
        self.redis_host = "localhost"
        self.redis_port = 6379
        self.db_path = "dashboard_data.db"
        
        self.checks = [
            self.check_api_health,
            self.check_redis_connectivity,
            self.check_database_integrity,
            self.check_openai_api,
            self.check_disk_space,
            self.check_memory_usage
        ]
    
    def run_all_checks(self):
        print("🔍 CerberusMesh Health Check")
        print("=" * 40)
        
        results = []
        for check in self.checks:
            try:
                result = check()
                results.append(result)
                status = "✅ PASS" if result["status"] == "healthy" else "❌ FAIL"
                print(f"{status} {result['name']}: {result['message']}")
            except Exception as e:
                results.append({
                    "name": check.__name__,
                    "status": "error",
                    "message": str(e)
                })
                print(f"❌ ERROR {check.__name__}: {e}")
        
        # Summary
        healthy_count = sum(1 for r in results if r["status"] == "healthy")
        total_count = len(results)
        
        print("\n" + "=" * 40)
        print(f"Health Check Summary: {healthy_count}/{total_count} checks passed")
        
        if healthy_count == total_count:
            print("🎉 All systems operational!")
            return 0
        else:
            print("⚠️  Some issues detected. Check logs above.")
            return 1
    
    def check_api_health(self):
        """Test API responsiveness"""
        try:
            response = requests.get(f"{self.api_url}/health", timeout=5)
            if response.status_code == 200:
                return {"name": "API Health", "status": "healthy", "message": "API responding"}
            else:
                return {"name": "API Health", "status": "unhealthy", "message": f"API returned {response.status_code}"}
        except requests.exceptions.RequestException as e:
            return {"name": "API Health", "status": "unhealthy", "message": f"API unreachable: {e}"}
    
    def check_redis_connectivity(self):
        """Test Redis connection"""
        try:
            client = redis.Redis(host=self.redis_host, port=self.redis_port)
            client.ping()
            return {"name": "Redis", "status": "healthy", "message": "Redis connected"}
        except redis.ConnectionError as e:
            return {"name": "Redis", "status": "unhealthy", "message": f"Redis connection failed: {e}"}
    
    def check_database_integrity(self):
        """Test database connection and integrity"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table'")
            table_count = cursor.fetchone()[0]
            conn.close()
            
            if table_count > 0:
                return {"name": "Database", "status": "healthy", "message": f"{table_count} tables found"}
            else:
                return {"name": "Database", "status": "unhealthy", "message": "No tables found"}
        except sqlite3.Error as e:
            return {"name": "Database", "status": "unhealthy", "message": f"Database error: {e}"}

if __name__ == "__main__":
    checker = HealthChecker()
    exit_code = checker.run_all_checks()
    sys.exit(exit_code)
```

### Log Analysis Tool
```python
#!/usr/bin/env python3
"""
Log Analysis Tool for CerberusMesh
Usage: python log_analyzer.py [--errors-only] [--last-hours 24]
"""

import re
import argparse
from datetime import datetime, timedelta
from collections import Counter

class LogAnalyzer:
    def __init__(self):
        self.error_patterns = [
            r"ERROR",
            r"CRITICAL",
            r"Exception",
            r"Traceback",
            r"ConnectionError",
            r"TimeoutError"
        ]
    
    def analyze_logs(self, log_file, hours_back=24, errors_only=False):
        """Analyze log file for patterns and issues"""
        cutoff_time = datetime.now() - timedelta(hours=hours_back)
        
        with open(log_file, 'r') as f:
            lines = f.readlines()
        
        # Parse log entries
        entries = []
        for line in lines:
            entry = self.parse_log_line(line)
            if entry and entry['timestamp'] >= cutoff_time:
                if not errors_only or entry['level'] in ['ERROR', 'CRITICAL']:
                    entries.append(entry)
        
        # Generate analysis
        analysis = {
            "total_entries": len(entries),
            "error_count": sum(1 for e in entries if e['level'] in ['ERROR', 'CRITICAL']),
            "warning_count": sum(1 for e in entries if e['level'] == 'WARNING'),
            "top_errors": self.get_top_errors(entries),
            "error_trends": self.analyze_error_trends(entries)
        }
        
        return analysis
    
    def parse_log_line(self, line):
        """Parse individual log line"""
        # Example format: 2024-01-15 14:30:22 - ERROR - Connection failed
        pattern = r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) - (\w+) - (.*)'
        match = re.match(pattern, line)
        
        if match:
            timestamp_str, level, message = match.groups()
            timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
            
            return {
                "timestamp": timestamp,
                "level": level,
                "message": message.strip()
            }
        return None

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--errors-only", action="store_true")
    parser.add_argument("--last-hours", type=int, default=24)
    parser.add_argument("--log-file", default="cerberusmesh.log")
    
    args = parser.parse_args()
    
    analyzer = LogAnalyzer()
    analysis = analyzer.analyze_logs(args.log_file, args.last_hours, args.errors_only)
    
    print(f"📊 Log Analysis Summary (Last {args.last_hours} hours)")
    print(f"Total entries: {analysis['total_entries']}")
    print(f"Errors: {analysis['error_count']}")
    print(f"Warnings: {analysis['warning_count']}")
```

---

## 📚 Related Notes

- [[Performance & Optimization]] - System performance tuning
- [[System Overview]] - Architecture understanding for troubleshooting
- [[Component Deep Dive]] - Technical details for debugging
- [[Demo Scenarios]] - What to do when demos fail

---
*Tags: #troubleshooting #debugging #diagnostics #maintenance #health-check*
