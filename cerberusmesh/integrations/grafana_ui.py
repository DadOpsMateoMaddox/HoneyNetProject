#!/usr/bin/env python3
"""
CerberusMesh Grafana-Style UI Integration

Provides comprehensive dashboard and visualization capabilities:
- Real-time monitoring dashboards
- Custom visualization panels
- Alert management
- Data source integration
- Interactive analytics
"""

import json
import logging
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, asdict
import uuid

# FastAPI imports with error handling
try:
    from fastapi import FastAPI, WebSocket, WebSocketDisconnect
    from fastapi.staticfiles import StaticFiles
    from fastapi.templating import Jinja2Templates
    from fastapi.responses import HTMLResponse, JSONResponse
    import uvicorn
    FASTAPI_AVAILABLE = True
except ImportError:
    FastAPI = None
    WebSocket = None
    WebSocketDisconnect = None
    StaticFiles = None
    Jinja2Templates = None
    HTMLResponse = None
    JSONResponse = None
    uvicorn = None
    FASTAPI_AVAILABLE = False

logger = logging.getLogger(__name__)

# Constants
DASHBOARD_NOT_FOUND = "Dashboard not found"

@dataclass
class Panel:
    """Dashboard panel configuration."""
    id: str
    title: str
    type: str  # graph, stat, table, heatmap, text, alert_list
    position: Dict[str, int]  # x, y, width, height
    targets: List[Dict[str, Any]]
    options: Dict[str, Any]
    field_config: Dict[str, Any]
    transparent: bool = False
    datasource: str = "cerberusmesh"

@dataclass
class Dashboard:
    """Dashboard configuration."""
    id: str
    title: str
    description: str
    tags: List[str]
    panels: List[Panel]
    time_range: Dict[str, str]
    refresh_interval: str = "5s"
    editable: bool = True
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

@dataclass
class Alert:
    """Alert configuration."""
    id: str
    name: str
    message: str
    frequency: str
    conditions: List[Dict[str, Any]]
    notifications: List[str]
    state: str = "pending"  # ok, pending, alerting, no_data
    created_at: Optional[datetime] = None
    last_triggered: Optional[datetime] = None

class ConnectionManager:
    """WebSocket connection manager for real-time updates."""
    
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
        await websocket.send_text(message)
    
    async def broadcast(self, message: str):
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception as e:
                logger.error(f"Error broadcasting message: {e}")
                self.disconnect(connection)

class GrafanaUIIntegration:
    """Grafana-style UI integration for CerberusMesh."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize Grafana UI integration."""
        self.config = config
        self.app = FastAPI(title="CerberusMesh Dashboard")
        self.templates = Jinja2Templates(directory="templates")
        self.connection_manager = ConnectionManager()
        
        # Storage for dashboards and panels
        self.dashboards: Dict[str, Dashboard] = {}
        self.alerts: Dict[str, Alert] = {}
        self.data_sources: Dict[str, Any] = {}
        
        # Setup routes
        self._setup_routes()
        
        # Initialize default dashboards
        self._create_default_dashboards()
        
        # Setup real-time data refresh
        self.refresh_task = None
    
    def _setup_routes(self):
        """Setup FastAPI routes."""
        
        # Static files
        self.app.mount("/static", StaticFiles(directory="static"), name="static")
        
        # Dashboard routes
        @self.app.get("/", response_class=HTMLResponse)
        async def dashboard_home(request):
            return self.templates.TemplateResponse("dashboard.html", {
                "request": request,
                "dashboards": list(self.dashboards.values())
            })
        
        @self.app.get("/api/dashboards")
        async def get_dashboards():
            return JSONResponse([asdict(dashboard) for dashboard in self.dashboards.values()])
        
        @self.app.get("/api/dashboards/{dashboard_id}")
        async def get_dashboard(dashboard_id: str):
            if dashboard_id in self.dashboards:
                return JSONResponse(asdict(self.dashboards[dashboard_id]))
            return JSONResponse({"error": DASHBOARD_NOT_FOUND}, status_code=404)
        
        @self.app.post("/api/dashboards")
        async def create_dashboard(dashboard_data: dict):
            dashboard = Dashboard(**dashboard_data)
            if not dashboard.id:
                dashboard.id = str(uuid.uuid4())
            dashboard.created_at = datetime.now()
            dashboard.updated_at = datetime.now()
            
            self.dashboards[dashboard.id] = dashboard
            return JSONResponse(asdict(dashboard))
        
        @self.app.put("/api/dashboards/{dashboard_id}")
        async def update_dashboard(dashboard_id: str, dashboard_data: dict):
            if dashboard_id not in self.dashboards:
                return JSONResponse({"error": DASHBOARD_NOT_FOUND}, status_code=404)
            
            dashboard_data["id"] = dashboard_id
            dashboard_data["updated_at"] = datetime.now()
            dashboard = Dashboard(**dashboard_data)
            
            self.dashboards[dashboard_id] = dashboard
            return JSONResponse(asdict(dashboard))
        
        @self.app.delete("/api/dashboards/{dashboard_id}")
        async def delete_dashboard(dashboard_id: str):
            if dashboard_id not in self.dashboards:
                return JSONResponse({"error": DASHBOARD_NOT_FOUND}, status_code=404)
            
            del self.dashboards[dashboard_id]
            return JSONResponse({"message": "Dashboard deleted"})
        
        # Data source routes
        @self.app.get("/api/datasources")
        async def get_datasources():
            return JSONResponse(list(self.data_sources.values()))
        
        @self.app.post("/api/datasources/query")
        async def query_datasource(query_data: dict):
            return await self._execute_query(query_data)
        
        # Alert routes
        @self.app.get("/api/alerts")
        async def get_alerts():
            return JSONResponse([asdict(alert) for alert in self.alerts.values()])
        
        @self.app.post("/api/alerts")
        async def create_alert(alert_data: dict):
            alert = Alert(**alert_data)
            if not alert.id:
                alert.id = str(uuid.uuid4())
            alert.created_at = datetime.now()
            
            self.alerts[alert.id] = alert
            return JSONResponse(asdict(alert))
        
        # WebSocket endpoint for real-time updates
        @self.app.websocket("/ws")
        async def websocket_endpoint(websocket: WebSocket):
            await self.connection_manager.connect(websocket)
            try:
                while True:
                    data = await websocket.receive_text()
                    # Handle incoming WebSocket messages
                    await self._handle_websocket_message(data, websocket)
            except WebSocketDisconnect:
                self.connection_manager.disconnect(websocket)
    
    def _create_default_dashboards(self):
        """Create default monitoring dashboards."""
        
        # Main honeypot overview dashboard
        overview_panels = [
            Panel(
                id="overview-stats",
                title="Attack Overview",
                type="stat",
                position={"x": 0, "y": 0, "width": 6, "height": 4},
                targets=[{"expr": "cerberusmesh_attacks_total", "format": "time_series"}],
                options={
                    "colorMode": "background",
                    "graphMode": "area",
                    "justifyMode": "auto",
                    "orientation": "horizontal"
                },
                field_config={
                    "defaults": {
                        "color": {"mode": "palette-classic"},
                        "custom": {"displayMode": "gradient"},
                        "thresholds": {"steps": [
                            {"color": "green", "value": 0},
                            {"color": "yellow", "value": 100},
                            {"color": "red", "value": 500}
                        ]}
                    }
                }
            ),
            
            Panel(
                id="attack-timeline",
                title="Attack Timeline",
                type="graph",
                position={"x": 6, "y": 0, "width": 18, "height": 8},
                targets=[
                    {"expr": "rate(cerberusmesh_attacks_total[5m])", "legend": "Attack Rate"},
                    {"expr": "cerberusmesh_unique_attackers", "legend": "Unique Attackers"}
                ],
                options={
                    "tooltip": {"mode": "multi", "sort": "desc"},
                    "legend": {"displayMode": "list", "placement": "bottom"},
                    "graph": {"drawStyle": "line", "spanNulls": False}
                },
                field_config={
                    "defaults": {
                        "color": {"mode": "palette-classic"},
                        "unit": "reqps"
                    }
                }
            ),
            
            Panel(
                id="top-attackers",
                title="Top Attacking IPs",
                type="table",
                position={"x": 0, "y": 8, "width": 12, "height": 6},
                targets=[{"expr": "topk(10, cerberusmesh_attacks_by_ip)", "format": "table"}],
                options={
                    "showHeader": True,
                    "sortBy": [{"desc": True, "displayName": "Attack Count"}]
                },
                field_config={
                    "defaults": {
                        "custom": {"align": "auto", "displayMode": "auto"}
                    },
                    "overrides": [
                        {
                            "matcher": {"id": "byName", "options": "IP Address"},
                            "properties": [{"id": "custom.width", "value": 150}]
                        }
                    ]
                }
            ),
            
            Panel(
                id="attack-map",
                title="Geographic Attack Distribution",
                type="geomap",
                position={"x": 12, "y": 8, "width": 12, "height": 6},
                targets=[{"expr": "cerberusmesh_attacks_by_country", "format": "table"}],
                options={
                    "view": {"id": "coords", "lat": 40, "lon": -74, "zoom": 3},
                    "controls": {"showZoom": True, "mouseWheelZoom": True},
                    "basemap": {"type": "default", "name": "Streets"}
                },
                field_config={
                    "defaults": {
                        "color": {"mode": "continuous-GrYlRd"},
                        "custom": {"hideFrom": {"legend": False, "tooltip": False, "vis": False}}
                    }
                }
            ),
            
            Panel(
                id="mitre-heatmap",
                title="MITRE ATT&CK Techniques",
                type="heatmap",
                position={"x": 0, "y": 14, "width": 24, "height": 6},
                targets=[{"expr": "cerberusmesh_mitre_techniques", "format": "time_series"}],
                options={
                    "calculate": True,
                    "calculation": {"xBuckets": {"mode": "size", "value": "1h"}},
                    "cellGap": 2,
                    "cellRadius": 0,
                    "cellValues": {"unit": "short"},
                    "showValue": "auto",
                    "yAxis": {"unit": "short"}
                },
                field_config={
                    "defaults": {
                        "color": {"mode": "spectrum", "scheme": "Spectral"},
                        "custom": {"hideFrom": {"legend": False, "tooltip": False, "vis": False}}
                    }
                }
            )
        ]
        
        overview_dashboard = Dashboard(
            id="overview",
            title="CerberusMesh Overview",
            description="Main honeypot monitoring dashboard",
            tags=["honeypot", "overview", "security"],
            panels=overview_panels,
            time_range={"from": "now-6h", "to": "now"}
        )
        
        self.dashboards["overview"] = overview_dashboard
        
        # AI Agent performance dashboard
        agent_panels = [
            Panel(
                id="decision-metrics",
                title="AI Decision Metrics",
                type="stat",
                position={"x": 0, "y": 0, "width": 8, "height": 4},
                targets=[
                    {"expr": "cerberusmesh_agent_decisions_total", "legend": "Total Decisions"},
                    {"expr": "cerberusmesh_agent_accuracy", "legend": "Accuracy"},
                    {"expr": "cerberusmesh_agent_response_time", "legend": "Response Time"}
                ],
                options={"colorMode": "background", "orientation": "horizontal"},
                field_config={
                    "defaults": {
                        "color": {"mode": "palette-classic"},
                        "thresholds": {"steps": [
                            {"color": "red", "value": 0},
                            {"color": "yellow", "value": 0.7},
                            {"color": "green", "value": 0.9}
                        ]}
                    }
                }
            ),
            
            Panel(
                id="confidence-distribution",
                title="Decision Confidence Distribution",
                type="histogram",
                position={"x": 8, "y": 0, "width": 16, "height": 8},
                targets=[{"expr": "histogram_quantile(0.95, cerberusmesh_agent_confidence)", "legend": "Confidence"}],
                options={
                    "bucketSize": 0.1,
                    "bucketBound": "auto"
                },
                field_config={
                    "defaults": {
                        "color": {"mode": "palette-classic"},
                        "unit": "percent"
                    }
                }
            )
        ]
        
        agent_dashboard = Dashboard(
            id="ai-agent",
            title="AI Agent Performance",
            description="AI decision-making and performance metrics",
            tags=["ai", "agent", "performance"],
            panels=agent_panels,
            time_range={"from": "now-1h", "to": "now"}
        )
        
        self.dashboards["ai-agent"] = agent_dashboard
        
        # Threat intelligence dashboard
        threat_panels = [
            Panel(
                id="threat-scores",
                title="Threat Score Timeline",
                type="graph",
                position={"x": 0, "y": 0, "width": 24, "height": 8},
                targets=[
                    {"expr": "cerberusmesh_threat_score_avg", "legend": "Average Threat Score"},
                    {"expr": "cerberusmesh_threat_score_max", "legend": "Peak Threat Score"}
                ],
                options={
                    "tooltip": {"mode": "multi"},
                    "legend": {"displayMode": "list"}
                },
                field_config={
                    "defaults": {
                        "color": {"mode": "palette-classic"},
                        "unit": "short",
                        "min": 0,
                        "max": 1
                    }
                }
            ),
            
            Panel(
                id="ioc-feed",
                title="Recent Indicators of Compromise",
                type="table",
                position={"x": 0, "y": 8, "width": 24, "height": 8},
                targets=[{"expr": "cerberusmesh_recent_iocs", "format": "table"}],
                options={
                    "showHeader": True,
                    "sortBy": [{"desc": True, "displayName": "First Seen"}]
                },
                field_config={
                    "defaults": {
                        "custom": {"align": "auto"}
                    }
                }
            )
        ]
        
        threat_dashboard = Dashboard(
            id="threat-intel",
            title="Threat Intelligence",
            description="Threat indicators and intelligence feeds",
            tags=["threat", "intelligence", "ioc"],
            panels=threat_panels,
            time_range={"from": "now-24h", "to": "now"}
        )
        
        self.dashboards["threat-intel"] = threat_dashboard
    
    async def _execute_query(self, query_data: Dict[str, Any]) -> JSONResponse:
        """Execute query against data source."""
        try:
            # This would integrate with your actual data sources
            # For now, return mock data
            mock_data = {
                "status": "success",
                "data": {
                    "resultType": "matrix",
                    "result": [
                        {
                            "metric": {"__name__": "cerberusmesh_attacks_total"},
                            "values": [
                                [datetime.now().timestamp(), "150"],
                                [(datetime.now() - timedelta(minutes=5)).timestamp(), "145"]
                            ]
                        }
                    ]
                }
            }
            
            return JSONResponse(mock_data)
            
        except Exception as e:
            logger.error(f"Query execution failed: {e}")
            return JSONResponse({
                "status": "error",
                "error": str(e)
            }, status_code=500)
    
    async def _handle_websocket_message(self, data: str, websocket: WebSocket):
        """Handle incoming WebSocket messages."""
        try:
            message = json.loads(data)
            message_type = message.get("type")
            
            if message_type == "subscribe":
                # Subscribe to dashboard updates
                dashboard_id = message.get("dashboard_id")
                await websocket.send_text(json.dumps({
                    "type": "subscription_confirmed",
                    "dashboard_id": dashboard_id
                }))
            
            elif message_type == "query":
                # Execute real-time query
                result = await self._execute_query(message.get("query", {}))
                await websocket.send_text(json.dumps({
                    "type": "query_result",
                    "data": result
                }))
            
        except Exception as e:
            logger.error(f"WebSocket message handling failed: {e}")
            await websocket.send_text(json.dumps({
                "type": "error",
                "message": str(e)
            }))
    
    async def start_real_time_updates(self):
        """Start real-time data updates."""
        async def update_loop():
            while True:
                try:
                    # Generate mock real-time data
                    update_data = {
                        "type": "data_update",
                        "timestamp": datetime.now().isoformat(),
                        "metrics": {
                            "attacks_total": 150 + (datetime.now().second % 10),
                            "unique_attackers": 25 + (datetime.now().second % 5),
                            "threat_score": 0.6 + (datetime.now().second % 10) / 100
                        }
                    }
                    
                    await self.connection_manager.broadcast(json.dumps(update_data))
                    await asyncio.sleep(5)  # Update every 5 seconds
                    
                except Exception as e:
                    logger.error(f"Real-time update failed: {e}")
                    await asyncio.sleep(10)
        
        self.refresh_task = asyncio.create_task(update_loop())
    
    async def stop_real_time_updates(self):
        """Stop real-time updates."""
        if self.refresh_task:
            self.refresh_task.cancel()
            try:
                await self.refresh_task
            except asyncio.CancelledError:
                pass
    
    def run(self, host: str = "0.0.0.0", port: int = 3000):
        """Run the Grafana UI server."""
        logger.info(f"Starting CerberusMesh Dashboard on {host}:{port}")
        
        # Start real-time updates
        asyncio.create_task(self.start_real_time_updates())
        
        # Run the server
        uvicorn.run(
            self.app,
            host=host,
            port=port,
            log_level="info"
        )
    
    # Dashboard template generation
    def generate_dashboard_config(self, dashboard_id: str) -> Dict[str, Any]:
        """Generate Grafana-compatible dashboard configuration."""
        if dashboard_id not in self.dashboards:
            return {}
        
        dashboard = self.dashboards[dashboard_id]
        
        config = {
            "dashboard": {
                "id": dashboard.id,
                "title": dashboard.title,
                "description": dashboard.description,
                "tags": dashboard.tags,
                "timezone": "browser",
                "panels": [],
                "time": {
                    "from": dashboard.time_range["from"],
                    "to": dashboard.time_range["to"]
                },
                "refresh": dashboard.refresh_interval,
                "schemaVersion": 30,
                "version": 1,
                "editable": dashboard.editable
            }
        }
        
        # Convert panels to Grafana format
        for panel in dashboard.panels:
            panel_config = {
                "id": panel.id,
                "title": panel.title,
                "type": panel.type,
                "gridPos": panel.position,
                "targets": panel.targets,
                "options": panel.options,
                "fieldConfig": panel.field_config,
                "transparent": panel.transparent,
                "datasource": panel.datasource
            }
            config["dashboard"]["panels"].append(panel_config)
        
        return config
    
    def create_custom_panel(self, panel_type: str, title: str, query: str, **options) -> Panel:
        """Create a custom panel with specified configuration."""
        panel_id = str(uuid.uuid4())
        
        # Default positions (can be customized)
        default_positions = {
            "stat": {"x": 0, "y": 0, "width": 6, "height": 4},
            "graph": {"x": 0, "y": 0, "width": 12, "height": 8},
            "table": {"x": 0, "y": 0, "width": 12, "height": 6},
            "heatmap": {"x": 0, "y": 0, "width": 24, "height": 8}
        }
        
        position = options.get("position", default_positions.get(panel_type, {"x": 0, "y": 0, "width": 6, "height": 4}))
        
        panel = Panel(
            id=panel_id,
            title=title,
            type=panel_type,
            position=position,
            targets=[{"expr": query, "legend": options.get("legend", title)}],
            options=options.get("panel_options", {}),
            field_config=options.get("field_config", {"defaults": {"color": {"mode": "palette-classic"}}}),
            transparent=options.get("transparent", False)
        )
        
        return panel
