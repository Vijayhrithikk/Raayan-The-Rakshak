"""
WebSocket Manager for Real-Time Streaming
Handles bidirectional communication for:
- Real-time log/traffic ingestion
- Alert broadcasting to connected dashboards
- Connection lifecycle management
"""
from fastapi import WebSocket, WebSocketDisconnect
from typing import List, Dict, Set, Optional
from datetime import datetime
import asyncio
import json


class ConnectionManager:
    """
    Manages WebSocket connections for real-time communication.
    
    Supports multiple channel types:
    - 'alerts': Subscribe to real-time alert stream
    - 'stream': Ingest logs/traffic data
    - 'status': System status updates
    """
    
    def __init__(self):
        # Active connections by channel
        self.active_connections: Dict[str, List[WebSocket]] = {
            "alerts": [],
            "stream": [],
            "status": []
        }
        # Connection metadata
        self.connection_info: Dict[WebSocket, Dict] = {}
        # Message queue for offline processing
        self.message_queue: asyncio.Queue = asyncio.Queue()
        
    async def connect(self, websocket: WebSocket, channel: str = "alerts"):
        """Accept and register a new WebSocket connection"""
        await websocket.accept()
        
        if channel not in self.active_connections:
            self.active_connections[channel] = []
            
        self.active_connections[channel].append(websocket)
        self.connection_info[websocket] = {
            "channel": channel,
            "connected_at": datetime.now().isoformat(),
            "messages_sent": 0,
            "messages_received": 0
        }
        
        # Send welcome message
        await websocket.send_json({
            "type": "connected",
            "channel": channel,
            "timestamp": datetime.now().isoformat(),
            "message": f"Connected to {channel} stream"
        })
        
    def disconnect(self, websocket: WebSocket):
        """Remove a WebSocket connection"""
        for channel, connections in self.active_connections.items():
            if websocket in connections:
                connections.remove(websocket)
                break
        
        if websocket in self.connection_info:
            del self.connection_info[websocket]
    
    async def broadcast_to_channel(self, channel: str, message: dict):
        """Broadcast a message to all connections on a channel"""
        if channel not in self.active_connections:
            return
            
        disconnected = []
        for connection in self.active_connections[channel]:
            try:
                await connection.send_json(message)
                if connection in self.connection_info:
                    self.connection_info[connection]["messages_sent"] += 1
            except Exception:
                disconnected.append(connection)
        
        # Cleanup disconnected clients
        for conn in disconnected:
            self.disconnect(conn)
    
    async def broadcast_alert(self, alert: dict):
        """Broadcast a security alert to all subscribers"""
        message = {
            "type": "alert",
            "timestamp": datetime.now().isoformat(),
            "data": alert
        }
        await self.broadcast_to_channel("alerts", message)
    
    async def broadcast_status(self, status: dict):
        """Broadcast system status update"""
        message = {
            "type": "status",
            "timestamp": datetime.now().isoformat(),
            "data": status
        }
        await self.broadcast_to_channel("status", message)
    
    async def receive_and_process(self, websocket: WebSocket, processor_callback):
        """
        Receive data from a WebSocket and process it.
        Used for real-time log ingestion.
        """
        try:
            while True:
                data = await websocket.receive_json()
                
                if websocket in self.connection_info:
                    self.connection_info[websocket]["messages_received"] += 1
                
                # Process the incoming data
                if processor_callback:
                    await processor_callback(data)
                    
        except WebSocketDisconnect:
            self.disconnect(websocket)
    
    def get_connection_stats(self) -> dict:
        """Get statistics about current connections"""
        stats = {
            "total_connections": sum(len(c) for c in self.active_connections.values()),
            "by_channel": {
                channel: len(connections) 
                for channel, connections in self.active_connections.items()
            },
            "connections": []
        }
        
        for ws, info in self.connection_info.items():
            stats["connections"].append({
                "channel": info["channel"],
                "connected_at": info["connected_at"],
                "messages_sent": info["messages_sent"],
                "messages_received": info["messages_received"]
            })
        
        return stats


class RealTimeProcessor:
    """
    Processes real-time data streams for threat detection.
    Uses sliding window analysis for continuous monitoring.
    """
    
    def __init__(self, window_size: int = 100, slide_interval: int = 10):
        self.window_size = window_size
        self.slide_interval = slide_interval
        self.buffer: List[dict] = []
        self.processed_count = 0
        self.alert_callback = None
        
    def set_alert_callback(self, callback):
        """Set callback function for when alerts are generated"""
        self.alert_callback = callback
    
    async def process_event(self, event: dict):
        """
        Process a single event from the real-time stream.
        
        Events can be:
        - Network flows
        - Login events
        - System logs
        - File access events
        """
        self.buffer.append({
            **event,
            "ingested_at": datetime.now().isoformat()
        })
        self.processed_count += 1
        
        # Trigger analysis when buffer reaches slide interval
        if len(self.buffer) >= self.slide_interval:
            await self._analyze_window()
    
    async def _analyze_window(self):
        """Analyze the current sliding window for threats"""
        if len(self.buffer) < self.window_size:
            window = self.buffer
        else:
            window = self.buffer[-self.window_size:]
        
        # Analysis will be performed by the detection services
        # This is a hook for real-time processing
        pass
    
    def get_stats(self) -> dict:
        """Get processing statistics"""
        return {
            "buffer_size": len(self.buffer),
            "total_processed": self.processed_count,
            "window_size": self.window_size
        }
    
    def clear_buffer(self):
        """Clear the processing buffer"""
        self.buffer = []


# Global instances
connection_manager = ConnectionManager()
realtime_processor = RealTimeProcessor()
