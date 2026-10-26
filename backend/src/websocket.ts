import { WebSocketServer, WebSocket } from 'ws';
import { Server } from 'http';
import { ThreatEvent } from './types';

class SocketManager {
  private wss: WebSocketServer | null = null;
  private clients: Set<WebSocket> = new Set();

  init(server: Server) {
    this.wss = new WebSocketServer({ server, path: '/ws' });

    this.wss.on('connection', (ws: WebSocket) => {
      this.clients.add(ws);

      // Send initial welcome message
      ws.send(JSON.stringify({
        type: 'SYSTEM_STATUS',
        payload: {
          connected: true,
          message: 'Connected to Real-Time Threat Stream WebSocket Gateway',
          timestamp: new Date().toISOString()
        }
      }));

      ws.on('close', () => {
        this.clients.delete(ws);
      });

      ws.on('error', () => {
        this.clients.delete(ws);
      });
    });
  }

  broadcast(type: string, payload: any) {
    const message = JSON.stringify({ type, payload, timestamp: new Date().toISOString() });
    for (const client of this.clients) {
      if (client.readyState === WebSocket.OPEN) {
        client.send(message);
      }
    }
  }

  broadcastThreat(threat: ThreatEvent) {
    this.broadcast('NEW_THREAT_EVENT', threat);
  }

  getConnectedCount(): number {
    return this.clients.size;
  }
}

export const socketManager = new SocketManager();
