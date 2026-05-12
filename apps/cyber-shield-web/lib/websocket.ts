// =============================================================================
// Cyber Global Shield — Supabase Realtime Client
// Replaces the custom WebSocket implementation with Supabase Realtime channels.
// =============================================================================

import type { WSEvent } from "./types";
import { createClient } from "./supabase/client";

type EventHandler = (event: WSEvent) => void;

class SupabaseRealtimeClient {
  private supabase: ReturnType<typeof createClient> | null = null;
  private channels: Map<string, any> = new Map();
  private handlers: Map<string, Set<EventHandler>> = new Map();
  private orgId: string;

  constructor(orgId: string = "default") {
    this.orgId = orgId;
  }

  connect(): void {
    if (this.supabase) return;

    this.supabase = createClient();

    // Subscribe to the org-specific channel for real-time events
    const channel = this.supabase
      .channel(`org:${this.orgId}`)
      .on(
        "broadcast",
        { event: "alert" },
        (payload: { payload: any }) => {
          this.emit("alert.*", {
            type: "alert." + (payload.payload?.severity ?? "info"),
            data: payload.payload ?? {},
            timestamp: new Date().toISOString(),
          });
        }
      )
      .on(
        "broadcast",
        { event: "soar_update" },
        (payload: { payload: any }) => {
          this.emit("soar.*", {
            type: "soar.update",
            data: payload.payload ?? {},
            timestamp: new Date().toISOString(),
          });
        }
      )
      .on(
        "broadcast",
        { event: "ml_detection" },
        (payload: { payload: any }) => {
          this.emit("ml.*", {
            type: "ml.detection",
            data: payload.payload ?? {},
            timestamp: new Date().toISOString(),
          });
        }
      )
      .on(
        "broadcast",
        { event: "system_notification" },
        (payload: { payload: any }) => {
          this.emit("system.*", {
            type: "system.notification",
            data: payload.payload ?? {},
            timestamp: new Date().toISOString(),
          });
        }
      )
      .on(
        "postgres_changes",
        {
          event: "INSERT",
          schema: "public",
          table: "alerts",
          filter: `org_id=eq.${this.orgId}`,
        },
        (payload: { new: any }) => {
          this.emit("alert.*", {
            type: "alert.new",
            data: payload.new ?? {},
            timestamp: new Date().toISOString(),
          });
        }
      )
      .on(
        "postgres_changes",
        {
          event: "INSERT",
          schema: "public",
          table: "soar_executions",
          filter: `org_id=eq.${this.orgId}`,
        },
        (payload: { new: any }) => {
          this.emit("soar.*", {
            type: "soar.execution",
            data: payload.new ?? {},
            timestamp: new Date().toISOString(),
          });
        }
      )
      .subscribe((status: string) => {
        if (status === "SUBSCRIBED") {
          this.emit("_connected", {
            type: "_connected",
            data: { org_id: this.orgId, channel: "supabase_realtime" },
            timestamp: new Date().toISOString(),
          });
        }
      });

    this.channels.set(`org:${this.orgId}`, channel);
  }

  disconnect(): void {
    this.channels.forEach((channel) => {
      this.supabase?.removeChannel(channel);
    });
    this.channels.clear();
    this.supabase = null;
  }

  on(eventType: string, handler: EventHandler): () => void {
    if (!this.handlers.has(eventType)) {
      this.handlers.set(eventType, new Set());
    }
    this.handlers.get(eventType)!.add(handler);

    return () => {
      this.handlers.get(eventType)?.delete(handler);
    };
  }

  private emit(eventType: string, event: WSEvent): void {
    this.handlers.get(eventType)?.forEach((handler) => {
      try {
        handler(event);
      } catch {
        // ignore handler errors
      }
    });
    // Also emit to wildcard listeners
    this.handlers.get("*")?.forEach((handler) => {
      try {
        handler(event);
      } catch {
        // ignore handler errors
      }
    });
  }

  get connected(): boolean {
    return this.channels.size > 0;
  }
}

// Singleton instance
let client: SupabaseRealtimeClient | null = null;

export function getWebSocketClient(
  orgId: string = "default"
): SupabaseRealtimeClient {
  if (!client) {
    client = new SupabaseRealtimeClient(orgId);
  }
  return client;
}

export function disconnectWebSocket(): void {
  client?.disconnect();
  client = null;
}
