"use client";

import { useEffect, useCallback } from "react";
import { getWebSocketClient, disconnectWebSocket } from "@/lib/websocket";
import type { WSEvent } from "@/lib/types";

interface RealtimeClientProps {
  onAlert?: (event: WSEvent) => void;
  onSoarUpdate?: (event: WSEvent) => void;
  onMLDetection?: (event: WSEvent) => void;
  onSystemHealth?: (event: WSEvent) => void;
}

export function RealtimeClient({
  onAlert,
  onSoarUpdate,
  onMLDetection,
  onSystemHealth,
}: RealtimeClientProps) {
  const handleEvent = useCallback(
    (event: WSEvent) => {
      switch (true) {
        case event.type.startsWith("alert."):
          onAlert?.(event);
          break;
        case event.type.startsWith("soar."):
          onSoarUpdate?.(event);
          break;
        case event.type.startsWith("ml."):
          onMLDetection?.(event);
          break;
        case event.type.startsWith("system."):
          onSystemHealth?.(event);
          break;
      }
    },
    [onAlert, onSoarUpdate, onMLDetection, onSystemHealth]
  );

  useEffect(() => {
    const client = getWebSocketClient();
    client.connect();

    const unsubscribe = client.on("*", handleEvent);

    return () => {
      unsubscribe();
      disconnectWebSocket();
    };
  }, [handleEvent]);

  return null;
}
