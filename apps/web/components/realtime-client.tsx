"use client";

import { useEffect } from "react";
import { io } from "socket.io-client";

export function RealtimeClient({ projectId }: { projectId: string }) {
  useEffect(() => {
    const socket = io(process.env.NEXT_PUBLIC_WS_URL ?? "http://localhost:4000", {
      transports: ["websocket"],
    });

    socket.emit("project:subscribe", projectId);
    socket.on("incident:new", () => window.location.reload());
    socket.on("incident:updated", () => window.location.reload());
    socket.on("incident:analysis_completed", () => window.location.reload());

    return () => socket.disconnect();
  }, [projectId]);

  return null;
}