import { Server as HttpServer } from "http";
import { Server } from "socket.io";

let io: Server | null = null;

export const initRealtime = (server: HttpServer) => {
  io = new Server(server, {
    cors: {
      origin: "*",
    },
  });

  io.on("connection", (socket) => {
    socket.on("project:subscribe", (projectId: string) => {
      socket.join(`project:${projectId}`);
    });
  });

  return io;
};

export const getRealtime = () => {
  if (!io) {
    throw new Error("Realtime server not initialized");
  }

  return io;
};

export const publishProjectEvent = (projectId: string, event: string, payload: unknown) => {
  if (!io) {
    return;
  }

  io.to(`project:${projectId}`).emit(event, payload);
};