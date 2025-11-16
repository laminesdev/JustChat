import { Server } from "socket.io";
import { socketAuthMiddleware } from "../middlewares/socketAuth.js";
import { setupUserHandlers } from "../handlers/userHandlers.js";
import { setupConversationHandlers } from "../handlers/conversationHandlers.js";
import { setupMessageHandlers } from "../handlers/messageHandlers.js";
import { setupTypingHandlers } from "../handlers/typingHandlers.js";
import {
    handleUserDisconnect,
    updateUserOnlineStatus,
    sendPendingNotifications,
    checkPendingDeliveries,
} from "../services/socketService.js";

// Global variables
let io = null;
export const connectedUsers = new Map();

// Initialize Socket.io server
export function initializeSocket(server) {
    io = new Server(server, {
        cors: {
            origin: process.env.CLIENT_URL || "http://localhost:5176",
            methods: ["GET", "POST"],
            credentials: true,
        },
        pingTimeout: 60000,
        pingInterval: 25000,
        connectionStateRecovery: {
            maxDisconnectionDuration: 120000,
        },
    });

    setupSocketMiddleware();
    setupConnectionHandlers();
    setupCleanupInterval();

    console.log("Socket.io server initialized");
    return io;
}

// Get IO instance
export function getIO() {
    if (!io) {
        throw new Error("Socket.io not initialized");
    }
    return io;
}

// Socket middleware setup
function setupSocketMiddleware() {
    io.use(socketAuthMiddleware);
}

// Clean up disconnected users periodically
function setupCleanupInterval() {
    setInterval(cleanupDisconnectedUsers, 5 * 60 * 1000); // Every 5 minutes
}

function cleanupDisconnectedUsers() {
    const now = new Date();
    let cleanedCount = 0;

    for (const [userId, connection] of connectedUsers.entries()) {
        const socket = io.sockets.sockets.get(connection.socketId);
        if (!socket || !socket.connected) {
            connectedUsers.delete(userId);
            cleanedCount++;
            console.log(`Cleaned up disconnected user: ${userId}`);
        }
    }

    if (cleanedCount > 0) {
        console.log(`Cleaned up ${cleanedCount} disconnected users`);
    }
}

// Main connection handler
function setupConnectionHandlers() {
    io.on("connection", (socket) => {
        // Check if user already has an active connection
        const existingConnection = connectedUsers.get(socket.userId);
        if (existingConnection) {
            console.log(
                `User ${socket.userId} already connected, disconnecting previous socket ${existingConnection.socketId}`
            );
            // Disconnect the previous socket
            const previousSocket = io.sockets.sockets.get(
                existingConnection.socketId
            );
            if (previousSocket) {
                previousSocket.disconnect(true);
            }
        }

        console.log(`User ${socket.userId} connected with socket ${socket.id}`);

        // Add user to connected users (replace existing)
        connectedUsers.set(socket.userId, {
            socketId: socket.id,
            user: socket.user,
            connectedAt: new Date(),
        });

        // Update user online status
        updateUserOnlineStatus(socket.userId, true);

        // Send pending notifications and check deliveries
        sendPendingNotifications(socket.userId);
        checkPendingDeliveries(socket.userId);

        // Setup all event handlers
        setupUserHandlers(socket);
        setupConversationHandlers(socket);
        setupMessageHandlers(socket);
        setupTypingHandlers(socket);

        // Handle disconnect
        socket.on("disconnect", (reason) => {
            console.log(`User ${socket.userId} disconnected: ${reason}`);
            handleUserDisconnect(socket);
        });

        // Handle errors
        socket.on("error", (error) => {
            console.error(`Socket error for user ${socket.userId}:`, error);
        });

        // Notify successful connection
        socket.emit("connection_success", {
            success: true,
            message: "Connected to real-time server",
            user: socket.user,
            socket_id: socket.id,
        });

        // Notify others user came online (only if this is a new connection)
        if (!existingConnection) {
            socket.broadcast.emit("user_online", {
                user_id: socket.userId,
                user: socket.user,
                timestamp: new Date().toISOString(),
            });
        }
    });
}
