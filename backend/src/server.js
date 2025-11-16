import app from "./app.js";
import dotenv from "dotenv";
// Load environment variables
dotenv.config();
import { connectDb } from "./config/database.js";
import { testCloudinary } from "./config/cloudinary.js";
import { initializeSocket } from "./config/socket.js";

const PORT = process.env.PORT || 3000;

async function start() {
    try {
        console.log("Starting Chat App Server...");

        // Connect to database
        await connectDb();
        console.log("Database connected successfully");

        // Test Cloudinary configuration
        await testCloudinary();
        console.log("Cloudinary configured successfully");

        // Start HTTP server
        const server = app.listen(PORT, () => {
            console.log(`Server running on http://localhost:${PORT}`);
            console.log(`API Documentation: http://localhost:${PORT}/api-docs`);
            console.log(`Health Check: http://localhost:${PORT}/health`);
            console.log(
                `Environment: ${process.env.NODE_ENV || "development"}`
            );
        });

        // Initialize Socket.io
        initializeSocket(server);
        console.log("Socket.io server initialized");
    } catch (error) {
        console.error("Failed to start server:", error);
        process.exit(1);
    }
}

// Global error handlers
process.on("uncaughtException", (error) => {
    console.error("Uncaught Exception:", error);
    process.exit(1);
});

process.on("unhandledRejection", (reason, promise) => {
    console.error("Unhandled Rejection at:", promise, "reason:", reason);
    process.exit(1);
});

// Graceful shutdown
process.on("SIGTERM", () => {
    console.log("SIGTERM received, shutting down gracefully");
    process.exit(0);
});

process.on("SIGINT", () => {
    console.log("SIGINT received, shutting down gracefully");
    process.exit(0);
});

start();
