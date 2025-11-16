# Project: src

## File: app.js
```js
import express from "express";
import routes from "./routes/index.js";
import { specs, swaggerUi } from "./config/swagger.js";
import cors from "cors";

const app = express();

const corsOptions = {
    origin: function (origin, callback) {
        if (!origin) return callback(null, true);
        const allowedOrigins = ["http://localhost:5176"]; 

        if (allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            console.log("Blocked by CORS:", origin);
            callback(new Error("Not allowed by CORS"));
        }
    },
    credentials: true,
    optionsSuccessStatus: 200,
    methods: ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With"],
};

app.use(cors(corsOptions));
app.use(express.json({ limit: "10mb" }));

// Parse JSON bodies
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));

// Logging middleware
app.use((req, res, next) => {
    console.log(`${req.method} ${req.url}`);
    next();
});

// Swagger documentation
app.use(
    "/api-docs",
    swaggerUi.serve,
    swaggerUi.setup(specs, {
        explorer: true,
        customCss: ".swagger-ui .topbar { display: none }",
        customSiteTitle: "Chat App API Documentation",
    })
);

// Health check endpoint
app.get("/health", (req, res) => {
    res.status(200).json({
        success: true,
        msg: "Chat App API is running",
        data: {
            timestamp: new Date().toISOString(),
            version: "1.0.0",
        },
    });
});

// API routes
app.use("/api", routes);

// 404 handler
app.use((req, res) => {
    res.status(404).json({
        success: false,
        msg: "Route not found",
    });
});

// Error handler
app.use((err, req, res, next) => {
    console.error("Error:", err);
    res.status(err.status || 500).json({
        success: false,
        msg: err.message || "Internal server error",
    });
});

export default app;

```

## File: config/cloudinary.js
```js
import { v2 as cloudinary } from "cloudinary";

// Configure Cloudinary with better connection settings
cloudinary.config({
    cloud_name: process.env.CLOUD_NAME,
    api_key: process.env.CLOUD_API_KEY,
    api_secret: process.env.CLOUD_API_SECRET,
    timeout: 30000, // 30 seconds timeout
    secure: true,
});

// Store the configuration state
let cloudinaryConfigured = false;

export async function testCloudinary() {
    try {
        const result = await cloudinary.api.ping();
        console.log("Cloudinary configuration successful!");
        console.log("Status:", result.status);
        cloudinaryConfigured = true;
        return true;
    } catch (error) {
        console.log("Cloudinary configuration failed:");
        console.log("Error:", error.message);
        cloudinaryConfigured = false;
        return false;
    }
}

// Reset function to reinitialize if needed
export async function resetCloudinary() {
    try {
        // Reconfigure cloudinary
        cloudinary.config({
            cloud_name: process.env.CLOUD_NAME,
            api_key: process.env.CLOUD_API_KEY,
            api_secret: process.env.CLOUD_API_SECRET,
            timeout: 30000,
            secure: true,
        });

        const result = await cloudinary.api.ping();
        cloudinaryConfigured = true;
        console.log("Cloudinary reset successful");
        return true;
    } catch (error) {
        cloudinaryConfigured = false;
        console.log("Cloudinary reset failed:", error.message);
        return false;
    }
}

export function isCloudinaryConfigured() {
    return cloudinaryConfigured;
}

export default cloudinary;

```

## File: config/constants.js
```js
// Socket event names
export const SocketEvents = {
    // Connection events
    CONNECTION: "connection",
    DISCONNECT: "disconnect",
    CONNECTION_SUCCESS: "connection_success",
    ERROR: "error",

    // User events
    USER_ONLINE: "user_online",
    USER_OFFLINE: "user_offline",
    GET_ONLINE_USERS: "get_online_users",
    PROFILE_UPDATED: "profile_updated",
    USER_PROFILE_UPDATED: "user_profile_updated",

    // Conversation events
    JOIN_CONVERSATION: "join_conversation",
    LEAVE_CONVERSATION: "leave_conversation",
    CREATE_CONVERSATION: "create_conversation",
    CONVERSATION_CREATED: "conversation_created",
    NEW_CONVERSATION: "new_conversation",
    DELETE_CONVERSATION: "delete_conversation",
    CONVERSATION_DELETED: "conversation_deleted",
    CONVERSATION_UPDATED: "conversation_updated",
    CONVERSATION_USER_UPDATED: "conversation_user_updated",

    // Message events
    SEND_MESSAGE: "send_message",
    NEW_MESSAGE: "new_message",
    MESSAGE_SENT: "message_sent",
    MESSAGE_DELIVERED: "message_delivered",
    MESSAGE_READ: "message_read",
    MARK_AS_READ: "mark_as_read",
    MARK_ALL_AS_READ: "mark_all_as_read",
    ALL_MESSAGES_READ: "all_messages_read",
    EDIT_MESSAGE: "edit_message",
    MESSAGE_EDITED: "message_edited",
    DELETE_MESSAGE: "delete_message",
    MESSAGE_DELETED: "message_deleted",

    // Typing events
    TYPING_START: "typing_start",
    TYPING_STOP: "typing_stop",
    USER_TYPING: "user_typing",

    // Notification events
    PENDING_CONVERSATIONS: "pending_conversations",
};

// Message types
export const MessageTypes = {
    TEXT: "TEXT",
    IMAGE: "IMAGE",
};

// File upload folders
export const UploadFolders = {
    PROFILES: "profiles",
    MESSAGES: "messages",
    FILES: "files",
};

// Resource types
export const ResourceTypes = {
    IMAGE: "image",
    RAW: "raw",
    VIDEO: "video",
    AUTO: "auto",
};

// Time constants
export const TimeConstants = {
    MESSAGE_EDIT_TIMEOUT: 5 * 60 * 1000, // 5 minutes
    TYPING_TIMEOUT: 3000, // 3 seconds
    TOKEN_CLEANUP_INTERVAL: 24 * 60 * 60 * 1000, // 24 hours
};

// HTTP status codes
export const HttpStatus = {
    OK: 200,
    CREATED: 201,
    BAD_REQUEST: 400,
    UNAUTHORIZED: 401,
    FORBIDDEN: 403,
    NOT_FOUND: 404,
    CONFLICT: 409,
    TOO_MANY_REQUESTS: 429,
    INTERNAL_SERVER_ERROR: 500,
    BAD_GATEWAY: 502,
    SERVICE_UNAVAILABLE: 503,
    GATEWAY_TIMEOUT: 504,
};

// User select fields (commonly used)
export const UserSelectFields = {
    id: true,
    email: true,
    full_name: true,
    avatar_url: true,
    is_online: true,
    last_seen: true,
    created_at: true,
};

// Public user fields (exclude sensitive data)
export const PublicUserFields = {
    id: true,
    email: true,
    full_name: true,
    avatar_url: true,
    is_online: true,
    last_seen: true,
};

```

## File: config/database.js
```js
import { PrismaClient } from "@prisma/client";

// Configure Prisma with optimized settings for Neon
const prisma = new PrismaClient({
    log:
        process.env.NODE_ENV === "development"
            ? ["query", "error", "warn"]
            : ["error"],
    errorFormat: "minimal",
    // Connection pool optimization
    transactionOptions: {
        maxWait: 10000, // 10 seconds
        timeout: 30000, // 30 seconds
    },
});

// Connection management
let isConnected = false;
let connectionRetries = 0;
const MAX_RETRIES = 5;

export default prisma;

export async function connectDb() {
    try {
        // Test connection with a simple query
        await prisma.$queryRaw`SELECT 1`;
        console.log("PostgreSQL Connected via Prisma");
        isConnected = true;
        connectionRetries = 0;
        return true;
    } catch (err) {
        console.log("Database connection error:", err.message);

        if (connectionRetries < MAX_RETRIES) {
            connectionRetries++;
            const delay = Math.min(2000 * connectionRetries, 10000); // Max 10 seconds
            console.log(
                `Retrying database connection (${connectionRetries}/${MAX_RETRIES}) in ${delay}ms...`
            );
            await new Promise((resolve) => setTimeout(resolve, delay));
            return connectDb();
        } else {
            console.error("Max database connection retries reached");
            throw new Error(
                "Database connection failed after multiple retries"
            );
        }
    }
}

// Health check with timeout
export async function checkDbHealth() {
    try {
        // Use Promise.race to timeout the health check
        const healthCheck = prisma.$queryRaw`SELECT 1`;
        const timeout = new Promise((_, reject) =>
            setTimeout(
                () => reject(new Error("Database health check timeout")),
                5000
            )
        );

        await Promise.race([healthCheck, timeout]);
        return {
            healthy: true,
            timestamp: new Date().toISOString(),
            connection_retries: connectionRetries,
        };
    } catch (error) {
        console.error("Database health check failed:", error.message);
        return {
            healthy: false,
            error: error.message,
            timestamp: new Date().toISOString(),
            connection_retries: connectionRetries,
        };
    }
}

// Connection pool monitoring
export function getConnectionStats() {
    return {
        isConnected,
        connectionRetries,
        timestamp: new Date().toISOString(),
    };
}

// Graceful shutdown
export async function disconnectDb() {
    try {
        await prisma.$disconnect();
        isConnected = false;
        console.log("Database disconnected gracefully");
    } catch (error) {
        console.error("Error disconnecting database:", error);
    }
}

// Automatic reconnection for queries with retry logic
export async function executeWithRetry(operation, maxRetries = 3) {
    let lastError;

    for (let attempt = 1; attempt <= maxRetries; attempt++) {
        try {
            return await operation();
        } catch (error) {
            lastError = error;

            // Check if it's a connection error
            if (error.code === "P1001" || error.code === "P2024") {
                console.log(
                    `Database connection error on attempt ${attempt}/${maxRetries}, retrying...`
                );

                if (attempt < maxRetries) {
                    // Wait before retry (exponential backoff)
                    const delay = Math.min(
                        1000 * Math.pow(2, attempt - 1),
                        10000
                    );
                    await new Promise((resolve) => setTimeout(resolve, delay));

                    // Try to reconnect
                    try {
                        await connectDb();
                    } catch (reconnectError) {
                        console.log(
                            "Reconnection failed, continuing with retry..."
                        );
                    }
                }
            } else {
                // Non-connection error, don't retry
                throw error;
            }
        }
    }

    throw lastError;
}

```

## File: config/env.js
```js
import dotenv from "dotenv";

dotenv.config();

class ConfigurationError extends Error {
    constructor(message) {
        super(message);
        this.name = "ConfigurationError";
    }
}

// Validate and parse environment variables
function validateEnv() {
    const required = [
        "DATABASE_URL",
        "JWT_SECRET",
        "REFRESH_TOKEN_SECRET",
        "CLOUD_NAME",
        "CLOUD_API_KEY",
        "CLOUD_API_SECRET",
    ];

    const missing = required.filter((key) => !process.env[key]);

    if (missing.length > 0) {
        throw new ConfigurationError(
            `Missing required environment variables: ${missing.join(", ")}`
        );
    }

    // Validate JWT secrets are strong enough
    if (process.env.JWT_SECRET.length < 32) {
        throw new ConfigurationError(
            "JWT_SECRET must be at least 32 characters long"
        );
    }

    if (process.env.REFRESH_TOKEN_SECRET.length < 32) {
        throw new ConfigurationError(
            "REFRESH_TOKEN_SECRET must be at least 32 characters long"
        );
    }
}

// Run validation
try {
    validateEnv();
} catch (error) {
    console.error("Configuration Error:", error.message);
    process.exit(1);
}

// Export typed configuration
export const config = {
    // Server
    port: parseInt(process.env.PORT || "3000", 10),
    nodeEnv: process.env.NODE_ENV || "development",

    // Database
    database: {
        url: process.env.DATABASE_URL,
    },

    // Authentication
    auth: {
        jwtSecret: process.env.JWT_SECRET,
        refreshTokenSecret: process.env.REFRESH_TOKEN_SECRET,
        accessTokenExpiry: process.env.ACCESS_TOKEN_EXPIRY || "15m",
        refreshTokenExpiry: process.env.REFRESH_TOKEN_EXPIRY || "30d",
        bcryptRounds: parseInt(process.env.ROUNDS || "12", 10),
    },

    // Cloudinary
    cloudinary: {
        cloudName: process.env.CLOUD_NAME,
        apiKey: process.env.CLOUD_API_KEY,
        apiSecret: process.env.CLOUD_API_SECRET,
        timeout: 30000,
    },

    // File Upload
    upload: {
        maxImageSize: 5 * 1024 * 1024, // 5MB
        maxFileSize: 10 * 1024 * 1024, // 10MB
        allowedImageFormats: ["jpg", "jpeg", "png", "gif", "webp", "bmp"],
        maxRetries: 2,
        retryDelay: 1000,
    },

    // OAuth
    oauth: {
        github: {
            clientId: process.env.GITHUB_CLIENT_ID,
            clientSecret: process.env.GITHUB_CLIENT_SECRET,
            callbackUrl:
                process.env.GITHUB_CALLBACK_URL ||
                "/api/auth/oauth/github/callback",
        },
        client: {
            url: process.env.CLIENT_URL || "http://localhost:5176",
            successRedirect:
                process.env.CLIENT_SUCCESS_REDIRECT || "/oauth-callback",
            errorRedirect: process.env.CLIENT_ERROR_REDIRECT || "/login",
        },
    },

    // WebSocket
    websocket: {
        pingTimeout: 60000,
        pingInterval: 25000,
        maxDisconnectionDuration: 120000,
    },

    // Rate Limiting
    rateLimit: {
        windowMs: 15 * 60 * 1000, // 15 minutes
        maxRequests: 100,
        authWindowMs: 15 * 60 * 1000, // 15 minutes
        maxAuthRequests: 5,
        uploadWindowMs: 60 * 1000, // 1 minute
        maxUploadRequests: 10,
    },

    // Message constraints
    message: {
        maxLength: 1000,
        editTimeoutMinutes: 5,
    },

    // Pagination
    pagination: {
        defaultLimit: 50,
        maxLimit: 100,
    },
};

// Validate OAuth configuration if being used
export function validateOAuthConfig() {
    const warnings = [];

    if (!config.oauth.github.clientId) {
        warnings.push("GitHub OAuth not configured (GITHUB_CLIENT_ID missing)");
    }

    if (!config.oauth.github.clientSecret) {
        warnings.push(
            "GitHub OAuth not configured (GITHUB_CLIENT_SECRET missing)"
        );
    }

    return {
        isConfigured:
            !!config.oauth.github.clientId &&
            !!config.oauth.github.clientSecret,
        warnings,
    };
}

export default config;

```

## File: config/oauth.js
```js
import passport from "passport";
import { Strategy as GitHubStrategy } from "passport-github2";
import { handleGitHubUser } from "../utils/oauthHelpers.js";
import { userRepository } from "../repositories/userRepository.js";

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    try {
        const user = await userRepository.findById(id);
        done(null, user);
    } catch (error) {
        done(error, null);
    }
});

passport.use(
    new GitHubStrategy(
        {
            clientID: process.env.GITHUB_CLIENT_ID,
            clientSecret: process.env.GITHUB_CLIENT_SECRET,
            callbackURL: "/api/auth/oauth/github/callback",
            scope: ["user:email"],
        },
        async (accessToken, refreshToken, profile, done) => {
            try {
                console.log("GitHub profile received:", {
                    id: profile.id,
                    username: profile.username,
                    displayName: profile.displayName,
                    emails: profile.emails,
                    photos: profile.photos,
                });

                const user = await handleGitHubUser(profile);
                done(null, user);
            } catch (error) {
                console.error("GitHub OAuth error:", error);
                done(error, null);
            }
        }
    )
);

export default passport;

```

## File: config/socket.js
```js
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

```

## File: config/swagger.js
```js
import swaggerJsdoc from "swagger-jsdoc";
import swaggerUi from "swagger-ui-express";

const options = {
    definition: {
        openapi: "3.0.0",
        info: {
            title: "Chat App API",
            version: "1.0.0",
            description: `
# Chat App API

A real-time chat application backend with complete messaging features.

## Features:
- User authentication with JWT
- Real-time messaging (text and images)
- Conversation management
- Read receipts and message status
- File upload with Cloudinary
- Profile management

## Authentication:
- Uses JWT Bearer tokens
- Access tokens expire in 15 minutes
- Refresh tokens expire in 30 days
- Include token in header: \`Authorization: Bearer <token>\`

## Common Status Codes:
- 200: Success
- 201: Created
- 400: Validation error
- 401: Unauthorized
- 404: Not found
- 409: Resource already exists
- 500: Server error
      `.trim(),
            contact: {
                name: "API Support",
                email: "support@chatapp.com",
            },
            license: {
                name: "MIT",
                url: "https://opensource.org/licenses/MIT",
            },
        },
        servers: [
            {
                url: "http://localhost:5001/api",
                description: "Development server",
            },
            {
                url: "https://api.chatapp.com/v1",
                description: "Production server",
            },
        ],
        components: {
            securitySchemes: {
                bearerAuth: {
                    type: "http",
                    scheme: "bearer",
                    bearerFormat: "JWT",
                    description:
                        "Enter your JWT access token obtained from login or signup",
                },
            },
            schemas: {
                // User Schemas
                User: {
                    type: "object",
                    properties: {
                        id: {
                            type: "string",
                            format: "uuid",
                            example: "123e4567-e89b-12d3-a456-426614174000",
                        },
                        email: {
                            type: "string",
                            format: "email",
                            example: "user@example.com",
                        },
                        full_name: {
                            type: "string",
                            example: "John Doe",
                        },
                        avatar_url: {
                            type: "string",
                            nullable: true,
                            example:
                                "https://res.cloudinary.com/dhv1xdi7a/image/upload/v1234567/avatar.jpg",
                        },
                        is_online: {
                            type: "boolean",
                            example: true,
                        },
                        last_seen: {
                            type: "string",
                            format: "date-time",
                            example: "2023-10-01T12:00:00Z",
                        },
                        created_at: {
                            type: "string",
                            format: "date-time",
                            example: "2023-10-01T12:00:00Z",
                        },
                    },
                },

                // Auth Schemas
                SignupRequest: {
                    type: "object",
                    required: ["email", "password", "full_name"],
                    properties: {
                        email: {
                            type: "string",
                            format: "email",
                            example: "user@example.com",
                        },
                        password: {
                            type: "string",
                            minLength: 6,
                            example: "password123",
                        },
                        full_name: {
                            type: "string",
                            minLength: 2,
                            maxLength: 100,
                            example: "John Doe",
                        },
                    },
                },
                LoginRequest: {
                    type: "object",
                    required: ["email", "password"],
                    properties: {
                        email: {
                            type: "string",
                            format: "email",
                            example: "user@example.com",
                        },
                        password: {
                            type: "string",
                            example: "password123",
                        },
                    },
                },
                AuthResponse: {
                    type: "object",
                    properties: {
                        user: {
                            $ref: "#/components/schemas/User",
                        },
                        accessToken: {
                            type: "string",
                            description: "JWT Access Token (15 minutes expiry)",
                            example: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                        },
                        refreshToken: {
                            type: "string",
                            description: "JWT Refresh Token (30 days expiry)",
                            example: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                        },
                    },
                },
                RefreshTokenRequest: {
                    type: "object",
                    required: ["refreshToken"],
                    properties: {
                        refreshToken: {
                            type: "string",
                            example: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                        },
                    },
                },
                RefreshTokenResponse: {
                    type: "object",
                    properties: {
                        accessToken: {
                            type: "string",
                            example: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                        },
                    },
                },
                LogoutRequest: {
                    type: "object",
                    required: ["refreshToken"],
                    properties: {
                        refreshToken: {
                            type: "string",
                            example: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                        },
                    },
                },

                // Conversation Schemas
                Conversation: {
                    type: "object",
                    properties: {
                        id: {
                            type: "string",
                            format: "uuid",
                            example: "123e4567-e89b-12d3-a456-426614174000",
                        },
                        user1_id: {
                            type: "string",
                            format: "uuid",
                            example: "123e4567-e89b-12d3-a456-426614174000",
                        },
                        user2_id: {
                            type: "string",
                            format: "uuid",
                            example: "123e4567-e89b-12d3-a456-426614174001",
                        },
                        created_at: {
                            type: "string",
                            format: "date-time",
                            example: "2023-10-01T12:00:00Z",
                        },
                        user1: {
                            $ref: "#/components/schemas/User",
                        },
                        user2: {
                            $ref: "#/components/schemas/User",
                        },
                        last_message: {
                            type: "object",
                            properties: {
                                id: {
                                    type: "string",
                                    example:
                                        "123e4567-e89b-12d3-a456-426614174002",
                                },
                                message_text: {
                                    type: "string",
                                    example: "Hello there!",
                                },
                                created_at: {
                                    type: "string",
                                    format: "date-time",
                                    example: "2023-10-01T12:05:00Z",
                                },
                                sender: {
                                    type: "object",
                                    properties: {
                                        id: {
                                            type: "string",
                                            example:
                                                "123e4567-e89b-12d3-a456-426614174000",
                                        },
                                        full_name: {
                                            type: "string",
                                            example: "John Doe",
                                        },
                                    },
                                },
                            },
                        },
                        unread_count: {
                            type: "integer",
                            example: 5,
                        },
                    },
                },
                CreateConversationRequest: {
                    type: "object",
                    required: ["user2_id"],
                    properties: {
                        user2_id: {
                            type: "string",
                            format: "uuid",
                            example: "123e4567-e89b-12d3-a456-426614174001",
                        },
                    },
                },

                // Message Schemas
                Message: {
                    type: "object",
                    properties: {
                        id: {
                            type: "string",
                            format: "uuid",
                            example: "123e4567-e89b-12d3-a456-426614174002",
                        },
                        conversation_id: {
                            type: "string",
                            format: "uuid",
                            example: "123e4567-e89b-12d3-a456-426614174000",
                        },
                        sender_id: {
                            type: "string",
                            format: "uuid",
                            example: "123e4567-e89b-12d3-a456-426614174000",
                        },
                        message_type: {
                            type: "string",
                            enum: ["TEXT", "IMAGE"],
                            example: "TEXT",
                        },
                        message_text: {
                            type: "string",
                            nullable: true,
                            example: "Hello, how are you?",
                        },
                        file_url: {
                            type: "string",
                            nullable: true,
                            example:
                                "https://res.cloudinary.com/dhv1xdi7a/image/upload/v1234567/image.jpg",
                        },
                        is_delivered: {
                            type: "boolean",
                            example: true,
                        },
                        delivered_at: {
                            type: "string",
                            format: "date-time",
                            nullable: true,
                            example: "2023-10-01T12:05:00Z",
                        },
                        created_at: {
                            type: "string",
                            format: "date-time",
                            example: "2023-10-01T12:00:00Z",
                        },
                        sender: {
                            $ref: "#/components/schemas/User",
                        },
                        read_receipts: {
                            type: "array",
                            items: {
                                $ref: "#/components/schemas/ReadReceipt",
                            },
                        },
                    },
                },
                CreateMessageRequest: {
                    type: "object",
                    properties: {
                        message_text: {
                            type: "string",
                            maxLength: 1000,
                            example: "Hello there!",
                        },
                        message_type: {
                            type: "string",
                            enum: ["TEXT", "IMAGE"],
                            default: "TEXT",
                        },
                        file_url: {
                            type: "string",
                            format: "uri",
                            example: "https://example.com/image.jpg",
                        },
                    },
                },
                UpdateMessageRequest: {
                    type: "object",
                    required: ["message_text"],
                    properties: {
                        message_text: {
                            type: "string",
                            maxLength: 1000,
                            example: "Updated message text",
                        },
                    },
                },

                // Profile Schemas
                UpdateProfileRequest: {
                    type: "object",
                    properties: {
                        full_name: {
                            type: "string",
                            minLength: 2,
                            maxLength: 100,
                            example: "John Updated",
                        },
                        avatar_file: {
                            type: "string",
                            format: "binary",
                            description:
                                "Image file for avatar (JPEG, PNG, WebP, max 5MB)",
                        },
                        currentPassword: {
                            type: "string",
                            minLength: 6,
                            example: "currentpassword123",
                        },
                        newPassword: {
                            type: "string",
                            minLength: 6,
                            example: "newpassword123",
                        },
                    },
                },

                // Read Receipt Schemas
                ReadReceipt: {
                    type: "object",
                    properties: {
                        id: {
                            type: "string",
                            format: "uuid",
                            example: "123e4567-e89b-12d3-a456-426614174003",
                        },
                        message_id: {
                            type: "string",
                            format: "uuid",
                            example: "123e4567-e89b-12d3-a456-426614174002",
                        },
                        reader_id: {
                            type: "string",
                            format: "uuid",
                            example: "123e4567-e89b-12d3-a456-426614174001",
                        },
                        read_at: {
                            type: "string",
                            format: "date-time",
                            example: "2023-10-01T12:05:00Z",
                        },
                        reader: {
                            type: "object",
                            properties: {
                                id: {
                                    type: "string",
                                    format: "uuid",
                                    example:
                                        "123e4567-e89b-12d3-a456-426614174001",
                                },
                                full_name: {
                                    type: "string",
                                    example: "Jane Smith",
                                },
                            },
                        },
                    },
                },

                // Pagination and Utility Schemas
                Pagination: {
                    type: "object",
                    properties: {
                        page: {
                            type: "integer",
                            example: 1,
                        },
                        limit: {
                            type: "integer",
                            example: 50,
                        },
                        total: {
                            type: "integer",
                            example: 150,
                        },
                    },
                },
                UnreadCount: {
                    type: "object",
                    properties: {
                        unread_count: {
                            type: "integer",
                            example: 5,
                        },
                    },
                },
                ParticipantsResponse: {
                    type: "object",
                    properties: {
                        participants: {
                            type: "array",
                            items: {
                                $ref: "#/components/schemas/User",
                            },
                        },
                    },
                },

                // Response Schemas
                SuccessResponse: {
                    type: "object",
                    properties: {
                        success: {
                            type: "boolean",
                            example: true,
                        },
                        msg: {
                            type: "string",
                            example: "Operation completed successfully",
                        },
                        data: {
                            type: "object",
                            additionalProperties: true,
                        },
                    },
                },
                ErrorResponse: {
                    type: "object",
                    properties: {
                        success: {
                            type: "boolean",
                            example: false,
                        },
                        msg: {
                            type: "string",
                            example: "Error message description",
                        },
                        data: {
                            type: "object",
                            nullable: true,
                        },
                    },
                },
                ValidationError: {
                    type: "object",
                    properties: {
                        success: {
                            type: "boolean",
                            example: false,
                        },
                        msg: {
                            type: "string",
                            example:
                                "Validation failed: email must be a valid email",
                        },
                        data: {
                            type: "object",
                            nullable: true,
                        },
                    },
                },
            },
            responses: {
                UnauthorizedError: {
                    description: "Access token is missing or invalid",
                    content: {
                        "application/json": {
                            schema: {
                                $ref: "#/components/schemas/ErrorResponse",
                            },
                            examples: {
                                missingToken: {
                                    summary: "Missing access token",
                                    value: {
                                        success: false,
                                        msg: "Access token required",
                                        data: null,
                                    },
                                },
                                invalidToken: {
                                    summary: "Invalid access token",
                                    value: {
                                        success: false,
                                        msg: "Invalid or expired token",
                                        data: null,
                                    },
                                },
                            },
                        },
                    },
                },
                ValidationError: {
                    description: "Request validation failed",
                    content: {
                        "application/json": {
                            schema: {
                                $ref: "#/components/schemas/ValidationError",
                            },
                        },
                    },
                },
                NotFoundError: {
                    description: "Resource not found",
                    content: {
                        "application/json": {
                            schema: {
                                $ref: "#/components/schemas/ErrorResponse",
                            },
                            examples: {
                                userNotFound: {
                                    summary: "User not found",
                                    value: {
                                        success: false,
                                        msg: "User not found",
                                        data: null,
                                    },
                                },
                                conversationNotFound: {
                                    summary: "Conversation not found",
                                    value: {
                                        success: false,
                                        msg: "Conversation not found",
                                        data: null,
                                    },
                                },
                                messageNotFound: {
                                    summary: "Message not found",
                                    value: {
                                        success: false,
                                        msg: "Message not found",
                                        data: null,
                                    },
                                },
                            },
                        },
                    },
                },
                ConflictError: {
                    description: "Resource already exists",
                    content: {
                        "application/json": {
                            schema: {
                                $ref: "#/components/schemas/ErrorResponse",
                            },
                            examples: {
                                userExists: {
                                    summary: "User already exists",
                                    value: {
                                        success: false,
                                        msg: "User already exists",
                                        data: null,
                                    },
                                },
                                conversationExists: {
                                    summary: "Conversation already exists",
                                    value: {
                                        success: false,
                                        msg: "Conversation already exists",
                                        data: null,
                                    },
                                },
                            },
                        },
                    },
                },
                BadRequestError: {
                    description: "Bad request",
                    content: {
                        "application/json": {
                            schema: {
                                $ref: "#/components/schemas/ErrorResponse",
                            },
                            examples: {
                                invalidCredentials: {
                                    summary: "Invalid credentials",
                                    value: {
                                        success: false,
                                        msg: "Invalid email or password",
                                        data: null,
                                    },
                                },
                                currentPasswordRequired: {
                                    summary: "Current password required",
                                    value: {
                                        success: false,
                                        msg: "Current password is required to set new password",
                                        data: null,
                                    },
                                },
                            },
                        },
                    },
                },
            },
            parameters: {
                ConversationId: {
                    name: "id",
                    in: "path",
                    required: true,
                    schema: {
                        type: "string",
                        format: "uuid",
                    },
                    description: "Conversation ID",
                },
                MessageId: {
                    name: "message_id",
                    in: "path",
                    required: true,
                    schema: {
                        type: "string",
                        format: "uuid",
                    },
                    description: "Message ID",
                },
                ConversationIdParam: {
                    name: "conversation_id",
                    in: "path",
                    required: true,
                    schema: {
                        type: "string",
                        format: "uuid",
                    },
                    description: "Conversation ID",
                },
                PageParam: {
                    name: "page",
                    in: "query",
                    schema: {
                        type: "integer",
                        minimum: 1,
                        default: 1,
                    },
                    description: "Page number",
                },
                LimitParam: {
                    name: "limit",
                    in: "query",
                    schema: {
                        type: "integer",
                        minimum: 1,
                        maximum: 100,
                        default: 50,
                    },
                    description: "Number of items per page",
                },
            },
        },
        security: [
            {
                bearerAuth: [],
            },
        ],
        tags: [
            {
                name: "Authentication",
                description: "User authentication endpoints",
            },
            {
                name: "Profile",
                description: "User profile management",
            },
            {
                name: "Users",
                description: "User search and management",
            },
            {
                name: "Upload",
                description: "File upload endpoints",
            },
            {
                name: "Conversations",
                description: "Conversation management",
            },
            {
                name: "Messages",
                description: "Message management",
            },
            {
                name: "System",
                description: "System health and status",
            },
        ],
    },
    apis: ["./src/routes/*.js"],
};

const specs = swaggerJsdoc(options);

export { specs, swaggerUi };

```

## File: controllers/authController.js
```js
import {
    signupService,
    loginService,
    logoutService,
    refreshTokenService,
    logoutAllDevicesService,
} from "../services/authService.js";
import { successResponse, createdResponse } from "../utils/responseHandler.js";
import { handleAuthError, handleTokenError } from "../utils/errorHandler.js";

export const signup = async (req, res) => {
    try {
        const result = await signupService(req.body);

        createdResponse(res, "User created successfully", {
            user: result.user,
            accessToken: result.accessToken,
            refreshToken: result.refreshToken,
        });
    } catch (error) {
        handleAuthError(res, error);
    }
};

export const login = async (req, res) => {
    try {
        const result = await loginService(req.body);

        successResponse(res, "Login successful", {
            user: result.user,
            accessToken: result.accessToken,
            refreshToken: result.refreshToken,
        });
    } catch (error) {
        handleAuthError(res, error);
    }
};

export const refreshToken = async (req, res) => {
    try {
        const { refreshToken } = req.body;
        const result = await refreshTokenService(refreshToken);

        successResponse(res, "Access token refreshed successfully", {
            accessToken: result.accessToken,
        });
    } catch (error) {
        handleTokenError(res, error);
    }
};

export const logout = async (req, res) => {
    try {
        const { refreshToken } = req.body;
        await logoutService(refreshToken);

        successResponse(res, "Logged out successfully");
    } catch (error) {
        handleTokenError(res, error);
    }
};

export const logoutAll = async (req, res) => {
    try {
        const userId = req.user.userId;
        await logoutAllDevicesService(userId);
        successResponse(res, "Logged out from all devices successfully");
    } catch (error) {
        handleTokenError(res, error);
    }
};

```

## File: controllers/conversationController.js
```js
import {
    createConversationService,
    getUserConversationsService,
    getConversationService,
    getConversationParticipantsService,
    deleteConversationService,
    checkConversationService,
} from "../services/conversationService.js";
import { successResponse, createdResponse } from "../utils/responseHandler.js";
import { handleConversationError } from "../utils/errorHandler.js";
import { getIO } from "../config/socket.js";
import { sendToUser } from "../services/socketService.js";

export const createConversation = async (req, res) => {
    try {
        const user1_id = req.user.userId;
        const { user2_id } = req.body;

        const conversation = await createConversationService(
            user1_id,
            user2_id
        );

        // Trigger real-time conversation creation event
        const io = getIO();
        io.emit("conversation_created", {
            conversation,
            created_by: user1_id,
            created_at: new Date().toISOString(),
        });

        // Specifically notify the other user if they're online
        sendToUser(user2_id, "new_conversation", {
            conversation,
            created_by: req.user,
        });

        createdResponse(res, "Conversation created successfully", {
            conversation,
        });
    } catch (error) {
        handleConversationError(res, error);
    }
};

export const getUserConversations = async (req, res) => {
    try {
        const user_id = req.user.userId;
        const conversations = await getUserConversationsService(user_id);

        successResponse(res, "Conversations retrieved successfully", {
            conversations,
        });
    } catch (error) {
        handleConversationError(res, error);
    }
};

export const getConversation = async (req, res) => {
    try {
        const user_id = req.user.userId;
        const { id } = req.params;

        const conversation = await getConversationService(id, user_id);

        successResponse(res, "Conversation retrieved successfully", {
            conversation,
        });
    } catch (error) {
        handleConversationError(res, error);
    }
};

export const getConversationParticipants = async (req, res) => {
    try {
        const user_id = req.user.userId;
        const { id } = req.params;

        const result = await getConversationParticipantsService(id, user_id);

        successResponse(res, "Participants retrieved successfully", result);
    } catch (error) {
        handleConversationError(res, error);
    }
};

export const deleteConversation = async (req, res) => {
    try {
        const user_id = req.user.userId;
        const { id } = req.params;

        // Get conversation details before deletion
        const conversation = await getConversationService(id, user_id);

        const result = await deleteConversationService(id, user_id);

        // Trigger real-time conversation deletion event
        const io = getIO();
        const otherUserId =
            conversation.user1_id === user_id
                ? conversation.user2_id
                : conversation.user1_id;

        io.emit("conversation_deleted", {
            conversation_id: id,
            deleted_by: user_id,
            deleted_at: new Date().toISOString(),
            participants: [user_id, otherUserId],
        });

        // Specifically notify the other user if they're online
        sendToUser(otherUserId, "conversation_deleted", {
            conversation_id: id,
            deleted_by: req.user,
        });

        successResponse(res, result.message);
    } catch (error) {
        handleConversationError(res, error);
    }
};

export const checkConversation = async (req, res) => {
    try {
        const user1_id = req.user.userId;
        const { user2_id } = req.params;

        const conversation = await checkConversationService(user1_id, user2_id);

        successResponse(res, "Conversation check completed", {
            exists: !!conversation,
            conversation: conversation || null,
        });
    } catch (error) {
        handleConversationError(res, error);
    }
};

```

## File: controllers/messageController.js
```js
import {
    createMessageService,
    getMessagesService,
    getMessageService,
    updateMessageService,
    deleteMessageService,
    markAsReadService,
    getUnreadCountService,
    markAllAsReadService,
} from "../services/messageService.js";
import { successResponse, createdResponse } from "../utils/responseHandler.js";
import { handleMessageError } from "../utils/errorHandler.js";

export const createMessage = async (req, res) => {
    try {
        const sender_id = req.user.userId;
        const { conversation_id } = req.params;
        const { message_text, message_type = "TEXT", file_url } = req.body;

        const message = await createMessageService({
            conversation_id,
            sender_id,
            message_text,
            message_type,
            file_url,
        });

        createdResponse(res, "Message sent successfully", {
            message,
        });
    } catch (error) {
        handleMessageError(res, error);
    }
};

export const getMessages = async (req, res) => {
    try {
        const user_id = req.user.userId;
        const { conversation_id } = req.params;
        const { page = 1, limit = 50 } = req.query;

        const messages = await getMessagesService(
            conversation_id,
            user_id,
            parseInt(page),
            parseInt(limit)
        );

        successResponse(res, "Messages retrieved successfully", {
            messages,
            pagination: {
                page: parseInt(page),
                limit: parseInt(limit),
                total: messages.length,
            },
        });
    } catch (error) {
        handleMessageError(res, error);
    }
};

export const getMessage = async (req, res) => {
    try {
        const user_id = req.user.userId;
        const { message_id } = req.params;

        const message = await getMessageService(message_id, user_id);

        successResponse(res, "Message retrieved successfully", {
            message,
        });
    } catch (error) {
        handleMessageError(res, error);
    }
};

export const updateMessage = async (req, res) => {
    try {
        const user_id = req.user.userId;
        const { message_id } = req.params;
        const { message_text } = req.body;

        if (!message_text || message_text.trim() === "") {
            return res.status(400).json({
                success: false,
                msg: "Message text cannot be empty",
            });
        }

        const updatedMessage = await updateMessageService(message_id, user_id, {
            message_text: message_text.trim(),
        });

        successResponse(res, "Message updated successfully", {
            message: updatedMessage,
        });
    } catch (error) {
        handleMessageError(res, error);
    }
};

export const deleteMessage = async (req, res) => {
    try {
        const user_id = req.user.userId;
        const { message_id } = req.params;

        const result = await deleteMessageService(message_id, user_id);

        successResponse(res, "Message deleted successfully", {
            result,
        });
    } catch (error) {
        handleMessageError(res, error);
    }
};

export const markAsRead = async (req, res) => {
    try {
        const user_id = req.user.userId;
        const { message_id } = req.params;

        const readReceipt = await markAsReadService(message_id, user_id);

        successResponse(res, "Message marked as read", {
            read_receipt: readReceipt,
        });
    } catch (error) {
        handleMessageError(res, error);
    }
};

export const getUnreadCount = async (req, res) => {
    try {
        const user_id = req.user.userId;
        const { conversation_id } = req.params;

        const result = await getUnreadCountService(conversation_id, user_id);

        successResponse(res, "Unread count retrieved successfully", result);
    } catch (error) {
        handleMessageError(res, error);
    }
};

export const markAllAsRead = async (req, res) => {
    try {
        const user_id = req.user.userId;
        const { conversation_id } = req.params;

        const result = await markAllAsReadService(conversation_id, user_id);

        successResponse(res, "All messages marked as read", {
            marked_count: result.marked_count,
            unread_count: result.unread_count,
            has_unread_messages: result.has_unread_messages,
            conversation: result.conversation,
        });
    } catch (error) {
        handleMessageError(res, error);
    }
};

```

## File: controllers/oauthController.js
```js
import passport from "../config/oauth.js";
import { oauthService } from "../services/oauthService.js";
import { successResponse } from "../utils/responseHandler.js";
import { handleOAuthError } from "../utils/errorHandler.js";

// GitHub OAuth initiation
export const githubAuth = passport.authenticate("github", {
    scope: ["user:email"],
});

// GitHub OAuth callback
export const githubCallback = (req, res, next) => {
    try {
        // Validate callback parameters first
        oauthService.validateCallbackParams(req);

        passport.authenticate(
            "github",
            { session: false },
            (err, user, info) => {
                handleOAuthCallback(req, res, err, user, info);
            }
        )(req, res, next);
    } catch (error) {
        console.error("OAuth callback validation error:", error);
        handleOAuthError(res, error);
    }
};

// Handle OAuth callback
const handleOAuthCallback = (req, res, err, user, info) => {
    console.log("OAuth callback started");

    if (err) {
        console.error("OAuth callback error:", err);
        return res.redirect(
            `${process.env.CLIENT_URL}${
                process.env.CLIENT_ERROR_REDIRECT || "/login"
            }?error=oauth_failed&message=${encodeURIComponent(err.message)}`
        );
    }

    if (!user) {
        console.error("No user returned from OAuth");
        return res.redirect(
            `${process.env.CLIENT_URL}${
                process.env.CLIENT_ERROR_REDIRECT || "/login"
            }?error=authentication_failed`
        );
    }

    console.log("OAuth successful for user:", user.user?.email);

    try {
        // Debug: Check environment variables directly
        console.log("Environment variables check:");
        console.log("CLIENT_URL:", process.env.CLIENT_URL);
        console.log(
            "CLIENT_SUCCESS_REDIRECT:",
            process.env.CLIENT_SUCCESS_REDIRECT
        );
        console.log(
            "CLIENT_ERROR_REDIRECT:",
            process.env.CLIENT_ERROR_REDIRECT
        );

        // Get config from service
        const config = oauthService.validateOAuthConfig();
        console.log("OAuth service config:");
        console.log("config.client.url:", config.client.url);
        console.log(
            "config.client.successRedirect:",
            config.client.successRedirect
        );
        console.log(
            "config.client.errorRedirect:",
            config.client.errorRedirect
        );

        // Use environment variables directly to ensure we have the latest values
        const clientUrl = process.env.CLIENT_URL;
        const successRedirect =
            process.env.CLIENT_SUCCESS_REDIRECT || "/oauth-callback";

        console.log("Using redirect values:");
        console.log("clientUrl:", clientUrl);
        console.log("successRedirect:", successRedirect);

        const redirectUrl = `${clientUrl}${successRedirect}?accessToken=${
            user.accessToken
        }&refreshToken=${user.refreshToken}&user=${encodeURIComponent(
            JSON.stringify(user.user)
        )}`;

        console.log("Final redirect URL:", redirectUrl);
        console.log(
            "User tokens generated - accessToken length:",
            user.accessToken?.length
        );
        console.log("User data:", {
            id: user.user?.id,
            email: user.user?.email,
            name: user.user?.full_name,
        });

        res.redirect(redirectUrl);
    } catch (redirectError) {
        console.error("Redirect error:", redirectError);
        console.error("Redirect error stack:", redirectError.stack);

        // Fallback to environment variables for error redirect
        const errorRedirectUrl = `${process.env.CLIENT_URL}${
            process.env.CLIENT_ERROR_REDIRECT || "/login"
        }?error=redirect_failed`;

        console.log("Error redirect URL:", errorRedirectUrl);
        res.redirect(errorRedirectUrl);
    }
};

// Get OAuth providers configuration
export const getOAuthProviders = (req, res) => {
    try {
        const config = oauthService.getOAuthConfig();

        successResponse(res, "OAuth providers retrieved successfully", config);
    } catch (error) {
        handleOAuthError(res, error);
    }
};

// Check OAuth health status
export const getOAuthHealth = (req, res) => {
    try {
        const config = oauthService.validateOAuthConfig();

        successResponse(res, "OAuth configuration is healthy", {
            healthy: true,
            github: config.github.enabled,
            clientUrl: config.client.url,
            successRedirect: config.client.successRedirect,
            errorRedirect: config.client.errorRedirect,
            timestamp: new Date().toISOString(),
            warnings: config.warnings,
        });
    } catch (error) {
        successResponse(res, "OAuth configuration has issues", {
            healthy: false,
            error: error.message,
            timestamp: new Date().toISOString(),
        });
    }
};

// Check if OAuth is enabled
export const getOAuthStatus = (req, res) => {
    try {
        const isEnabled = oauthService.isOAuthEnabled();

        successResponse(res, "OAuth status retrieved", {
            enabled: isEnabled,
            timestamp: new Date().toISOString(),
        });
    } catch (error) {
        handleOAuthError(res, error);
    }
};

```

## File: controllers/profileController.js
```js
import {
    updateProfileService,
    getProfileService,
} from "../services/profileService.js";
import { successResponse } from "../utils/responseHandler.js";
import {
    handleProfileError,
    handleCloudinaryError,
} from "../utils/errorHandler.js";
import { getIO } from "../config/socket.js";

export const updateProfile = async (req, res) => {
    try {
        const userId = req.user.userId;

        const updateData = {
            ...req.body,
            avatar_file: req.file,
        };

        const updatedUser = await updateProfileService(userId, updateData);

        // Trigger real-time profile update event
        const io = getIO();
        io.emit("user_profile_updated", {
            user_id: userId,
            user: updatedUser,
            updated_at: new Date().toISOString(),
            updated_fields: {
                full_name: !!updateData.full_name,
                avatar_url: !!req.file,
            },
        });

        successResponse(res, "Profile updated successfully", {
            user: updatedUser,
        });
    } catch (error) {
        if (
            error.message === "UPLOAD_FAILED" ||
            error.message === "DELETE_FAILED"
        ) {
            handleCloudinaryError(res, error);
        } else {
            handleProfileError(res, error);
        }
    }
};

export const getProfile = async (req, res) => {
    try {
        const userId = req.user.userId;
        const user = await getProfileService(userId);

        successResponse(res, "Profile retrieved successfully", { user });
    } catch (error) {
        handleProfileError(res, error);
    }
};

```

## File: controllers/uploadController.js
```js
import {
    uploadFileService,
    uploadImageService,
} from "../services/fileStorageService.js";
import { successResponse } from "../utils/responseHandler.js";
import { handleCloudinaryError } from "../utils/errorHandler.js";
import { resetCloudinary } from "../config/cloudinary.js";

export const uploadFile = async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({
                success: false,
                msg: "No file provided",
            });
        }

        // Validate file size (10MB limit)
        if (req.file.size > 10 * 1024 * 1024) {
            return res.status(400).json({
                success: false,
                msg: "File size too large. Maximum size: 10MB",
            });
        }

        const folder = req.body.type === "profile" ? "profiles" : "files";
        console.log(
            `Starting upload for file: ${req.file.originalname}, size: ${req.file.size} bytes`
        );

        const result = await uploadFileService(
            req.file.buffer,
            req.file.originalname,
            folder
        );

        console.log(`Upload completed successfully: ${result.public_id}`);

        successResponse(res, "File uploaded successfully", {
            url: result.secure_url,
            public_id: result.public_id,
            resource_type: result.resource_type,
            file_extension: result.file_extension,
            original_name: result.original_name,
            bytes: result.bytes,
        });
    } catch (error) {
        console.error("Upload controller error:", error.message);

        // Try to reset Cloudinary on timeout errors
        if (
            error.message === "UPLOAD_TIMEOUT" ||
            error.message === "UPLOAD_STREAM_ERROR"
        ) {
            console.log("Attempting to reset Cloudinary connection...");
            await resetCloudinary();
        }

        handleCloudinaryError(res, error);
    }
};

// Keep the old function for backward compatibility
export const uploadImage = async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({
                success: false,
                msg: "No image file provided",
            });
        }

        // Validate file size (5MB limit for images)
        if (req.file.size > 5 * 1024 * 1024) {
            return res.status(400).json({
                success: false,
                msg: "Image size too large. Maximum size: 5MB",
            });
        }

        // Validate file type
        if (!req.file.mimetype.startsWith("image/")) {
            return res.status(400).json({
                success: false,
                msg: "Invalid file type. Only image files are allowed.",
            });
        }

        const folder = req.body.type === "profile" ? "profiles" : "messages";
        console.log(
            `Starting image upload: ${req.file.originalname}, size: ${req.file.size} bytes`
        );

        const result = await uploadImageService(req.file.buffer, folder);

        console.log(`Image upload completed successfully: ${result.public_id}`);

        successResponse(res, "Image uploaded successfully", {
            url: result.secure_url,
            public_id: result.public_id,
        });
    } catch (error) {
        console.error("Image upload controller error:", error.message);

        // Try to reset Cloudinary on timeout errors
        if (
            error.message === "UPLOAD_TIMEOUT" ||
            error.message === "UPLOAD_STREAM_ERROR"
        ) {
            console.log("Attempting to reset Cloudinary connection...");
            await resetCloudinary();
        }

        handleCloudinaryError(res, error);
    }
};

// Add a health check endpoint for Cloudinary
export const cloudinaryHealth = async (req, res) => {
    try {
        const result = await resetCloudinary();
        if (result) {
            successResponse(res, "Cloudinary is healthy");
        } else {
            res.status(503).json({
                success: false,
                msg: "Cloudinary is not responding",
            });
        }
    } catch (error) {
        res.status(503).json({
            success: false,
            msg: "Cloudinary health check failed",
            error: error.message,
        });
    }
};

```

## File: controllers/userController.js
```js
import {
    searchUsersService,
    updateOnlineStatusService,
    getAllUsersService,
    getUserByIdService,
} from "../services/userService.js";
import { successResponse } from "../utils/responseHandler.js";
import { handleUserError } from "../utils/errorHandler.js";

export const searchUsers = async (req, res) => {
    try {
        const currentUserId = req.user.userId;
        const { q, limit = 10 } = req.query;

        const users = await searchUsersService(q, currentUserId, limit);

        successResponse(res, "Users retrieved successfully", {
            users,
            count: users.length,
        });
    } catch (error) {
        handleUserError(res, error);
    }
};

export const getAllUsers = async (req, res) => {
    try {
        const currentUserId = req.user.userId;
        const { limit = 50 } = req.query;

        const users = await getAllUsersService(currentUserId, limit);

        successResponse(res, "Users retrieved successfully", {
            users,
            count: users.length,
        });
    } catch (error) {
        handleUserError(res, error);
    }
};

export const getUserById = async (req, res) => {
    try {
        const { id } = req.params;
        const user = await getUserByIdService(id);

        successResponse(res, "User retrieved successfully", { user });
    } catch (error) {
        handleUserError(res, error);
    }
};

export const updateOnlineStatus = async (req, res) => {
    try {
        const userId = req.user.userId;
        const { is_online } = req.body;

        const updatedUser = await updateOnlineStatusService(userId, is_online);

        successResponse(res, "Online status updated successfully", {
            user: updatedUser,
        });
    } catch (error) {
        handleUserError(res, error);
    }
};

```

## File: handlers/conversationHandlers.js
```js
import { getIO } from "../config/socket.js";
import { sendToUser } from "../services/socketService.js";

export const setupConversationHandlers = (socket) => {
    const joinedConversations = new Set();

    socket.on("join_conversation", (conversationId) => {
        if (conversationId && !joinedConversations.has(conversationId)) {
            socket.join(`conversation:${conversationId}`);
            joinedConversations.add(conversationId);
            console.log(
                `User ${socket.userId} joined conversation ${conversationId}`
            );
        }
    });

    socket.on("leave_conversation", (conversationId) => {
        if (conversationId && joinedConversations.has(conversationId)) {
            socket.leave(`conversation:${conversationId}`);
            joinedConversations.delete(conversationId);
            console.log(
                `User ${socket.userId} left conversation ${conversationId}`
            );
        }
    });

    // Create conversation with real-time notification
    socket.on("create_conversation", async (data, callback) => {
        try {
            const { user2_id } = data;

            if (!user2_id) {
                if (typeof callback === "function") {
                    callback({
                        success: false,
                        error: "User ID is required",
                    });
                }
                return;
            }

            const { createConversationService } = await import(
                "../services/conversationService.js"
            );

            const conversation = await createConversationService(
                socket.userId,
                user2_id
            );

            // Notify both users about the new conversation
            getIO().emit("conversation_created", {
                conversation,
                created_by: socket.userId,
                created_at: new Date().toISOString(),
            });

            // Specifically notify the other user if they're online
            sendToUser(user2_id, "new_conversation", {
                conversation,
                created_by: socket.user,
            });

            if (typeof callback === "function") {
                callback({
                    success: true,
                    conversation,
                });
            }
        } catch (error) {
            console.error("Error creating conversation:", error);
            if (typeof callback === "function") {
                callback({
                    success: false,
                    error: error.message || "Failed to create conversation",
                });
            }
        }
    });

    // Delete conversation with real-time notification
    socket.on("delete_conversation", async (data, callback) => {
        try {
            const { conversation_id } = data;

            if (!conversation_id) {
                if (typeof callback === "function") {
                    callback({
                        success: false,
                        error: "Conversation ID is required",
                    });
                }
                return;
            }

            const { deleteConversationService, getConversationService } =
                await import("../services/conversationService.js");

            // Get conversation details before deletion
            const conversation = await getConversationService(
                conversation_id,
                socket.userId
            );

            await deleteConversationService(conversation_id, socket.userId);

            // Notify both users about the deleted conversation
            const otherUserId =
                conversation.user1_id === socket.userId
                    ? conversation.user2_id
                    : conversation.user1_id;

            getIO().emit("conversation_deleted", {
                conversation_id,
                deleted_by: socket.userId,
                deleted_at: new Date().toISOString(),
                participants: [socket.userId, otherUserId],
            });

            // Specifically notify the other user if they're online
            sendToUser(otherUserId, "conversation_deleted", {
                conversation_id,
                deleted_by: socket.user,
            });

            // Leave the conversation room
            socket.leave(`conversation:${conversation_id}`);
            joinedConversations.delete(conversation_id);

            if (typeof callback === "function") {
                callback({
                    success: true,
                    message: "Conversation deleted successfully",
                });
            }
        } catch (error) {
            console.error("Error deleting conversation:", error);
            if (typeof callback === "function") {
                callback({
                    success: false,
                    error: error.message || "Failed to delete conversation",
                });
            }
        }
    });

    // Clean up joined conversations on disconnect
    socket.on("disconnect", () => {
        joinedConversations.clear();
    });
};

```

## File: handlers/messageHandlers.js
```js
import { getIO, connectedUsers } from "../config/socket.js";
import {
    getUserSocket,
    sendToConversation,
} from "../services/socketService.js";

export const setupMessageHandlers = (socket) => {
    socket.on("send_message", async (data, callback) => {
        try {
            const {
                conversation_id,
                message_text,
                message_type = "TEXT",
                file_url,
            } = data;

            if (!conversation_id) {
                if (typeof callback === "function") {
                    callback({
                        success: false,
                        error: "Conversation ID is required",
                    });
                }
                return;
            }

            const { createMessageService } = await import(
                "../services/messageService.js"
            );

            const message = await createMessageService({
                conversation_id,
                sender_id: socket.userId,
                message_text,
                message_type,
                file_url,
            });

            // Get conversation participants
            const { conversationRepository } = await import(
                "../repositories/conversationRepository.js"
            );
            const conversation =
                await conversationRepository.findByIdWithAccess(
                    conversation_id,
                    socket.userId
                );

            const otherUserId =
                conversation.user1_id === socket.userId
                    ? conversation.user2_id
                    : conversation.user1_id;
            const isRecipientOnline = connectedUsers.has(otherUserId);

            // Emit to all users in the conversation room except sender
            socket.to(`conversation:${conversation_id}`).emit("new_message", {
                message,
                conversation_id,
                is_delivered: isRecipientOnline,
            });

            // Also emit to sender for consistency
            socket.emit("message_sent", {
                message,
                conversation_id,
                is_delivered: isRecipientOnline,
            });

            // Update delivery status if recipient is online
            if (isRecipientOnline) {
                const { messageRepository } = await import(
                    "../repositories/messageRepository.js"
                );
                await messageRepository.markAsDelivered(
                    conversation_id,
                    otherUserId
                );

                // Notify sender that message was delivered
                socket.emit("message_delivered", {
                    message_id: message.id,
                    conversation_id,
                    delivered_at: new Date().toISOString(),
                });
            }

            // Notify participants about new message (for sidebar updates)
            getIO().emit("conversation_updated", {
                conversation_id,
                last_message: message,
                updated_at: new Date().toISOString(),
                has_unread_messages: !isRecipientOnline,
            });

            if (typeof callback === "function") {
                callback({
                    success: true,
                    message: message,
                    is_delivered: isRecipientOnline,
                });
            }
        } catch (error) {
            console.error("Error sending message:", error);
            if (typeof callback === "function") {
                callback({
                    success: false,
                    error: error.message || "Failed to send message",
                });
            }
        }
    });

    socket.on("mark_as_read", async (data, callback) => {
        try {
            const { message_id, conversation_id } = data;

            if (!message_id || !conversation_id) {
                if (typeof callback === "function") {
                    callback({
                        success: false,
                        error: "Message ID and Conversation ID are required",
                    });
                }
                return;
            }

            const { markAsReadService } = await import(
                "../services/messageService.js"
            );

            const readReceipt = await markAsReadService(
                message_id,
                socket.userId
            );

            // Notify the sender that their message was read
            const senderSocket = getUserSocket(readReceipt.message.sender_id);
            if (senderSocket) {
                senderSocket.emit("message_read", {
                    message_id,
                    conversation_id,
                    read_by: socket.user,
                    read_at: readReceipt.read_at,
                });
            }

            if (typeof callback === "function") {
                callback({
                    success: true,
                    read_receipt: readReceipt,
                });
            }
        } catch (error) {
            console.error("Error marking message as read:", error);
            if (typeof callback === "function") {
                callback({
                    success: false,
                    error: error.message || "Failed to mark message as read",
                });
            }
        }
    });

    socket.on("mark_all_as_read", async (data, callback) => {
        try {
            const { conversation_id } = data;

            if (!conversation_id) {
                if (typeof callback === "function") {
                    callback({
                        success: false,
                        error: "Conversation ID is required",
                    });
                }
                return;
            }

            const { markAllAsReadService } = await import(
                "../services/messageService.js"
            );

            const result = await markAllAsReadService(
                conversation_id,
                socket.userId
            );

            // Notify other participants in the conversation
            socket
                .to(`conversation:${conversation_id}`)
                .emit("all_messages_read", {
                    conversation_id,
                    read_by: socket.userId,
                    read_at: new Date().toISOString(),
                });

            if (typeof callback === "function") {
                callback({
                    success: true,
                    ...result,
                });
            }
        } catch (error) {
            console.error("Error marking all messages as read:", error);
            if (typeof callback === "function") {
                callback({
                    success: false,
                    error: error.message || "Failed to mark messages as read",
                });
            }
        }
    });

    // Real-time message editing
    socket.on("edit_message", async (data, callback) => {
        try {
            const { message_id, conversation_id, message_text } = data;

            if (!message_id || !conversation_id || !message_text) {
                if (typeof callback === "function") {
                    callback({
                        success: false,
                        error: "Message ID, Conversation ID, and message text are required",
                    });
                }
                return;
            }

            const { updateMessageService } = await import(
                "../services/messageService.js"
            );

            const updatedMessage = await updateMessageService(
                message_id,
                socket.userId,
                {
                    message_text: message_text.trim(),
                }
            );

            // Notify all participants in the conversation
            sendToConversation(conversation_id, "message_edited", {
                message: updatedMessage,
                conversation_id,
                edited_by: socket.userId,
                edited_at: new Date().toISOString(),
            });

            if (typeof callback === "function") {
                callback({
                    success: true,
                    message: updatedMessage,
                });
            }
        } catch (error) {
            console.error("Error editing message:", error);
            if (typeof callback === "function") {
                callback({
                    success: false,
                    error: error.message || "Failed to edit message",
                });
            }
        }
    });

    // Real-time message deletion
    socket.on("delete_message", async (data, callback) => {
        try {
            const { message_id, conversation_id } = data;

            if (!message_id || !conversation_id) {
                if (typeof callback === "function") {
                    callback({
                        success: false,
                        error: "Message ID and Conversation ID are required",
                    });
                }
                return;
            }

            const { deleteMessageService } = await import(
                "../services/messageService.js"
            );

            const result = await deleteMessageService(
                message_id,
                socket.userId
            );

            // Notify all participants in the conversation
            sendToConversation(conversation_id, "message_deleted", {
                message_id,
                conversation_id,
                deleted_by: socket.userId,
                deleted_at: new Date().toISOString(),
                deleted_message: result,
            });

            if (typeof callback === "function") {
                callback({
                    success: true,
                    message: result,
                });
            }
        } catch (error) {
            console.error("Error deleting message:", error);
            if (typeof callback === "function") {
                callback({
                    success: false,
                    error: error.message || "Failed to delete message",
                });
            }
        }
    });
};

```

## File: handlers/typingHandlers.js
```js
const typingTimeouts = new Map();

export const setupTypingHandlers = (socket) => {
    socket.on("typing_start", (data) => {
        const { conversation_id } = data;

        if (conversation_id) {
            // Notify other users in the conversation
            socket.to(`conversation:${conversation_id}`).emit("user_typing", {
                conversation_id,
                user_id: socket.userId,
                user: socket.user,
                typing: true,
            });

            // Clear existing timeout
            if (typingTimeouts.has(conversation_id)) {
                clearTimeout(typingTimeouts.get(conversation_id));
            }

            // Set new timeout to automatically stop typing indicator
            const timeout = setTimeout(() => {
                socket
                    .to(`conversation:${conversation_id}`)
                    .emit("user_typing", {
                        conversation_id,
                        user_id: socket.userId,
                        user: socket.user,
                        typing: false,
                    });
                typingTimeouts.delete(conversation_id);
            }, 3000);

            typingTimeouts.set(conversation_id, timeout);
        }
    });

    socket.on("typing_stop", (data) => {
        const { conversation_id } = data;

        if (conversation_id) {
            // Clear timeout
            if (typingTimeouts.has(conversation_id)) {
                clearTimeout(typingTimeouts.get(conversation_id));
                typingTimeouts.delete(conversation_id);
            }

            // Notify other users
            socket.to(`conversation:${conversation_id}`).emit("user_typing", {
                conversation_id,
                user_id: socket.userId,
                user: socket.user,
                typing: false,
            });
        }
    });

    // Clean up timeouts on disconnect
    socket.on("disconnect", () => {
        typingTimeouts.forEach((timeout, conversationId) => {
            clearTimeout(timeout);
        });
        typingTimeouts.clear();
    });
};

```

## File: handlers/userHandlers.js
```js
import { connectedUsers, getIO } from "../config/socket.js";
import { sendToConversation } from "../services/socketService.js";

export const setupUserHandlers = (socket) => {
    socket.on("get_online_users", async (callback) => {
        try {
            const onlineUsers = Array.from(connectedUsers.values()).map(
                (conn) => conn.user
            );

            if (typeof callback === "function") {
                callback({
                    success: true,
                    online_users: onlineUsers,
                });
            }
        } catch (error) {
            console.error("Error getting online users:", error);
            if (typeof callback === "function") {
                callback({
                    success: false,
                    error: "Failed to get online users",
                });
            }
        }
    });

    // Listen for profile updates
    socket.on("profile_updated", async (data, callback) => {
        try {
            const { full_name, avatar_url } = data;

            // Update user in connected users map
            const userConnection = connectedUsers.get(socket.userId);
            if (userConnection) {
                if (full_name) userConnection.user.full_name = full_name;
                if (avatar_url) userConnection.user.avatar_url = avatar_url;
                connectedUsers.set(socket.userId, userConnection);
            }

            // Notify all users about profile update
            getIO().emit("user_profile_updated", {
                user_id: socket.userId,
                user: userConnection?.user || socket.user,
                updated_at: new Date().toISOString(),
                updated_fields: {
                    full_name: !!full_name,
                    avatar_url: !!avatar_url,
                },
            });

            // Notify all conversations this user is part of
            const { conversationRepository } = await import(
                "../repositories/conversationRepository.js"
            );
            const conversations = await conversationRepository.findByUserId(
                socket.userId
            );

            conversations.forEach((conversation) => {
                sendToConversation(
                    conversation.id,
                    "conversation_user_updated",
                    {
                        conversation_id: conversation.id,
                        user_id: socket.userId,
                        user: userConnection?.user || socket.user,
                        updated_at: new Date().toISOString(),
                    }
                );
            });

            if (typeof callback === "function") {
                callback({
                    success: true,
                    message: "Profile update broadcasted",
                });
            }
        } catch (error) {
            console.error("Error broadcasting profile update:", error);
            if (typeof callback === "function") {
                callback({
                    success: false,
                    error: "Failed to broadcast profile update",
                });
            }
        }
    });
};

```

## File: middlewares/auth.js
```js
import { tokenService } from "../services/tokenService.js";
import { unauthorizedResponse } from "../utils/responseHandler.js";

export const authenticateToken = (req, res, next) => {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];

    if (!token) {
        return unauthorizedResponse(res, "Access token required");
    }

    try {
        const decoded = tokenService.validateAccessToken(token);
        req.user = decoded;
        next();
    } catch (error) {
        return unauthorizedResponse(res, "Invalid or expired token");
    }
};

```

## File: middlewares/errorHandler.js
```js
import { AppError } from "../utils/errors.js";
import { logger } from "../utils/logger.js";
import { HttpStatus } from "../config/constants.js";

export const errorHandler = (err, req, res, next) => {
    // Log error
    logger.error("Error occurred", err, {
        method: req.method,
        path: req.path,
        userId: req.user?.userId,
    });

    // Handle operational errors
    if (err.isOperational) {
        return res.status(err.statusCode).json({
            success: false,
            msg: err.message,
            code: err.code,
            data: null,
        });
    }

    // Handle Prisma errors
    if (err.code && err.code.startsWith("P")) {
        return handlePrismaError(err, res);
    }

    // Handle validation errors (from Joi)
    if (err.isJoi) {
        return res.status(HttpStatus.BAD_REQUEST).json({
            success: false,
            msg: "Validation error",
            code: "VALIDATION_ERROR",
            data: {
                details: err.details,
            },
        });
    }

    // Handle JWT errors
    if (err.name === "JsonWebTokenError") {
        return res.status(HttpStatus.UNAUTHORIZED).json({
            success: false,
            msg: "Invalid token",
            code: "INVALID_TOKEN",
            data: null,
        });
    }

    if (err.name === "TokenExpiredError") {
        return res.status(HttpStatus.UNAUTHORIZED).json({
            success: false,
            msg: "Token expired",
            code: "TOKEN_EXPIRED",
            data: null,
        });
    }

    // Handle multer errors
    if (err.name === "MulterError") {
        return res.status(HttpStatus.BAD_REQUEST).json({
            success: false,
            msg: `File upload error: ${err.message}`,
            code: "FILE_UPLOAD_ERROR",
            data: null,
        });
    }

    // Default error response (unexpected errors)
    logger.error("Unexpected error", err);

    return res.status(HttpStatus.INTERNAL_SERVER_ERROR).json({
        success: false,
        msg: "Internal server error",
        code: "INTERNAL_ERROR",
        data: null,
    });
};

function handlePrismaError(err, res) {
    const errorMap = {
        P2002: {
            statusCode: HttpStatus.CONFLICT,
            message: "A record with this information already exists",
            code: "DUPLICATE_RECORD",
        },
        P2025: {
            statusCode: HttpStatus.NOT_FOUND,
            message: "Record not found",
            code: "RECORD_NOT_FOUND",
        },
        P2003: {
            statusCode: HttpStatus.BAD_REQUEST,
            message: "Invalid reference to related record",
            code: "INVALID_REFERENCE",
        },
        P2001: {
            statusCode: HttpStatus.NOT_FOUND,
            message: "Record not found",
            code: "RECORD_NOT_FOUND",
        },
    };

    const errorInfo = errorMap[err.code] || {
        statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
        message: "Database error",
        code: "DATABASE_ERROR",
    };

    return res.status(errorInfo.statusCode).json({
        success: false,
        msg: errorInfo.message,
        code: errorInfo.code,
        data: null,
    });
}

// Async error wrapper
export const asyncHandler = (fn) => {
    return (req, res, next) => {
        Promise.resolve(fn(req, res, next)).catch(next);
    };
};

```

## File: middlewares/rateLimiter.js
```js
import { RateLimitError } from "../utils/errors.js";
import config from "../config/env.js";

// Simple in-memory rate limiter (for production, use Redis)
class RateLimiter {
    constructor() {
        this.requests = new Map(); // key -> { count, resetTime }
        this.cleanup();
    }

    cleanup() {
        // Clean up expired entries every minute
        setInterval(() => {
            const now = Date.now();
            for (const [key, data] of this.requests.entries()) {
                if (data.resetTime < now) {
                    this.requests.delete(key);
                }
            }
        }, 60000);
    }

    check(key, maxRequests, windowMs) {
        const now = Date.now();
        const data = this.requests.get(key);

        if (!data || data.resetTime < now) {
            // First request or window expired
            this.requests.set(key, {
                count: 1,
                resetTime: now + windowMs,
            });
            return { allowed: true, remaining: maxRequests - 1 };
        }

        if (data.count >= maxRequests) {
            const retryAfter = Math.ceil((data.resetTime - now) / 1000);
            return {
                allowed: false,
                remaining: 0,
                retryAfter,
            };
        }

        data.count++;
        return {
            allowed: true,
            remaining: maxRequests - data.count,
        };
    }
}

const limiter = new RateLimiter();

// General API rate limiter
export const apiRateLimiter = (req, res, next) => {
    const key = `api:${req.ip}`;
    const result = limiter.check(
        key,
        config.rateLimit.maxRequests,
        config.rateLimit.windowMs
    );

    res.setHeader("X-RateLimit-Limit", config.rateLimit.maxRequests);
    res.setHeader("X-RateLimit-Remaining", result.remaining);

    if (!result.allowed) {
        res.setHeader("Retry-After", result.retryAfter);
        return next(
            new RateLimitError("Too many requests, please try again later")
        );
    }

    next();
};

// Auth-specific rate limiter (stricter)
export const authRateLimiter = (req, res, next) => {
    const key = `auth:${req.ip}`;
    const result = limiter.check(
        key,
        config.rateLimit.maxAuthRequests,
        config.rateLimit.authWindowMs
    );

    res.setHeader("X-RateLimit-Limit", config.rateLimit.maxAuthRequests);
    res.setHeader("X-RateLimit-Remaining", result.remaining);

    if (!result.allowed) {
        res.setHeader("Retry-After", result.retryAfter);
        return next(
            new RateLimitError(
                "Too many authentication attempts, please try again later"
            )
        );
    }

    next();
};

// Upload rate limiter
export const uploadRateLimiter = (req, res, next) => {
    const userId = req.user?.userId || req.ip;
    const key = `upload:${userId}`;
    const result = limiter.check(
        key,
        config.rateLimit.maxUploadRequests,
        config.rateLimit.uploadWindowMs
    );

    res.setHeader("X-RateLimit-Limit", config.rateLimit.maxUploadRequests);
    res.setHeader("X-RateLimit-Remaining", result.remaining);

    if (!result.allowed) {
        res.setHeader("Retry-After", result.retryAfter);
        return next(
            new RateLimitError(
                "Too many upload requests, please try again later"
            )
        );
    }

    next();
};

// Socket event rate limiter
export class SocketRateLimiter {
    constructor() {
        this.limiter = new RateLimiter();
    }

    check(userId, event, maxEvents = 20, windowMs = 10000) {
        const key = `socket:${userId}:${event}`;
        return this.limiter.check(key, maxEvents, windowMs);
    }
}

export const socketRateLimiter = new SocketRateLimiter();

```

## File: middlewares/socketAuth.js
```js
import { tokenService } from "../services/tokenService.js";
import { userRepository } from "../repositories/userRepository.js";

export const socketAuthMiddleware = async (socket, next) => {
    try {
        const token = socket.handshake.auth.token;

        if (!token) {
            console.log("Socket authentication failed: No token provided");
            return next(new Error("Authentication error: No token provided"));
        }

        const decoded = tokenService.validateAccessToken(token);
        const user = await userRepository.findById(decoded.userId);

        if (!user) {
            console.log(
                `Socket authentication failed: User ${decoded.userId} not found`
            );
            return next(new Error("Authentication error: User not found"));
        }

        socket.userId = decoded.userId;
        socket.user = {
            id: user.id,
            email: user.email,
            full_name: user.full_name,
            avatar_url: user.avatar_url,
        };

        console.log(
            `Socket authentication successful for user ${socket.userId}`
        );
        next();
    } catch (error) {
        console.error("Socket authentication error:", error.message);
        next(new Error("Authentication error: Invalid token"));
    }
};

```

## File: middlewares/upload.js
```js
import multer from "multer";

const storage = multer.memoryStorage();

// Allow all file types
const fileFilter = (req, file, cb) => {
    // You can add restrictions here if needed
    // For example, limit file types or sizes
    cb(null, true);
};

const upload = multer({
    storage: storage,
    fileFilter: fileFilter,
    limits: {
        fileSize: 50 * 1024 * 1024, // 50MB limit
    },
});

export { upload };

```

## File: middlewares/validation.js
```js
import { badRequestResponse } from "../utils/responseHandler.js";

export const validate = (schema, property = "body") => {
    return (req, res, next) => {
        const { error } = schema.validate(req[property], {
            abortEarly: false,
            stripUnknown: true,
        });

        if (error) {
            const errorMessage = error.details
                .map((detail) => detail.message)
                .join(", ");

            return badRequestResponse(res, errorMessage);
        }

        if (property === "body") {
            req.body = schema.validate(req.body).value;
        }

        next();
    };
};

export const validateParams = (schema) => validate(schema, "params");

export const validateQuery = (schema) => validate(schema, "query");

```

## File: repositories/authRepository.js
```js
import prisma from "../config/database.js";

export const authRepository = {

    createRefreshToken: async (tokenData) => {
        return await prisma.refreshToken.create({
            data: tokenData,
        });
    },

    storeRefreshToken: async (userId, token) => {
        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + 30);

        return await prisma.refreshToken.create({
            data: {
                token,
                user_id: userId,
                expires_at: expiresAt,
            },
        });
    },

    findRefreshToken: async (token) => {
        return await prisma.refreshToken.findUnique({
            where: { token },
            include: { user: true },
        });
    },

    deleteRefreshToken: async (token) => {
        return await prisma.refreshToken.delete({
            where: { token },
        });
    },

    deleteAllUserRefreshTokens: async (user_id) => {
        return await prisma.refreshToken.deleteMany({
            where: { user_id },
        });
    },

    findExpiredTokens: async () => {
        return await prisma.refreshToken.findMany({
            where: {
                expires_at: {
                    lt: new Date(),
                },
            },
        });
    },
};

```

## File: repositories/conversationRepository.js
```js
import prisma from "../config/database.js";

export const conversationRepository = {
    findByParticipants: async (user1_id, user2_id) => {
        const [sortedUser1, sortedUser2] = [user1_id, user2_id].sort();

        return await prisma.conversation.findUnique({
            where: {
                user1_id_user2_id: {
                    user1_id: sortedUser1,
                    user2_id: sortedUser2,
                },
            },
        });
    },

    create: async (conversationData) => {
        return await prisma.conversation.create({
            data: conversationData,
            include: {
                user1: {
                    select: {
                        id: true,
                        email: true,
                        full_name: true,
                        avatar_url: true,
                        is_online: true,
                        last_seen: true,
                    },
                },
                user2: {
                    select: {
                        id: true,
                        email: true,
                        full_name: true,
                        avatar_url: true,
                        is_online: true,
                        last_seen: true,
                    },
                },
            },
        });
    },

    findByUserId: async (user_id) => {
        return await prisma.conversation.findMany({
            where: {
                OR: [{ user1_id: user_id }, { user2_id: user_id }],
            },
            include: {
                user1: {
                    select: {
                        id: true,
                        email: true,
                        full_name: true,
                        avatar_url: true,
                        is_online: true,
                        last_seen: true,
                    },
                },
                user2: {
                    select: {
                        id: true,
                        email: true,
                        full_name: true,
                        avatar_url: true,
                        is_online: true,
                        last_seen: true,
                    },
                },
                messages: {
                    take: 1,
                    orderBy: { created_at: "desc" },
                    include: {
                        sender: {
                            select: {
                                id: true,
                                full_name: true,
                            },
                        },
                    },
                },
                _count: {
                    select: {
                        messages: {
                            where: {
                                sender_id: { not: user_id }, // Messages where current user is NOT sender
                                read_receipts: {
                                    none: {
                                        reader_id: user_id, // No read receipt from current user
                                    },
                                },
                            },
                        },
                    },
                },
            },
            orderBy: {
                messages: {
                    _count: "desc",
                },
            },
        });
    },

    findByIdWithAccess: async (conversation_id, user_id) => {
        return await prisma.conversation.findFirst({
            where: {
                id: conversation_id,
                OR: [{ user1_id: user_id }, { user2_id: user_id }],
            },
            include: {
                user1: {
                    select: {
                        id: true,
                        email: true,
                        full_name: true,
                        avatar_url: true,
                        is_online: true,
                        last_seen: true,
                    },
                },
                user2: {
                    select: {
                        id: true,
                        email: true,
                        full_name: true,
                        avatar_url: true,
                        is_online: true,
                        last_seen: true,
                    },
                },
            },
        });
    },

    delete: async (conversation_id) => {
        return await prisma.conversation.delete({
            where: { id: conversation_id },
        });
    },
};

```

## File: repositories/messageRepository.js
```js
import prisma from "../config/database.js";

export const messageRepository = {
    create: async (messageData) => {
        return await prisma.message.create({
            data: messageData,
            include: {
                sender: {
                    select: {
                        id: true,
                        email: true,
                        full_name: true,
                        avatar_url: true,
                    },
                },
                conversation: {
                    select: {
                        id: true,
                        user1_id: true,
                        user2_id: true,
                    },
                },
            },
        });
    },

    findByConversation: async (conversation_id, skip = 0, limit = 50) => {
        return await prisma.message.findMany({
            where: { conversation_id },
            include: {
                sender: {
                    select: {
                        id: true,
                        email: true,
                        full_name: true,
                        avatar_url: true,
                    },
                },
                read_receipts: {
                    include: {
                        reader: {
                            select: {
                                id: true,
                                full_name: true,
                            },
                        },
                    },
                },
            },
            orderBy: { created_at: "desc" },
            skip: parseInt(skip),
            take: parseInt(limit),
        });
    },

    findByIdWithAccess: async (message_id, user_id) => {
        return await prisma.message.findFirst({
            where: {
                id: message_id,
                conversation: {
                    OR: [{ user1_id: user_id }, { user2_id: user_id }],
                },
            },
            include: {
                sender: {
                    select: {
                        id: true,
                        email: true,
                        full_name: true,
                        avatar_url: true,
                    },
                },
                read_receipts: {
                    include: {
                        reader: {
                            select: {
                                id: true,
                                full_name: true,
                            },
                        },
                    },
                },
                conversation: {
                    select: {
                        id: true,
                        user1_id: true,
                        user2_id: true,
                    },
                },
            },
        });
    },

    update: async (message_id, updateData) => {
        return await prisma.message.update({
            where: { id: message_id },
            data: updateData,
            include: {
                sender: {
                    select: {
                        id: true,
                        email: true,
                        full_name: true,
                        avatar_url: true,
                    },
                },
                read_receipts: {
                    include: {
                        reader: {
                            select: {
                                id: true,
                                full_name: true,
                            },
                        },
                    },
                },
            },
        });
    },

    delete: async (message_id) => {
        return await prisma.message.delete({
            where: { id: message_id },
        });
    },

    markAsDelivered: async (conversation_id, user_id) => {
        return await prisma.message.updateMany({
            where: {
                conversation_id,
                sender_id: { not: user_id },
                is_delivered: false,
            },
            data: {
                is_delivered: true,
                delivered_at: new Date(),
            },
        });
    },

    countUnread: async (conversation_id, user_id) => {
        return await prisma.message.count({
            where: {
                conversation_id,
                sender_id: { not: user_id },
                read_receipts: {
                    none: {
                        reader_id: user_id,
                    },
                },
            },
        });
    },

    markAllAsRead: async (conversation_id, reader_id) => {
        // Use a single query to create all read receipts at once
        // This prevents race conditions and duplicate errors
        const result = await prisma.$transaction(async (tx) => {
            // Get unread messages
            const unreadMessages = await tx.message.findMany({
                where: {
                    conversation_id,
                    sender_id: { not: reader_id },
                    read_receipts: {
                        none: {
                            reader_id: reader_id,
                        },
                    },
                },
                select: {
                    id: true,
                },
            });

            if (unreadMessages.length === 0) {
                return {
                    marked_count: 0,
                    read_receipts: [],
                };
            }

            // Create read receipts for all unread messages
            const now = new Date();
            const readReceiptData = unreadMessages.map((message) => ({
                message_id: message.id,
                reader_id: reader_id,
                read_at: now,
            }));

            // Use createMany with skipDuplicates to avoid unique constraint errors
            await tx.readReceipt.createMany({
                data: readReceiptData,
                skipDuplicates: true, // This prevents duplicate errors
            });

            // Get the created read receipts
            const readReceipts = await tx.readReceipt.findMany({
                where: {
                    message_id: {
                        in: unreadMessages.map((m) => m.id),
                    },
                    reader_id: reader_id,
                },
                include: {
                    reader: {
                        select: {
                            id: true,
                            full_name: true,
                        },
                    },
                },
            });

            return {
                marked_count: unreadMessages.length,
                read_receipts: readReceipts,
            };
        });

        return result;
    },

    getUnreadCountAfterMark: async (conversation_id, user_id) => {
        return await prisma.message.count({
            where: {
                conversation_id,
                sender_id: { not: user_id },
                read_receipts: {
                    none: {
                        reader_id: user_id,
                    },
                },
            },
        });
    },
};

```

## File: repositories/readReceiptRepository.js
```js
import prisma from "../config/database.js";

export const readReceiptRepository = {
    upsert: async (receiptData) => {
        return await prisma.readReceipt.upsert({
            where: {
                message_id_reader_id: {
                    message_id: receiptData.message_id,
                    reader_id: receiptData.reader_id,
                },
            },
            update: {
                read_at: receiptData.read_at,
            },
            create: receiptData,
            include: {
                reader: {
                    select: {
                        id: true,
                        full_name: true,
                    },
                },
            },
        });
    },

    createMany: async (receiptsData) => {
        return await prisma.readReceipt.createMany({
            data: receiptsData,
            skipDuplicates: true, // Prevent duplicate errors
        });
    },

    findByMessageAndReader: async (message_id, reader_id) => {
        return await prisma.readReceipt.findUnique({
            where: {
                message_id_reader_id: {
                    message_id,
                    reader_id,
                },
            },
        });
    },

    exists: async (message_id, reader_id) => {
        const receipt = await prisma.readReceipt.findUnique({
            where: {
                message_id_reader_id: {
                    message_id,
                    reader_id,
                },
            },
            select: {
                id: true,
            },
        });
        return !!receipt;
    },
};

```

## File: repositories/tokenRepository.js
```js
import prisma from "../config/database.js";

export const tokenRepository = {
    
    storeRefreshToken: async (userId, token) => {
        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + 30);

        return await prisma.refreshToken.create({
            data: {
                token,
                user_id: userId,
                expires_at: expiresAt,
            },
        });
    },

    findRefreshToken: async (token) => {
        return await prisma.refreshToken.findUnique({
            where: { token },
            include: { user: true },
        });
    },

    deleteRefreshToken: async (token) => {
        return await prisma.refreshToken.delete({
            where: { token },
        });
    },

    deleteAllUserRefreshTokens: async (user_id) => {
        return await prisma.refreshToken.deleteMany({
            where: { user_id },
        });
    },

    findExpiredTokens: async () => {
        return await prisma.refreshToken.findMany({
            where: {
                expires_at: {
                    lt: new Date(),
                },
            },
        });
    },

    cleanupExpiredTokens: async () => {
        return await prisma.refreshToken.deleteMany({
            where: {
                expires_at: {
                    lt: new Date(),
                },
            },
        });
    },

    findUserRefreshTokens: async (user_id) => {
        return await prisma.refreshToken.findMany({
            where: { user_id },
            orderBy: { created_at: "desc" },
        });
    },

    verifyTokenValidity: async (token) => {
        const storedToken = await prisma.refreshToken.findUnique({
            where: { token },
            include: { user: true },
        });

        if (!storedToken) {
            return { valid: false, reason: "TOKEN_NOT_FOUND" };
        }

        if (new Date() > storedToken.expires_at) {
            await prisma.refreshToken.delete({
                where: { token },
            });
            return { valid: false, reason: "TOKEN_EXPIRED" };
        }

        return { valid: true, token: storedToken };
    },
};

```

## File: repositories/userRepository.js
```js
import prisma from "../config/database.js";

export const userRepository = {
    
    findMany: async (excludeUserId, limit = 50) => {
        return await prisma.user.findMany({
            where: {
                id: { not: excludeUserId },
            },
            select: {
                id: true,
                email: true,
                full_name: true,
                avatar_url: true,
                is_online: true,
                last_seen: true,
            },
            take: parseInt(limit),
            orderBy: [{ is_online: "desc" }, { full_name: "asc" }],
        });
    },

    findByEmail: async (email) => {
        return await prisma.user.findUnique({
            where: { email },
        });
    },

    findById: async (id) => {
        return await prisma.user.findUnique({
            where: { id },
        });
    },

    create: async (userData) => {
        return await prisma.user.create({
            data: userData,
        });
    },

    update: async (id, updateData) => {
        return await prisma.user.update({
            where: { id },
            data: updateData,
            select: {
                id: true,
                email: true,
                full_name: true,
                avatar_url: true,
                is_online: true,
                last_seen: true,
                created_at: true,
            },
        });
    },

    findByIds: async (ids) => {
        return await prisma.user.findMany({
            where: { id: { in: ids } },
            select: {
                id: true,
                email: true,
                full_name: true,
                avatar_url: true,
                is_online: true,
                last_seen: true,
            },
        });
    },

    searchUsers: async (query, currentUserId, limit = 10) => {
        return await prisma.user.findMany({
            where: {
                AND: [
                    { id: { not: currentUserId } }, // Exclude current user
                    {
                        OR: [
                            {
                                full_name: {
                                    contains: query,
                                    mode: "insensitive",
                                },
                            },
                            { email: { contains: query, mode: "insensitive" } },
                        ],
                    },
                ],
            },
            select: {
                id: true,
                email: true,
                full_name: true,
                avatar_url: true,
                is_online: true,
                last_seen: true,
            },
            take: parseInt(limit),
            orderBy: [
                { is_online: "desc" }, // Online users first
                { full_name: "asc" },
            ],
        });
    },

    updateOnlineStatus: async (userId, isOnline) => {
        return await prisma.user.update({
            where: { id: userId },
            data: {
                is_online: isOnline,
                last_seen: new Date(),
            },
            select: {
                id: true,
                is_online: true,
                last_seen: true,
            },
        });
    },
};

```

## File: routes/auth.js
```js
import express from "express";
import {
    signup,
    login,
    logout,
    refreshToken,
    logoutAll,
} from "../controllers/authController.js";
import { authenticateToken } from "../middlewares/auth.js";
import { validate } from "../middlewares/validation.js";
import { authValidation } from "../utils/validationSchemas.js";

const router = express.Router();

/**
 * @swagger
 * tags:
 *   name: Authentication
 *   description: User authentication endpoints
 */

/**
 * @swagger
 * /auth/signup:
 *   post:
 *     summary: Register a new user
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/SignupRequest'
 *     responses:
 *       201:
 *         description: User created successfully
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/SuccessResponse'
 *             examples:
 *               success:
 *                 value:
 *                   success: true
 *                   msg: "User created successfully"
 *                   data:
 *                     user:
 *                       id: "123e4567-e89b-12d3-a456-426614174000"
 *                       email: "user@example.com"
 *                       full_name: "John Doe"
 *                       avatar_url: null
 *                       is_online: false
 *                       last_seen: "2023-10-01T12:00:00Z"
 *                       created_at: "2023-10-01T12:00:00Z"
 *                     accessToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
 *                     refreshToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
 *       400:
 *         $ref: '#/components/responses/ValidationError'
 *       409:
 *         $ref: '#/components/responses/ConflictError'
 */
router.post("/signup", validate(authValidation.signup), signup);

/**
 * @swagger
 * /auth/login:
 *   post:
 *     summary: Authenticate user
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/LoginRequest'
 *     responses:
 *       200:
 *         description: Login successful
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/SuccessResponse'
 *             examples:
 *               success:
 *                 value:
 *                   success: true
 *                   msg: "Login successful"
 *                   data:
 *                     user:
 *                       id: "123e4567-e89b-12d3-a456-426614174000"
 *                       email: "user@example.com"
 *                       full_name: "John Doe"
 *                       avatar_url: null
 *                       is_online: true
 *                       last_seen: "2023-10-01T12:00:00Z"
 *                       created_at: "2023-10-01T12:00:00Z"
 *                     accessToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
 *                     refreshToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
 *       400:
 *         $ref: '#/components/responses/ValidationError'
 *       401:
 *         $ref: '#/components/responses/BadRequestError'
 */
router.post("/login", validate(authValidation.login), login);

/**
 * @swagger
 * /auth/refresh-token:
 *   post:
 *     summary: Refresh access token
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/RefreshTokenRequest'
 *     responses:
 *       200:
 *         description: Token refreshed successfully
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/SuccessResponse'
 *             examples:
 *               success:
 *                 value:
 *                   success: true
 *                   msg: "Access token refreshed successfully"
 *                   data:
 *                     accessToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
 *       400:
 *         $ref: '#/components/responses/ValidationError'
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 */
router.post(
    "/refresh-token",
    validate(authValidation.refreshToken),
    refreshToken
);

/**
 * @swagger
 * /auth/logout:
 *   post:
 *     summary: Logout user
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/LogoutRequest'
 *     responses:
 *       200:
 *         description: Logged out successfully
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/SuccessResponse'
 *       400:
 *         $ref: '#/components/responses/ValidationError'
 */
router.post("/logout", validate(authValidation.logout), logout);

/**
 * @swagger
 * /auth/logout-all:
 *   post:
 *     summary: Logout from all devices
 *     tags: [Authentication]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Logged out from all devices
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/SuccessResponse'
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 */
router.post("/logout-all", authenticateToken, logoutAll);

export default router;

```

## File: routes/conversation.js
```js
import express from "express";
import {
    createConversation,
    getUserConversations,
    getConversation,
    getConversationParticipants,
    deleteConversation,
    checkConversation, // Add this import
} from "../controllers/conversationController.js";
import { authenticateToken } from "../middlewares/auth.js";
import { validate, validateParams } from "../middlewares/validation.js";
import { conversationValidation } from "../utils/validationSchemas.js";

const router = express.Router();

router.use(authenticateToken);

/**
 * @swagger
 * tags:
 *   name: Conversations
 *   description: Conversation management endpoints
 */

/**
 * @swagger
 * /conversations:
 *   post:
 *     summary: Create a new conversation
 *     tags: [Conversations]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/CreateConversationRequest'
 *     responses:
 *       201:
 *         description: Conversation created successfully
 *       400:
 *         $ref: '#/components/responses/ValidationError'
 *       404:
 *         $ref: '#/components/responses/NotFoundError'
 *       409:
 *         $ref: '#/components/responses/ConflictError'
 */
router.post(
    "/",
    validate(conversationValidation.createConversation),
    createConversation
);

/**
 * @swagger
 * /conversations:
 *   get:
 *     summary: Get user's conversations
 *     tags: [Conversations]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Conversations retrieved successfully
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 */
router.get("/", getUserConversations);

/**
 * @swagger
 * /conversations/check/{user2_id}:
 *   get:
 *     summary: Check if conversation exists with user
 *     tags: [Conversations]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - name: user2_id
 *         in: path
 *         required: true
 *         schema:
 *           type: string
 *           format: uuid
 *         description: ID of the other user
 *     responses:
 *       200:
 *         description: Conversation check completed
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/SuccessResponse'
 *             examples:
 *               exists:
 *                 value:
 *                   success: true
 *                   msg: "Conversation check completed"
 *                   data:
 *                     exists: true
 *                     conversation:
 *                       id: "123e4567-e89b-12d3-a456-426614174000"
 *                       user1_id: "123e4567-e89b-12d3-a456-426614174000"
 *                       user2_id: "123e4567-e89b-12d3-a456-426614174001"
 *               notExists:
 *                 value:
 *                   success: true
 *                   msg: "Conversation check completed"
 *                   data:
 *                     exists: false
 *                     conversation: null
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 */
router.get(
    "/check/:user2_id",
    validateParams(conversationValidation.checkConversation),
    checkConversation
);

/**
 * @swagger
 * /conversations/{id}:
 *   get:
 *     summary: Get specific conversation
 *     tags: [Conversations]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - $ref: '#/components/parameters/ConversationId'
 *     responses:
 *       200:
 *         description: Conversation retrieved successfully
 *       400:
 *         $ref: '#/components/responses/ValidationError'
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 *       404:
 *         $ref: '#/components/responses/NotFoundError'
 */
router.get(
    "/:id",
    validateParams(conversationValidation.conversationParams),
    getConversation
);

/**
 * @swagger
 * /conversations/{id}/participants:
 *   get:
 *     summary: Get conversation participants
 *     tags: [Conversations]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - $ref: '#/components/parameters/ConversationId'
 *     responses:
 *       200:
 *         description: Participants retrieved successfully
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 *       404:
 *         $ref: '#/components/responses/NotFoundError'
 */
router.get(
    "/:id/participants",
    validateParams(conversationValidation.conversationParams),
    getConversationParticipants
);

/**
 * @swagger
 * /conversations/{id}:
 *   delete:
 *     summary: Delete a conversation
 *     tags: [Conversations]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - $ref: '#/components/parameters/ConversationId'
 *     responses:
 *       200:
 *         description: Conversation deleted successfully
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 *       404:
 *         $ref: '#/components/responses/NotFoundError'
 */
router.delete(
    "/:id",
    validateParams(conversationValidation.conversationParams),
    deleteConversation
);

export default router;

```

## File: routes/index.js
```js
import express from "express";
import authRoutes from "./auth.js";
import oauthRoutes from "./oauth.js";
import profileRoutes from "./profile.js";
import conversationRoutes from "./conversation.js";
import messageRoutes from "./message.js";
import userRoutes from "./user.js";
import uploadRoutes from "./upload.js";

const router = express.Router();

router.use("/auth", authRoutes);
router.use("/auth/oauth", oauthRoutes);
router.use("/profile", profileRoutes);
router.use("/conversations", conversationRoutes);
router.use("/conversations", messageRoutes);
router.use("/users", userRoutes);
router.use("/upload", uploadRoutes);

export default router;

```

## File: routes/message.js
```js
import express from "express";
import {
    createMessage,
    getMessages,
    getMessage,
    updateMessage,
    deleteMessage,
    markAsRead,
    getUnreadCount,
    markAllAsRead,
} from "../controllers/messageController.js";
import { authenticateToken } from "../middlewares/auth.js";
import {
    validate,
    validateParams,
    validateQuery,
} from "../middlewares/validation.js";
import {
    messageValidation,
    readReceiptValidation,
} from "../utils/validationSchemas.js";

const router = express.Router();

router.use(authenticateToken);

/**
 * @swagger
 * tags:
 *   name: Messages
 *   description: Message management endpoints
 */

/**
 * @swagger
 * /conversations/{conversation_id}/messages:
 *   post:
 *     summary: Send a message
 *     tags: [Messages]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - $ref: '#/components/parameters/ConversationIdParam'
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/CreateMessageRequest'
 *     responses:
 *       201:
 *         description: Message sent successfully
 */
router.post(
    "/:conversation_id/messages",
    validateParams(messageValidation.conversationParams),
    validate(messageValidation.createMessage),
    createMessage
);

/**
 * @swagger
 * /conversations/{conversation_id}/messages:
 *   get:
 *     summary: Get messages from a conversation
 *     tags: [Messages]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - $ref: '#/components/parameters/ConversationIdParam'
 *       - $ref: '#/components/parameters/PageParam'
 *       - $ref: '#/components/parameters/LimitParam'
 *     responses:
 *       200:
 *         description: Messages retrieved successfully
 */
router.get(
    "/:conversation_id/messages",
    validateParams(messageValidation.conversationParams),
    validateQuery(messageValidation.queryParams),
    getMessages
);

/**
 * @swagger
 * /conversations/{conversation_id}/unread-count:
 *   get:
 *     summary: Get unread message count
 *     tags: [Messages]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - $ref: '#/components/parameters/ConversationIdParam'
 *     responses:
 *       200:
 *         description: Unread count retrieved successfully
 */
router.get(
    "/:conversation_id/unread-count",
    validateParams(messageValidation.conversationParams),
    getUnreadCount
);

/**
 * @swagger
 * /conversations/{conversation_id}/mark-all-read:
 *   post:
 *     summary: Mark all messages in conversation as read
 *     tags: [Messages]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - $ref: '#/components/parameters/ConversationIdParam'
 *     responses:
 *       200:
 *         description: All messages marked as read successfully
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/SuccessResponse'
 *             examples:
 *               success:
 *                 value:
 *                   success: true
 *                   msg: "All messages marked as read"
 *                   data:
 *                     marked_count: 5
 *                     unread_count: 0
 *                     has_unread_messages: false
 *                     conversation:
 *                       id: "123e4567-e89b-12d3-a456-426614174000"
 *                       user1_id: "123e4567-e89b-12d3-a456-426614174000"
 *                       user2_id: "123e4567-e89b-12d3-a456-426614174001"
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 *       404:
 *         $ref: '#/components/responses/NotFoundError'
 */
router.post(
    "/:conversation_id/mark-all-read",
    validateParams(messageValidation.conversationParams),
    markAllAsRead
);

/**
 * @swagger
 * /conversations/{conversation_id}/messages/{message_id}:
 *   get:
 *     summary: Get a specific message
 *     tags: [Messages]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - $ref: '#/components/parameters/ConversationIdParam'
 *       - name: message_id
 *         in: path
 *         required: true
 *         schema:
 *           type: string
 *           format: uuid
 *     responses:
 *       200:
 *         description: Message retrieved successfully
 */
router.get(
    "/:conversation_id/messages/:message_id",
    validateParams(messageValidation.messageParamsWithConversation),
    getMessage
);

/**
 * @swagger
 * /conversations/{conversation_id}/messages/{message_id}:
 *   put:
 *     summary: Update a message
 *     tags: [Messages]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - $ref: '#/components/parameters/ConversationIdParam'
 *       - name: message_id
 *         in: path
 *         required: true
 *         schema:
 *           type: string
 *           format: uuid
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/UpdateMessageRequest'
 *     responses:
 *       200:
 *         description: Message updated successfully
 */
router.put(
    "/:conversation_id/messages/:message_id",
    validateParams(messageValidation.messageParamsWithConversation),
    validate(messageValidation.updateMessage),
    updateMessage
);

/**
 * @swagger
 * /conversations/{conversation_id}/messages/{message_id}:
 *   delete:
 *     summary: Delete a message
 *     tags: [Messages]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - $ref: '#/components/parameters/ConversationIdParam'
 *       - name: message_id
 *         in: path
 *         required: true
 *         schema:
 *           type: string
 *           format: uuid
 *     responses:
 *       200:
 *         description: Message deleted successfully
 */
router.delete(
    "/:conversation_id/messages/:message_id",
    validateParams(messageValidation.messageParamsWithConversation),
    deleteMessage
);

/**
 * @swagger
 * /conversations/{conversation_id}/messages/{message_id}/read:
 *   post:
 *     summary: Mark a message as read
 *     tags: [Messages]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - $ref: '#/components/parameters/ConversationIdParam'
 *       - name: message_id
 *         in: path
 *         required: true
 *         schema:
 *           type: string
 *           format: uuid
 *     responses:
 *       200:
 *         description: Message marked as read
 */
router.post(
    "/:conversation_id/messages/:message_id/read",
    validateParams(messageValidation.messageParamsWithConversation),
    markAsRead
);

export default router;

```

## File: routes/oauth.js
```js
import express from "express";
import {
    githubAuth,
    githubCallback,
    getOAuthProviders,
    getOAuthHealth,
    getOAuthStatus,
} from "../controllers/oauthController.js";

const router = express.Router();

/**
 * @swagger
 * tags:
 *   name: OAuth
 *   description: OAuth authentication endpoints
 */

/**
 * @swagger
 * /auth/oauth/providers:
 *   get:
 *     summary: Get available OAuth providers
 *     tags: [OAuth]
 *     responses:
 *       200:
 *         description: OAuth providers retrieved successfully
 */
router.get("/providers", getOAuthProviders);

/**
 * @swagger
 * /auth/oauth/health:
 *   get:
 *     summary: Check OAuth configuration health
 *     tags: [OAuth]
 *     responses:
 *       200:
 *         description: OAuth health status
 */
router.get("/health", getOAuthHealth);

/**
 * @swagger
 * /auth/oauth/status:
 *   get:
 *     summary: Check if OAuth is enabled
 *     tags: [OAuth]
 *     responses:
 *       200:
 *         description: OAuth status
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 msg:
 *                   type: string
 *                 data:
 *                   type: object
 *                   properties:
 *                     enabled:
 *                       type: boolean
 *                     timestamp:
 *                       type: string
 */
router.get("/status", getOAuthStatus);

// GitHub OAuth routes
router.get("/github", githubAuth);
router.get("/github/callback", githubCallback);

export default router;

```

## File: routes/profile.js
```js
import express from "express";
import { updateProfile, getProfile } from "../controllers/profileController.js";
import { authenticateToken } from "../middlewares/auth.js";
import { validate } from "../middlewares/validation.js";
import { profileValidation } from "../utils/validationSchemas.js";
import { upload } from "../middlewares/upload.js";

const router = express.Router();

/**
 * @swagger
 * tags:
 *   name: Profile
 *   description: User profile management endpoints
 */

/**
 * @swagger
 * /profile/me:
 *   get:
 *     summary: Get current user profile
 *     tags: [Profile]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Profile retrieved successfully
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/SuccessResponse'
 */
router.get("/me", authenticateToken, getProfile);

/**
 * @swagger
 * /profile/update:
 *   put:
 *     summary: Update user profile
 *     tags: [Profile]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         multipart/form-data:
 *           schema:
 *             $ref: '#/components/schemas/UpdateProfileRequest'
 *     responses:
 *       200:
 *         description: Profile updated successfully
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/SuccessResponse'
 */
router.put(
    "/update",
    authenticateToken,
    upload.single("avatar_file"),
    updateProfile
);

export default router;

```

## File: routes/upload.js
```js
import express from "express";
import {
    uploadFile,
    uploadImage,
    cloudinaryHealth,
} from "../controllers/uploadController.js";
import { authenticateToken } from "../middlewares/auth.js";
import { upload } from "../middlewares/upload.js";

const router = express.Router();

router.use(authenticateToken);

/**
 * @swagger
 * tags:
 *   name: Upload
 *   description: File upload endpoints
 */

/**
 * @swagger
 * /upload/health:
 *   get:
 *     summary: Check Cloudinary health status
 *     tags: [Upload]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Cloudinary is healthy
 *       503:
 *         description: Cloudinary is not responding
 */
router.get("/health", cloudinaryHealth);

// ... rest of your existing routes ...

/**
 * @swagger
 * /upload/file:
 *   post:
 *     summary: Upload any file type
 *     tags: [Upload]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         multipart/form-data:
 *           schema:
 *             type: object
 *             properties:
 *               file:
 *                 type: string
 *                 format: binary
 *               type:
 *                 type: string
 *                 enum: [message, profile]
 *                 default: message
 *     responses:
 *       200:
 *         description: File uploaded successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 msg:
 *                   type: string
 *                 data:
 *                   type: object
 *                   properties:
 *                     url:
 *                       type: string
 *                     public_id:
 *                       type: string
 *                     resource_type:
 *                       type: string
 *                     file_extension:
 *                       type: string
 *                     original_name:
 *                       type: string
 *                     bytes:
 *                       type: integer
 */
router.post("/file", upload.single("file"), uploadFile);

/**
 * @swagger
 * /upload/image:
 *   post:
 *     summary: Upload an image (backward compatibility)
 *     tags: [Upload]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         multipart/form-data:
 *           schema:
 *             type: object
 *             properties:
 *               image:
 *                 type: string
 *                 format: binary
 *               type:
 *                 type: string
 *                 enum: [message, profile]
 *                 default: message
 *     responses:
 *       200:
 *         description: Image uploaded successfully
 */
router.post("/image", upload.single("image"), uploadImage);

export default router;

```

## File: routes/user.js
```js
import express from "express";
import {
    searchUsers,
    getAllUsers,
    getUserById,
    updateOnlineStatus,
} from "../controllers/userController.js";
import { authenticateToken } from "../middlewares/auth.js";
import {
    validate,
    validateQuery,
    validateParams,
} from "../middlewares/validation.js";
import { userValidation } from "../utils/validationSchemas.js";

const router = express.Router();

router.use(authenticateToken);

/**
 * @swagger
 * tags:
 *   name: Users
 *   description: User management and search endpoints
 */

/**
 * @swagger
 * /users/search:
 *   get:
 *     summary: Search for users
 *     tags: [Users]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - name: q
 *         in: query
 *         required: true
 *         schema:
 *           type: string
 *           minLength: 2
 *         description: Search query (searches in full name and email)
 *         example: "john"
 *       - name: limit
 *         in: query
 *         schema:
 *           type: integer
 *           minimum: 1
 *           maximum: 50
 *           default: 10
 *         description: Maximum number of results
 *     responses:
 *       200:
 *         description: Users found successfully
 *       400:
 *         $ref: '#/components/responses/ValidationError'
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 */
router.get("/search", validateQuery(userValidation.searchQuery), searchUsers);

/**
 * @swagger
 * /users:
 *   get:
 *     summary: Get all users (excluding current user)
 *     tags: [Users]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - name: limit
 *         in: query
 *         schema:
 *           type: integer
 *           minimum: 1
 *           maximum: 100
 *           default: 50
 *     responses:
 *       200:
 *         description: Users retrieved successfully
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 */
router.get("/", validateQuery(userValidation.getAllUsers), getAllUsers);

/**
 * @swagger
 * /users/{id}:
 *   get:
 *     summary: Get user by ID
 *     tags: [Users]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - name: id
 *         in: path
 *         required: true
 *         schema:
 *           type: string
 *           format: uuid
 *     responses:
 *       200:
 *         description: User retrieved successfully
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 *       404:
 *         $ref: '#/components/responses/NotFoundError'
 */
router.get("/:id", validateParams(userValidation.userIdParams), getUserById);

/**
 * @swagger
 * /users/online-status:
 *   put:
 *     summary: Update user online status
 *     tags: [Users]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - is_online
 *             properties:
 *               is_online:
 *                 type: boolean
 *                 description: Online status
 *                 example: true
 *     responses:
 *       200:
 *         description: Online status updated successfully
 *       400:
 *         $ref: '#/components/responses/ValidationError'
 *       401:
 *         $ref: '#/components/responses/UnauthorizedError'
 *       404:
 *         $ref: '#/components/responses/NotFoundError'
 */
router.put(
    "/online-status",
    validate(userValidation.updateOnlineStatus),
    updateOnlineStatus
);

export default router;

```

## File: server.js
```js
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

```

## File: services/authService.js
```js
import bcrypt from "bcryptjs";
import { userRepository } from "../repositories/userRepository.js";
import { tokenService } from "./tokenService.js";

const saltRounds = parseInt(process.env.ROUNDS) || 12;

export const signupService = async (userData) => {
    const { email, full_name, password } = userData;

    const existingUser = await userRepository.findByEmail(email);
    if (existingUser) {
        throw new Error("USER_ALREADY_EXISTS");
    }

    const password_hash = await bcrypt.hash(password, saltRounds);

    const user = await userRepository.create({
        email,
        full_name,
        password_hash,
    });

    const { accessToken, refreshToken } = await tokenService.generateAuthTokens(
        user.id
    );

    return {
        user: {
            id: user.id,
            email: user.email,
            full_name: user.full_name,
        },
        accessToken,
        refreshToken,
    };
};

export const loginService = async (credentials) => {
    const { email, password } = credentials;

    const user = await userRepository.findByEmail(email);
    if (!user) {
        throw new Error("INVALID_CREDENTIALS");
    }

    const isPasswordValid = await bcrypt.compare(password, user.password_hash);
    if (!isPasswordValid) {
        throw new Error("INVALID_CREDENTIALS");
    }

    const { accessToken, refreshToken } = await tokenService.generateAuthTokens(
        user.id
    );

    return {
        user: {
            id: user.id,
            email: user.email,
            full_name: user.full_name,
        },
        accessToken,
        refreshToken,
    };
};

export const refreshTokenService = async (token) => {
    const result = await tokenService.refreshAccessToken(token);
    return result;
};

export const logoutService = async (token) => {
    const result = await tokenService.revokeToken(token);
    return result;
};

export const logoutAllDevicesService = async (userId) => {
    const result = await tokenService.revokeAllUserTokens(userId);
    return result;
};

```

## File: services/connectionService.js
```js
import { getIO } from "../config/socket.js";
import { SocketEvents } from "../config/constants.js";

// Store multiple connections per user
const userConnections = new Map(); // userId -> Set of socketIds
const socketToUser = new Map(); // socketId -> userId

export const connectionService = {
    // Add a connection for a user
    addConnection(userId, socketId, user) {
        if (!userConnections.has(userId)) {
            userConnections.set(userId, new Set());
        }

        userConnections.get(userId).add(socketId);
        socketToUser.set(socketId, userId);

        console.log(
            `User ${userId} connected with socket ${socketId}. Total connections: ${
                userConnections.get(userId).size
            }`
        );

        return {
            isFirstConnection: userConnections.get(userId).size === 1,
            connectionCount: userConnections.get(userId).size,
        };
    },

    // Remove a connection
    removeConnection(socketId) {
        const userId = socketToUser.get(socketId);

        if (!userId) {
            return { userId: null, isLastConnection: false };
        }

        const connections = userConnections.get(userId);
        if (connections) {
            connections.delete(socketId);

            const isLastConnection = connections.size === 0;

            if (isLastConnection) {
                userConnections.delete(userId);
            }

            console.log(
                `User ${userId} disconnected socket ${socketId}. Remaining connections: ${connections.size}`
            );

            socketToUser.delete(socketId);

            return {
                userId,
                isLastConnection,
                connectionCount: connections.size,
            };
        }

        socketToUser.delete(socketId);
        return { userId, isLastConnection: true, connectionCount: 0 };
    },

    // Check if user is online (has at least one connection)
    isUserOnline(userId) {
        const connections = userConnections.get(userId);
        return connections && connections.size > 0;
    },

    // Get all socket IDs for a user
    getUserSockets(userId) {
        const connections = userConnections.get(userId);
        return connections ? Array.from(connections) : [];
    },

    // Get socket instance for a user (returns first available)
    getUserSocket(userId) {
        const socketIds = this.getUserSockets(userId);
        if (socketIds.length === 0) return null;

        const io = getIO();
        return io.sockets.sockets.get(socketIds[0]);
    },

    // Get all socket instances for a user
    getAllUserSockets(userId) {
        const socketIds = this.getUserSockets(userId);
        const io = getIO();

        return socketIds
            .map((id) => io.sockets.sockets.get(id))
            .filter((socket) => socket !== undefined);
    },

    // Send event to all user's connections
    sendToUser(userId, event, data) {
        const sockets = this.getAllUserSockets(userId);
        sockets.forEach((socket) => socket.emit(event, data));
        return sockets.length > 0;
    },

    // Send event to a specific conversation
    sendToConversation(conversationId, event, data, excludeSocketId = null) {
        const io = getIO();
        const room = `conversation:${conversationId}`;

        if (excludeSocketId) {
            io.to(room).except(excludeSocketId).emit(event, data);
        } else {
            io.to(room).emit(event, data);
        }
    },

    // Get all online users
    getOnlineUsers() {
        return Array.from(userConnections.keys());
    },

    // Get connection info for a user
    getUserConnectionInfo(userId) {
        const connections = userConnections.get(userId);
        if (!connections) return null;

        return {
            userId,
            connectionCount: connections.size,
            isOnline: connections.size > 0,
            socketIds: Array.from(connections),
        };
    },

    // Get total connection count
    getTotalConnections() {
        let total = 0;
        userConnections.forEach((connections) => {
            total += connections.size;
        });
        return total;
    },

    // Get user ID from socket ID
    getUserIdFromSocket(socketId) {
        return socketToUser.get(socketId);
    },

    // Clear all connections (for cleanup/restart)
    clearAllConnections() {
        userConnections.clear();
        socketToUser.clear();
    },
};

```

## File: services/conversationService.js
```js
import { conversationRepository } from "../repositories/conversationRepository.js";
import { userRepository } from "../repositories/userRepository.js";

export const createConversationService = async (user1_id, user2_id) => {
    const [sortedUser1, sortedUser2] = [user1_id, user2_id].sort();

    const existingConversation =
        await conversationRepository.findByParticipants(
            sortedUser1,
            sortedUser2
        );
    if (existingConversation) {
        throw new Error("CONVERSATION_ALREADY_EXISTS");
    }

    const users = await userRepository.findByIds([sortedUser1, sortedUser2]);
    if (users.length !== 2) {
        throw new Error("USER_NOT_FOUND");
    }

    const conversation = await conversationRepository.create({
        user1_id: sortedUser1,
        user2_id: sortedUser2,
    });

    return conversation;
};

export const getUserConversationsService = async (user_id) => {
    const conversations = await conversationRepository.findByUserId(user_id);

    // Transform the response to include unread_count and has_unread_messages
    const transformedConversations = conversations.map((conversation) => {
        const unread_count = conversation._count?.messages || 0;

        return {
            ...conversation,
            unread_count: unread_count,
            has_unread_messages: unread_count > 0,
            // Remove the _count field from the response
            _count: undefined,
        };
    });

    return transformedConversations;
};

export const getConversationService = async (conversation_id, user_id) => {
    const conversation = await conversationRepository.findByIdWithAccess(
        conversation_id,
        user_id
    );
    if (!conversation) {
        throw new Error("CONVERSATION_NOT_FOUND");
    }
    return conversation;
};

export const getConversationParticipantsService = async (
    conversation_id,
    user_id
) => {
    const conversation = await conversationRepository.findByIdWithAccess(
        conversation_id,
        user_id
    );
    if (!conversation) {
        throw new Error("CONVERSATION_NOT_FOUND");
    }

    return {
        participants: [conversation.user1, conversation.user2],
    };
};

export const deleteConversationService = async (conversation_id, user_id) => {
    const conversation = await conversationRepository.findByIdWithAccess(
        conversation_id,
        user_id
    );
    if (!conversation) {
        throw new Error("CONVERSATION_NOT_FOUND");
    }

    await conversationRepository.delete(conversation_id);
    return { success: true, message: "Conversation deleted successfully" };
};

export const checkConversationService = async (user1_id, user2_id) => {
    const [sortedUser1, sortedUser2] = [user1_id, user2_id].sort();

    const conversation = await conversationRepository.findByParticipants(
        sortedUser1,
        sortedUser2
    );

    return conversation;
};

```

## File: services/fileStorageService.js
```js
import cloudinary, {
    resetCloudinary,
    isCloudinaryConfigured,
} from "../config/cloudinary.js";

// Track upload attempts for retry logic
const MAX_RETRIES = 2;
const RETRY_DELAY = 1000; // 1 second

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export const uploadFileService = async (
    fileBuffer,
    originalName,
    folder = "files",
    retryCount = 0
) => {
    // Check if Cloudinary is configured
    if (!isCloudinaryConfigured()) {
        console.log("Cloudinary not configured, attempting reset...");
        await resetCloudinary();
    }

    return new Promise((resolve, reject) => {
        // Determine resource type based on file extension
        const extension = originalName.split(".").pop().toLowerCase();
        const imageExtensions = [
            "jpg",
            "jpeg",
            "png",
            "gif",
            "webp",
            "bmp",
            "svg",
        ];

        let resourceType = "raw";
        let transformation = [];

        if (imageExtensions.includes(extension)) {
            resourceType = "image";
            transformation = [
                { width: 800, height: 800, crop: "limit" },
                { quality: "auto" },
            ];
        }

        const uploadOptions = {
            folder: folder,
            resource_type: resourceType,
            allowed_formats: null,
            transformation: transformation,
            timeout: 30000,
        };

        console.log(
            `Upload attempt ${
                retryCount + 1
            }: ${originalName}, type: ${resourceType}, folder: ${folder}, size: ${
                fileBuffer.length
            } bytes`
        );

        const uploadStream = cloudinary.uploader.upload_stream(
            uploadOptions,
            async (error, result) => {
                if (error) {
                    console.error(
                        `Cloudinary upload error (attempt ${retryCount + 1}):`,
                        error
                    );

                    // Retry logic for timeout errors
                    if (
                        (error.name === "TimeoutError" ||
                            error.http_code === 499) &&
                        retryCount < MAX_RETRIES
                    ) {
                        console.log(
                            `Retrying upload (${
                                retryCount + 1
                            }/${MAX_RETRIES})...`
                        );
                        await delay(RETRY_DELAY * (retryCount + 1));
                        try {
                            const retryResult = await uploadFileService(
                                fileBuffer,
                                originalName,
                                folder,
                                retryCount + 1
                            );
                            resolve(retryResult);
                        } catch (retryError) {
                            reject(retryError);
                        }
                        return;
                    }

                    if (
                        error.message.includes("File size too large") ||
                        error.http_code === 413
                    ) {
                        reject(new Error("FILE_TOO_LARGE"));
                    } else if (
                        error.message.includes("Invalid file") ||
                        error.http_code === 422
                    ) {
                        reject(new Error("INVALID_FILE_FORMAT"));
                    } else if (
                        error.name === "TimeoutError" ||
                        error.http_code === 499
                    ) {
                        reject(new Error("UPLOAD_TIMEOUT"));
                    } else if (error.http_code === 401) {
                        reject(new Error("CLOUDINARY_AUTH_ERROR"));
                    } else {
                        reject(new Error("UPLOAD_FAILED"));
                    }
                } else {
                    console.log(
                        `Cloudinary upload successful (attempt ${
                            retryCount + 1
                        }): ${result.public_id}`
                    );
                    resolve({
                        ...result,
                        resource_type: resourceType,
                        file_extension: extension,
                        original_name: originalName,
                    });
                }
            }
        );

        // Handle stream errors
        uploadStream.on("error", async (error) => {
            console.error(
                `Cloudinary stream error (attempt ${retryCount + 1}):`,
                error
            );

            if (retryCount < MAX_RETRIES) {
                console.log(
                    `Retrying upload due to stream error (${
                        retryCount + 1
                    }/${MAX_RETRIES})...`
                );
                await delay(RETRY_DELAY * (retryCount + 1));
                try {
                    const retryResult = await uploadFileService(
                        fileBuffer,
                        originalName,
                        folder,
                        retryCount + 1
                    );
                    resolve(retryResult);
                } catch (retryError) {
                    reject(retryError);
                }
            } else {
                reject(new Error("UPLOAD_STREAM_ERROR"));
            }
        });

        // Write the buffer to the stream
        try {
            uploadStream.end(fileBuffer);
        } catch (streamError) {
            console.error("Stream write error:", streamError);
            reject(new Error("STREAM_WRITE_ERROR"));
        }
    });
};

export const deleteFileService = async (publicId, resourceType = "image") => {
    try {
        const result = await cloudinary.uploader.destroy(publicId, {
            resource_type: resourceType,
            timeout: 15000,
        });

        if (result.result !== "ok") {
            throw new Error("DELETE_FAILED");
        }

        return result;
    } catch (error) {
        console.error("Cloudinary delete error:", error);
        throw new Error("DELETE_FAILED");
    }
};

// Keep the old function for backward compatibility
export const uploadImageService = async (fileBuffer, folder = "profiles") => {
    return uploadFileService(fileBuffer, `image_${Date.now()}.jpg`, folder);
};

// Add back the deleteImageService for backward compatibility
export const deleteImageService = async (publicId) => {
    return deleteFileService(publicId, "image");
};

```

## File: services/messageService.js
```js
import { messageRepository } from "../repositories/messageRepository.js";
import { readReceiptRepository } from "../repositories/readReceiptRepository.js";
import { conversationRepository } from "../repositories/conversationRepository.js";
import { connectedUsers } from "../config/socket.js";
import { sendToUser } from "./socketService.js";

export const createMessageService = async (messageData) => {
    const {
        conversation_id,
        sender_id,
        message_type,
        message_text,
        file_url,
        file_name,
        file_size,
        file_type,
    } = messageData;

    const conversation = await conversationRepository.findByIdWithAccess(
        conversation_id,
        sender_id
    );
    if (!conversation) {
        throw new Error("CONVERSATION_NOT_FOUND_OR_ACCESS_DENIED");
    }

    // Validate message content based on type
    if (message_type === "TEXT") {
        if (!message_text || message_text.trim() === "") {
            throw new Error("MESSAGE_TEXT_REQUIRED");
        }
        if (file_url) {
            throw new Error("TEXT_MESSAGES_CANNOT_HAVE_FILE_URL");
        }
    } else if (message_type === "IMAGE") {
        if (!file_url) {
            throw new Error("FILE_URL_REQUIRED");
        }
    } else {
        throw new Error("INVALID_MESSAGE_TYPE");
    }

    const message = await messageRepository.create({
        conversation_id,
        sender_id,
        message_type: message_type || "TEXT",
        message_text: message_text?.trim(),
        file_url,
        file_name,
        file_size,
        file_type,
        is_delivered: false, // Will be updated in real-time if recipient is online
    });

    // Check if recipient is online and update delivery status immediately
    const otherUserId =
        conversation.user1_id === sender_id
            ? conversation.user2_id
            : conversation.user1_id;
    const isRecipientOnline = connectedUsers.has(otherUserId);

    if (isRecipientOnline) {
        // Mark as delivered immediately
        await messageRepository.markAsDelivered(conversation_id, otherUserId);

        // Update the message object to reflect delivery status
        message.is_delivered = true;
        message.delivered_at = new Date();
    }

    return message;
};

export const getMessagesService = async (conversation_id, user_id, page = 1, limit = 50) => {
    const conversation = await conversationRepository.findByIdWithAccess(
        conversation_id,
        user_id
    );
    if (!conversation) {
        throw new Error("CONVERSATION_NOT_FOUND_OR_ACCESS_DENIED");
    }

    const skip = (page - 1) * limit;
    const messages = await messageRepository.findByConversation(
        conversation_id,
        skip,
        limit
    );

    return messages;
};

export const getMessageService = async (message_id, user_id) => {
    const message = await messageRepository.findByIdWithAccess(message_id, user_id);
    if (!message) {
        throw new Error("MESSAGE_NOT_FOUND");
    }
    return message;
};

export const updateMessageService = async (message_id, user_id, updateData) => {
    const message = await messageRepository.findByIdWithAccess(message_id, user_id);
    
    if (!message) {
        throw new Error("MESSAGE_NOT_FOUND");
    }

    if (message.sender_id !== user_id) {
        throw new Error("MESSAGE_NOT_FOUND_OR_NOT_EDITABLE");
    }

    if (message.message_type !== "TEXT") {
        throw new Error("ONLY_TEXT_MESSAGES_CAN_BE_EDITED");
    }

    // Check if message is within edit timeout (5 minutes)
    const editTimeout = 5 * 60 * 1000;
    if (Date.now() - new Date(message.created_at).getTime() > editTimeout) {
        throw new Error("MESSAGE_EDIT_TIMEOUT");
    }

    const updatedMessage = await messageRepository.update(message_id, {
        message_text: updateData.message_text,
    });

    return updatedMessage;
};

export const deleteMessageService = async (message_id, user_id) => {
    const message = await messageRepository.findByIdWithAccess(message_id, user_id);
    
    if (!message) {
        throw new Error("MESSAGE_NOT_FOUND");
    }

    if (message.sender_id !== user_id) {
        throw new Error("MESSAGE_NOT_FOUND_OR_NOT_DELETABLE");
    }

    await messageRepository.delete(message_id);
    return message;
};

export const markAsReadService = async (message_id, reader_id) => {
    const message = await messageRepository.findByIdWithAccess(message_id, reader_id);
    
    if (!message) {
        throw new Error("MESSAGE_NOT_FOUND");
    }

    if (message.sender_id === reader_id) {
        throw new Error("CANNOT_MARK_OWN_MESSAGE_READ");
    }

    const readReceipt = await readReceiptRepository.upsert({
        message_id,
        reader_id,
        read_at: new Date(),
    });

    return { ...readReceipt, message };
};

export const getUnreadCountService = async (conversation_id, user_id) => {
    const conversation = await conversationRepository.findByIdWithAccess(
        conversation_id,
        user_id
    );
    if (!conversation) {
        throw new Error("CONVERSATION_NOT_FOUND");
    }

    const unread_count = await messageRepository.countUnread(conversation_id, user_id);
    return { unread_count };
};

export const markAllAsReadService = async (conversation_id, user_id) => {
    const conversation = await conversationRepository.findByIdWithAccess(
        conversation_id,
        user_id
    );
    if (!conversation) {
        throw new Error("CONVERSATION_NOT_FOUND");
    }

    const result = await messageRepository.markAllAsRead(conversation_id, user_id);
    const unread_count = await messageRepository.getUnreadCountAfterMark(conversation_id, user_id);

    return {
        marked_count: result.marked_count,
        unread_count,
        has_unread_messages: unread_count > 0,
        conversation,
    };
};
```

## File: services/oauthService.js
```js
import { handleGitHubUser } from "../utils/oauthHelpers.js";
import { oauthValidators } from "../utils/oauthValidators.js";

export const oauthService = {
    // Process GitHub OAuth callback
    processGitHubCallback: async (profile) => {
        try {
            // Validate the GitHub profile before processing
            oauthValidators.validateGitHubProfile(profile);

            const result = await handleGitHubUser(profile);
            return result;
        } catch (error) {
            console.error("OAuth service error:", error);
            throw error;
        }
    },

    // Validate OAuth configuration (delegates to validator)
    validateOAuthConfig: () => {
        return oauthValidators.validateOAuthConfig();
    },

    // Validate callback parameters
    validateCallbackParams: (req) => {
        return oauthValidators.validateCallbackParams(req);
    },

    // Check if OAuth is enabled
    isOAuthEnabled: () => {
        return oauthValidators.isOAuthEnabled();
    },

    // Get OAuth configuration for frontend
    getOAuthConfig: () => {
        const config = oauthValidators.validateOAuthConfig();

        return {
            providers: {
                github: config.github.enabled
                    ? {
                          name: "GitHub",
                          url: "/api/auth/github",
                          enabled: true,
                      }
                    : null,
            },
            client: {
                url: config.client.url,
                successRedirect: config.client.successRedirect,
                errorRedirect: config.client.errorRedirect,
            },
        };
    },
};

```

## File: services/profileService.js
```js
import bcrypt from "bcryptjs";
import { userRepository } from "../repositories/userRepository.js";
import { uploadFileService, deleteFileService } from "./fileStorageService.js";
import { extractPublicId } from "../utils/cloudinaryUtils.js";

const saltRounds = parseInt(process.env.ROUNDS) || 12;

export const updateProfileService = async (userId, updateData) => {
    const { full_name, avatar_file, currentPassword, newPassword } = updateData;

    const user = await userRepository.findById(userId);
    if (!user) {
        throw new Error("USER_NOT_FOUND");
    }

    const updateFields = {};

    if (full_name) updateFields.full_name = full_name;

    let newAvatarUrl = null;
    if (avatar_file) {
        // Validate file type
        if (!avatar_file.mimetype.startsWith("image/")) {
            throw new Error("INVALID_IMAGE_FORMAT");
        }

        // Validate file size (5MB limit)
        if (avatar_file.size > 5 * 1024 * 1024) {
            throw new Error("IMAGE_TOO_LARGE");
        }

        try {
            const uploadResult = await uploadFileService(
                avatar_file.buffer,
                avatar_file.originalname,
                "profiles"
            );
            newAvatarUrl = uploadResult.secure_url;
            updateFields.avatar_url = newAvatarUrl;

            // Delete old avatar if exists
            if (user.avatar_url) {
                const oldPublicId = extractPublicId(user.avatar_url);
                if (oldPublicId) {
                    try {
                        await deleteFileService(oldPublicId, "image");
                    } catch (error) {
                        console.log(
                            "Failed to delete old image:",
                            error.message
                        );
                        // Don't throw error, continue with update
                    }
                }
            }
        } catch (error) {
            throw error;
        }
    }

    if (newPassword) {
        if (!currentPassword) {
            throw new Error("CURRENT_PASSWORD_REQUIRED");
        }

        const isCurrentPasswordValid = await bcrypt.compare(
            currentPassword,
            user.password_hash
        );
        if (!isCurrentPasswordValid) {
            throw new Error("INVALID_CURRENT_PASSWORD");
        }

        updateFields.password_hash = await bcrypt.hash(newPassword, saltRounds);
    }

    const updatedUser = await userRepository.update(userId, updateFields);
    return updatedUser;
};

export const getProfileService = async (userId) => {
    const user = await userRepository.findById(userId);
    if (!user) {
        throw new Error("USER_NOT_FOUND");
    }
    return user;
};

```

## File: services/socketService.js
```js
import { connectedUsers, getIO } from "../config/socket.js";
import { updateOnlineStatusService } from "./userService.js";

export const updateUserOnlineStatus = async (userId, isOnline) => {
    try {
        await updateOnlineStatusService(userId, isOnline);
    } catch (error) {
        console.error("Error updating user online status:", error);
    }
};

export const handleUserDisconnect = (socket) => {
    // Only remove user if this is their current socket
    const currentConnection = connectedUsers.get(socket.userId);
    if (currentConnection && currentConnection.socketId === socket.id) {
        // Remove user from connected users
        connectedUsers.delete(socket.userId);

        // Update user online status
        updateUserOnlineStatus(socket.userId, false);

        // Notify others that user went offline
        socket.broadcast.emit("user_offline", {
            user_id: socket.userId,
            timestamp: new Date().toISOString(),
        });

        console.log(
            `User ${socket.userId} fully disconnected and marked offline`
        );
    } else {
        console.log(
            `User ${socket.userId} disconnected old socket ${socket.id}, keeping new connection active`
        );
    }
};

export const getUserSocket = (userId) => {
    const userConnection = connectedUsers.get(userId);
    return userConnection
        ? getIO().sockets.sockets.get(userConnection.socketId)
        : null;
};

export const sendToUser = (userId, event, data) => {
    const userSocket = getUserSocket(userId);
    if (userSocket) {
        userSocket.emit(event, data);
        return true;
    }
    return false;
};

export const sendToConversation = (
    conversationId,
    event,
    data,
    excludeSender = null
) => {
    const io = getIO();
    if (excludeSender) {
        io.to(`conversation:${conversationId}`)
            .except(excludeSender)
            .emit(event, data);
    } else {
        io.to(`conversation:${conversationId}`).emit(event, data);
    }
};

export const getConnectedUsers = () => {
    return Array.from(connectedUsers.values()).map((conn) => conn.user);
};

export const isUserConnected = (userId) => {
    return connectedUsers.has(userId);
};

export const getUserConnectionInfo = (userId) => {
    return connectedUsers.get(userId);
};

// Send offline notifications when user comes online
export const sendPendingNotifications = async (userId) => {
    try {
        const { conversationRepository } = await import(
            "../repositories/conversationRepository.js"
        );
        const conversations = await conversationRepository.findByUserId(userId);

        const userSocket = getUserSocket(userId);
        if (userSocket && conversations.length > 0) {
            userSocket.emit("pending_conversations", {
                conversations,
                timestamp: new Date().toISOString(),
            });
        }
    } catch (error) {
        console.error("Error sending pending notifications:", error);
    }
};

// Check and send delivery status for pending messages
export const checkPendingDeliveries = async (userId) => {
    try {
        const { messageRepository } = await import(
            "../repositories/messageRepository.js"
        );
        const { conversationRepository } = await import(
            "../repositories/conversationRepository.js"
        );

        // Get all conversations for the user
        const conversations = await conversationRepository.findByUserId(userId);

        for (const conversation of conversations) {
            // Mark all undelivered messages as delivered
            const updatedCount = await messageRepository.markAsDelivered(
                conversation.id,
                userId
            );

            if (updatedCount > 0) {
                // Notify senders that their messages were delivered
                const undeliveredMessages =
                    await messageRepository.findByConversation(
                        conversation.id,
                        0,
                        100
                    );
                const deliveredMessages = undeliveredMessages.filter(
                    (msg) => msg.sender_id !== userId && !msg.is_delivered
                );

                for (const message of deliveredMessages) {
                    const senderSocket = getUserSocket(message.sender_id);
                    if (senderSocket) {
                        senderSocket.emit("message_delivered", {
                            message_id: message.id,
                            conversation_id: conversation.id,
                            delivered_at: new Date().toISOString(),
                        });
                    }
                }
            }
        }
    } catch (error) {
        console.error("Error checking pending deliveries:", error);
    }
};

```

## File: services/tokenService.js
```js
import { tokenRepository } from "../repositories/tokenRepository.js";
import {
    generateAccessToken,
    generateRefreshToken,
    verifyRefreshToken,
    verifyAccessToken,
} from "../utils/jwt.js";

export const tokenService = {
    generateAuthTokens: async (userId) => {
        const accessToken = generateAccessToken(userId);
        const refreshToken = generateRefreshToken(userId);

        await tokenRepository.storeRefreshToken(userId, refreshToken);

        return { accessToken, refreshToken };
    },

    refreshAccessToken: async (refreshToken) => {
        if (!refreshToken) {
            throw new Error("REFRESH_TOKEN_REQUIRED");
        }
        const decoded = verifyRefreshToken(refreshToken);
        const validity = await tokenRepository.verifyTokenValidity(
            refreshToken
        );
        if (!validity.valid) {
            throw new Error(validity.reason);
        }
        const accessToken = generateAccessToken(decoded.userId);

        return { accessToken };
    },

    revokeToken: async (token) => {
        if (token) {
            await tokenRepository.deleteRefreshToken(token);
        }
        return { success: true };
    },

    revokeAllUserTokens: async (userId) => {
        await tokenRepository.deleteAllUserRefreshTokens(userId);
        return { success: true, message: "All tokens revoked" };
    },

    validateAccessToken: (token) => {
        try {
            return verifyAccessToken(token);
        } catch (error) {
            console.error("Token validation error:", error.message);
            throw new Error("INVALID_ACCESS_TOKEN");
        }
    },

    getUserSessions: async (userId) => {
        const tokens = await tokenRepository.findUserRefreshTokens(userId);
        return tokens.map((token) => ({
            id: token.id,
            created_at: token.created_at,
            expires_at: token.expires_at,
            is_expired: new Date() > token.expires_at,
        }));
    },

    cleanupExpiredTokens: async () => {
        const result = await tokenRepository.cleanupExpiredTokens();
        return { deletedCount: result.count };
    },
};

```

## File: services/userService.js
```js
import { userRepository } from "../repositories/userRepository.js";

export const searchUsersService = async (query, currentUserId, limit = 10) => {
    if (!query || query.trim().length === 0) {
        throw new Error("SEARCH_QUERY_REQUIRED");
    }

    if (query.trim().length < 2) {
        throw new Error("SEARCH_QUERY_TOO_SHORT");
    }

    const users = await userRepository.searchUsers(
        query.trim(),
        currentUserId,
        limit
    );

    return users;
};

export const getAllUsersService = async (currentUserId, limit = 50) => {
    const users = await userRepository.findMany(currentUserId, limit);
    return users;
};

export const getUserByIdService = async (userId) => {
    const user = await userRepository.findById(userId);

    if (!user) {
        throw new Error("USER_NOT_FOUND");
    }

    // Return user without sensitive data
    const { password_hash, ...userWithoutPassword } = user;
    return userWithoutPassword;
};

export const updateOnlineStatusService = async (userId, isOnline) => {
    const user = await userRepository.findById(userId);
    if (!user) {
        throw new Error("USER_NOT_FOUND");
    }

    const updatedUser = await userRepository.updateOnlineStatus(
        userId,
        isOnline
    );

    return updatedUser;
};

```

## File: utils/cloudinaryUtils.js
```js
import cloudinary from "../config/cloudinary.js";

export const extractPublicId = (url) => {
    if (!url) return null;

    const matches = url.match(/\/upload\/.*\/([^/.]+)(?=\.[^.]*$)/);
    return matches ? matches[1] : null;
};

export const uploadToCloudinary = async (fileBuffer, folder = "profiles") => {
    return new Promise((resolve, reject) => {
        const uploadStream = cloudinary.uploader.upload_stream(
            {
                folder: folder,
                resource_type: "image",
            },
            (error, result) => {
                if (error) {
                    reject(new Error("UPLOAD_FAILED"));
                } else {
                    resolve(result);
                }
            }
        );

        uploadStream.end(fileBuffer);
    });
};

export const deleteFromCloudinary = async (publicId) => {
    try {
        const result = await cloudinary.uploader.destroy(publicId);
        return result;
    } catch (error) {
        throw new Error("DELETE_FAILED");
    }
};

```

## File: utils/errorHandler.js
```js
import {
    errorResponse,
    badRequestResponse,
    unauthorizedResponse,
    conflictResponse,
    notFoundResponse,
} from "./responseHandler.js";

export const handleAuthError = (res, error) => {
    const errorMap = {
        USER_ALREADY_EXISTS: () => conflictResponse(res, "User already exists"),
        INVALID_CREDENTIALS: () =>
            unauthorizedResponse(res, "Invalid email or password"),
    };

    const handler = errorMap[error.message];
    if (handler) {
        handler();
    } else {
        console.error("Auth error:", error);
        errorResponse(res, "Internal server error");
    }
};

export const handleProfileError = (res, error) => {
    const errorMap = {
        CURRENT_PASSWORD_REQUIRED: () =>
            badRequestResponse(
                res,
                "Current password is required to set new password"
            ),
        INVALID_CURRENT_PASSWORD: () =>
            unauthorizedResponse(res, "Current password is incorrect"),
        USER_NOT_FOUND: () => notFoundResponse(res, "User not found"),
        UPLOAD_FAILED: () => errorResponse(res, "Failed to upload image", 502),
        DELETE_FAILED: () => errorResponse(res, "Failed to delete image", 502),
        INVALID_IMAGE_FORMAT: () =>
            badRequestResponse(
                res,
                "Invalid image format. Supported formats: JPEG, PNG, WebP"
            ),
        IMAGE_TOO_LARGE: () =>
            badRequestResponse(res, "Image size too large. Maximum size: 5MB"),
    };

    const handler = errorMap[error.message];
    if (handler) {
        handler();
    } else {
        console.error("Profile error:", error);
        errorResponse(res, "Internal server error");
    }
};

export const handleCloudinaryError = (res, error) => {
    const errorMap = {
        UPLOAD_FAILED: () =>
            errorResponse(
                res,
                "Failed to upload image to cloud storage. Please try again.",
                502
            ),
        UPLOAD_TIMEOUT: () =>
            errorResponse(
                res,
                "Image upload timeout. The service may be temporarily unavailable. Please try again in a moment.",
                504
            ),
        UPLOAD_STREAM_ERROR: () =>
            errorResponse(
                res,
                "Upload connection error. Please try again.",
                502
            ),
        STREAM_WRITE_ERROR: () =>
            errorResponse(
                res,
                "Error processing file upload. Please try again.",
                500
            ),
        DELETE_FAILED: () =>
            errorResponse(
                res,
                "Failed to delete image from cloud storage",
                502
            ),
        INVALID_IMAGE_FORMAT: () =>
            badRequestResponse(
                res,
                "Invalid image format. Supported formats: JPEG, PNG, WebP, GIF, BMP"
            ),
        IMAGE_TOO_LARGE: () =>
            badRequestResponse(res, "Image size too large. Maximum size: 5MB"),
        FILE_TOO_LARGE: () =>
            badRequestResponse(res, "File size too large. Maximum size: 10MB"),
        CLOUDINARY_CONFIG_ERROR: () =>
            errorResponse(res, "Cloud storage configuration error", 503),
        CLOUDINARY_AUTH_ERROR: () =>
            errorResponse(res, "Cloud storage authentication error", 503),
        IMAGE_PROCESSING_ERROR: () =>
            errorResponse(res, "Error processing image", 500),
        FILE_URL_REQUIRED: () =>
            badRequestResponse(res, "File URL is required for file messages"),
        INVALID_MESSAGE_TYPE: () =>
            badRequestResponse(res, "Invalid message type"),
        TEXT_MESSAGES_CANNOT_HAVE_FILE_URL: () =>
            badRequestResponse(res, "Text messages cannot contain file URLs"),
    };

    const handler = errorMap[error.message];
    if (handler) {
        handler();
    } else {
        console.error("Cloudinary error:", error);
        errorResponse(
            res,
            "Image service temporarily unavailable. Please try again in a moment."
        );
    }
};

export const handleTokenError = (res, error) => {
    const errorMap = {
        REFRESH_TOKEN_REQUIRED: () =>
            badRequestResponse(res, "Refresh token required"),
        TOKEN_NOT_FOUND: () =>
            unauthorizedResponse(res, "Invalid refresh token"),
        TOKEN_EXPIRED: () => unauthorizedResponse(res, "Refresh token expired"),
        INVALID_ACCESS_TOKEN: () =>
            unauthorizedResponse(res, "Invalid access token"),
        INVALID_REFRESH_TOKEN: () =>
            unauthorizedResponse(res, "Invalid refresh token"),
        REFRESH_TOKEN_EXPIRED: () =>
            unauthorizedResponse(res, "Refresh token expired"),
    };

    const handler = errorMap[error.message];
    if (handler) {
        handler();
    } else {
        console.error("Token error:", error);
        errorResponse(res, "Token service error");
    }
};

export const handleConversationError = (res, error) => {
    const errorMap = {
        CONVERSATION_ALREADY_EXISTS: () =>
            conflictResponse(res, "Conversation already exists"),
        CONVERSATION_NOT_FOUND: () =>
            notFoundResponse(res, "Conversation not found"),
        USER_NOT_FOUND: () => notFoundResponse(res, "User not found"),
    };

    const handler = errorMap[error.message];
    if (handler) {
        handler();
    } else {
        console.error("Conversation error:", error);
        errorResponse(res, "Internal server error");
    }
};

export const handleMessageError = (res, error) => {
    const errorMap = {
        CONVERSATION_NOT_FOUND_OR_ACCESS_DENIED: () =>
            notFoundResponse(res, "Conversation not found or access denied"),
        MESSAGE_NOT_FOUND: () => notFoundResponse(res, "Message not found"),
        MESSAGE_NOT_FOUND_OR_NOT_EDITABLE: () =>
            unauthorizedResponse(
                res,
                "Message not found or you don't have permission to edit it"
            ),
        MESSAGE_NOT_FOUND_OR_NOT_DELETABLE: () =>
            unauthorizedResponse(
                res,
                "Message not found or you don't have permission to delete it"
            ),
        MESSAGE_TEXT_REQUIRED: () =>
            badRequestResponse(
                res,
                "Message text is required for text messages"
            ),
        FILE_URL_REQUIRED_FOR_IMAGE: () =>
            badRequestResponse(res, "File URL is required for image messages"),
        ONLY_TEXT_MESSAGES_CAN_BE_EDITED: () =>
            badRequestResponse(res, "Only text messages can be edited"),
        MESSAGE_EDIT_TIMEOUT: () =>
            badRequestResponse(
                res,
                "Message can only be edited within 5 minutes of sending"
            ),
        CANNOT_MARK_OWN_MESSAGE_READ: () =>
            badRequestResponse(res, "Cannot mark your own message as read"),
        DATABASE_ERROR: () =>
            errorResponse(res, "Database error occurred", 500),
        FILE_URL_REQUIRED: () =>
            badRequestResponse(res, "File URL is required for file messages"),
        INVALID_MESSAGE_TYPE: () =>
            badRequestResponse(res, "Invalid message type"),
        TEXT_MESSAGES_CANNOT_HAVE_FILE_URL: () =>
            badRequestResponse(res, "Text messages cannot contain file URLs"),
    };

    const handler = errorMap[error.message];
    if (handler) {
        handler();
    } else {
        console.error("Message error:", error);
        errorResponse(res, "Internal server error");
    }
};

export const handleUserError = (res, error) => {
    const errorMap = {
        SEARCH_QUERY_REQUIRED: () =>
            badRequestResponse(res, "Search query is required"),
        SEARCH_QUERY_TOO_SHORT: () =>
            badRequestResponse(
                res,
                "Search query must be at least 2 characters"
            ),
        USER_NOT_FOUND: () => notFoundResponse(res, "User not found"),
    };

    const handler = errorMap[error.message];
    if (handler) {
        handler();
    } else {
        console.error("User error:", error);
        errorResponse(res, "Internal server error");
    }
};

export const handleOAuthError = (res, error) => {
    const errorMap = {
        EMAIL_REQUIRED_FOR_OAUTH: () =>
            badRequestResponse(
                res,
                "Email is required for OAuth authentication. Please ensure your GitHub account has a public email."
            ),
        OAUTH_PROVIDER_ERROR: () =>
            errorResponse(res, "OAuth provider error", 502),
        MISSING_OAUTH_CONFIG: () =>
            errorResponse(res, "OAuth configuration is incomplete", 503),
    };

    const handler = errorMap[error.message];
    if (handler) {
        handler();
    } else {
        console.error("OAuth error:", error);
        errorResponse(res, "OAuth authentication failed");
    }
};

```

## File: utils/errors.js
```js
// Custom error classes for better error handling
export class AppError extends Error {
    constructor(message, statusCode, code) {
        super(message);
        this.statusCode = statusCode;
        this.code = code;
        this.isOperational = true;
        Error.captureStackTrace(this, this.constructor);
    }
}

export class ValidationError extends AppError {
    constructor(message, details = null) {
        super(message, 400, "VALIDATION_ERROR");
        this.details = details;
    }
}

export class AuthenticationError extends AppError {
    constructor(message = "Authentication failed") {
        super(message, 401, "AUTHENTICATION_ERROR");
    }
}

export class AuthorizationError extends AppError {
    constructor(message = "Access denied") {
        super(message, 403, "AUTHORIZATION_ERROR");
    }
}

export class NotFoundError extends AppError {
    constructor(resource = "Resource") {
        super(`${resource} not found`, 404, "NOT_FOUND");
        this.resource = resource;
    }
}

export class ConflictError extends AppError {
    constructor(message = "Resource already exists") {
        super(message, 409, "CONFLICT_ERROR");
    }
}

export class ExternalServiceError extends AppError {
    constructor(service, message = "External service error") {
        super(message, 502, "EXTERNAL_SERVICE_ERROR");
        this.service = service;
    }
}

export class RateLimitError extends AppError {
    constructor(message = "Too many requests") {
        super(message, 429, "RATE_LIMIT_ERROR");
    }
}

export class FileUploadError extends AppError {
    constructor(message, code = "FILE_UPLOAD_ERROR") {
        super(message, 400, code);
    }
}

// Error code constants
export const ErrorCodes = {
    // Auth errors
    USER_ALREADY_EXISTS: "USER_ALREADY_EXISTS",
    INVALID_CREDENTIALS: "INVALID_CREDENTIALS",
    TOKEN_EXPIRED: "TOKEN_EXPIRED",
    TOKEN_INVALID: "TOKEN_INVALID",
    REFRESH_TOKEN_REQUIRED: "REFRESH_TOKEN_REQUIRED",

    // User errors
    USER_NOT_FOUND: "USER_NOT_FOUND",
    CURRENT_PASSWORD_REQUIRED: "CURRENT_PASSWORD_REQUIRED",
    INVALID_CURRENT_PASSWORD: "INVALID_CURRENT_PASSWORD",
    SEARCH_QUERY_REQUIRED: "SEARCH_QUERY_REQUIRED",
    SEARCH_QUERY_TOO_SHORT: "SEARCH_QUERY_TOO_SHORT",

    // Conversation errors
    CONVERSATION_ALREADY_EXISTS: "CONVERSATION_ALREADY_EXISTS",
    CONVERSATION_NOT_FOUND: "CONVERSATION_NOT_FOUND",

    // Message errors
    MESSAGE_NOT_FOUND: "MESSAGE_NOT_FOUND",
    MESSAGE_TEXT_REQUIRED: "MESSAGE_TEXT_REQUIRED",
    MESSAGE_NOT_EDITABLE: "MESSAGE_NOT_EDITABLE",
    MESSAGE_EDIT_TIMEOUT: "MESSAGE_EDIT_TIMEOUT",
    CANNOT_MARK_OWN_MESSAGE_READ: "CANNOT_MARK_OWN_MESSAGE_READ",
    FILE_URL_REQUIRED: "FILE_URL_REQUIRED",
    INVALID_MESSAGE_TYPE: "INVALID_MESSAGE_TYPE",

    // File upload errors
    FILE_TOO_LARGE: "FILE_TOO_LARGE",
    INVALID_FILE_FORMAT: "INVALID_FILE_FORMAT",
    UPLOAD_FAILED: "UPLOAD_FAILED",
    UPLOAD_TIMEOUT: "UPLOAD_TIMEOUT",
    DELETE_FAILED: "DELETE_FAILED",

    // OAuth errors
    EMAIL_REQUIRED_FOR_OAUTH: "EMAIL_REQUIRED_FOR_OAUTH",
    OAUTH_PROVIDER_ERROR: "OAUTH_PROVIDER_ERROR",
    MISSING_OAUTH_CONFIG: "MISSING_OAUTH_CONFIG",

    // Database errors
    DATABASE_ERROR: "DATABASE_ERROR",
    TRANSACTION_FAILED: "TRANSACTION_FAILED",
};

```

## File: utils/jwt.js
```js
import jwt from "jsonwebtoken";

export const generateAccessToken = (userId) => {
    return jwt.sign({ userId }, process.env.JWT_SECRET, {
        expiresIn: "15m",
    });
};

export const generateRefreshToken = (userId) => {
    return jwt.sign({ userId }, process.env.REFRESH_TOKEN_SECRET, {
        expiresIn: "30d",
    });
};

export const verifyAccessToken = (token) => {
    return jwt.verify(token, process.env.JWT_SECRET);
};

export const verifyRefreshToken = (token) => {
    return jwt.verify(token, process.env.REFRESH_TOKEN_SECRET);
};

```

## File: utils/logger.js
```js
import config from "../config/env.js";

// Log levels
const LogLevels = {
    ERROR: "ERROR",
    WARN: "WARN",
    INFO: "INFO",
    DEBUG: "DEBUG",
};

const logLevelPriority = {
    ERROR: 0,
    WARN: 1,
    INFO: 2,
    DEBUG: 3,
};

class Logger {
    constructor() {
        this.level =
            config.nodeEnv === "production" ? LogLevels.INFO : LogLevels.DEBUG;
    }

    shouldLog(level) {
        return logLevelPriority[level] <= logLevelPriority[this.level];
    }

    formatMessage(level, message, meta = {}) {
        const timestamp = new Date().toISOString();
        const metaStr =
            Object.keys(meta).length > 0 ? JSON.stringify(meta) : "";

        return `[${timestamp}] [${level}] ${message} ${metaStr}`;
    }

    error(message, error = null, meta = {}) {
        if (!this.shouldLog(LogLevels.ERROR)) return;

        const errorMeta = error
            ? {
                  ...meta,
                  error: {
                      message: error.message,
                      stack: error.stack,
                      code: error.code,
                  },
              }
            : meta;

        console.error(this.formatMessage(LogLevels.ERROR, message, errorMeta));
    }

    warn(message, meta = {}) {
        if (!this.shouldLog(LogLevels.WARN)) return;
        console.warn(this.formatMessage(LogLevels.WARN, message, meta));
    }

    info(message, meta = {}) {
        if (!this.shouldLog(LogLevels.INFO)) return;
        console.log(this.formatMessage(LogLevels.INFO, message, meta));
    }

    debug(message, meta = {}) {
        if (!this.shouldLog(LogLevels.DEBUG)) return;
        console.log(this.formatMessage(LogLevels.DEBUG, message, meta));
    }

    // Specific log methods for common scenarios
    authLog(action, userId, success, meta = {}) {
        this.info(`Auth: ${action}`, {
            userId,
            success,
            ...meta,
        });
    }

    socketLog(event, userId, socketId, meta = {}) {
        this.debug(`Socket: ${event}`, {
            userId,
            socketId,
            ...meta,
        });
    }

    dbLog(operation, table, success, meta = {}) {
        this.debug(`DB: ${operation} on ${table}`, {
            success,
            ...meta,
        });
    }

    apiLog(method, path, statusCode, duration, meta = {}) {
        const level =
            statusCode >= 500
                ? LogLevels.ERROR
                : statusCode >= 400
                ? LogLevels.WARN
                : LogLevels.INFO;

        const message = `${method} ${path} ${statusCode} ${duration}ms`;

        if (level === LogLevels.ERROR) {
            this.error(message, null, meta);
        } else if (level === LogLevels.WARN) {
            this.warn(message, meta);
        } else {
            this.info(message, meta);
        }
    }
}

export const logger = new Logger();
export default logger;

```

## File: utils/oauthHelpers.js
```js
import bcrypt from "bcryptjs";
import { userRepository } from "../repositories/userRepository.js";
import { tokenService } from "../services/tokenService.js";

// Extract email from GitHub profile
export const getEmailFromGitHubProfile = (profile) => {
    // GitHub might not return email if it's private
    if (profile.emails && profile.emails.length > 0) {
        return profile.emails[0].value;
    }

    // Fallback: use GitHub username to create an email
    if (profile.username) {
        return `${profile.username}@github.com`;
    }

    // Last resort: use profile ID
    return `${profile.id}@github.com`;
};

// Extract full name from GitHub profile
export const getFullNameFromGitHubProfile = (profile) => {
    return profile.displayName || profile.username || "GitHub User";
};

// Extract avatar from GitHub profile
export const getAvatarFromGitHubProfile = (profile) => {
    return profile.photos && profile.photos[0] ? profile.photos[0].value : null;
};

// Generate random password for OAuth users
export const generateRandomPassword = async () => {
    const randomPassword =
        Math.random().toString(36).slice(-16) +
        Math.random().toString(36).slice(-16);
    return await bcrypt.hash(
        randomPassword,
        parseInt(process.env.ROUNDS) || 12
    );
};

// Main OAuth user handler
export const handleGitHubUser = async (profile) => {
    const email = getEmailFromGitHubProfile(profile);

    if (!email) {
        throw new Error("EMAIL_REQUIRED_FOR_OAUTH");
    }

    // Check if user exists
    let user = await userRepository.findByEmail(email);

    if (!user) {
        // Create new user
        const passwordHash = await generateRandomPassword();

        user = await userRepository.create({
            email: email,
            full_name: getFullNameFromGitHubProfile(profile),
            password_hash: passwordHash,
            avatar_url: getAvatarFromGitHubProfile(profile),
            is_online: true,
        });
    } else {
        // Update existing user's online status
        user = await userRepository.update(user.id, {
            is_online: true,
            last_seen: new Date(),
        });
    }

    // Generate tokens
    const { accessToken, refreshToken } = await tokenService.generateAuthTokens(
        user.id
    );

    return {
        user: {
            id: user.id,
            email: user.email,
            full_name: user.full_name,
            avatar_url: user.avatar_url,
            is_online: user.is_online,
            last_seen: user.last_seen,
            created_at: user.created_at,
        },
        accessToken,
        refreshToken,
    };
};

```

## File: utils/oauthValidators.js
```js
export const oauthValidators = {
    // Validate OAuth environment configuration
    validateOAuthConfig: () => {
        const missingVars = [];
        const warnings = [];

        // Required environment variables
        if (!process.env.GITHUB_CLIENT_ID) {
            missingVars.push("GITHUB_CLIENT_ID");
        }

        if (!process.env.GITHUB_CLIENT_SECRET) {
            missingVars.push("GITHUB_CLIENT_SECRET");
        }

        if (!process.env.CLIENT_URL) {
            missingVars.push("CLIENT_URL");
        }

        // Optional but recommended environment variables
        if (!process.env.CLIENT_SUCCESS_REDIRECT) {
            warnings.push("CLIENT_SUCCESS_REDIRECT (default: /chat)");
        }

        if (!process.env.CLIENT_ERROR_REDIRECT) {
            warnings.push("CLIENT_ERROR_REDIRECT (default: /login)");
        }

        // Throw error for missing required variables
        if (missingVars.length > 0) {
            throw new Error(
                `Missing required OAuth environment variables: ${missingVars.join(
                    ", "
                )}`
            );
        }

        return {
            github: {
                enabled: !!process.env.GITHUB_CLIENT_ID,
                clientId: process.env.GITHUB_CLIENT_ID
                    ? "configured"
                    : "missing",
                clientSecret: process.env.GITHUB_CLIENT_SECRET
                    ? "configured"
                    : "missing",
                callbackUrl: "/api/auth/github/callback",
            },
            client: {
                url: process.env.CLIENT_URL,
                successRedirect: process.env.CLIENT_SUCCESS_REDIRECT || "/chat",
                errorRedirect: process.env.CLIENT_ERROR_REDIRECT || "/login",
            },
            warnings: warnings.length > 0 ? warnings : null,
        };
    },

    // Validate GitHub profile structure
    validateGitHubProfile: (profile) => {
        if (!profile) {
            throw new Error("GitHub profile is null or undefined");
        }

        if (!profile.id) {
            throw new Error("GitHub profile missing ID");
        }

        if (!profile.username && !profile.displayName) {
            throw new Error("GitHub profile missing username and display name");
        }

        // Check if we have at least one way to identify the user
        const hasEmail = profile.emails && profile.emails.length > 0;
        const hasUsername = !!profile.username;

        if (!hasEmail && !hasUsername) {
            throw new Error("GitHub profile missing both email and username");
        }

        return true;
    },

    // Validate OAuth callback parameters
    validateCallbackParams: (req) => {
        const { error, error_description, code } = req.query;

        if (error) {
            throw new Error(
                `OAuth provider error: ${error} - ${
                    error_description || "No description"
                }`
            );
        }

        if (!code) {
            throw new Error("Missing authorization code in callback");
        }

        return true;
    },

    // Check if OAuth is properly configured
    isOAuthEnabled: () => {
        try {
            const config = oauthValidators.validateOAuthConfig();
            return config.github.enabled;
        } catch (error) {
            return false;
        }
    },
};

```

## File: utils/responseHandler.js
```js
export const successResponse = (res, msg, data = null, statusCode = 200) => {
    return res.status(statusCode).json({
        success: true,
        msg,
        data,
    });
};

export const errorResponse = (res, msg, statusCode = 500) => {
    return res.status(statusCode).json({
        success: false,
        msg,
        data: null,
    });
};

export const createdResponse = (res, msg, data = null) => {
    return successResponse(res, msg, data, 201);
};

export const badRequestResponse = (res, msg) => {
    return errorResponse(res, msg, 400);
};

export const unauthorizedResponse = (res, msg = "Unauthorized") => {
    return errorResponse(res, msg, 401);
};

export const notFoundResponse = (res, msg = "Resource not found") => {
    return errorResponse(res, msg, 404);
};

export const conflictResponse = (res, msg = "Resource already exists") => {
    return errorResponse(res, msg, 409);
};

```

## File: utils/validationSchemas.js
```js
import Joi from "joi";

const uuidSchema = Joi.string().uuid().required();
const emailSchema = Joi.string().email().required();
const passwordSchema = Joi.string().min(6).required();

export const authValidation = {
    signup: Joi.object({
        email: emailSchema,
        password: passwordSchema,
        full_name: Joi.string().min(2).max(100).required(),
    }),

    login: Joi.object({
        email: emailSchema,
        password: passwordSchema,
    }),

    refreshToken: Joi.object({
        refreshToken: Joi.string().required(),
    }),

    logout: Joi.object({
        refreshToken: Joi.string().required(),
    }),
};

export const profileValidation = {
    updateProfile: Joi.object({
        full_name: Joi.string().min(2).max(100).optional(),
        // Remove avatar_file from Joi validation since it's handled by Multer
        currentPassword: Joi.string().min(6).optional(),
        newPassword: Joi.string().min(6).optional(),
    }).custom((value, helpers) => {
        if (value.newPassword && !value.currentPassword) {
            return helpers.error("any.custom", {
                message:
                    "Current password is required when setting new password",
            });
        }
        return value;
    }),
};

export const conversationValidation = {
    createConversation: Joi.object({
        user2_id: uuidSchema,
    }),

    conversationParams: Joi.object({
        id: uuidSchema,
    }),

    checkConversation: Joi.object({
        user2_id: uuidSchema,
    }),
};

export const messageValidation = {
    createMessage: Joi.object({
        message_text: Joi.string()
            .max(1000)
            .when("message_type", {
                is: "TEXT",
                then: Joi.required(),
                otherwise: Joi.optional().allow(""),
            }),
        message_type: Joi.string().valid("TEXT", "IMAGE").default("TEXT"),
        file_url: Joi.string()
            .uri()
            .when("message_type", {
                is: "IMAGE",
                then: Joi.required(),
                otherwise: Joi.optional().allow(null),
            }),
        file_name: Joi.string().max(255).optional(),
        file_size: Joi.number().integer().min(0).optional(),
        file_type: Joi.string().max(100).optional(),
    }),

    updateMessage: Joi.object({
        message_text: Joi.string().max(1000).required(),
    }),

    conversationParams: Joi.object({
        conversation_id: uuidSchema,
    }),

    messageParams: Joi.object({
        message_id: uuidSchema,
    }),

    // ADD THIS NEW SCHEMA FOR ROUTES WITH BOTH PARAMS
    messageParamsWithConversation: Joi.object({
        conversation_id: uuidSchema,
        message_id: uuidSchema,
    }),

    queryParams: Joi.object({
        page: Joi.number().integer().min(1).default(1),
        limit: Joi.number().integer().min(1).max(100).default(50),
    }),
};

export const readReceiptValidation = {
    markAsRead: Joi.object({
        message_id: uuidSchema,
    }),
    markAsReadWithConversation: Joi.object({
        conversation_id: uuidSchema,
        message_id: uuidSchema,
    }),
};

export const userValidation = {
    searchQuery: Joi.object({
        q: Joi.string().min(2).max(100).required(),
        limit: Joi.number().integer().min(1).max(50).default(10),
    }),

    updateOnlineStatus: Joi.object({
        is_online: Joi.boolean().required(),
    }),

    getAllUsers: Joi.object({
        limit: Joi.number().integer().min(1).max(100).default(50),
    }),

    userIdParams: Joi.object({
        id: uuidSchema,
    }),
};

```

