import { PrismaClient } from "@prisma/client";

// Configure Prisma with optimized settings for Neon
const prisma = new PrismaClient({
    log:
        process.env.NODE_ENV === "development"
            ? ["query", "error", "warn"]
            : ["error"],
    errorFormat: "minimal",
    // Connection pool optimization for Neon
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
