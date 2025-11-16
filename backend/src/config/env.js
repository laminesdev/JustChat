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
        "CLIENT_URL", // ADDED
        "CLIENT_SUCCESS_REDIRECT", // ADDED
        "CLIENT_ERROR_REDIRECT", // ADDED
        "GITHUB_CLIENT_ID", // ADDED
        "GITHUB_CLIENT_SECRET", // ADDED
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

    // Validate URLs
    if (process.env.CLIENT_URL && !process.env.CLIENT_URL.startsWith("http")) {
        throw new ConfigurationError(
            "CLIENT_URL must be a valid URL starting with http:// or https://"
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
