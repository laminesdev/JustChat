import express from "express";
import routes from "./routes/index.js";
import { specs, swaggerUi } from "./config/swagger.js";
import cors from "cors";

const app = express();

const corsOptions = {
    origin: function (origin, callback) {
        if (!origin) return callback(null, true);

        const allowedOrigins = [
            "http://localhost:5176",
            process.env.CLIENT_URL,
        ].filter(Boolean);

        if (allowedOrigins.some((allowed) => origin.startsWith(allowed))) {
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

// Parse JSON bodies - REMOVED DUPLICATE
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
