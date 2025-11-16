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

        try {
            // First verify the JWT structure
            const decoded = verifyRefreshToken(refreshToken);

            // Then check if it exists in database and is valid
            const validity = await tokenRepository.verifyTokenValidity(
                refreshToken
            );

            if (!validity.valid) {
                throw new Error(validity.reason);
            }

            const accessToken = generateAccessToken(decoded.userId);
            return { accessToken };
        } catch (error) {
            console.error("Token refresh error:", error.message);

            // Handle JWT verification errors
            if (error.name === "JsonWebTokenError") {
                throw new Error("INVALID_REFRESH_TOKEN");
            }
            if (error.name === "TokenExpiredError") {
                throw new Error("REFRESH_TOKEN_EXPIRED");
            }

            // Re-throw our custom errors
            if (
                error.message === "REFRESH_TOKEN_REQUIRED" ||
                error.message === "TOKEN_NOT_FOUND" ||
                error.message === "TOKEN_EXPIRED" ||
                error.message === "INVALID_REFRESH_TOKEN" ||
                error.message === "REFRESH_TOKEN_EXPIRED"
            ) {
                throw error;
            }

            // For any unexpected errors
            throw new Error("TOKEN_SERVICE_ERROR");
        }
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
