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
        TOKEN_SERVICE_ERROR: () =>
            errorResponse(res, "Token service error", 500),
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
