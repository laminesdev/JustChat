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

    // Check if recipient is online for immediate delivery status
    const otherUserId =
        conversation.user1_id === sender_id
            ? conversation.user2_id
            : conversation.user1_id;
    const isRecipientOnline = connectedUsers.has(otherUserId);

    // Create message with correct delivery status
    const message = await messageRepository.create({
        conversation_id,
        sender_id,
        message_type: message_type || "TEXT",
        message_text: message_text?.trim(),
        file_url,
        file_name,
        file_size,
        file_type,
        is_delivered: isRecipientOnline, // Set immediately based on online status
        delivered_at: isRecipientOnline ? new Date() : null,
    });

    return message;
};

export const getMessagesService = async (
    conversation_id,
    user_id,
    page = 1,
    limit = 50
) => {
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
    const message = await messageRepository.findByIdWithAccess(
        message_id,
        user_id
    );
    if (!message) {
        throw new Error("MESSAGE_NOT_FOUND");
    }
    return message;
};

export const updateMessageService = async (message_id, user_id, updateData) => {
    const message = await messageRepository.findByIdWithAccess(
        message_id,
        user_id
    );

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
    const message = await messageRepository.findByIdWithAccess(
        message_id,
        user_id
    );

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
    const message = await messageRepository.findByIdWithAccess(
        message_id,
        reader_id
    );

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

    const unread_count = await messageRepository.countUnread(
        conversation_id,
        user_id
    );
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

    const result = await messageRepository.markAllAsRead(
        conversation_id,
        user_id
    );
    const unread_count = await messageRepository.getUnreadCountAfterMark(
        conversation_id,
        user_id
    );

    return {
        marked_count: result.marked_count,
        unread_count,
        has_unread_messages: unread_count > 0,
        conversation,
    };
};
