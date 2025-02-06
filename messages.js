const pool = require('./db'); // Import the database connection

// Send a new message
async function sendMessage(roomId, userId, message) {
    try {
        console.log(`User ${userId} sent a message in room ${roomId}:`, message);

        // Insert the message into the database
        await pool.query('INSERT INTO messages (room_id, user_id, message) VALUES (?, ?, ?)', [roomId, userId, message]);

        return { success: true };
    } catch (error) {
        console.error('Error sending message:', error.message);
        return { error: 'Failed to send message' };
    }
}

// Fetch all messages for a room
async function fetchMessagesForRoom(roomId) {
    try {
        console.log('Fetching messages for room ID:', roomId);

        // Query the database for messages
        const [rows] = await pool.query(
            'SELECT m.id, u.username, m.message, m.timestamp, m.likes, m.dislikes ' +
            'FROM messages m JOIN users u ON m.user_id = u.id ' +
            'WHERE m.room_id = ? ORDER BY m.timestamp ASC',
            [roomId]
        );

        return rows;
    } catch (error) {
        console.error('Error fetching messages:', error.message);
        return [];
    }
}

// Like or dislike a message
async function updateMessageReaction(roomId, messageId, userId, reactionType) {
    try {
        console.log(`User ${userId} ${reactionType}d message ${messageId} in room ${roomId}`);

        // Check if the message exists
        const [messageRows] = await pool.query('SELECT * FROM messages WHERE id = ? AND room_id = ?', [messageId, roomId]);
        if (!messageRows.length) {
            return { error: 'Message not found' };
        }

        // Update the likes or dislikes count
        if (reactionType === 'like') {
            await pool.query('UPDATE messages SET likes = likes + 1 WHERE id = ?', [messageId]);
        } else if (reactionType === 'dislike') {
            await pool.query('UPDATE messages SET dislikes = dislikes + 1 WHERE id = ?', [messageId]);
        } else {
            return { error: 'Invalid reaction type' };
        }

        return { success: true };
    } catch (error) {
        console.error('Error updating message reaction:', error.message);
        return { error: 'Failed to update reaction' };
    }
}

// Reply to a message
async function replyToMessage(roomId, userId, parentMessageId, replyText) {
    try {
        console.log(`User ${userId} replied to message ${parentMessageId} in room ${roomId}`);

        // Check if the parent message exists
        const [messageRows] = await pool.query('SELECT * FROM messages WHERE id = ? AND room_id = ?', [parentMessageId, roomId]);
        if (!messageRows.length) {
            return { error: 'Parent message not found' };
        }

        // Insert the reply into the database
        await pool.query('INSERT INTO messages (room_id, user_id, message, parent_message_id) VALUES (?, ?, ?, ?)', [
            roomId,
            userId,
            replyText,
            parentMessageId
        ]);

        return { success: true };
    } catch (error) {
        console.error('Error replying to message:', error.message);
        return { error: 'Failed to reply to message' };
    }
}

module.exports = {
    sendMessage,
    fetchMessagesForRoom,
    updateMessageReaction,
    replyToMessage
};