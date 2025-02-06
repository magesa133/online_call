const express = require('express');
const http = require('http');
const bcrypt = require('bcrypt');
const socketIo = require('socket.io');
const path = require('path');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const { v4: uuidv4 } = require('uuid'); // For generating unique room IDs
const pool = require('./db'); // Database connection module
const messages = require('./messages'); // Message handling module

dotenv.config();

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

// Middleware
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Authenticate token middleware
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        console.error('Missing token in Authorization header');
        return res.status(401).json({ error: 'Access denied' });
    }

    jwt.verify(token, process.env.JWT_SECRET, async (err, user) => {
        if (err) {
            console.error('Invalid or expired token:', err.message);
            return res.status(403).json({ error: 'Invalid token' });
        }

        // Ensure the user exists in the database
        try {
            const [rows] = await pool.query('SELECT * FROM users WHERE id = ?', [user.userId]);
            if (!rows.length) {
                console.error('User not found in the database:', user.userId);
                return res.status(404).json({ error: 'User not found' });
            }
            req.user = user;
            next();
        } catch (error) {
            console.error('Error verifying user:', error.message);
            res.status(500).json({ error: 'Internal server error' });
        }
    });
}

// Test database connection route
app.get('/test-db', async (req, res) => {
    try {
        await pool.query('SELECT 1');
        res.send('Database connection successful');
    } catch (error) {
        console.error('Database connection failed:', error.message);
        res.status(500).send('Database connection failed');
    }
});


// Register a new user
app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' });
    }

    try {
        console.log('Attempting to register user:', username);

        // Check if the username already exists
        const [rows] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
        if (rows.length > 0) {
            return res.status(409).json({ error: 'Username already exists' });
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert the user into the database
        const [result] = await pool.query('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword]);
        console.log('User registered successfully:', username);

        // Return the user ID
        res.status(201).json({ userId: result.insertId });
    } catch (error) {
        console.error('Error during registration:', error.message, error.stack);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Log in a user
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' });
    }

    try {
        console.log('Attempting to log in user:', username);

        // Fetch the user from the database
        const [rows] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
        if (!rows.length) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const user = rows[0];

        // Compare the provided password with the hashed password
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Generate and return a JWT token
        const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        console.log('User logged in successfully:', username);
        res.json({ token });
    } catch (error) {
        console.error('Error during login:', error.message, error.stack);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Define dynamic /meeting route
app.get('/meeting', (req, res) => {
    const roomId = req.query.room; // Get the room ID from the query string

    if (!roomId) {
        return res.status(400).send('Invalid room ID');
    }

    // Send the meeting.html file
    res.sendFile(path.join(__dirname, 'public', 'meeting.html'));
});

// Create a meeting
app.post('/create-meeting', authenticateToken, async (req, res) => {
    const { userId } = req.user;

    try {
        console.log(`Creating meeting for user ID: ${userId}`);

        // Generate a unique room ID
        const roomId = uuidv4();

        // Insert the meeting into the database
        await pool.query('INSERT INTO meetings (room_id, created_by) VALUES (?, ?)', [roomId, userId]);
        console.log(`Meeting created successfully with room ID: ${roomId}`);

        // Return the meeting URL
        const meetingUrl = `http://localhost:4000/meeting?room=${roomId}`;
        res.json({ roomId, meetingUrl });
    } catch (error) {
        console.error('Error creating meeting:', error.message);
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ error: 'Meeting with this room ID already exists' });
        }
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Join an existing meeting
app.post('/join-meeting', authenticateToken, async (req, res) => {
    const { roomId } = req.body;
    const { userId } = req.user;

    if (!roomId) {
        return res.status(400).json({ error: 'Room ID is required' });
    }

    try {
        console.log(`Attempting to join meeting with room ID: ${roomId}`);

        // Check if the meeting exists
        const [meetingRows] = await pool.query('SELECT * FROM meetings WHERE room_id = ?', [roomId]);
        if (!meetingRows.length) {
            return res.status(404).json({ error: 'Meeting not found' });
        }

        // Add the user as a participant
        const connectionId = `${userId}-${Date.now()}`;
        await pool.query('INSERT INTO participants (user_id, room_id, connection_id) VALUES (?, ?, ?)', [userId, roomId, connectionId]);
        console.log(`User ${userId} joined room ${roomId}`);

        res.json({ success: true });
    } catch (error) {
        console.error('Error joining meeting:', error.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Send a chat message
app.post('/send-message', authenticateToken, async (req, res) => {
    const { roomId, message } = req.body;
    const { userId } = req.user;

    if (!roomId || !message) {
        return res.status(400).json({ error: 'Room ID and message are required' });
    }

    try {
        console.log(`User ${userId} sent a message in room ${roomId}:`, message);

        // Send the message via the messages module
        const result = await messages.sendMessage(roomId, userId, message);
        if (result.success) {
            io.to(roomId).emit('new-message', { userId, message, timestamp: new Date() });
            res.json({ success: true });
        } else {
            res.status(500).json(result);
        }
    } catch (error) {
        console.error('Error sending message:', error.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Update message reaction (like/dislike)
app.post('/update-reaction', authenticateToken, async (req, res) => {
    const { roomId, messageId, reactionType } = req.body;
    const { userId } = req.user;

    if (!roomId || !messageId || !reactionType) {
        return res.status(400).json({ error: 'Room ID, message ID, and reaction type are required' });
    }

    try {
        console.log(`User ${userId} ${reactionType}d message ${messageId} in room ${roomId}`);

        // Update the reaction via the messages module
        const result = await messages.updateMessageReaction(roomId, messageId, userId, reactionType);
        if (result.success) {
            io.to(roomId).emit('reaction-updated', { messageId, reactionType });
            res.json({ success: true });
        } else {
            res.status(500).json(result);
        }
    } catch (error) {
        console.error('Error updating reaction:', error.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Reply to a message
app.post('/reply-to-message', authenticateToken, async (req, res) => {
    const { roomId, parentMessageId, replyText } = req.body;
    const { userId } = req.user;

    if (!roomId || !parentMessageId || !replyText) {
        return res.status(400).json({ error: 'Room ID, parent message ID, and reply text are required' });
    }

    try {
        console.log(`User ${userId} replied to message ${parentMessageId} in room ${roomId}`);

        // Reply to the message via the messages module
        const result = await messages.replyToMessage(roomId, userId, parentMessageId, replyText);
        if (result.success) {
            io.to(roomId).emit('new-reply', { parentMessageId, userId, replyText, timestamp: new Date() });
            res.json({ success: true });
        } else {
            res.status(500).json(result);
        }
    } catch (error) {
        console.error('Error replying to message:', error.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Fetch user ID from JWT
app.post('/get-user-id', authenticateToken, async (req, res) => {
    const { userId } = req.user;
    console.log(`Fetched user ID: ${userId}`);
    res.json({ userId });
});

// Socket.IO logic
io.on('connection', async (socket) => {
    console.log('A user connected:', socket.id);

    socket.on('join-room', async (roomId, userId) => {
        socket.join(roomId);
        socket.userId = userId;
        console.log(`User ${userId} joined room ${roomId}`);

        try {
            // Notify other users in the room
            socket.to(roomId).emit('user-connected', userId);

            // Send the list of participants to the new user
            const [participantRows] = await pool.query('SELECT user_id FROM participants WHERE room_id = ?', [roomId]);
            socket.emit('room-users', participantRows.map(row => row.user_id));

            // Fetch and send previous chat messages
            const messagesData = await messages.fetchMessagesForRoom(roomId);
            socket.emit('previous-messages', messagesData);
        } catch (error) {
            console.error('Error handling user join:', error.message);
            socket.emit('error', { message: 'Failed to join the meeting' });
        }
    });

    socket.on('disconnect', async () => {
        console.log('User disconnected:', socket.id);

        try {
            // Remove the participant from the database
            const connectionId = `${socket.userId}-${socket.id}`;
            await pool.query('DELETE FROM participants WHERE connection_id = ?', [connectionId]);

            // Notify others in the room
            socket.broadcast.emit('user-disconnected', socket.userId);
        } catch (error) {
            console.error('Error removing participant:', error.message);
        }
    });
});

// Start server
const PORT = process.env.PORT || 4000;
server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});