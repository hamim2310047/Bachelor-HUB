const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const http = require('http');
const socketIo = require('socket.io');
const session = require('express-session');
const multer = require('multer');
const jwt = require('jsonwebtoken');
const path = require('path'); // Required for serving files

const app = express();
const PORT = 3000;
const server = http.createServer(app);
const io = socketIo(server);

// Database connection
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'Mdhamim07',
    database: 'BachelorHub'
});

db.connect((err) => {
    if (err) throw err;
    console.log('Connected to MySQL database.');
});

// Middleware
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(express.static('public')); // Serve static files
app.use('/uploads', express.static(path.join(__dirname, 'uploads'))); // Serve image files
app.use(session({
    secret: 'bachelorhubsecret',
    resave: false,
    saveUninitialized: false
}));

// Serve login.html
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Serve register.html
app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

// Registration endpoint
app.post('/register', async (req, res) => {
    const { username, name, password, contact } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    const sql = "INSERT INTO user (username, name, password, contact) VALUES (?, ?, ?, ?)";
    db.query(sql, [username, name, hashedPassword, contact], (err, result) => {
        if (err) {
            console.error(err);
            res.send('Registration failed. Please try again.');
        } else {
            res.send('Registration successful! <a href="/login">Login here</a>');
        }
    });
});

// Login endpoint
// Login endpoint (POST)
// Login endpoint (POST)
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).send('Please provide both username and password.');
    }

    const sql = "SELECT * FROM user WHERE username = ?";
    db.query(sql, [username], async (err, results) => {
        if (err) {
            console.error('Error querying database:', err);
            return res.status(500).send('Error querying database.');
        }

        if (results.length === 0) {
            return res.status(400).send('No user found with that username.');
        }

        const user = results[0];
        const isPasswordValid = await bcrypt.compare(password, user.password);

        if (isPasswordValid) {
            req.session.user = { id: user.id, username: user.username };
            return res.redirect(`/home`);
        } else {
            return res.status(400).send('Invalid credentials. <a href="/login">Try again</a>');
        }
    });
});


// Home page
// Home page
app.get('/home', (req, res) => {
    if (!req.session.user) {
        return res.redirect('/login');
    }

    const userId = req.session.user.id;

    // Fetch user data from the database
    const sql = "SELECT * FROM user WHERE id = ?";
    db.query(sql, [userId], (err, results) => {
        if (err) {
            console.error('Error querying database:', err);
            return res.status(500).send('Error fetching user data.');
        }

        if (results.length === 0) {
            return res.status(404).send('User not found.');
        }

        const user = results[0];

        // Render profile page with user data
        res.sendFile(path.join(__dirname, 'public', 'homepage.html'));
    });
});

// Endpoint to fetch user data
app.get('/api/user', (req, res) => {
    if (!req.session.user) {
        return res.status(401).send('Unauthorized');
    }

    const userId = req.session.user.id;

    const sql = "SELECT * FROM user WHERE id = ?";
    db.query(sql, [userId], (err, results) => {
        if (err) {
            console.error('Error querying database:', err);
            return res.status(500).send('Error fetching user data.');
        }

        if (results.length === 0) {
            return res.status(404).send('User not found.');
        }

        res.json(results[0]);
    });
});
// Update name
// Ensure the user is logged in before accessing their information
app.post('/update-name', (req, res) => {
    if (!req.session.user) {
        return res.status(401).send('Please log in first.');
    }

    const { name } = req.body;
    const userId = req.session.user.id;  // Access user id only if logged in

    const sql = "UPDATE user SET name = ? WHERE id = ?";
    db.query(sql, [name, userId], (err, result) => {
        if (err) {
            return res.status(500).send('Failed to update name.');
        }
        res.send('Name updated successfully!');
    });
});

app.post('/update-username', (req, res) => {
    if (!req.session.user) {
        return res.status(401).send('Please log in first.');
    }

    const { username } = req.body;
    const userId = req.session.user.id;  // Access user id only if logged in

    const sql = "UPDATE user SET username = ? WHERE id = ?";
    db.query(sql, [username, userId], (err, result) => {
        if (err) {
            return res.status(500).send('Failed to update username.');
        }
        res.send('Username updated successfully!');
    });
});

app.post('/update-password', async (req, res) => {
    if (!req.session.user) {
        return res.status(401).send('Please log in first.');
    }

    const { password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const userId = req.session.user.id;  // Access user id only if logged in

    const sql = "UPDATE user SET password = ? WHERE id = ?";
    db.query(sql, [hashedPassword, userId], (err, result) => {
        if (err) {
            return res.status(500).send('Failed to update password.');
        }
        res.send('Password updated successfully!');
    });
});

app.post('/update-contact', (req, res) => {
    if (!req.session.user) {
        return res.status(401).send('Please log in first.');
    }

    const { contact } = req.body;
    const userId = req.session.user.id;  // Access user id only if logged in

    const sql = "UPDATE user SET contact = ? WHERE id = ?";
    db.query(sql, [contact, userId], (err, result) => {
        if (err) {
            return res.status(500).send('Failed to update contact.');
        }
        res.send('Contact updated successfully!');
    });
});

app.post('/delete-account', (req, res) => {
    if (!req.session.user) {
        return res.status(401).send('Please log in first.');
    }

    const userId = req.session.user.id;

    const sql = "DELETE FROM user WHERE id = ?";
    db.query(sql, [userId], (err, result) => {
        if (err) {
            console.error('Error deleting account:', err); // Log detailed error
            return res.status(500).send('Failed to delete account.');
        }

        req.session.destroy(err => {
            if (err) {
                console.error('Error destroying session:', err); // Log error if session destruction fails
                return res.status(500).send('Account deleted but failed to end session.');
            }
            res.send('Account deleted successfully.');
        });
    });
});


// Logout endpoint
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).send('Could not log out. Please try again.');
        }
        res.redirect('/login');  // Redirect to login page after logging out
    });
});

// Middleware to check if the user is logged in
function ensureLoggedIn(req, res, next) {
    if (!req.session.user) {
        return res.status(401).send('Please log in to access this feature.');
    }
    next();
}
// Multer configuration for image uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/'); // Directory for uploads
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname)); // Unique file name
    }
});
const upload = multer({
    storage: storage,
    fileFilter: (req, file, cb) => {
        const fileTypes = /jpeg|jpg|png/;
        const extname = fileTypes.test(path.extname(file.originalname).toLowerCase());
        const mimeType = fileTypes.test(file.mimetype);

        if (extname && mimeType) return cb(null, true);
        cb(new Error('Only images (jpeg, jpg, png) are allowed.'));
    }
});
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
// Tolet posting route
// Serve add-tolet.html
app.get('/add-tolet', (req, res) => {
    if (req.session.user) {
        res.sendFile(path.join(__dirname, 'public', 'add-tolet.html'));
    } else {
        res.redirect('/login');
    }
});

// Handle To-Let post submission
app.post('/add-tolet', upload.single('image'), (req, res) => {
    const { title, description, price, location } = req.body;
    const imagePath = req.file ? `/uploads/${req.file.filename}` : null;

    if (!title || !description || !price || !location || !imagePath) {
        return res.status(400).send('All fields are required.');
    }

    const sql = `
        INSERT INTO tolet_posts (user_id, title, description, price, location, image)
        VALUES (?, ?, ?, ?, ?, ?)
    `;
    db.query(sql, [req.session.user.id, title, description, price, location, imagePath], (err) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Error saving the post.');
        }
        res.redirect('/tolet');
    });
});

// Serve tolet.html
app.get('/tolet', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'tolet.html'));
});

// Fetch all To-Let posts with contact info
app.get('/api/tolet', (req, res) => {
    const sql = `
        SELECT tp.*, u.contact,u.username 
        FROM tolet_posts tp 
        JOIN user u ON tp.user_id = u.id
        ORDER BY created_at DESC
    `;
    db.query(sql, (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Error fetching posts.');
        }
        res.json(results);
    });
});
//for home page
app.get('/api/home-tolet', (req, res) => {
    const sql = `
        SELECT tp.*, u.contact,u.username 
        FROM tolet_posts tp 
        JOIN user u ON tp.user_id = u.id
        ORDER BY created_at DESC
        LIMIT 1
    `;
    db.query(sql, (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Error fetching posts.');
        }
        res.json(results);
    });
});
// Handle "Interested" button click
app.post('/tolet/interested', (req, res) => {
    if (!req.session.user) {
        return res.status(401).send('Please log in to express interest.');
    }

    const { postId } = req.body;
    const userId = req.session.user.id;

    const sql = "INSERT INTO interested_users (post_id, user_id) VALUES (?, ?)";
    db.query(sql, [postId, userId], (err) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Error expressing interest.');
        }
        res.send('Interest expressed successfully.');
    });
});
//update tolet post
// Middleware to authenticate and set req.user
function authenticate(req, res, next) {
    const token = req.header('Authorization')?.replace('Bearer ', ''); // Extract token from header
    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }

    jwt.verify(token, 'your_jwt_secret', (err, decoded) => {
        if (err) {
            return res.status(401).json({ error: 'Invalid or expired token' });
        }
        req.user = decoded; // decoded contains the user info
        next(); // Call the next middleware or route handler
    });
}

// Update a to-let post
app.get('/api/my-posts', (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ error: 'Unauthorized. Please log in.' });
    }

    const sql = `
        SELECT * FROM tolet_posts
        WHERE user_id = ?
        ORDER BY created_at DESC
    `;
    db.query(sql, [req.session.user.id], (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ error: 'Error fetching user posts. Please try again later.' });
        }
        res.status(200).json(results);
    });
});
app.put("/api/update-post/:id", (req, res) => {
    const postId = req.params.id;
    const { title, description, location, price } = req.body;
    console.log(req.body);

    //sconst image = req.file ? `/uploads/${req.file.filename}` : null;

    const sql = "UPDATE tolet_posts SET title = ?, description = ?, location = ?, price = ? WHERE id = ?";
    db.query(sql, [title, description, location, price, postId], (err, result) => {
        if (err) {
            console.error("Error updating post:", err);
            res.status(500).send("Failed to update post.");
            return;
        }
        res.send("Post updated successfully.");
    });
});

app.delete('/api/delete-post/:id', (req, res) => {
    if (!req.session.user) {
        return res.status(401).send('Unauthorized. Please log in.');
    }

    const postId = req.params.id;
    const sql = `
        DELETE FROM tolet_posts
        WHERE id = ? AND user_id = ?
    `;
    db.query(sql, [postId, req.session.user.id], (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Error deleting post.');
        }
        if (result.affectedRows === 0) {
            return res.status(404).send('Post not found or unauthorized.');
        }
        res.status(200).send('Post deleted successfully.');
    });
});
// Handle To-Let post submission
app.post('/add-item', upload.single('image'), (req, res) => {
    const { title, description, price, location } = req.body;
    const imagePath = req.file ? `/uploads/${req.file.filename}` : null;

    // Basic validation
    if (!title || !description || !price || !location) {
        return res.status(400).send('All fields except image are required.');
    }

    // Check if user is authenticated
    if (!req.session.user || !req.session.user.id) {
        return res.status(401).send('Unauthorized. Please log in.');
    }

    const sql = `
        INSERT INTO posts (user_id, title, description, price, location, image)
        VALUES (?, ?, ?, ?, ?, ?)
    `;
    db.query(sql, [req.session.user.id, title, description, price, location, imagePath], (err) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).send('Error saving the post.');
        }
        res.redirect('/buysell');
    });
});

// Serve buysell.html
app.get('/buysell', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'buysell.html'));
});

// Fetch all To-Let posts with contact info
app.get('/api/buy', (req, res) => {
    const sql = `
        SELECT tp.*, u.contact,u.username 
        FROM posts tp 
        JOIN user u ON tp.user_id = u.id
        ORDER BY created_at DESC
    `;
    db.query(sql, (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Error fetching posts.');
        }
        res.json(results);
    });
});
//for home page
app.get('/api/home-item', (req, res) => {
    const sql = `
        SELECT tp.*, u.contact,u.username 
        FROM posts tp 
        JOIN user u ON tp.user_id = u.id
        ORDER BY created_at DESC
        LIMIT 1
    `;
    db.query(sql, (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Error fetching posts.');
        }
        res.json(results);
    });
});

app.get('/api/item/:id', (req, res) => {
    const itemId = req.params.id;

    const sql = `
        SELECT posts.*, user.username, user.contact 
        FROM posts 
        JOIN user ON posts.user_id = user.id 
        WHERE posts.id = ?
    `;

    db.query(sql, [itemId], (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Error retrieving item details.');
        }

        res.json(results[0] || null); // Send the item or null if not found
    });
});
//sell post in my profile
app.get('/api/my-itemposts', (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ error: 'Unauthorized. Please log in.' });
    }

    const sql = `
        SELECT * FROM posts
        WHERE user_id = ?
        ORDER BY created_at DESC
    `;
    db.query(sql, [req.session.user.id], (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ error: 'Error fetching user posts. Please try again later.' });
        }
        res.status(200).json(results);
    });
});
app.put("/api/update-itempost/:id", (req, res) => {
    const postId = req.params.id;
    const { title, description, location, price } = req.body;
    console.log(req.body);

    //sconst image = req.file ? `/uploads/${req.file.filename}` : null;

    const sql = "UPDATE posts SET title = ?, description = ?, location = ?, price = ? WHERE id = ?";
    db.query(sql, [title, description, location, price, postId], (err, result) => {
        if (err) {
            console.error("Error updating post:", err);
            res.status(500).send("Failed to update post.");
            return;
        }
        res.send("Post updated successfully.");
    });
});

app.delete('/api/delete-itempost/:id', (req, res) => {
    if (!req.session.user) {
        return res.status(401).send('Unauthorized. Please log in.');
    }

    const postId = req.params.id;
    const sql = `
        DELETE FROM posts
        WHERE id = ? AND user_id = ?
    `;
    db.query(sql, [postId, req.session.user.id], (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Error deleting post.');
        }
        if (result.affectedRows === 0) {
            return res.status(404).send('Post not found or unauthorized.');
        }
        res.status(200).send('Post deleted successfully.');
    });
});
// API to get users and groups
// Fetch all users
app.get('/api/get-users', (req, res) => {
    const query = 'SELECT id, name FROM user';
    db.query(query, (err, results) => {
        if (err) return res.status(500).json({ error: 'Failed to fetch users' });
        res.json(results);
    });
});

// Fetch chat messages between two users
app.get('/api/get-messages', (req, res) => {
    const { senderId, recipientId } = req.query;

    if (!senderId || !recipientId) {
        return res.status(400).json({ error: 'Sender and recipient IDs are required.' });
    }

    const query = `
        SELECT m.sender_id AS senderId, m.recipient_id AS recipientId, m.message, m.created_at, 
               u1.name AS senderName, u2.name AS recipientName
        FROM messages m
        LEFT JOIN user u1 ON m.sender_id = u1.id
        LEFT JOIN user u2 ON m.recipient_id = u2.id
        WHERE (m.sender_id = ? AND m.recipient_id = ?)
           OR (m.sender_id = ? AND m.recipient_id = ?)
        ORDER BY m.created_at ASC
    `;

    db.query(query, [senderId, recipientId, recipientId, senderId], (err, results) => {
        if (err) {
            console.error('Error fetching messages:', err);
            return res.status(500).json({ error: 'Internal server error' });
        }

        console.log('Fetched messages from DB:', results);

        if (results.length > 0) {
            return res.json(results);
        } else {
            return res.json({ message: 'No messages found' });
        }
    });
});



// Send a message
app.post('/api/send-message', (req, res) => {
    const { senderId, recipientId, text } = req.body;
    console.log('Message received:', { senderId, recipientId, text }); // Debug log

    if (!senderId || !recipientId || !text) {
        return res.status(400).json({ error: 'Invalid data' });
    }

    const query = 'INSERT INTO messages (sender_id, recipient_id, message) VALUES (?, ?, ?)';
    db.query(query, [senderId, recipientId, text], (err, result) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Failed to send message' });
        }

        const message = { senderId, recipientId, text, timestamp: new Date() };
        io.to(recipientId.toString()).emit('new-message', message); // Emit to recipient
        res.status(201).json({ success: true, message });
    });
});


// Socket.IO for Real-Time Messaging
io.on('connection', (socket) => {
    console.log(`User connected: ${socket.id}`);

    // Handle user joining
    socket.on('join', (userId) => {
        // Store the user's socket ID in the database
        const query = 'UPDATE user SET socket_id = ? WHERE id = ?';
        db.query(query, [socket.id, userId], (err) => {
            if (err) console.error('Failed to update user socket ID:', err);
        });
        console.log(`User ${userId} joined their room`);
    });

    // Handle disconnection
    socket.on('disconnect', () => {
        console.log(`User disconnected: ${socket.id}`);

        // Clear the socket ID from the database
        const query = 'UPDATE user SET socket_id = NULL WHERE socket_id = ?';
        db.query(query, [socket.id], (err) => {
            if (err) console.error('Failed to clear user socket ID:', err);
        });
    });
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
