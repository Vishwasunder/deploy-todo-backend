const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');

// Initialize Express
const app = express();
app.use(express.json());
app.use(cors());

// Setup SQLite in-memory database
const db = new sqlite3.Database(':memory:');

// Create tables
db.serialize(() => {
  db.run(`
    CREATE TABLE users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL
    )
  `);

  db.run(`
    CREATE TABLE todos (
      id TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL,
      title TEXT NOT NULL,
      status TEXT DEFAULT 'pending',
      FOREIGN KEY(user_id) REFERENCES users(id)
    )
  `);
});

// JWT Secret and Port Configuration
const JWT_SECRET = 'mysecretkey'; // Replace with a stronger secret for production
const PORT = 5000;

// Middleware for authenticating JWT token
const authenticateToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Access token required' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });
    req.user = user;
    next();
  });
};

// Register new user
app.post('/api/signup', async (req, res) => {
  const { name, email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  db.run(`INSERT INTO users (name, email, password) VALUES (?, ?, ?)`, [name, email, hashedPassword], function(err) {
    if (err) return res.status(400).json({ message: 'User already exists' });
    const token = jwt.sign({ id: this.lastID, email, name }, JWT_SECRET);
    res.json({ token });
  });
});

// Login user
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;

  db.get(`SELECT * FROM users WHERE email = ?`, [email], async (err, user) => {
    if (err || !user) return res.status(400).json({ message: 'Invalid email or password' });

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(400).json({ message: 'Invalid email or password' });

    const token = jwt.sign({ id: user.id, email: user.email, name: user.name }, JWT_SECRET);
    res.json({ token });
  });
});

// Get Todos
app.get('/api/todos', authenticateToken, (req, res) => {
  const userId = req.user.id;

  db.all(`SELECT * FROM todos WHERE user_id = ?`, [userId], (err, todos) => {
    if (err) return res.status(500).json({ message: 'Error fetching todos' });
    res.json(todos);
  });
});

// Create new Todo
app.post('/api/todos', authenticateToken, (req, res) => {
  const { title } = req.body;
  const userId = req.user.id;
  const id = uuidv4();

  db.run(`INSERT INTO todos (id, user_id, title) VALUES (?, ?, ?)`, [id, userId, title], function(err) {
    if (err) return res.status(500).json({ message: 'Error creating todo' });
    res.json({ id, userId, title, status: 'pending' });
  });
});

// Update Todo
app.put('/api/todos/:id', authenticateToken, (req, res) => {
  const { title, status } = req.body;
  const todoId = req.params.id;

  db.run(`UPDATE todos SET title = ?, status = ? WHERE id = ?`, [title, status, todoId], function(err) {
    if (err) return res.status(500).json({ message: 'Error updating todo' });
    res.json({ message: 'Todo updated successfully' });
  });
});

// Delete Todo
app.delete('/api/todos/:id', authenticateToken, (req, res) => {
  const todoId = req.params.id;

  db.run(`DELETE FROM todos WHERE id = ?`, [todoId], function(err) {
    if (err) return res.status(500).json({ message: 'Error deleting todo' });
    res.json({ message: 'Todo deleted successfully' });
  });
});

// Update user profile
app.put('/api/profile', authenticateToken, async (req, res) => {
  const { name, email, password } = req.body;
  const userId = req.user.id;

  db.get(`SELECT * FROM users WHERE id = ?`, [userId], async (err, user) => {
    if (err || !user) return res.status(404).json({ message: 'User not found' });

    user.name = name || user.name;
    user.email = email || user.email;

    if (password) {
      user.password = await bcrypt.hash(password, 10);
    }

    db.run(`UPDATE users SET name = ?, email = ?, password = ? WHERE id = ?`, [user.name, user.email, user.password, userId], function(err) {
      if (err) return res.status(500).json({ message: 'Error updating profile' });
      res.json({ message: 'Profile updated successfully', user: { name: user.name, email: user.email } });
    });
  });
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
