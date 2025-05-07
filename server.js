const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

const db = new sqlite3.Database(':memory:');
db.serialize(() => {
    db.run(`CREATE TABLE users (
        email TEXT PRIMARY KEY,
        name TEXT,
        password TEXT,
        balance REAL,
        role TEXT,
        status TEXT DEFAULT 'active'
    )`);
    db.run(`CREATE TABLE transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        userEmail TEXT,
        type TEXT,
        amount REAL,
        details TEXT,
        date TEXT,
        FOREIGN KEY(userEmail) REFERENCES users(email)
    )`);
    const adminPassword = bcrypt.hashSync('admin123', 10);
    db.run(`INSERT INTO users (email, name, password, balance, role, status)
        VALUES ('admin@neobank.com', 'Admin', ?, 0, 'admin', 'active')`, [adminPassword]);
});

const SECRET_KEY = 'your-secret-key-secure-this-in-production';

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Token required' });
    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.status(403).json({ message: 'Invalid token' });
        req.user = user;
        next();
    });
}

function logTransaction(userEmail, type, amount, details) {
    const date = new Date().toISOString();
    db.run(`INSERT INTO transactions (userEmail, type, amount, details, date)
        VALUES (?, ?, ?, ?, ?)`, [userEmail, type, amount, details, date]);
}

app.post('/api/register', async (req, res) => {
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ message: 'All fields required' });
    try {
        db.get('SELECT email FROM users WHERE email = ?', [email], async (err, row) => {
            if (row) return res.status(400).json({ message: 'Email already exists' });
            const hashedPassword = await bcrypt.hash(password, 10);
            db.run('INSERT INTO users (email, name, password, balance, role, status) VALUES (?, ?, ?, ?, ?, ?)',
                [email, name, hashedPassword, 1000, 'user', 'active'], (err) => {
                    if (err) return res.status(500).json({ message: 'Error registering user' });
                    const token = jwt.sign({ email, role: 'user' }, SECRET_KEY);
                    res.json({ token });
                });
        });
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
        if (!user) return res.status(400).json({ message: 'User not found' });
        if (user.status !== 'active') return res.status(403).json({ message: 'Account suspended' });
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(400).json({ message: 'Invalid password' });
        const token = jwt.sign({ email: user.email, role: user.role }, SECRET_KEY);
        res.json({ token, user: { name: user.name, balance: user.balance, role: user.role } });
    });
});

app.get('/api/me', authenticateToken, (req, res) => {
    db.get('SELECT email, name, balance, role, status FROM users WHERE email = ?', [req.user.email], (err, user) => {
        if (err || !user) return res.status(500).json({ message: 'Error fetching user' });
        res.json(user);
    });
});

app.get('/api/users', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: 'Admin access required' });
    db.all('SELECT email, name, balance, status FROM users WHERE role = ?', ['user'], (err, users) => {
        if (err) return res.status(500).json({ message: 'Error fetching users' });
        res.json(users);
    });
});

app.put('/api/users/:email/status', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: 'Admin access required' });
    const { status } = req.body;
    if (!['active', 'suspended'].includes(status)) return res.status(400).json({ message: 'Invalid status' });
    db.run('UPDATE users SET status = ? WHERE email = ?', [status, req.params.email], (err) => {
        if (err) return res.status(500).json({ message: 'Error updating status' });
        res.json({ success: true });
    });
});

app.delete('/api/users/:email', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: 'Admin access required' });
    db.run('DELETE FROM users WHERE email = ?', [req.params.email], (err) => {
        if (err) return res.status(500).json({ message: 'Error deleting user' });
        db.run('DELETE FROM transactions WHERE userEmail = ?', [req.params.email]);
        res.json({ success: true });
    });
});

app.post('/api/admin/topup', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: 'Admin access required' });
    const { email, amount } = req.body;
    if (!email || !amount || amount <= 0) return res.status(400).json({ message: 'Invalid email or amount' });
    db.get('SELECT email, status FROM users WHERE email = ?', [email], (err, user) => {
        if (err || !user) return res.status(400).json({ message: 'User not found' });
        if (user.status !== 'active') return res.status(400).json({ message: 'User account suspended' });
        db.run('UPDATE users SET balance = balance + ? WHERE email = ?', [amount, email], (err) => {
            if (err) return res.status(500).json({ message: 'Error topping up balance' });
            logTransaction(email, 'topup', amount, `Admin topped up $${amount}`);
            res.json({ success: true });
        });
    });
});

app.get('/api/transactions', authenticateToken, (req, res) => {
    db.all('SELECT * FROM transactions WHERE userEmail = ? ORDER BY date DESC', [req.user.email], (err, transactions) => {
        if (err) return res.status(500).json({ message: 'Error fetching transactions' });
        res.json(transactions);
    });
});

app.get('/api/admin/transactions', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: 'Admin access required' });
    db.all('SELECT * FROM transactions ORDER BY date DESC', [], (err, transactions) => {
        if (err) return res.status(500).json({ message: 'Error fetching transactions' });
        res.json(transactions);
    });
});

app.listen(3000, () => console.log('Server running on port 3000'));
