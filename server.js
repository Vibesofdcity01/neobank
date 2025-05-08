const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');

const app = express();
app.use(cors({
    origin: 'https://mellifluous-kataifi-1cca0c.netlify.app',
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    credentials: true
}));
app.use(express.json());

// Initialize SQLite database
const db = new sqlite3.Database(':memory:');
db.serialize(() => {
    db.run(`CREATE TABLE users (
        email TEXT PRIMARY KEY,
        name TEXT,
        password TEXT,
        balance REAL,
        role TEXT,
        status TEXT DEFAULT 'pending'
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

const SECRET_KEY = process.env.SECRET_KEY || 'your-secret-key-secure-this-in-production';

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
        VALUES (?, ?, ?, ?, ?)`, [userEmail, type, amount, details, date], (err) => {
        if (err) console.error('Error logging transaction:', err);
    });
}

app.post('/api/register', async (req, res) => {
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ message: 'All fields required' });
    try {
        db.get('SELECT email FROM users WHERE email = ?', [email], async (err, row) => {
            if (err) return res.status(500).json({ message: 'Database error' });
            if (row) return res.status(400).json({ message: 'Email already exists' });
            const hashedPassword = await bcrypt.hash(password, 10);
            db.run('INSERT INTO users (email, name, password, balance, role, status) VALUES (?, ?, ?, ?, ?, ?)',
                [email, name, hashedPassword, 0, 'user', 'pending'], (err) => {
                    if (err) return res.status(500).json({ message: 'Error registering user' });
                    const token = jwt.sign({ email, role: 'user' }, SECRET_KEY);
                    res.json({ token });
                });
        });
    } catch (error) {
        console.error('Error in /register:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: 'Email and password required' });
    db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
        if (err) return res.status(500).json({ message: 'Database error' });
        if (!user) return res.status(400).json({ message: 'User not found' });
        if (user.status === 'pending') return res.status(403).json({ message: 'Account pending approval' });
        if (user.status === 'blocked') return res.status(403).json({ message: 'Account blocked' });
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(400).json({ message: 'Invalid password' });
        const token = jwt.sign({ email: user.email, role: user.role }, SECRET_KEY);
        res.json({ token, user: { name: user.name, balance: user.balance, role: user.role, status: user.status } });
    });
});

app.get('/api/me', authenticateToken, (req, res) => {
    db.get('SELECT email, name, balance, role, status FROM users WHERE email = ?', [req.user.email], (err, user) => {
        if (err) return res.status(500).json({ message: 'Database error' });
        if (!user) return res.status(404).json({ message: 'User not found' });
        res.json(user);
    });
});

app.get('/api/users', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: 'Admin access required' });
    db.all('SELECT email, name, balance, status FROM users WHERE role = ? ORDER BY email', ['user'], (err, users) => {
        if (err) return res.status(500).json({ message: 'Database error' });
        res.json(users || []);
    });
});

app.put('/api/users/:email/status', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: 'Admin access required' });
    const { status } = req.body;
    if (!['active', 'pending', 'blocked'].includes(status)) return res.status(400).json({ message: 'Invalid status' });
    db.run('UPDATE users SET status = ? WHERE email = ?', [status, req.params.email], (err) => {
        if (err) return res.status(500).json({ message: 'Database error' });
        res.json({ success: true });
    });
});

app.delete('/api/users/:email', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: 'Admin access required' });
    db.run('DELETE FROM users WHERE email = ?', [req.params.email], (err) => {
        if (err) return res.status(500).json({ message: 'Database error' });
        db.run('DELETE FROM transactions WHERE userEmail = ?', [req.params.email], (err) => {
            if (err) console.error('Error deleting transactions:', err);
        });
        res.json({ success: true });
    });
});

app.post('/api/admin/add-balance', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: 'Admin access required' });
    const { email, amount } = req.body;
    if (!email || !amount || amount <= 0) return res.status(400).json({ message: 'Invalid email or amount' });
    db.get('SELECT email, status FROM users WHERE email = ?', [email], (err, user) => {
        if (err) return res.status(500).json({ message: 'Database error' });
        if (!user) return res.status(404).json({ message: 'User not found' });
        if (user.status !== 'active') return res.status(400).json({ message: 'User account not active' });
        db.run('UPDATE users SET balance = balance + ? WHERE email = ?', [amount, email], (err) => {
            if (err) return res.status(500).json({ message: 'Database error' });
            logTransaction(email, 'add-balance', amount, `Admin added $${amount}`);
            res.json({ success: true });
        });
    });
});

app.post('/api/admin/deduct-balance', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: 'Admin access required' });
    const { email, amount } = req.body;
    if (!email || !amount || amount <= 0) return res.status(400).json({ message: 'Invalid email or amount' });
    db.get('SELECT balance, status FROM users WHERE email = ?', [email], (err, user) => {
        if (err) return res.status(500).json({ message: 'Database error' });
        if (!user) return res.status(404).json({ message: 'User not found' });
        if (user.status !== 'active') return res.status(400).json({ message: 'User account not active' });
        if (user.balance < amount) return res.status(400).json({ message: 'Insufficient balance' });
        db.run('UPDATE users SET balance = balance - ? WHERE email = ?', [amount, email], (err) => {
            if (err) return res.status(500).json({ message: 'Database error' });
            logTransaction(email, 'deduct-balance', amount, `Admin deducted $${amount}`);
            res.json({ success: true });
        });
    });
});

app.post('/api/deposit', authenticateToken, (req, res) => {
    const { amount } = req.body;
    if (!amount || amount <= 0) return res.status(400).json({ message: 'Invalid amount' });
    db.get('SELECT status FROM users WHERE email = ?', [req.user.email], (err, user) => {
        if (err) return res.status(500).json({ message: 'Database error' });
        if (!user) return res.status(404).json({ message: 'User not found' });
        if (user.status !== 'active') return res.status(400).json({ message: 'Account not active' });
        res.json({ success: true, message: 'Please contact admin for deposit instructions.' });
    });
});

app.post('/api/confirm-deposit', authenticateToken, (req, res) => {
    const { amount } = req.body;
    if (!amount || amount <= 0) return res.status(400).json({ message: 'Invalid amount' });
    db.run('UPDATE users SET balance = balance + ? WHERE email = ?', [amount, req.user.email], (err) => {
        if (err) return res.status(500).json({ message: 'Database error' });
        logTransaction(req.user.email, 'deposit', amount, `Deposited $${amount}`);
        res.json({ success: true });
    });
});

app.post('/api/withdraw', authenticateToken, (req, res) => {
    const { amount } = req.body;
    if (!amount || amount <= 0) return res.status(400).json({ message: 'Invalid amount' });
    const fee = amount * 0.01;
    const totalDeduction = amount + fee;
    db.get('SELECT balance, status FROM users WHERE email = ?', [req.user.email], (err, user) => {
        if (err) return res.status(500).json({ message: 'Database error' });
        if (!user) return res.status(404).json({ message: 'User not found' });
        if (user.status !== 'active') return res.status(400).json({ message: 'Account not active' });
        if (user.balance < totalDeduction) return res.status(400).json({ message: 'Insufficient balance for withdrawal and fee' });
        res.json({ success: true, fee, totalDeduction, message: 'Please contact admin for payment method to cover the withdrawal fee.' });
    });
});

app.post('/api/transfer', authenticateToken, (req, res) => {
    const { toEmail, amount, type } = req.body;
    if (!toEmail || !amount || amount <= 0 || !['domestic', 'international'].includes(type)) return res.status(400).json({ message: 'Invalid email, amount, or transfer type' });
    const fee = amount * 0.01;
    const totalDeduction = amount + fee;
    db.get('SELECT balance, status FROM users WHERE email = ?', [req.user.email], (err, fromUser) => {
        if (err) return res.status(500).json({ message: 'Database error' });
        if (!fromUser) return res.status(404).json({ message: 'Sender not found' });
        if (fromUser.status !== 'active') return res.status(400).json({ message: 'Sender account not active' });
        if (fromUser.balance < totalDeduction) return res.status(400).json({ message: 'Insufficient balance for transfer and fee' });
        db.get('SELECT email, status FROM users WHERE email = ?', [toEmail], (err, toUser) => {
            if (err) return res.status(500).json({ message: 'Database error' });
            if (!toUser) return res.status(404).json({ message: 'Recipient not found' });
            if (toUser.status !== 'active') return res.status(400).json({ message: 'Recipient account not active' });
            res.json({ success: true, fee, totalDeduction, message: 'Please contact admin for payment method to cover the transfer fee.' });
        });
    });
});

app.post('/api/confirm-withdrawal', authenticateToken, (req, res) => {
    const { amount, totalDeduction } = req.body;
    if (!amount || amount <= 0) return res.status(400).json({ message: 'Invalid amount' });
    db.get('SELECT balance, status FROM users WHERE email = ?', [req.user.email], (err, user) => {
        if (err) return res.status(500).json({ message: 'Database error' });
        if (!user) return res.status(404).json({ message: 'User not found' });
        if (user.status !== 'active') return res.status(400).json({ message: 'Account not active' });
        if (user.balance < totalDeduction) return res.status(400).json({ message: 'Insufficient balance' });
        db.run('UPDATE users SET balance = balance - ? WHERE email = ?', [totalDeduction, req.user.email], (err) => {
            if (err) return res.status(500).json({ message: 'Database error' });
            logTransaction(req.user.email, 'withdrawal', amount, `Withdrew $${amount} with $${totalDeduction - amount} fee`);
            res.json({ success: true });
        });
    });
});

app.post('/api/confirm-transfer', authenticateToken, (req, res) => {
    const { toEmail, amount, type, totalDeduction } = req.body;
    if (!toEmail || !amount || amount <= 0 || !['domestic', 'international'].includes(type)) return res.status(400).json({ message: 'Invalid email, amount, or transfer type' });
    db.get('SELECT balance, status FROM users WHERE email = ?', [req.user.email], (err, fromUser) => {
        if (err) return res.status(500).json({ message: 'Database error' });
        if (!fromUser) return res.status(404).json({ message: 'Sender not found' });
        if (fromUser.status !== 'active') return res.status(400).json({ message: 'Sender account not active' });
        if (fromUser.balance < totalDeduction) return res.status(400).json({ message: 'Insufficient balance' });
        db.get('SELECT email, status FROM users WHERE email = ?', [toEmail], (err, toUser) => {
            if (err) return res.status(500).json({ message: 'Database error' });
            if (!toUser) return res.status(404).json({ message: 'Recipient not found' });
            if (toUser.status !== 'active') return res.status(400).json({ message: 'Recipient account not active' });
            db.run('UPDATE users SET balance = balance - ? WHERE email = ?', [totalDeduction, req.user.email], (err) => {
                if (err) return res.status(500).json({ message: 'Database error' });
                db.run('UPDATE users SET balance = balance + ? WHERE email = ?', [amount, toEmail], (err) => {
                    if (err) return res.status(500).json({ message: 'Database error' });
                    logTransaction(req.user.email, 'transfer', amount, `Transferred $${amount} (${type}) to ${toEmail} with $${totalDeduction - amount} fee`);
                    logTransaction(toEmail, 'transfer', amount, `Received $${amount} (${type}) from ${req.user.email}`);
                    res.json({ success: true });
                });
            });
        });
    });
});

app.get('/api/transactions', authenticateToken, (req, res) => {
    db.all('SELECT * FROM transactions WHERE userEmail = ? ORDER BY date DESC', [req.user.email], (err, transactions) => {
        if (err) return res.status(500).json({ message: 'Database error' });
        res.json(transactions || []);
    });
});

app.get('/api/admin/transactions', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: 'Admin access required' });
    db.all('SELECT * FROM transactions ORDER BY date DESC', [], (err, transactions) => {
        if (err) return res.status(500).json({ message: 'Database error' });
        res.json(transactions || []);
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
