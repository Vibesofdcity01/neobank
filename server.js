const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const cors = require('cors');

const app = express();
app.use(cors({
    origin: 'https://mellifluous-kataifi-1cca0c.netlify.app',
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    credentials: true
}));
app.use(express.json());

// Initialize PostgreSQL connection
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// Create tables if they don't exist
const initializeDatabase = async () => {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                email TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                password TEXT NOT NULL,
                balance REAL DEFAULT 0,
                role TEXT NOT NULL,
                status TEXT DEFAULT 'pending'
            )
        `);
        await pool.query(`
            CREATE TABLE IF NOT EXISTS transactions (
                id SERIAL PRIMARY KEY,
                userEmail TEXT NOT NULL,
                type TEXT NOT NULL,
                amount REAL NOT NULL,
                details TEXT NOT NULL,
                date TEXT NOT NULL,
                FOREIGN KEY (userEmail) REFERENCES users(email)
            )
        `);
        // Seed admin user if not exists
        const adminPassword = await bcrypt.hash('admin123', 10);
        await pool.query(`
            INSERT INTO users (email, name, password, balance, role, status)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (email) DO NOTHING
        `, ['admin@neobank.com', 'Admin', adminPassword, 0, 'admin', 'active']);
    } catch (error) {
        console.error('Error initializing database:', error);
    }
};
initializeDatabase();

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
    pool.query(
        'INSERT INTO transactions (userEmail, type, amount, details, date) VALUES ($1, $2, $3, $4, $5)',
        [userEmail, type, amount, details, date],
        (err) => {
            if (err) console.error('Error logging transaction:', err);
        }
    );
}

app.post('/api/register', async (req, res) => {
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ message: 'All fields required' });
    try {
        const { rows: existingUsers } = await pool.query('SELECT email FROM users WHERE email = $1', [email]);
        if (existingUsers.length > 0) return res.status(400).json({ message: 'Email already exists' });
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.query(
            'INSERT INTO users (email, name, password, balance, role, status) VALUES ($1, $2, $3, $4, $5, $6)',
            [email, name, hashedPassword, 0, 'user', 'pending']
        );
        const token = jwt.sign({ email, role: 'user' }, SECRET_KEY);
        res.json({ token });
    } catch (error) {
        console.error('Error in /register:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: 'Email and password required' });
    try {
        const { rows: users } = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (users.length === 0) return res.status(400).json({ message: 'User not found' });
        const user = users[0];
        if (user.status === 'pending') return res.status(403).json({ message: 'Account pending approval' });
        if (user.status === 'blocked') return res.status(403).json({ message: 'Account blocked' });
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(400).json({ message: 'Invalid password' });
        const token = jwt.sign({ email: user.email, role: user.role }, SECRET_KEY);
        res.json({ token, user: { name: user.name, balance: user.balance, role: user.role, status: user.status } });
    } catch (error) {
        console.error('Error in /login:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.get('/api/me', authenticateToken, async (req, res) => {
    try {
        const { rows: users } = await pool.query('SELECT email, name, balance, role, status FROM users WHERE email = $1', [req.user.email]);
        if (users.length === 0) return res.status(404).json({ message: 'User not found' });
        res.json(users[0]);
    } catch (error) {
        console.error('Error in /me:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.get('/api/users', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: 'Admin access required' });
    try {
        const { rows: users } = await pool.query('SELECT email, name, balance, status FROM users WHERE role = $1 ORDER BY email', ['user']);
        res.json(users || []);
    } catch (error) {
        console.error('Error in /users:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.put('/api/users/:email/status', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: 'Admin access required' });
    const { status } = req.body;
    if (!['active', 'pending', 'blocked'].includes(status)) return res.status(400).json({ message: 'Invalid status' });
    try {
        await pool.query('UPDATE users SET status = $1 WHERE email = $2', [status, req.params.email]);
        res.json({ success: true });
    } catch (error) {
        console.error('Error in /users/:email/status:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.delete('/api/users/:email', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: 'Admin access required' });
    try {
        await pool.query('DELETE FROM transactions WHERE userEmail = $1', [req.params.email]);
        await pool.query('DELETE FROM users WHERE email = $1', [req.params.email]);
        res.json({ success: true });
    } catch (error) {
        console.error('Error in /users/:email DELETE:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/admin/add-balance', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: 'Admin access required' });
    const { email, amount } = req.body;
    if (!email || !amount || amount <= 0) return res.status(400).json({ message: 'Invalid email or amount' });
    try {
        const { rows: users } = await pool.query('SELECT email, status FROM users WHERE email = $1', [email]);
        if (users.length === 0) return res.status(404).json({ message: 'User not found' });
        const user = users[0];
        if (user.status !== 'active') return res.status(400).json({ message: 'User account not active' });
        await pool.query('UPDATE users SET balance = balance + $1 WHERE email = $2', [amount, email]);
        logTransaction(email, 'add-balance', amount, `Admin added $${amount}`);
        res.json({ success: true });
    } catch (error) {
        console.error('Error in /admin/add-balance:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/admin/deduct-balance', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: 'Admin access required' });
    const { email, amount } = req.body;
    if (!email || !amount || amount <= 0) return res.status(400).json({ message: 'Invalid email or amount' });
    try {
        const { rows: users } = await pool.query('SELECT balance, status FROM users WHERE email = $1', [email]);
        if (users.length === 0) return res.status(404).json({ message: 'User not found' });
        const user = users[0];
        if (user.status !== 'active') return res.status(400).json({ message: 'User account not active' });
        if (user.balance < amount) return res.status(400).json({ message: 'Insufficient balance' });
        await pool.query('UPDATE users SET balance = balance - $1 WHERE email = $2', [amount, email]);
        logTransaction(email, 'deduct-balance', amount, `Admin deducted $${amount}`);
        res.json({ success: true });
    } catch (error) {
        console.error('Error in /admin/deduct-balance:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/deposit', authenticateToken, async (req, res) => {
    const { amount } = req.body;
    if (!amount || amount <= 0) return res.status(400).json({ message: 'Invalid amount' });
    try {
        const { rows: users } = await pool.query('SELECT status FROM users WHERE email = $1', [req.user.email]);
        if (users.length === 0) return res.status(404).json({ message: 'User not found' });
        const user = users[0];
        if (user.status !== 'active') return res.status(400).json({ message: 'Account not active' });
        res.json({ success: true, message: 'Please contact admin for deposit instructions.' });
    } catch (error) {
        console.error('Error in /deposit:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/confirm-deposit', authenticateToken, async (req, res) => {
    const { amount } = req.body;
    if (!amount || amount <= 0) return res.status(400).json({ message: 'Invalid amount' });
    try {
        await pool.query('UPDATE users SET balance = balance + $1 WHERE email = $2', [amount, req.user.email]);
        logTransaction(req.user.email, 'deposit', amount, `Deposited $${amount}`);
        res.json({ success: true });
    } catch (error) {
        console.error('Error in /confirm-deposit:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/withdraw', authenticateToken, async (req, res) => {
    const { amount } = req.body;
    if (!amount || amount <= 0) return res.status(400).json({ message: 'Invalid amount' });
    const fee = amount * 0.01;
    const totalDeduction = amount + fee;
    try {
        const { rows: users } = await pool.query('SELECT balance, status FROM users WHERE email = $1', [req.user.email]);
        if (users.length === 0) return res.status(404).json({ message: 'User not found' });
        const user = users[0];
        if (user.status !== 'active') return res.status(400).json({ message: 'Account not active' });
        if (user.balance < totalDeduction) return res.status(400).json({ message: 'Insufficient balance for withdrawal and fee' });
        res.json({ success: true, fee, totalDeduction, message: 'Please contact admin for payment method to cover the withdrawal fee.' });
    } catch (error) {
        console.error('Error in /withdraw:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/transfer', authenticateToken, async (req, res) => {
    const { toEmail, amount, type } = req.body;
    if (!toEmail || !amount || amount <= 0 || !['domestic', 'international'].includes(type)) return res.status(400).json({ message: 'Invalid email, amount, or transfer type' });
    const fee = amount * 0.01;
    const totalDeduction = amount + fee;
    try {
        const { rows: senderUsers } = await pool.query('SELECT balance, status FROM users WHERE email = $1', [req.user.email]);
        if (senderUsers.length === 0) return res.status(404).json({ message: 'Sender not found' });
        const sender = senderUsers[0];
        if (sender.status !== 'active') return res.status(400).json({ message: 'Sender account not active' });
        if (sender.balance < totalDeduction) return res.status(400).json({ message: 'Insufficient balance for transfer and fee' });
        const { rows: recipientUsers } = await pool.query('SELECT email, status FROM users WHERE email = $1', [toEmail]);
        if (recipientUsers.length === 0) return res.status(404).json({ message: 'Recipient not found' });
        const recipient = recipientUsers[0];
        if (recipient.status !== 'active') return res.status(400).json({ message: 'Recipient account not active' });
        res.json({ success: true, fee, totalDeduction, message: 'Please contact admin for payment method to cover the transfer fee.' });
    } catch (error) {
        console.error('Error in /transfer:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/confirm-withdrawal', authenticateToken, async (req, res) => {
    const { amount, totalDeduction } = req.body;
    if (!amount || amount <= 0) return res.status(400).json({ message: 'Invalid amount' });
    try {
        const { rows: users } = await pool.query('SELECT balance, status FROM users WHERE email = $1', [req.user.email]);
        if (users.length === 0) return res.status(404).json({ message: 'User not found' });
        const user = users[0];
        if (user.status !== 'active') return res.status(400).json({ message: 'Account not active' });
        if (user.balance < totalDeduction) return res.status(400).json({ message: 'Insufficient balance' });
        await pool.query('UPDATE users SET balance = balance - $1 WHERE email = $2', [totalDeduction, req.user.email]);
        logTransaction(req.user.email, 'withdrawal', amount, `Withdrew $${amount} with $${totalDeduction - amount} fee`);
        res.json({ success: true });
    } catch (error) {
        console.error('Error in /confirm-withdrawal:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/confirm-transfer', authenticateToken, async (req, res) => {
    const { toEmail, amount, type, totalDeduction } = req.body;
    if (!toEmail || !amount || amount <= 0 || !['domestic', 'international'].includes(type)) return res.status(400).json({ message: 'Invalid email, amount, or transfer type' });
    try {
        const { rows: senderUsers } = await pool.query('SELECT balance, status FROM users WHERE email = $1', [req.user.email]);
        if (senderUsers.length === 0) return res.status(404).json({ message: 'Sender not found' });
        const sender = senderUsers[0];
        if (sender.status !== 'active') return res.status(400).json({ message: 'Sender account not active' });
        if (sender.balance < totalDeduction) return res.status(400).json({ message: 'Insufficient balance' });
        const { rows: recipientUsers } = await pool.query('SELECT email, status FROM users WHERE email = $1', [toEmail]);
        if (recipientUsers.length === 0) return res.status(404).json({ message: 'Recipient not found' });
        const recipient = recipientUsers[0];
        if (recipient.status !== 'active') return res.status(400).json({ message: 'Recipient account not active' });
        await pool.query('UPDATE users SET balance = balance - $1 WHERE email = $2', [totalDeduction, req.user.email]);
        await pool.query('UPDATE users SET balance = balance + $1 WHERE email = $2', [amount, toEmail]);
        logTransaction(req.user.email, 'transfer', amount, `Transferred $${amount} (${type}) to ${toEmail} with $${totalDeduction - amount} fee`);
        logTransaction(toEmail, 'transfer', amount, `Received $${amount} (${type}) from ${req.user.email}`);
        res.json({ success: true });
    } catch (error) {
        console.error('Error in /confirm-transfer:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.get('/api/transactions', authenticateToken, async (req, res) => {
    try {
        const { rows: transactions } = await pool.query('SELECT * FROM transactions WHERE userEmail = $1 ORDER BY date DESC', [req.user.email]);
        res.json(transactions || []);
    } catch (error) {
        console.error('Error in /transactions:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.get('/api/admin/transactions', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: 'Admin access required' });
    try {
        const { rows: transactions } = await pool.query('SELECT * FROM transactions ORDER BY date DESC');
        res.json(transactions || []);
    } catch (error) {
        console.error('Error in /admin/transactions:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
