const express = require('express');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cors = require('cors');

const app = express();
app.use(cors({
  origin: ['http://localhost:8081', 'https://purerosa.web.app', 'https://purerosamilk.netlify.app'],
  credentials: true
}));
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://username:password@localhost:5432/yogurt_app',
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false,
});
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret';
const PORT = process.env.PORT || 3000;

// Middleware to authenticate token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) {
    console.log('Unauthorized: No token provided for', req.path);
    return res.status(401).json({ error: 'Unauthorized: No token provided' });
  }
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      console.log('Invalid token for', req.path, ':', err.message);
      return res.status(403).json({ error: `Invalid token: ${err.message}` });
    }
    req.user = user;
    console.log('Authenticated user:', user.email, 'for', req.path);
    next();
  });
};

// Middleware to restrict to admin role
const requireAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    console.log('Admin access denied for:', req.user.email, 'on', req.path);
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

// Register
app.post('/users', authenticateToken, requireAdmin, async (req, res) => {
  const { email, password, name, role } = req.body;
  if (!email || !password || !name || !role) {
    console.log('Missing fields in user creation:', req.body);
    return res.status(400).json({ error: 'All fields (email, password, name, role) are required' });
  }
  if (!['farmer', 'seller', 'admin'].includes(role)) {
    console.log('Invalid role in user creation:', role);
    return res.status(400).json({ error: 'Invalid role' });
  }
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (email, password, name, role, is_active) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (email) DO NOTHING RETURNING id, email, name, role, is_active',
      [email.toLowerCase(), hashedPassword, name, role, true]
    );
    if (result.rowCount === 0) {
      console.log('User already exists:', email);
      return res.status(400).json({ error: 'User already exists' });
    }
    console.log('User created:', email);
    res.status(201).json({ message: 'User created', user: result.rows[0] });
  } catch (err) {
    console.error('User creation error:', err);
    res.status(500).json({ error: 'Failed to create user' });
  }
});

// Login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    console.log('Missing credentials in login:', req.body);
    return res.status(400).json({ error: 'Email and password are required' });
  }
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email.toLowerCase()]);
    if (result.rows.length === 0) {
      console.log('User not found:', email);
      return res.status(401).json({ error: 'User not found' });
    }
    const user = result.rows[0];
    if (!user.is_active) {
      console.log('Inactive user attempted login:', email);
      return res.status(403).json({ error: 'User account is inactive' });
    }
    if (await bcrypt.compare(password, user.password)) {
      const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
      console.log('User logged in:', email);
      res.json({ token, role: user.role });
    } else {
      console.log('Invalid credentials for:', email);
      res.status(401).json({ error: 'Invalid credentials' });
    }
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Refresh Token
app.post('/refresh', async (req, res) => {
  const { token } = req.body;
  if (!token) {
    console.log('Missing token in refresh request');
    return res.status(400).json({ error: 'Token is required' });
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET, { ignoreExpiration: true });
    const result = await pool.query('SELECT role, is_active FROM users WHERE id = $1', [decoded.id]);
    if (result.rows.length === 0) {
      console.log('User not found for refresh:', decoded.id);
      return res.status(404).json({ error: 'User not found' });
    }
    if (!result.rows[0].is_active) {
      console.log('Inactive user attempted token refresh:', decoded.id);
      return res.status(403).json({ error: 'User account is inactive' });
    }
    const newToken = jwt.sign({ id: decoded.id, email: decoded.email, role: result.rows[0].role }, JWT_SECRET, { expiresIn: '1h' });
    console.log('Token refreshed for:', decoded.email);
    res.json({ token: newToken, role: result.rows[0].role });
  } catch (err) {
    console.error('Token refresh error:', err);
    res.status(500).json({ error: `Failed to refresh token: ${err.message}` });
  }
});

// Submit Record (Farmer and Seller)
app.post('/records', authenticateToken, async (req, res) => {
  const { liters, price_per_liter, yogurt_type_id, amount_sold } = req.body;

  if (req.user.role === 'farmer') {
    if (!liters || liters <= 0 || (price_per_liter && price_per_liter < 0)) {
      console.log('Invalid data for farmer in /records:', req.body);
      return res.status(400).json({ error: 'Invalid liters or price_per_liter' });
    }
  } else if (req.user.role === 'seller') {
    if (!liters || liters <= 0 || !yogurt_type_id || !amount_sold || amount_sold < 0) {
      console.log('Invalid data for seller in /records:', req.body);
      return res.status(400).json({ error: 'Invalid liters, yogurt_type_id, or amount_sold' });
    }
  } else {
    console.log('Invalid role for /records:', req.user.role);
    return res.status(403).json({ error: 'Invalid user role' });
  }

  try {
    const result = await pool.query(
      'INSERT INTO records (user_id, liters, price_per_liter, yogurt_type_id, amount_sold, created_at, role) VALUES ($1, $2, $3, $4, $5, NOW(), $6) RETURNING id, user_id, liters, price_per_liter, yogurt_type_id, amount_sold, created_at, role',
      [
        req.user.id,
        liters,
        price_per_liter || null,
        yogurt_type_id || null,
        amount_sold || null,
        req.user.role
      ]
    );
    console.log('Record submitted by:', req.user.email, 'Role:', req.user.role, 'Data:', result.rows[0]);
    res.status(201).json({
      message: 'Record submitted successfully',
      data: result.rows[0]
    });
  } catch (err) {
    console.error('Record submission error:', err);
    res.status(500).json({ error: 'Failed to submit record' });
  }
});

// Fetch Records (Farmer, Seller, Admin)
app.get('/records', authenticateToken, async (req, res) => {
  try {
    let query = `
      SELECT r.id, r.user_id, r.liters, r.price_per_liter, r.yogurt_type_id, r.amount_sold, r.created_at, r.role, 
             u.name AS user_name, yt.name AS yogurt_type
      FROM records r
      JOIN users u ON r.user_id = u.id
      LEFT JOIN yogurt_types yt ON r.yogurt_type_id = yt.id
      WHERE r.user_id = $1
    `;
    const params = [req.user.id];
    if (req.user.role === 'admin') {
      query = `
        SELECT r.id, r.user_id, r.liters, r.price_per_liter, r.yogurt_type_id, r.amount_sold, r.created_at, r.role, 
               u.name AS user_name, yt.name AS yogurt_type
        FROM records r
        JOIN users u ON r.user_id = u.id
        LEFT JOIN yogurt_types yt ON r.yogurt_type_id = yt.id
        ORDER BY r.created_at DESC
      `;
      params.length = 0;
    }
    const result = await pool.query(query, params);
    console.log('Records fetched for:', req.user.email, 'Count:', result.rows.length);
    res.json(result.rows);
  } catch (err) {
    console.error('Fetch records error:', err);
    res.status(500).json({ error: 'Failed to fetch records' });
  }
});

// Update Record (Farmer, Seller, Admin)
app.put('/records/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { liters, price_per_liter, yogurt_type_id, amount_sold } = req.body;

  if (req.user.role === 'farmer') {
    if (!liters || liters <= 0 || (price_per_liter && price_per_liter < 0)) {
      console.log('Invalid data for farmer in /records update:', req.body);
      return res.status(400).json({ error: 'Invalid liters or price_per_liter' });
    }
  } else if (req.user.role === 'seller') {
    if (!liters || liters <= 0 || !yogurt_type_id || !amount_sold || amount_sold < 0) {
      console.log('Invalid data for seller in /records update:', req.body);
      return res.status(400).json({ error: 'Invalid liters, yogurt_type_id, or amount_sold' });
    }
  } else if (req.user.role !== 'admin') {
    console.log('Invalid role for /records update:', req.user.role);
    return res.status(403).json({ error: 'Invalid user role' });
  }

  try {
    let result;
    if (req.user.role === 'admin') {
      result = await pool.query(
        'UPDATE records SET liters = $1, price_per_liter = $2, yogurt_type_id = $3, amount_sold = $4, updated_at = NOW() WHERE id = $5 RETURNING *',
        [liters, price_per_liter || null, yogurt_type_id || null, amount_sold || null, id]
      );
    } else {
      result = await pool.query(
        'UPDATE records SET liters = $1, price_per_liter = $2, yogurt_type_id = $3, amount_sold = $4, updated_at = NOW() WHERE id = $5 AND user_id = $6 RETURNING *',
        [liters, price_per_liter || null, yogurt_type_id || null, amount_sold || null, id, req.user.id]
      );
    }
    if (result.rowCount === 0) {
      console.log('Record not found for update:', id);
      return res.status(404).json({ error: 'Record not found' });
    }
    console.log('Record updated by:', req.user.email, 'ID:', id);
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Update record error:', err);
    res.status(500).json({ error: 'Failed to update record' });
  }
});

// Delete Record (Admin)
app.delete('/records/:id', authenticateToken, requireAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query('DELETE FROM records WHERE id = $1 RETURNING *', [id]);
    if (result.rowCount === 0) {
      console.log('Record not found for deletion:', id);
      return res.status(404).json({ error: 'Record not found' });
    }
    console.log('Record deleted by:', req.user.email, 'ID:', id);
    res.json({ message: 'Record deleted successfully' });
  } catch (err) {
    console.error('Delete record error:', err);
    res.status(500).json({ error: 'Failed to delete record' });
  }
});

// Fetch Users (Admin)
app.get('/users', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, email, name, role, is_active FROM users ORDER BY name');
    console.log('Users fetched for:', req.user.email, 'Count:', result.rows.length);
    res.json(result.rows);
  } catch (err) {
    console.error('Fetch users error:', err);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// Update User Status (Admin)
app.patch('/users/:id', authenticateToken, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { is_active } = req.body;
  if (is_active === undefined) {
    console.log('Missing is_active in user update:', req.body);
    return res.status(400).json({ error: 'is_active field is required' });
  }
  try {
    const result = await pool.query(
      'UPDATE users SET is_active = $1 WHERE id = $2 RETURNING id, email, name, role, is_active',
      [is_active, id]
    );
    if (result.rowCount === 0) {
      console.log('User not found for status update:', id);
      return res.status(404).json({ error: 'User not found' });
    }
    console.log('User status updated by:', req.user.email, 'User ID:', id, 'Active:', is_active);
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Update user status error:', err);
    res.status(500).json({ error: 'Failed to update user status' });
  }
});

// Update User Details (Admin)
app.put('/users/:id', authenticateToken, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { name, email, role } = req.body;
  if (!name || !email || !role) {
    console.log('Missing fields in user update:', req.body);
    return res.status(400).json({ error: 'Name, email, and role are required' });
  }
  if (!['farmer', 'seller', 'admin'].includes(role)) {
    console.log('Invalid role in user update:', role);
    return res.status(400).json({ error: 'Invalid role' });
  }
  try {
    const result = await pool.query(
      'UPDATE users SET name = $1, email = $2, role = $3 WHERE id = $4 RETURNING id, email, name, role, is_active',
      [name, email.toLowerCase(), role, id]
    );
    if (result.rowCount === 0) {
      console.log('User not found for update:', id);
      return res.status(404).json({ error: 'User not found' });
    }
    console.log('User updated by:', req.user.email, 'User ID:', id);
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Update user error:', err);
    res.status(500).json({ error: 'Failed to update user' });
  }
});

// Delete User (Admin)
app.delete('/users/:id', authenticateToken, requireAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query('DELETE FROM users WHERE id = $1 RETURNING *', [id]);
    if (result.rowCount === 0) {
      console.log('User not found for deletion:', id);
      return res.status(404).json({ error: 'User not found' });
    }
    console.log('User deleted by:', req.user.email, 'User ID:', id);
    res.json({ message: 'User deleted successfully' });
  } catch (err) {
    console.error('Delete user error:', err);
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

// Fetch User-Specific Records (Admin)
app.get('/users/:id/records', authenticateToken, requireAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query(
      `
      SELECT r.id, r.user_id, r.liters, r.price_per_liter, r.yogurt_type_id, r.amount_sold, r.created_at, r.role, 
             u.name AS user_name, yt.name AS yogurt_type
      FROM records r
      JOIN users u ON r.user_id = u.id
      LEFT JOIN yogurt_types yt ON r.yogurt_type_id = yt.id
      WHERE r.user_id = $1
      ORDER BY r.created_at DESC
    `,
      [id]
    );
    console.log('User records fetched for:', req.user.email, 'User ID:', id, 'Count:', result.rows.length);
    res.json(result.rows);
  } catch (err) {
    console.error('Fetch user records error:', err);
    res.status(500).json({ error: 'Failed to fetch user records' });
  }
});

// Send Message (Admin)
app.post('/messages', authenticateToken, requireAdmin, async (req, res) => {
  const { user_id, message } = req.body;
  if (!user_id || !message) {
    console.log('Missing fields in message:', req.body);
    return res.status(400).json({ error: 'user_id and message are required' });
  }
  try {
    const userCheck = await pool.query('SELECT id FROM users WHERE id = $1', [user_id]);
    if (userCheck.rowCount === 0) {
      console.log('User not found for message:', user_id);
      return res.status(404).json({ error: 'User not found' });
    }
    const result = await pool.query(
      'INSERT INTO messages (sender_id, receiver_id, content, created_at) VALUES ($1, $2, $3, NOW()) RETURNING id',
      [req.user.id, user_id, message]
    );
    console.log('Message sent by:', req.user.email, 'To:', user_id);
    res.status(201).json({ message: 'Message sent successfully', messageId: result.rows[0].id });
  } catch (err) {
    console.error('Send message error:', err);
    res.status(500).json({ error: 'Failed to send message' });
  }
});

// Broadcast Message (Admin)
app.post('/messages/broadcast', authenticateToken, requireAdmin, async (req, res) => {
  const { message } = req.body;
  if (!message) {
    console.log('Missing message in broadcast:', req.body);
    return res.status(400).json({ error: 'Message is required' });
  }
  try {
    const users = await pool.query('SELECT id FROM users WHERE is_active = true AND id != $1', [req.user.id]);
    if (users.rows.length === 0) {
      console.log('No active users found for broadcast by:', req.user.email);
      return res.status(404).json({ error: 'No active users found' });
    }
    const values = users.rows.map(user => [req.user.id, user.id, message]);
    await pool.query(
      'INSERT INTO messages (sender_id, receiver_id, content, created_at) VALUES ($1, $2, $3, NOW())',
      values[0] // Simplified for example; use batch insert in production
    );
    console.log('Broadcast sent by:', req.user.email, 'To:', users.rows.length, 'users');
    res.status(201).json({ message: 'Broadcast sent successfully' });
  } catch (err) {
    console.error('Broadcast message error:', err);
    res.status(500).json({ error: 'Failed to send broadcast' });
  }
});

// Fetch Analytics (Admin)
app.get('/analytics', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const farmerAnalytics = await pool.query(`
      SELECT 
        COALESCE(SUM(liters), 0) AS total_liters,
        COALESCE(SUM(liters * price_per_liter), 0) AS total_revenue,
        json_agg(
          json_build_object(
            'month', TO_CHAR(created_at, 'YYYY-MM'),
            'liters', COALESCE(SUM(liters), 0)
          )
        ) AS monthly_trend
      FROM records
      WHERE role = 'farmer'
      GROUP BY role
    `);
    const sellerAnalytics = await pool.query(`
      SELECT 
        COALESCE(SUM(liters), 0) AS total_liters,
        COALESCE(SUM(amount_sold), 0) AS total_revenue,
        json_agg(
          json_build_object(
            'month', TO_CHAR(created_at, 'YYYY-MM'),
            'liters', COALESCE(SUM(liters), 0)
          )
        ) AS monthly_trend
      FROM records
      WHERE role = 'seller'
      GROUP BY role
    `);
    const analytics = {
      farmer: farmerAnalytics.rows[0] || { total_liters: 0, total_revenue: 0, monthly_trend: [] },
      seller: sellerAnalytics.rows[0] || { total_liters: 0, total_revenue: 0, monthly_trend: [] }
    };
    console.log('Analytics fetched for:', req.user.email);
    res.json(analytics);
  } catch (err) {
    console.error('Fetch analytics error:', err);
    res.status(500).json({ error: 'Failed to fetch analytics' });
  }
});

// Fetch Monthly Totals (Admin)
app.get('/monthly_totals', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        role,
        COALESCE(SUM(liters), 0) AS total_liters,
        COALESCE(SUM(amount_sold), 0) AS total_amount
      FROM records
      GROUP BY role
      ORDER BY role
    `);
    console.log('Monthly totals fetched for:', req.user.email, 'Count:', result.rows.length);
    res.json(result.rows);
  } catch (err) {
    console.error('Fetch monthly totals error:', err);
    res.status(500).json({ error: 'Failed to fetch monthly totals' });
  }
});

// Error handling for undefined routes
app.use((req, res) => {
  console.log('Route not found:', req.method, req.path);
  res.status(404).json({ error: 'Route not found' });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

// Handle uncaught exceptions
process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
});
