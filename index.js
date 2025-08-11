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
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret';

// Middleware to authenticate token with detailed logging
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

// Register
app.post('/register', async (req, res) => {
  const { email, password, name, role } = req.body;
  if (!email || !password || !name || !role) {
    console.log('Missing fields in register:', req.body);
    return res.status(400).json({ error: 'All fields (email, password, name, role) are required' });
  }
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (email, password, name, role) VALUES ($1, $2, $3, $4) ON CONFLICT (email) DO NOTHING RETURNING id',
      [email.toLowerCase(), hashedPassword, name, role]
    );
    if (result.rowCount === 0) {
      console.log('User already exists:', email);
      return res.status(400).json({ error: 'User already exists' });
    }
    console.log('User registered:', email);
    res.status(201).json({ message: 'User registered', userId: result.rows[0].id });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ error: 'Registration failed' });
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
    const result = await pool.query('SELECT role FROM users WHERE id = $1', [decoded.id]);
    if (result.rows.length === 0) {
      console.log('User not found for refresh:', decoded.id);
      return res.status(404).json({ error: 'User not found' });
    }
    const newToken = jwt.sign({ id: decoded.id, email: decoded.email, role: decoded.role }, JWT_SECRET, { expiresIn: '1h' });
    console.log('Token refreshed for:', decoded.email);
    res.json({ token: newToken, role: result.rows[0].role });
  } catch (err) {
    console.error('Token refresh error:', err);
    res.status(500).json({ error: `Failed to refresh token: ${err.message}` });
  }
});

// Submit Sales Record (Farmer and Seller)
app.post('/records', authenticateToken, async (req, res) => {
  const { liters, price_per_liter, yogurt_type_id, amount_sold } = req.body;

  // Validation based on user role
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
      'INSERT INTO records (user_id, liters, price_per_liter, yogurt_type_id, amount_sold, created_at, role) VALUES ($1, $2, $3, $4, $5, NOW(), $6) RETURNING id, liters, price_per_liter, yogurt_type_id, amount_sold, created_at',
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
      id: result.rows[0].id,
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
    let query = 'SELECT id, user_id, liters, price_per_liter, yogurt_type_id, amount_sold, created_at, role FROM records WHERE user_id = $1';
    const params = [req.user.id];
    if (req.user.role === 'admin') {
      query = 'SELECT id, user_id, liters, price_per_liter, yogurt_type_id, amount_sold, created_at, role FROM records';
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

  // Validation based on user role
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
    const result = await pool.query(
      'UPDATE records SET liters = $1, price_per_liter = $2, yogurt_type_id = $3, amount_sold = $4, updated_at = NOW() WHERE id = $5 AND user_id = $6 RETURNING *',
      [
        liters,
        price_per_liter || null,
        yogurt_type_id || null,
        amount_sold || null,
        id,
        req.user.id
      ]
    );
    if (result.rowCount === 0) {
      if (req.user.role === 'admin') {
        const adminResult = await pool.query(
          'UPDATE records SET liters = $1, price_per_liter = $2, yogurt_type_id = $3, amount_sold = $4, updated_at = NOW() WHERE id = $5 RETURNING *',
          [
            liters,
            price_per_liter || null,
            yogurt_type_id || null,
            amount_sold || null,
            id
          ]
        );
        if (adminResult.rowCount === 0) {
          console.log('Record not found for admin update:', id);
          return res.status(404).json({ error: 'Record not found' });
        }
        console.log('Record updated by admin:', id);
        return res.json(adminResult.rows[0]);
      }
      console.log('Record not found for user:', id);
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
app.delete('/records/:id', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    console.log('Admin access denied for:', req.user.email, 'on', req.path);
    return res.status(403).json({ error: 'Admin access required' });
  }
  const { id } = req.params;
  try {
    const result = await pool.query('DELETE FROM records WHERE id = $1 RETURNING *', [id]);
    if (result.rowCount === 0) {
      console.log('Record not found for deletion:', id);
      return res.status(404).json({ error: 'Record not found' });
    }
    console.log('Record deleted by admin:', id);
    res.status(200).json({ message: 'Record deleted' });
  } catch (err) {
    console.error('Delete record error:', err);
    res.status(500).json({ error: 'Failed to delete record' });
  }
});

// Add Yogurt Type (Seller)
app.post('/yogurt_types', authenticateToken, async (req, res) => {
  if (req.user.role !== 'seller') {
    console.log('Seller access denied for:', req.user.email, 'on', req.path);
    return res.status(403).json({ error: 'Seller access required' });
  }
  const { name } = req.body;
  if (!name) {
    console.log('Missing name in /yogurt_types:', req.body);
    return res.status(400).json({ error: 'Name is required' });
  }
  try {
    const result = await pool.query(
      'INSERT INTO yogurt_types (name, created_by) VALUES ($1, $2) ON CONFLICT (name) DO NOTHING RETURNING id',
      [name, req.user.id]
    );
    if (result.rowCount === 0) {
      console.log('Yogurt type already exists:', name);
      return res.status(400).json({ error: 'Yogurt type already exists' });
    }
    console.log('Yogurt type added by:', req.user.email, 'Name:', name);
    res.status(201).json({ id: result.rows[0].id, message: 'Yogurt type added' });
  } catch (err) {
    console.error('Add yogurt type error:', err);
    res.status(500).json({ error: 'Failed to add yogurt type' });
  }
});

// Fetch Yogurt Types (Seller)
app.get('/yogurt_types', authenticateToken, async (req, res) => {
  if (req.user.role !== 'seller') {
    console.log('Seller access denied for:', req.user.email, 'on', req.path);
    return res.status(403).json({ error: 'Seller access required' });
  }
  try {
    const result = await pool.query('SELECT id, name FROM yogurt_types');
    console.log('Yogurt types fetched for:', req.user.email, 'Count:', result.rows.length);
    res.json(result.rows);
  } catch (err) {
    console.error('Fetch yogurt types error:', err);
    res.status(500).json({ error: 'Failed to fetch yogurt types' });
  }
});

// Fetch Daily Totals (Seller)
app.get('/daily_totals', authenticateToken, async (req, res) => {
  if (req.user.role !== 'seller') {
    console.log('Seller access denied for:', req.user.email, 'on', req.path);
    return res.status(403).json({ error: 'Seller access required' });
  }
  try {
    const result = await pool.query(
      `SELECT yt.name, SUM(r.liters) as total_liters, SUM(r.amount_sold) as total_amount 
       FROM records r 
       JOIN yogurt_types yt ON r.yogurt_type_id = yt.id 
       WHERE r.user_id = $1 AND DATE(r.created_at) = CURRENT_DATE 
       GROUP BY yt.name`,
      [req.user.id]
    );
    console.log('Daily totals fetched for:', req.user.email, 'Count:', result.rows.length);
    res.json(result.rows);
  } catch (err) {
    console.error('Fetch daily totals error:', err);
    res.status(500).json({ error: 'Failed to fetch daily totals' });
  }
});

// Fetch Seller Summary
app.get('/seller_summary', authenticateToken, async (req, res) => {
  if (req.user.role !== 'seller') {
    console.log('Seller access denied for:', req.user.email, 'on', req.path);
    return res.status(403).json({ error: 'Seller access required' });
  }
  try {
    const result = await pool.query(
      `SELECT SUM(liters) as total_liters, SUM(amount_sold) as total_revenue 
       FROM records 
       WHERE user_id = $1`,
      [req.user.id]
    );
    console.log('Seller summary fetched for:', req.user.email);
    res.json({
      total_liters: result.rows[0].total_liters || 0,
      total_revenue: result.rows[0].total_revenue || 0
    });
  } catch (err) {
    console.error('Fetch seller summary error:', err);
    res.status(500).json({ error: 'Failed to fetch summary' });
  }
});

// Messages (for AdminDashboard and Seller/Farmer)
app.post('/messages', authenticateToken, async (req, res) => {
  const { user_id, message } = req.body;
  if (!user_id || !message) {
    console.log('Missing fields in /messages:', req.body);
    return res.status(400).json({ error: 'User ID and message are required' });
  }
  try {
    const result = await pool.query(
      'INSERT INTO messages (user_id, message, created_at) VALUES ($1, $2, NOW()) RETURNING id, user_id, message, created_at',
      [user_id, message]
    );
    console.log('Message sent by:', req.user.email, 'to user:', user_id);
    res.status(201).json({ id: result.rows[0].id, message: 'Message sent', data: result.rows[0] });
  } catch (err) {
    console.error('Send message error:', err);
    res.status(500).json({ error: 'Failed to send message' });
  }
});

// Fetch Messages (Admin, Seller, Farmer)
app.get('/messages', authenticateToken, async (req, res) => {
  try {
    let query = 'SELECT id, user_id, message, created_at FROM messages';
    const params = [];
    if (req.user.role === 'seller' || req.user.role === 'farmer') {
      query += ' WHERE user_id = $1';
      params.push(req.user.id);
    }
    query += ' ORDER BY created_at DESC';
    const result = await pool.query(query, params);
    console.log('Messages fetched for:', req.user.email, 'Role:', req.user.role, 'Count:', result.rows.length);
    res.json(result.rows);
  } catch (err) {
    console.error('Fetch messages error:', err);
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
});

// Admin Endpoints
app.get('/users', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    console.log('Admin access denied for:', req.user.email, 'on', req.path);
    return res.status(403).json({ error: 'Admin access required' });
  }
  try {
    const result = await pool.query('SELECT id, email, name, role FROM users');
    console.log('Users fetched by admin:', req.user.email, 'Count:', result.rows.length);
    res.json(result.rows);
  } catch (err) {
    console.error('Fetch users error:', err);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

app.post('/users', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    console.log('Admin access denied for:', req.user.email, 'on', req.path);
    return res.status(403).json({ error: 'Admin access required' });
  }
  const { email, password, name, role } = req.body;
  if (!email || !password || !name || !role) {
    console.log('Missing fields in /users:', req.body);
    return res.status(400).json({ error: 'All fields are required' });
  }
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (email, password, name, role) VALUES ($1, $2, $3, $4) ON CONFLICT (email) DO NOTHING RETURNING id',
      [email.toLowerCase(), hashedPassword, name, role]
    );
    if (result.rowCount === 0) {
      console.log('User already exists:', email);
      return res.status(400).json({ error: 'User already exists' });
    }
    console.log('User added by admin:', email);
    res.status(201).json({ id: result.rows[0].id });
  } catch (err) {
    console.error('Add user error:', err);
    res.status(500).json({ error: 'Failed to add user' });
  }
});

app.delete('/users/:id', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    console.log('Admin access denied for:', req.user.email, 'on', req.path);
    return res.status(403).json({ error: 'Admin access required' });
  }
  const { id } = req.params;
  try {
    const result = await pool.query('DELETE FROM users WHERE id = $1 RETURNING *', [id]);
    if (result.rowCount === 0) {
      console.log('User not found for deletion:', id);
      return res.status(404).json({ error: 'User not found' });
    }
    console.log('User deleted by admin:', id);
    res.status(200).json({ message: 'User deleted' });
  } catch (err) {
    console.error('Delete user error:', err);
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

app.get('/analytics', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    console.log('Admin access denied for:', req.user.email, 'on', req.path);
    return res.status(403).json({ error: 'Admin access required' });
  }
  try {
    const farmerResult = await pool.query(
      'SELECT SUM(liters) as total_liters, SUM(liters * COALESCE(price_per_liter, 0)) as total_revenue FROM records WHERE role = $1',
      ['farmer']
    );
    const sellerResult = await pool.query(
      'SELECT SUM(liters) as total_liters, SUM(amount_sold) as total_revenue FROM records WHERE role = $1',
      ['seller']
    );
    console.log('Analytics fetched by admin:', req.user.email);
    res.json({
      farmer: {
        total_liters: farmerResult.rows[0].total_liters || 0,
        total_revenue: farmerResult.rows[0].total_revenue || 0,
      },
      seller: {
        total_liters: sellerResult.rows[0].total_liters || 0,
        total_revenue: sellerResult.rows[0].total_revenue || 0,
      },
    });
  } catch (err) {
    console.error('Fetch analytics error:', err);
    res.status(500).json({ error: 'Failed to fetch analytics' });
  }
});

// Ping Endpoint for Debugging
app.get('/ping', (req, res) => {
  console.log('Ping received at', new Date().toISOString());
  res.json({ message: 'Server is alive', timestamp: new Date().toISOString() });
});

// Error Handling Middleware
app.use((err, req, res, next) => {
  console.error('Server error:', err.stack);
  res.status(500).json({ error: 'Something went wrong on the server!' });
});

// 404 Handler
app.use((req, res) => {
  console.log('404 Not Found:', req.path);
  res.status(404).json({ error: 'Route not found' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('Server running on port', PORT));
