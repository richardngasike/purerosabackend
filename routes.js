const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const { Pool } = require('pg');
const router = express.Router();

// Initialize PostgreSQL connection (shared with index.js)
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT || 5432,
});

// Configure nodemailer (shared with index.js)
const transporter = nodemailer.createTransport({
  service: process.env.EMAIL_SERVICE || 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Middleware to validate request body
const validateRequest = (req, res, requiredFields) => {
  for (const field of requiredFields) {
    if (!req.body[field]) {
      return res.status(400).json({ success: false, error: `Missing required field: ${field}` });
    }
  }
};

// JWT middleware for authentication
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) {
    return res.status(401).json({ success: false, error: 'No token provided' });
  }
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    console.error('Token verification error:', error.message);
    return res.status(401).json({ success: false, error: 'Invalid or expired token' });
  }
};

// Role-based middleware
const restrictToRole = (roles) => (req, res, next) => {
  if (!roles.includes(req.user.role)) {
    return res.status(403).json({ success: false, error: 'Unauthorized for this role' });
  }
  next();
};

// Register route
router.post('/register', async (req, res) => {
  try {
    const { email, password, role, name, phone } = req.body;
    validateRequest(req, res, ['email', 'password', 'role', 'name', 'phone']);
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ success: false, error: 'Invalid email format' });
    }
    const validRoles = ['farmer', 'seller', 'admin'];
    if (!validRoles.includes(role)) {
      return res.status(400).json({ success: false, error: 'Invalid role' });
    }
    const phoneRegex = /^\+?\d{10,12}$/;
    if (!phoneRegex.test(phone)) {
      return res.status(400).json({ success: false, error: 'Invalid phone number' });
    }
    const existingUser = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (existingUser.rows.length > 0) {
      return res.status(409).json({ success: false, error: 'Email already exists' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (email, password, role, name, phone, created_at) VALUES ($1, $2, $3, $4, $5, NOW()) RETURNING id, email, role, name, phone',
      [email, hashedPassword, role, name, phone]
    );
    const token = jwt.sign(
      { id: result.rows[0].id, role: result.rows[0].role },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    res.status(201).json({
      success: true,
      message: 'User registered successfully',
      user: result.rows[0],
      token,
    });
  } catch (error) {
    console.error('Registration error:', error.message, error.stack);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Login route
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    validateRequest(req, res, ['email', 'password']);
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      return res.status(401).json({ success: false, error: 'Invalid credentials' });
    }
    const user = result.rows[0];
    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) {
      return res.status(401).json({ success: false, error: 'Invalid credentials' });
    }
    const token = jwt.sign(
      { id: user.id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    res.json({
      success: true,
      token,
      user: { id: user.id, email: user.email, role: user.role, name: user.name, phone: user.phone },
    });
  } catch (error) {
    console.error('Login error:', error.message, error.stack);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Reset password request route
router.post('/reset-password', async (req, res) => {
  try {
    const { email } = req.body;
    validateRequest(req, res, ['email']);
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }
    const resetToken = jwt.sign(
      { id: result.rows[0].id, email },
      process.env.JWT_SECRET,
      { expiresIn: '15m' }
    );
    await pool.query(
      'INSERT INTO password_resets (user_id, token, expires_at) VALUES ($1, $2, NOW() + INTERVAL \'15 minutes\')',
      [result.rows[0].id, resetToken]
    );
    const resetUrl = `${process.env.FRONTEND_URL}/reset-password?token=${resetToken}`;
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'PureRosaMilk Password Reset',
      html: `
        <p>You requested a password reset for your PureRosaMilk account.</p>
        <p>Click <a href="${resetUrl}">here</a> to reset your password.</p>
        <p>This link will expire in 15 minutes.</p>
      `,
    });
    res.json({ success: true, message: 'Password reset link sent' });
  } catch (error) {
    console.error('Password reset error:', error.message, error.stack);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Reset password confirmation route
router.post('/reset-password/confirm', async (req, res) => {
  try {
    const { token, newPassword } = req.body;
    validateRequest(req, res, ['token', 'newPassword']);
    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (error) {
      console.error('Token verification error:', error.message);
      return res.status(400).json({ success: false, error: 'Invalid or expired token' });
    }
    const result = await pool.query(
      'SELECT * FROM password_resets WHERE token = $1 AND expires_at > NOW()',
      [token]
    );
    if (result.rows.length === 0) {
      return res.status(400).json({ success: false, error: 'Invalid or expired token' });
    }
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE users SET password = $1 WHERE id = $2', [
      hashedPassword,
      decoded.id,
    ]);
    await pool.query('DELETE FROM password_resets WHERE token = $1', [token]);
    res.json({ success: true, message: 'Password reset successfully' });
  } catch (error) {
    console.error('Password reset confirmation error:', error.message, error.stack);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Milk submissions route (Admin and Farmer)
router.get('/submissions', authenticateToken, async (req, res) => {
  try {
    let query, params;
    if (req.user.role === 'admin') {
      query = `
        SELECT ms.id, ms.litres, ms.price_per_litre, ms.submission_date, u.name
        FROM milk_submissions ms
        JOIN users u ON ms.farmer_id = u.id
        WHERE u.role = 'farmer'
        ORDER BY ms.submission_date DESC
      `;
      params = [];
    } else if (req.user.role === 'farmer') {
      query = `
        SELECT ms.id, ms.litres, ms.price_per_litre, ms.submission_date
        FROM milk_submissions ms
        WHERE ms.farmer_id = $1
        ORDER BY ms.submission_date DESC
      `;
      params = [req.user.id];
    } else {
      return res.status(403).json({ success: false, error: 'Unauthorized for this role' });
    }
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (error) {
    console.error('Fetch submissions error:', error.message, error.stack);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Submit milk route (Farmer only)
router.post('/submit', authenticateToken, restrictToRole(['farmer']), async (req, res) => {
  try {
    const { litres, price_per_litre } = req.body;
    validateRequest(req, res, ['litres', 'price_per_litre']);
    if (litres <= 0 || price_per_litre <= 0) {
      return res.status(400).json({ success: false, error: 'Litres and price must be positive' });
    }
    const result = await pool.query(
      'INSERT INTO milk_submissions (farmer_id, litres, price_per_litre, submission_date, created_at) VALUES ($1, $2, $3, NOW(), NOW()) RETURNING id, litres, price_per_litre, submission_date',
      [req.user.id, litres, price_per_litre]
    );
    res.status(200).json({ success: true, message: 'Milk submitted successfully', submission: result.rows[0] });
  } catch (error) {
    console.error('Submit milk error:', error.message, error.stack);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Send message route (Admin only)
router.post('/send', authenticateToken, restrictToRole(['admin']), async (req, res) => {
  try {
    const { content } = req.body;
    validateRequest(req, res, ['content']);
    const result = await pool.query(
      'INSERT INTO messages (admin_id, content, created_at) VALUES ($1, $2, NOW()) RETURNING id, content, created_at',
      [req.user.id, content]
    );
    res.status(200).json({ success: true, message: 'Message sent successfully', data: result.rows[0] });
  } catch (error) {
    console.error('Send message error:', error.message, error.stack);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Fetch messages route (Farmer only)
router.get('/messages', authenticateToken, restrictToRole(['farmer']), async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT m.id, m.content, m.created_at, u.name as admin_name
      FROM messages m
      JOIN users u ON m.admin_id = u.id
      ORDER BY m.created_at DESC
      `
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Fetch messages error:', error.message, error.stack);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Fetch yogurts route (Seller only)
router.get('/', authenticateToken, restrictToRole(['seller']), async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, name, price FROM yogurts WHERE seller_id = $1 ORDER BY created_at DESC',
      [req.user.id]
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Fetch yogurts error:', error.message, error.stack);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Add yogurt route (Seller only)
router.post('/add', authenticateToken, restrictToRole(['seller']), async (req, res) => {
  try {
    const { name, price } = req.body;
    validateRequest(req, res, ['name', 'price']);
    if (price <= 0) {
      return res.status(400).json({ success: false, error: 'Price must be positive' });
    }
    const result = await pool.query(
      'INSERT INTO yogurts (seller_id, name, price, created_at) VALUES ($1, $2, $3, NOW()) RETURNING id, name, price',
      [req.user.id, name, price]
    );
    res.status(200).json({ success: true, message: 'Yogurt added successfully', yogurt: result.rows[0] });
  } catch (error) {
    console.error('Add yogurt error:', error.message, error.stack);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Sell yogurt route (Seller only)
router.post('/sell', authenticateToken, restrictToRole(['seller']), async (req, res) => {
  try {
    const { yogurt_id, quantity, payment_method } = req.body;
    validateRequest(req, res, ['yogurt_id', 'quantity', 'payment_method']);
    if (quantity <= 0) {
      return res.status(400).json({ success: false, error: 'Quantity must be positive' });
    }
    const validPaymentMethods = ['cash', 'mpesa'];
    if (!validPaymentMethods.includes(payment_method)) {
      return res.status(400).json({ success: false, error: 'Invalid payment method' });
    }
    const yogurtCheck = await pool.query('SELECT * FROM yogurts WHERE id = $1 AND seller_id = $2', [yogurt_id, req.user.id]);
    if (yogurtCheck.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Yogurt not found' });
    }
    const result = await pool.query(
      'INSERT INTO yogurt_sales (seller_id, yogurt_id, quantity, payment_method, sale_date, created_at) VALUES ($1, $2, $3, $4, NOW(), NOW()) RETURNING id, yogurt_id, quantity, payment_method, sale_date',
      [req.user.id, yogurt_id, quantity, payment_method]
    );
    res.status(200).json({ success: true, message: 'Sale recorded successfully', sale: result.rows[0] });
  } catch (error) {
    console.error('Sell yogurt error:', error.message, error.stack);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Fetch daily sales route (Seller only)
router.get('/daily-sales', authenticateToken, restrictToRole(['seller']), async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT ys.id, y.name, ys.quantity, ys.payment_method, y.price, ys.sale_date
      FROM yogurt_sales ys
      JOIN yogurts y ON ys.yogurt_id = y.id
      WHERE ys.seller_id = $1
      AND DATE(ys.sale_date) = CURRENT_DATE
      ORDER BY ys.sale_date DESC
      `,
      [req.user.id]
    );
    const total = result.rows.reduce((sum, sale) => sum + (sale.quantity * sale.price), 0);
    res.json({
      success: true,
      sales: result.rows,
      total,
    });
  } catch (error) {
    console.error('Fetch daily sales error:', error.message, error.stack);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

module.exports = router;
