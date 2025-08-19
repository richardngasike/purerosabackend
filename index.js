// server.js
const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const twilio = require('twilio');

const app = express();

// Load environment variables
dotenv.config();
console.log('Environment variables loaded');

// Validate critical environment variables
if (!process.env.JWT_SECRET || !process.env.TWILIO_ACCOUNT_SID || !process.env.TWILIO_AUTH_TOKEN || !process.env.TWILIO_PHONE_NUMBER) {
  console.error('Missing critical environment variables (JWT_SECRET, TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, or TWILIO_PHONE_NUMBER)');
  process.exit(1);
}

// Initialize PostgreSQL connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://purerosadb_user:eLrws1GTCdlwqMeSF56BMFaHKfBm7cOU@dpg-d2ab4h9r0fns7396k8t0-a/purerosadb',
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

// Test database connection
pool.connect((err, client, release) => {
  if (err) {
    console.error('Database connection error:', err.message, err.stack);
    process.exit(1);
  }
  console.log('Database connected successfully');
  release();
});

// Initialize Twilio client
const twilioClient = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);

// Middleware
app.use(cors({
  origin: process.env.FRONTEND_URL || '*', // Allow all origins for debugging; restrict in production
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));
app.use(express.json());
console.log('Middleware configured');

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ success: true, status: 'OK' });
});

// Middleware to validate request body
const validateRequest = (req, res, requiredFields) => {
  for (const field of requiredFields) {
    if (!req.body[field]) {
      console.warn(`Validation failed: Missing required field: ${field}`);
      return res.status(400).json({ success: false, error: `Missing required field: ${field}` });
    }
  }
};

// JWT middleware for authentication
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) {
    console.warn('No token provided for request:', req.url);
    return res.status(401).json({ success: false, error: 'No token provided' });
  }
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    console.error('Token verification error:', error.message, error.stack);
    return res.status(401).json({ success: false, error: 'Invalid or expired token' });
  }
};

// Role-based middleware
const restrictToRole = (roles) => (req, res, next) => {
  if (!req.user || !roles.includes(req.user.role)) {
    console.warn(`Unauthorized access attempt by user: ${req.user?.id} with role: ${req.user?.role}`);
    return res.status(403).json({ success: false, error: 'Unauthorized for this role' });
  }
  next();
};

// Define router for expenses
const router = express.Router();

// Expenses: Get all expenses (admin-only)
router.get('/', authenticateToken, restrictToRole(['admin']), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT id, name, cost, description, category, expense_date
      FROM expenses
      ORDER BY expense_date DESC
    `);
    res.json({ success: true, data: result.rows });
  } catch (err) {
    console.error('Error fetching expenses:', err.message, err.stack);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Expenses: Add a new expense (admin-only)
router.post('/add', authenticateToken, restrictToRole(['admin']), async (req, res) => {
  const { name, cost, description, category, expense_date } = req.body;

  if (!name || !cost || !description || !category || !expense_date) {
    return res.status(400).json({ success: false, error: 'All fields are required' });
  }

  try {
    const result = await pool.query(
      `
      INSERT INTO expenses (name, cost, description, category, expense_date)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING id, name, cost, description, category, expense_date
      `,
      [name, cost, description, category, expense_date]
    );
    res.json({ success: true, data: result.rows[0] });
  } catch (err) {
    console.error('Error adding expense:', err.message, err.stack);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Expenses: Edit an existing expense (admin-only)
router.post('/edit/:id', authenticateToken, restrictToRole(['admin']), async (req, res) => {
  const { id } = req.params;
  const { name, cost, description, category, expense_date } = req.body;

  if (!name || !cost || !description || !category || !expense_date) {
    return res.status(400).json({ success: false, error: 'All fields are required' });
  }

  try {
    const result = await pool.query(
      `
      UPDATE expenses
      SET name = $1, cost = $2, description = $3, category = $4, expense_date = $5
      WHERE id = $6
      RETURNING id, name, cost, description, category, expense_date
      `,
      [name, cost, description, category, expense_date, id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ success: false, error: 'Expense not found' });
    }

    res.json({ success: true, data: result.rows[0] });
  } catch (err) {
    console.error('Error updating expense:', err.message, err.stack);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Expenses: Delete an expense (admin-only)
router.delete('/delete/:id', authenticateToken, restrictToRole(['admin']), async (req, res) => {
  const { id } = req.params;

  try {
    const result = await pool.query(
      'DELETE FROM expenses WHERE id = $1 RETURNING id',
      [id]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ success: false, error: 'Expense not found' });
    }

    res.json({ success: true, message: 'Expense deleted successfully' });
  } catch (err) {
    console.error('Error deleting expense:', err.message, err.stack);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Mount expenses routes
app.use('/api/expenses', router);

// Auth: Register
app.post('/api/auth/register', async (req, res) => {
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
      { id: result.rows[0].id, role: result.rows[0].role, email: result.rows[0].email, name: result.rows[0].name, phone: result.rows[0].phone },
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

// Auth: Login
app.post('/api/auth/login', async (req, res) => {
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
      { id: user.id, role: user.role, email: user.email, name: user.name, phone: user.phone },
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

// Auth: Reset Password
app.post('/api/auth/reset-password', (req, res) => {
  res.json({ success: false, message: 'Password reset functionality coming soon' });
});

// Milk: Submissions
app.get('/api/milk/submissions', authenticateToken, async (req, res) => {
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
    res.json({ success: true, data: result.rows });
  } catch (error) {
    console.error('Fetch submissions error:', error.message, error.stack);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Milk: Submit
app.post('/api/milk/submit', authenticateToken, restrictToRole(['farmer']), async (req, res) => {
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

// Messages: Send
app.post('/api/messages/send', authenticateToken, restrictToRole(['admin']), async (req, res) => {
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

// Messages: Fetch
app.get('/api/messages', authenticateToken, restrictToRole(['farmer']), async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT m.id, m.content, m.created_at, u.name as admin_name
      FROM messages m
      JOIN users u ON m.admin_id = u.id
      ORDER BY m.created_at DESC
      `
    );
    res.json({ success: true, data: result.rows });
  } catch (error) {
    console.error('Fetch messages error:', error.message, error.stack);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Yogurt: Fetch
app.get('/api/yogurt', authenticateToken, restrictToRole(['seller']), async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, name, price, quantity, created_at FROM yogurts WHERE seller_id = $1 ORDER BY created_at DESC',
      [req.user.id]
    );
    res.json({ success: true, data: result.rows });
  } catch (error) {
    console.error('Fetch yogurts error:', error.message, error.stack);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Yogurt: Add
app.post('/api/yogurt/add', authenticateToken, restrictToRole(['seller']), async (req, res) => {
  try {
    const { name, price, quantity } = req.body;
    validateRequest(req, res, ['name', 'price', 'quantity']);
    if (price <= 0 || quantity < 0) {
      return res.status(400).json({ success: false, error: 'Price must be positive and quantity must be non-negative' });
    }
    if (typeof name !== 'string' || name.trim().length === 0) {
      return res.status(400).json({ success: false, error: 'Name must be a non-empty string' });
    }
    const result = await pool.query(
      'INSERT INTO yogurts (seller_id, name, price, quantity, created_at) VALUES ($1, $2, $3, $4, NOW()) RETURNING id, name, price, quantity, created_at',
      [req.user.id, name.trim(), price, quantity]
    );
    res.status(200).json({ success: true, message: 'Yogurt added successfully', yogurt: result.rows[0] });
  } catch (error) {
    console.error('Add yogurt error:', error.message, error.stack);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Yogurt: Update Quantity
app.put('/api/yogurt/:id', authenticateToken, restrictToRole(['seller']), async (req, res) => {
  try {
    const { id } = req.params;
    const { quantity } = req.body;
    validateRequest(req, res, ['quantity']);
    if (quantity < 0) {
      return res.status(400).json({ success: false, error: 'Quantity must be non-negative' });
    }
    const result = await pool.query(
      'UPDATE yogurts SET quantity = $1 WHERE id = $2 AND seller_id = $3 RETURNING id, name, price, quantity, created_at',
      [quantity, id, req.user.id]
    );
    if (result.rowCount === 0) {
      return res.status(404).json({ success: false, error: 'Yogurt not found or unauthorized' });
    }
    res.status(200).json({ success: true, message: 'Yogurt quantity updated successfully', yogurt: result.rows[0] });
  } catch (error) {
    console.error('Update yogurt error:', error.message, error.stack);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Yogurt: Delete
app.delete('/api/yogurt/:id', authenticateToken, restrictToRole(['seller']), async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query(
      'DELETE FROM yogurts WHERE id = $1 AND seller_id = $2 RETURNING id',
      [id, req.user.id]
    );
    if (result.rowCount === 0) {
      return res.status(404).json({ success: false, error: 'Yogurt not found or unauthorized' });
    }
    res.status(200).json({ success: true, message: 'Yogurt deleted successfully' });
  } catch (error) {
    console.error('Delete yogurt error:', error.message, error.stack);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Yogurt: Sell
app.post('/api/yogurt/sell', authenticateToken, restrictToRole(['seller']), async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { yogurt_id, quantity, payment_method } = req.body;
    validateRequest(req, res, ['yogurt_id', 'quantity', 'payment_method']);
    if (quantity <= 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({ success: false, error: 'Quantity must be positive' });
    }
    const validPaymentMethods = ['cash', 'mpesa'];
    if (!validPaymentMethods.includes(payment_method)) {
      await client.query('ROLLBACK');
      return res.status(400).json({ success: false, error: 'Invalid payment method' });
    }
    const yogurtCheck = await client.query(
      'SELECT id, name, price, quantity FROM yogurts WHERE id = $1 AND seller_id = $2 FOR UPDATE',
      [yogurt_id, req.user.id]
    );
    if (yogurtCheck.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ success: false, error: 'Yogurt not found or unauthorized' });
    }
    const yogurt = yogurtCheck.rows[0];
    if (yogurt.quantity < quantity) {
      await client.query('ROLLBACK');
      return res.status(400).json({ success: false, error: 'Insufficient stock' });
    }
    await client.query(
      'UPDATE yogurts SET quantity = quantity - $1 WHERE id = $2',
      [quantity, yogurt_id]
    );
    const result = await client.query(
      'INSERT INTO yogurt_sales (seller_id, yogurt_id, quantity, payment_method, price, sale_date, created_at) VALUES ($1, $2, $3, $4, $5, NOW(), NOW()) RETURNING id, yogurt_id, quantity, payment_method, price, sale_date',
      [req.user.id, yogurt_id, quantity, payment_method, yogurt.price]
    );
    await client.query('COMMIT');
    res.status(200).json({ success: true, message: 'Sale recorded successfully', sale: result.rows[0] });
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Sell yogurt error:', error.message, error.stack);
    res.status(500).json({ success: false, error: 'Server error' });
  } finally {
    client.release();
  }
});

// Yogurt: Daily Sales
app.get('/api/yogurt/daily-sales', authenticateToken, restrictToRole(['seller']), async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT ys.id, y.name, ys.quantity, ys.payment_method, ys.price, ys.sale_date
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

// Yogurt: Monthly Sales for Seller
app.get('/api/yogurt/monthly-sales/seller', authenticateToken, restrictToRole(['seller']), async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT 
        DATE_TRUNC('month', ys.sale_date) AS month,
        SUM(ys.quantity) AS total_quantity,
        SUM(ys.quantity * ys.price) AS total_value
      FROM yogurt_sales ys
      JOIN yogurts y ON ys.yogurt_id = y.id
      WHERE ys.seller_id = $1
      GROUP BY DATE_TRUNC('month', ys.sale_date)
      ORDER BY month DESC
      `,
      [req.user.id]
    );
    res.json({ success: true, data: result.rows });
  } catch (error) {
    console.error('Fetch seller monthly yogurt sales error:', error.message, error.stack);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Yogurt: Daily Sales for Admin
app.get('/api/yogurt/admin/daily-sales', authenticateToken, restrictToRole(['admin']), async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT 
        ys.id,
        y.name AS yogurt_name,
        ys.quantity,
        ys.payment_method,
        ys.price,
        ys.sale_date,
        u.id AS seller_id,
        u.name AS seller_name
      FROM yogurt_sales ys
      JOIN yogurts y ON ys.yogurt_id = y.id
      JOIN users u ON ys.seller_id = u.id
      WHERE DATE(ys.sale_date) = CURRENT_DATE
      ORDER BY ys.sale_date DESC
      `
    );
    const total = result.rows.reduce((sum, sale) => sum + (sale.quantity * sale.price), 0);
    res.json({
      success: true,
      sales: result.rows,
      total,
    });
  } catch (error) {
    console.error('Fetch admin daily yogurt sales error:', error.message, error.stack);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Yogurt: Monthly Sales for Admin
app.get('/api/yogurt/admin/monthly-sales', authenticateToken, restrictToRole(['admin']), async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT 
        DATE_TRUNC('month', ys.sale_date) AS month,
        SUM(ys.quantity) AS total_quantity,
        SUM(ys.quantity * ys.price) AS total_value,
        COUNT(DISTINCT ys.seller_id) AS seller_count
      FROM yogurt_sales ys
      JOIN yogurts y ON ys.yogurt_id = y.id
      GROUP BY DATE_TRUNC('month', ys.sale_date)
      ORDER BY month DESC
      `
    );
    res.json({ success: true, data: result.rows });
  } catch (error) {
    console.error('Fetch admin monthly yogurt sales error:', error.message, error.stack);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Spoiled Yogurt: Fetch
app.get('/api/spoiled-yogurt', authenticateToken, restrictToRole(['seller']), async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT sy.id, y.name, sy.quantity, sy.reason, sy.report_date
      FROM spoiled_yogurts sy
      JOIN yogurts y ON sy.yogurt_id = y.id
      WHERE sy.seller_id = $1
      ORDER BY sy.report_date DESC
      `,
      [req.user.id]
    );
    res.json({ success: true, data: result.rows });
  } catch (error) {
    console.error('Fetch spoiled yogurts error:', {
      message: error.message,
      stack: error.stack,
      userId: req.user.id,
      endpoint: '/api/spoiled-yogurt',
    });
    res.status(500).json({ success: false, error: 'Failed to fetch spoiled yogurts' });
  }
});

// Spoiled Yogurt: Report
app.post('/api/spoiled-yogurt/report', authenticateToken, restrictToRole(['seller']), async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { yogurt_id, quantity, reason } = req.body;
    validateRequest(req, res, ['yogurt_id', 'quantity', 'reason']);
    if (quantity <= 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({ success: false, error: 'Quantity must be positive' });
    }
    if (typeof reason !== 'string' || reason.trim().length === 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({ success: false, error: 'Reason must be a non-empty string' });
    }
    const yogurt = await client.query(
      'SELECT id, name, quantity FROM yogurts WHERE id = $1 AND seller_id = $2 FOR UPDATE',
      [yogurt_id, req.user.id]
    );
    if (yogurt.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ success: false, error: 'Yogurt not found or unauthorized' });
    }
    if (yogurt.rows[0].quantity < quantity) {
      await client.query('ROLLBACK');
      return res.status(400).json({ success: false, error: 'Insufficient yogurt quantity' });
    }
    await client.query(
      'UPDATE yogurts SET quantity = quantity - $1 WHERE id = $2',
      [quantity, yogurt_id]
    );
    const result = await client.query(
      'INSERT INTO spoiled_yogurts (seller_id, yogurt_id, quantity, reason, report_date) VALUES ($1, $2, $3, $4, NOW()) RETURNING id, yogurt_id, quantity, reason, report_date',
      [req.user.id, yogurt_id, quantity, reason.trim()]
    );
    await client.query('COMMIT');
    res.json({ success: true, message: 'Spoiled yogurt reported successfully', data: result.rows[0] });
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Report spoiled yogurt error:', {
      message: error.message,
      stack: error.stack,
      userId: req.user.id,
      requestBody: req.body,
      endpoint: '/api/spoiled-yogurt/report',
    });
    res.status(500).json({ success: false, error: 'Failed to report spoiled yogurt' });
  } finally {
    client.release();
  }
});

// Spoiled Yogurt: Delete
app.delete('/api/spoiled-yogurt/:id', authenticateToken, restrictToRole(['seller']), async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query(
      'DELETE FROM spoiled_yogurts WHERE id = $1 AND seller_id = $2 RETURNING id',
      [id, req.user.id]
    );
    if (result.rowCount === 0) {
      return res.status(404).json({ success: false, error: 'Spoiled yogurt record not found or unauthorized' });
    }
    res.json({ success: true, message: 'Spoiled yogurt record deleted successfully' });
  } catch (error) {
    console.error('Delete spoiled yogurt error:', {
      message: error.message,
      stack: error.stack,
      userId: req.user.id,
      spoiledYogurtId: req.params.id,
      endpoint: '/api/spoiled-yogurt/:id',
    });
    res.status(500).json({ success: false, error: 'Failed to delete spoiled yogurt record' });
  }
});

// Other Farmers: Submit milk data and send SMS
app.post('/api/milk/other-farmers/submit', authenticateToken, restrictToRole(['admin']), async (req, res) => {
  try {
    const { farmer_name, phone_number, litres, amount, submission_date } = req.body;
    validateRequest(req, res, ['farmer_name', 'phone_number', 'litres', 'amount', 'submission_date']);
    if (litres <= 0 || amount <= 0) {
      return res.status(400).json({ success: false, error: 'Litres and amount must be positive' });
    }
    const phoneRegex = /^\+?\d{10,12}$/;
    if (!phoneRegex.test(phone_number)) {
      return res.status(400).json({ success: false, error: 'Invalid phone number format' });
    }
    const dateRegex = /^\d{4}-\d{2}-\d{2}$/;
    if (!dateRegex.test(submission_date)) {
      return res.status(400).json({ success: false, error: 'Invalid date format (use YYYY-MM-DD)' });
    }
    const result = await pool.query(
      'INSERT INTO other_farmers_submissions (admin_id, farmer_name, phone_number, litres, amount, submission_date, created_at) VALUES ($1, $2, $3, $4, $5, $6, NOW()) RETURNING id, farmer_name, phone_number, litres, amount, submission_date',
      [req.user.id, farmer_name, phone_number, litres, amount, submission_date]
    );
    try {
      await twilioClient.messages.create({
        body: `Dear ${farmer_name}, your milk submission of ${litres} litres on ${submission_date} has been recorded. Amount to be paid: $${amount.toFixed(2)}. Thank you! - PureRosa`,
        from: process.env.TWILIO_PHONE_NUMBER,
        to: phone_number,
      });
      console.log(`SMS sent to ${phone_number}`);
    } catch (smsError) {
      console.error('SMS sending error:', smsError.message);
    }
    res.status(200).json({
      success: true,
      message: 'Submission recorded successfully',
      submission: result.rows[0],
    });
  } catch (error) {
    console.error('Submit other farmers milk error:', error.message, error.stack);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Other Farmers: Fetch submissions
app.get('/api/milk/other-farmers/submissions', authenticateToken, restrictToRole(['admin']), async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, farmer_name, phone_number, litres, amount, submission_date FROM other_farmers_submissions WHERE admin_id = $1 ORDER BY submission_date DESC',
      [req.user.id]
    );
    res.json({ success: true, data: result.rows });
  } catch (error) {
    console.error('Fetch other farmers submissions error:', error.message, error.stack);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Fetch all farmers (admin-only)
app.get('/api/users/farmers', authenticateToken, restrictToRole(['admin']), async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, name, email, phone FROM users WHERE role = $1 ORDER BY name ASC',
      ['farmer']
    );
    res.json({ success: true, data: result.rows });
  } catch (error) {
    console.error('Fetch farmers error:', error.message, error.stack);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Fetch monthly milk totals by farmer (admin-only)
app.get('/api/milk/monthly-totals', authenticateToken, restrictToRole(['admin']), async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT 
        u.id AS farmer_id,
        u.name AS farmer_name,
        DATE_TRUNC('month', ms.submission_date) AS month,
        SUM(ms.litres) AS total_litres,
        SUM(ms.litres * ms.price_per_litre) AS total_value
      FROM milk_submissions ms
      JOIN users u ON ms.farmer_id = u.id
      WHERE u.role = 'farmer'
      GROUP BY u.id, u.name, DATE_TRUNC('month', ms.submission_date)
      ORDER BY month DESC, u.name ASC
      `
    );
    res.json({ success: true, data: result.rows });
  } catch (error) {
    console.error('Fetch monthly milk totals error:', error.message, error.stack);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Fetch monthly milk totals for authenticated farmer
app.get('/api/milk/monthly-totals/farmer', authenticateToken, restrictToRole(['farmer']), async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT 
        DATE_TRUNC('month', ms.submission_date) AS month,
        SUM(ms.litres) AS total_litres,
        SUM(ms.litres * ms.price_per_litre) AS total_value
      FROM milk_submissions ms
      WHERE ms.farmer_id = $1
      GROUP BY DATE_TRUNC('month', ms.submission_date)
      ORDER BY month DESC
      `,
      [req.user.id]
    );
    res.json({ success: true, data: result.rows });
  } catch (error) {
    console.error('Fetch farmer monthly milk totals error:', error.message, error.stack);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Fetch all sellers (for admin dropdown)
app.get('/api/users/sellers', authenticateToken, restrictToRole(['admin']), async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT id, name
      FROM users
      WHERE role = 'seller'
      ORDER BY name ASC
      `
    );
    res.json({ success: true, data: result.rows });
  } catch (error) {
    console.error('Fetch sellers error:', error.message, error.stack);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Fetch monthly yogurt sales for a specific seller (admin access)
app.get('/api/yogurt/monthly-sales/seller/:sellerId', authenticateToken, restrictToRole(['admin']), async (req, res) => {
  try {
    const sellerId = parseInt(req.params.sellerId);
    if (isNaN(sellerId)) {
      return res.status(400).json({ success: false, error: 'Invalid seller ID' });
    }
    const result = await pool.query(
      `
      SELECT 
        DATE_TRUNC('month', ys.sale_date) AS month,
        SUM(ys.quantity) AS total_quantity,
        SUM(ys.quantity * ys.price) AS total_value
      FROM yogurt_sales ys
      JOIN yogurts y ON ys.yogurt_id = y.id
      WHERE ys.seller_id = $1
      GROUP BY DATE_TRUNC('month', ys.sale_date)
      ORDER BY month DESC
      `,
      [sellerId]
    );
    res.json({ success: true, data: result.rows });
  } catch (error) {
    console.error('Fetch seller monthly yogurt sales error:', error.message, error.stack);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('Global error handler:', {
    message: err.message,
    stack: err.stack,
    path: req.path,
    method: req.method,
  });
  res.status(500).json({ success: false, error: 'Server error' });
});

// Handle 404s
app.use((req, res) => {
  console.warn(`404 Not Found: ${req.method} ${req.url}`);
  res.status(404).json({ success: false, error: 'Not Found' });
});

// Uncaught exception handler
process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err.message, err.stack);
  process.exit(1);
});

// Unhandled promise rejection handler
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
  process.exit(1);
});

// Start server
const PORT = process.env.PORT || 10000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
});
