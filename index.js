console.log('Starting PureRosa backend...');
const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// Load environment variables
dotenv.config();
console.log('Environment variables loaded');

// Validate critical environment variables
if (!process.env.JWT_SECRET) {
  console.error('JWT_SECRET is not defined in .env');
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

const app = express();

// Middleware
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000', // Update with your Flutter app URL
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
  if (!req.user || !roles.includes(req.user.role)) {
    return res.status(403).json({ success: false, error: 'Unauthorized for this role' });
  }
  next();
};

// Routes
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
      'SELECT id, name, price FROM yogurts WHERE seller_id = $1 ORDER BY created_at DESC',
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

// Yogurt: Sell
app.post('/api/yogurt/sell', authenticateToken, restrictToRole(['seller']), async (req, res) => {
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

// Yogurt: Daily Sales
app.get('/api/yogurt/daily-sales', authenticateToken, restrictToRole(['seller']), async (req, res) => {
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
// ... (Previous server code remains unchanged up to the yogurt-related endpoints)

// Yogurt: Daily Sales
app.get('/api/yogurt/daily-sales', authenticateToken, restrictToRole(['seller']), async (req, res) => {
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

// Fetch monthly yogurt sales for authenticated seller
app.get('/api/yogurt/monthly-sales/seller', authenticateToken, restrictToRole(['seller']), async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT 
        DATE_TRUNC('month', ys.sale_date) AS month,
        SUM(ys.quantity) AS total_quantity,
        SUM(ys.quantity * y.price) AS total_value
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
        y.price,
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
        SUM(ys.quantity * y.price) AS total_value,
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
// ... (Previous server code remains unchanged)

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
        SUM(ys.quantity * y.price) AS total_value
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
  console.error('Global error handler:', err.message, err.stack);
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



