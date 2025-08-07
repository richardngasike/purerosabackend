const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const JWT_SECRET = process.env.JWT_SECRET;

const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Forbidden' });
    req.user = user;
    next();
  });
};

app.post('/register', async (req, res) => {
  const { email, password, name, role } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (email, password, name, role) VALUES ($1, $2, $3, $4) RETURNING id, email, role',
      [email, hashedPassword, name, role]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) return res.status(400).json({ error: 'User not found' });

    const user = result.rows[0];
    if (await bcrypt.compare(password, user.password)) {
      const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
      res.json({ token, role: user.role });
    } else {
      res.status(400).json({ error: 'Invalid password' });
    }
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/yogurt_types', authenticateToken, async (req, res) => {
  if (req.user.role !== 'seller') return res.status(403).json({ error: 'Forbidden' });
  const { name } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO yogurt_types (name, created_by) VALUES ($1, $2) RETURNING *',
      [name, req.user.id]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.get('/yogurt_types', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM yogurt_types WHERE created_by = $1', [req.user.id]);
    res.json(result.rows);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/records', authenticateToken, async (req, res) => {
  const { liters, price_per_liter, yogurt_type_id, amount_sold } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO records (user_id, role, liters, price_per_liter, yogurt_type_id, amount_sold, date) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *',
      [req.user.id, req.user.role, liters, price_per_liter, yogurt_type_id || null, amount_sold || null, new Date()]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.get('/records', authenticateToken, async (req, res) => {
  try {
    const result = req.user.role === 'admin'
      ? await pool.query(`
          SELECT r.*, y.name as yogurt_type, u.name as user_name 
          FROM records r 
          LEFT JOIN yogurt_types y ON r.yogurt_type_id = y.id 
          JOIN users u ON r.user_id = u.id
        `)
      : await pool.query('SELECT * FROM records WHERE user_id = $1', [req.user.id]);
    res.json(result.rows);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.get('/daily_totals', authenticateToken, async (req, res) => {
  if (req.user.role !== 'seller') return res.status(403).json({ error: 'Forbidden' });
  try {
    const result = await pool.query(`
      SELECT y.name, SUM(r.liters) as total_liters, SUM(r.amount_sold) as total_amount
      FROM records r 
      JOIN yogurt_types y ON r.yogurt_type_id = y.id 
      WHERE r.user_id = $1 AND r.date = CURRENT_DATE
      GROUP BY y.name
    `, [req.user.id]);
    res.json(result.rows);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.get('/monthly_totals', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
  try {
    const result = await pool.query(`
      SELECT role, SUM(liters) as total_liters, SUM(amount_sold) as total_amount
      FROM records 
      WHERE date >= date_trunc('month', CURRENT_DATE)
      GROUP BY role
    `);
    res.json(result.rows);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/messages', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
  const { user_id, message } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO messages (user_id, message, timestamp) VALUES ($1, $2, $3) RETURNING *',
      [user_id, message, new Date()]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.get('/messages', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM messages WHERE user_id = $1', [req.user.id]);
    res.json(result.rows);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.listen(process.env.PORT, () => console.log(`Server running on port ${process.env.PORT}`));