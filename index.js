console.log('Starting PureRosa backend...');
const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const { Pool } = require('pg');
const nodemailer = require('nodemailer');
const routes = require('./routes');

dotenv.config();
console.log('Environment variables loaded');

// Initialize PostgreSQL connection using the database URL
const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://purerosadb_user:eLrws1GTCdlwqMeSF56BMFaHKfBm7cOU@dpg-d2ab4h9r0fns7396k8t0-a/purerosadb',
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

pool.connect((err, client, release) => {
  if (err) {
    console.error('Database connection error:', err.message, err.stack);
    process.exit(1);
  }
  console.log('Database connected successfully');
  release();
});

// Configure nodemailer
const transporter = nodemailer.createTransport({
  service: process.env.EMAIL_SERVICE || 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

transporter.verify((error, success) => {
  if (error) {
    console.error('Nodemailer configuration error:', error.message, error.stack);
    process.exit(1);
  }
  console.log('Nodemailer configured successfully');
});

const app = express();

// Middleware
app.use(cors({
  origin: process.env.FRONTEND_URL || '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));
app.use(express.json());
console.log('Middleware configured');

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'OK' });
});

// Mount routes
app.use('/api/auth', routes);
app.use('/api/milk', routes);
app.use('/api/messages', routes);
app.use('/api/yogurt', routes);

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

const PORT = process.env.PORT || 10000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
});
