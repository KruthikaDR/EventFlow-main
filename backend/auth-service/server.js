const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

// Import routes and middleware
const authRoutes = require('./src/routes/authRoutes');
const errorHandler = require('./src/middleware/errorHandler');
const connectDB = require('./src/config/db');

// Create Express app
const app = express();

// Middleware
app.use(helmet());
app.use(cors());
app.use(express.json());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.'
});
app.use('/api', limiter);

// Connect to MongoDB
connectDB();

// Routes
app.use('/api/auth', authRoutes);

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok', service: 'auth-service' });
});

// Error handling middleware
app.use(errorHandler);

// Start server
const PORT = process.env.PORT || 8001;
app.listen(PORT, () => {
  console.log(`Auth service running on port ${PORT}`);
});