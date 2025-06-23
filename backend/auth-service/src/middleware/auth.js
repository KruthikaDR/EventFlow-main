const jwt = require('jsonwebtoken');
const User = require('../models/User');

/**
 * Middleware to verify JWT token
 */
exports.verifyToken = async (req, res, next) => {
  try {
    // Get token from header
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ message: 'Access denied. No token provided.' });
    }
    
    const token = authHeader.split(' ')[1];
    
    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Add user to request object
    req.user = decoded;
    
    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ message: 'Token expired' });
    }
    
    return res.status(401).json({ message: 'Invalid token' });
  }
};

/**
 * Middleware to check if user has required role
 */
exports.checkRole = (roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ message: 'Unauthorized' });
    }
    
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ message: 'Forbidden: Insufficient permissions' });
    }
    
    next();
  };
};

/**
 * Middleware to verify refresh token
 */
exports.verifyRefreshToken = async (req, res, next) => {
  try {
    const { refreshToken } = req.body;
    
    if (!refreshToken) {
      return res.status(401).json({ message: 'Refresh token is required' });
    }
    
    // Verify refresh token
    const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET);
    
    // Find user with this refresh token
    const user = await User.findOne({ _id: decoded.id, refreshToken });
    
    if (!user) {
      return res.status(401).json({ message: 'Invalid refresh token' });
    }
    
    // Add user to request object
    req.user = {
      id: user._id,
      firstName: user.firstName,
      lastName: user.lastName,
      username: user.username,
      email: user.email,
      role: user.role
    };
    req.refreshToken = refreshToken;
    
    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ message: 'Refresh token expired' });
    }
    
    return res.status(401).json({ message: 'Invalid refresh token' });
  }
};