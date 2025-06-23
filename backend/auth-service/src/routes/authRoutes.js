const express = require('express');
const authController = require('../controllers/authController');
const { verifyToken, verifyRefreshToken } = require('../middleware/auth');

const router = express.Router();

/**
 * @route   POST /api/auth/register
 * @desc    Register a new user
 * @access  Public
 */
router.post('/register', authController.register);

/**
 * @route   POST /api/auth/login
 * @desc    Login user
 * @access  Public
 */
router.post('/login', authController.login);

/**
 * @route   POST /api/auth/refresh-token
 * @desc    Refresh access token
 * @access  Public (with refresh token)
 */
router.post('/refresh-token', verifyRefreshToken, authController.refreshToken);

/**
 * @route   POST /api/auth/logout
 * @desc    Logout user
 * @access  Public (with refresh token)
 */
router.post('/logout', authController.logout);

/**
 * @route   GET /api/auth/me
 * @desc    Get current user
 * @access  Private
 */
router.get('/me', verifyToken, authController.getCurrentUser);

module.exports = router;