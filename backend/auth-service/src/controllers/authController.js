const jwt = require('jsonwebtoken');
const User = require('../models/User');

/**
 * Generate JWT tokens
 */
const generateTokens = (user) => {
  // Create access token
  const accessToken = jwt.sign(
    { 
      id: user._id,
      firstName: user.firstName,
      lastName: user.lastName,
      username: user.username,
      email: user.email,
      role: user.role 
    },
    process.env.JWT_SECRET,
    { expiresIn: '1h' }
  );

  // Create refresh token
  const refreshToken = jwt.sign(
    { id: user._id },
    process.env.JWT_SECRET,
    { expiresIn: '7d' }
  );

  return { accessToken, refreshToken };
};

/**
 * Register a new user
 */
exports.register = async (req, res) => {
  try {
    const { firstName, lastName, username, email, password, college, role } = req.body;

    // Check if email already exists
    const existingEmail = await User.findOne({ email });
    if (existingEmail) {
      return res.status(400).json({ 
        message: 'User already exists with this email' 
      });
    }

    // Check if username exists if provided
    if (username) {
      const existingUsername = await User.findOne({ username });
      if (existingUsername) {
        return res.status(400).json({ 
          message: 'Username already taken' 
        });
      }
    }

    // Only allow admin to create organizers
    if (role === 'organizer' || role === 'admin') {
      // Check if request is from an admin
      const authHeader = req.headers.authorization;
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(403).json({ message: 'Forbidden: Only admins can create organizer accounts' });
      }

      try {
        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        
        if (decoded.role !== 'admin') {
          return res.status(403).json({ message: 'Forbidden: Only admins can create organizer accounts' });
        }
      } catch (error) {
        return res.status(401).json({ message: 'Invalid token' });
      }
    }

    // Generate username if not provided
    let generatedUsername = username;
    if (!generatedUsername) {
      // Create a base username from firstName and lastName
      generatedUsername = `${firstName.toLowerCase()}${lastName.toLowerCase()}`;
      
      // Check if this username exists
      const existingUsername = await User.findOne({ username: generatedUsername });
      if (existingUsername) {
        // Add a random number to make it unique
        generatedUsername = `${generatedUsername}${Math.floor(1000 + Math.random() * 9000)}`;
      }
    }

    // Create new user
    const newUser = new User({
      firstName,
      lastName,
      username: generatedUsername,
      email,
      password,
      college,
      role: role || 'participant' // Default to participant if no role specified
    });

    await newUser.save();

    // Generate tokens
    const { accessToken, refreshToken } = generateTokens(newUser);

    // Save refresh token to user
    newUser.refreshToken = refreshToken;
    await newUser.save();

    res.status(201).json({
      message: 'User registered successfully',
      user: {
        id: newUser._id,
        firstName: newUser.firstName,
        lastName: newUser.lastName,
        username: newUser.username,
        email: newUser.email,
        role: newUser.role,
        college: newUser.college
      },
      accessToken,
      refreshToken
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ message: 'Server error during registration' });
  }
};

/**
 * Login user
 */
exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Check if user exists
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    // Check password
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    // Generate tokens
    const { accessToken, refreshToken } = generateTokens(user);

    // Save refresh token to user
    user.refreshToken = refreshToken;
    await user.save();

    res.status(200).json({
      message: 'Login successful',
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        username: user.username,
        email: user.email,
        role: user.role,
        college: user.college
      },
      accessToken,
      refreshToken
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error during login' });
  }
};

/**
 * Refresh access token
 */
exports.refreshToken = async (req, res) => {
  try {
    // User and refreshToken are added by verifyRefreshToken middleware
    const user = req.user;
    const oldRefreshToken = req.refreshToken;

    // Generate new tokens
    const { accessToken, refreshToken } = generateTokens(user);

    // Update refresh token in database
    await User.findByIdAndUpdate(user.id, { refreshToken });

    res.status(200).json({
      accessToken,
      refreshToken
    });
  } catch (error) {
    console.error('Token refresh error:', error);
    res.status(500).json({ message: 'Server error during token refresh' });
  }
};

/**
 * Logout user
 */
exports.logout = async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(400).json({ message: 'Refresh token is required' });
    }

    // Find user with this refresh token and remove it
    await User.findOneAndUpdate(
      { refreshToken },
      { $unset: { refreshToken: 1 } }
    );

    res.status(200).json({ message: 'Logged out successfully' });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ message: 'Server error during logout' });
  }
};

/**
 * Get current user
 */
exports.getCurrentUser = async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password -refreshToken');
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    res.status(200).json({
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        username: user.username,
        email: user.email,
        role: user.role,
        college: user.college,
        createdAt: user.createdAt
      }
    });
  } catch (error) {
    console.error('Get current user error:', error);
    res.status(500).json({ message: 'Server error' });
  }
};