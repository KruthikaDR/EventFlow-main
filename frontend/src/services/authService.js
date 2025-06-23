import axios from 'axios';

// Base URL for auth service
const API_URL = 'http://localhost:8001/api/auth';

// Create axios instance with default config
const authApi = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json'
  }
});

// Add token to requests if available
authApi.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Authentication service functions
const authService = {
  // Register a new user
  register: async (userData) => {
    try {
      const response = await authApi.post('/register', userData);
      return response.data;
    } catch (error) {
      throw new Error(error.response?.data?.message || 'Registration failed');
    }
  },

  // Login user
  login: async (email, password) => {
    try {
      const response = await authApi.post('/login', { email, password });
      
      // Store token in localStorage
      if (response.data.accessToken) {
        localStorage.setItem('token', response.data.accessToken);
      }
      
      return response.data;
    } catch (error) {
      throw new Error(error.response?.data?.message || 'Login failed');
    }
  },

  // Logout user
  logout: () => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
  },

  // Get current user profile
  getCurrentUser: async () => {
    try {
      const response = await authApi.get('/me');
      return response.data;
    } catch (error) {
      throw new Error(error.response?.data?.message || 'Failed to get user profile');
    }
  },

  // Check if user is authenticated
  isAuthenticated: () => {
    return !!localStorage.getItem('token');
  }
};

export default authService;