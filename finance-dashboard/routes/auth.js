const express = require('express');
const router = express.Router();
const {
  signUp,
  login,
  forgotPassword,
  resetPassword,
  getUserProfile,
  updateUserProfile,
} = require('../controllers/authController');

// @route   POST /api/auth/signup
// @desc    Register a new user
router.post('/signup', signUp);

// @route   POST /api/auth/login
// @desc    Login a user
router.post('/login', login);

// @route   POST /api/auth/forgot-password
// @desc    Request password reset
router.post('/forgot-password', forgotPassword);

// @route   POST /api/auth/reset-password
// @desc    Reset password
router.post('/reset-password', resetPassword);

// @route   GET /api/auth/profile
// @desc    Get user profile
router.get('/profile', getUserProfile);
router.put('/profile', updateUserProfile);

module.exports = router;
