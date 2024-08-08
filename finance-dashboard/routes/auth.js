const express = require('express');
const router = express.Router();
const { signUp, login } = require('../controllers/authController');

// @route   POST /api/auth/signup
// @desc    Register a new user
router.post('/signup', signUp);

// @route   POST /api/auth/login
// @desc    Login a user
router.post('/login', login);

module.exports = router;
