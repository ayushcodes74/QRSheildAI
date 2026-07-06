const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const authMiddleware = require('../middleware/authMiddleware');

// Auth endpoints
router.post('/auth/signup', authController.signup);
router.post('/auth/login', authController.login);
router.post('/auth/google', authController.googleLogin);
router.post('/auth/logout', authController.logout);

// User profile endpoints
router.get('/user/profile', authMiddleware, authController.getUserProfile);

module.exports = router;
