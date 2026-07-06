const express = require('express');
const router = express.Router();
const scanController = require('../controllers/scanController');
const authMiddleware = require('../middleware/authMiddleware');
const jwt = require('jsonwebtoken');

// Soft Authentication middleware to capture user info if logged in, but not block anonymous scans
const softAuthMiddleware = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    try {
      const token = authHeader.split(' ')[1];
      const decoded = jwt.verify(token, process.env.JWT_SECRET || 'qr_shield_secret_key_2026_demo_key');
      req.user = decoded;
    } catch (err) {
      // Silently fall back to anonymous if token invalid/expired
    }
  }
  next();
};

// Scan logs endpoints
router.post('/scan', softAuthMiddleware, scanController.createScan);
router.get('/scans', authMiddleware, scanController.getScans);

module.exports = router;
