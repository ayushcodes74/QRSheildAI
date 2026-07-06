const express = require('express');
const router = express.Router();
const reportController = require('../controllers/reportController');
const authMiddleware = require('../middleware/authMiddleware');

// Report endpoints (both require authentication to prevent spam)
router.post('/report', authMiddleware, reportController.createReport);
router.get('/reports', authMiddleware, reportController.getReports);

module.exports = router;
