const express = require('express');
const router = express.Router();
const adminController = require('../controllers/adminController');
const authMiddleware = require('../middleware/authMiddleware');
const adminMiddleware = require('../middleware/adminMiddleware');

// Admin panel endpoints (requires both authentication and Admin/Police roles)
router.get('/admin/dashboard', authMiddleware, adminMiddleware, adminController.getDashboardStats);
router.get('/admin/users', authMiddleware, adminMiddleware, adminController.getAllUsers);
router.get('/admin/reports', authMiddleware, adminMiddleware, adminController.getAllReports);
router.get('/admin/scans', authMiddleware, adminMiddleware, adminController.getAllScans);

// Threat Intel, Analytics, Geospatial Markers, and Audit Activity logs
router.get('/admin/stats', authMiddleware, adminMiddleware, adminController.getThreatIntelligence);
router.get('/admin/analytics', authMiddleware, adminMiddleware, adminController.getAnalytics);
router.get('/admin/map', authMiddleware, adminMiddleware, adminController.getMapMarkers);
router.get('/admin/activity', authMiddleware, adminMiddleware, adminController.getActivityLogs);

// Administrative modification actions
router.post('/admin/block', authMiddleware, adminMiddleware, adminController.blockThreat);
router.put('/admin/report/:id', authMiddleware, adminMiddleware, adminController.updateReportStatus);
router.delete('/admin/report/:id', authMiddleware, adminMiddleware, adminController.deleteReport);
router.put('/admin/user/:id/role', authMiddleware, adminMiddleware, adminController.updateUserRole);

module.exports = router;
