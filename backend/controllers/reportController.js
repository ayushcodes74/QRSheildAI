const { db, bucket, isSandbox } = require('../config/firebase');
const sandboxDb = require('../services/sandboxDb');

// Helper: Determine default threat severity score based on categories
const getCategoryRisk = (category) => {
  switch (category) {
    case 'Phishing Website': return 90;
    case 'Fake Payment QR': return 85;
    case 'UPI Fraud': return 80;
    case 'Dangerous WiFi Network': return 50;
    case 'Malware Distribution': return 95;
    default: return 70;
  }
};

// POST /report
exports.createReport = async (req, res, next) => {
  try {
    const {
      scanId,
      payload,
      reason,
      riskScore,
      city,
      state,
      country,
      description,
      screenshot // base64 string
    } = req.body;

    if (!payload || !reason || !description) {
      return res.status(400).json({ success: false, message: 'Payload, classification reason, and description are required.' });
    }

    const userId = req.user.uid;
    const reportId = 'rep-' + Date.now();
    const createdAt = new Date().toISOString();
    const dateStr = createdAt.split('T')[0];

    const finalRisk = parseInt(riskScore) || getCategoryRisk(reason);
    const finalCity = city || 'Unknown';
    const finalState = state || 'Unknown';
    const finalCountry = country || 'India';

    let screenshotUrl = null;

    // Handle Screenshot Storage Upload
    if (screenshot && screenshot.startsWith('data:image')) {
      if (isSandbox || !bucket) {
        // Fallback to storing base64 string directly in sandbox memory or Firestore document
        screenshotUrl = screenshot;
      } else {
        try {
          // Decode Base64 string to buffer
          const mimeType = screenshot.match(/data:([a-zA-Z0-9]+\/[a-zA-Z0-9-.+]+);base64,/)[1];
          const base64Data = screenshot.replace(/^data:image\/\w+;base64,/, '');
          const buffer = Buffer.from(base64Data, 'base64');
          
          const fileExtension = mimeType.split('/')[1] || 'png';
          const filePath = `reports/${reportId}.${fileExtension}`;
          const file = bucket.file(filePath);

          await file.save(buffer, {
            metadata: { contentType: mimeType },
            public: true
          });

          // Google Cloud Storage Public URL
          screenshotUrl = `https://storage.googleapis.com/${bucket.name}/${filePath}`;
        } catch (storageErr) {
          console.error('[-] Firebase Storage upload failed, storing raw base64:', storageErr.message);
          screenshotUrl = screenshot; // fall back to inline storage
        }
      }
    }

    const reportRecord = {
      reportId,
      userId,
      scanId: scanId || null,
      payload,
      reason, // category
      riskScore: finalRisk,
      city: finalCity,
      state: finalState,
      country: finalCountry,
      status: 'Pending',
      description,
      screenshot: screenshotUrl,
      createdAt
    };

    if (isSandbox) {
      // Sandbox storage
      sandboxDb.reports.unshift(reportRecord);
      sandboxDb.incrementAnalytics(dateStr, 'report');

      return res.status(201).json({
        success: true,
        message: 'Incident report submitted successfully (Sandbox Mode)',
        report: reportRecord
      });
    } else {
      // Real Firestore storage
      await db.collection('reports').doc(reportId).set(reportRecord);

      // Increment reports counter in daily analytics document
      const analyticsDocRef = db.collection('analytics').doc(dateStr);
      await db.runTransaction(async (transaction) => {
        const doc = await transaction.get(analyticsDocRef);
        let data = {
          dailyScans: 0,
          safeScans: 0,
          dangerousScans: 0,
          highRisk: 0,
          mediumRisk: 0,
          criticalRisk: 0,
          reportsToday: 0
        };

        if (doc.exists) {
          data = doc.data();
        }

        data.reportsToday = (data.reportsToday || 0) + 1;
        transaction.set(analyticsDocRef, data, { merge: true });
      });

      return res.status(201).json({
        success: true,
        message: 'Incident report submitted successfully',
        report: reportRecord
      });
    }
  } catch (error) {
    next(error);
  }
};

// GET /reports
exports.getReports = async (req, res, next) => {
  try {
    const userId = req.user.uid;

    if (isSandbox) {
      const userReports = sandboxDb.reports.filter(r => r.userId === userId);
      return res.status(200).json({
        success: true,
        reports: userReports
      });
    } else {
      const snapshot = await db.collection('reports')
        .where('userId', '==', userId)
        .orderBy('createdAt', 'desc')
        .get();

      const reportsList = [];
      snapshot.forEach(doc => {
        reportsList.push(doc.data());
      });

      return res.status(200).json({
        success: true,
        reports: reportsList
      });
    }
  } catch (error) {
    next(error);
  }
};
