const { db, isSandbox } = require('../config/firebase');
const sandboxDb = require('../services/sandboxDb');
const googleSafeBrowsing = require('../services/googleSafeBrowsing');
const virusTotal = require('../services/virusTotal');
const openRouter = require('../services/openRouter');
const riskEngine = require('../services/riskEngine');
const { getThreatLevel, getRiskStatus } = require('../services/severityPolicy');

// In-Memory API Cache to protect key quotas (TTL: 5 minutes)
const apiCache = {};
const CACHE_TTL = 5 * 60 * 1000;

function getCachedResult(payload) {
  const item = apiCache[payload];
  if (item && Date.now() < item.expiry) {
    return item.data;
  }
  return null;
}

function setCachedResult(payload, data) {
  apiCache[payload] = {
    data,
    expiry: Date.now() + CACHE_TTL
  };
}

// Helper: Extract domain from URL
const getDomainName = (urlStr) => {
  try {
    let target = urlStr.trim();
    if (!/^https?:\/\//i.test(target)) {
      target = 'http://' + target;
    }
    const parsed = new URL(target);
    return parsed.hostname.toLowerCase();
  } catch (e) {
    return null;
  }
};

// Helper: Auto-detect QR Payload Type
function detectQrType(payload) {
  const trimmed = payload.trim();
  if (/^https?:\/\//i.test(trimmed) || /^[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}(:[0-9]{1,5})?(\/.*)?$/i.test(trimmed)) {
    const lower = trimmed.toLowerCase();
    if (lower.endsWith('.pdf')) return 'PDF';
    if (lower.includes('play.google.com')) return 'Play Store';
    if (lower.includes('apps.apple.com')) return 'App Store';
    if (lower.includes('.gov') || lower.includes('.nic.in')) return 'Government';
    if (lower.includes('instagram.com') || lower.includes('twitter.com') || lower.includes('facebook.com') || lower.includes('linkedin.com')) {
      return 'Social';
    }
    return 'Website';
  }
  
  if (trimmed.startsWith('upi://pay') || (trimmed.includes('@') && (trimmed.toLowerCase().includes('upi') || trimmed.toLowerCase().includes('ybl') || trimmed.toLowerCase().includes('okaxis')))) {
    return 'UPI';
  }
  
  if (trimmed.startsWith('tel:')) return 'Phone';
  if (trimmed.startsWith('sms:') || trimmed.startsWith('smsto:')) return 'SMS';
  if (trimmed.startsWith('mailto:')) return 'Email';
  if (trimmed.startsWith('WIFI:')) return 'WiFi';
  if (trimmed.startsWith('BEGIN:VCARD')) return 'vCard';
  if (trimmed.startsWith('geo:')) return 'Geo';
  if (trimmed.startsWith('BEGIN:VEVENT')) return 'Calendar';
  if (trimmed.startsWith('bitcoin:') || trimmed.startsWith('ethereum:') || trimmed.startsWith('litecoin:')) {
    return 'Crypto Wallet';
  }
  if (trimmed.startsWith('slack://') || trimmed.startsWith('zoommtg://') || trimmed.startsWith('tg://')) {
    return 'Deep Link';
  }
  return 'Text';
}

// Helper: Fetch Community Reports Count
async function getCommunityReportsCount(normalizedPayload, domain) {
  let count = 0;
  try {
    if (isSandbox) {
      count = sandboxDb.reports.filter(r => {
        const repUrl = r.url?.toLowerCase() || '';
        const repUpi = r.upi?.toLowerCase() || '';
        return (domain && repUrl.includes(domain)) || repUpi === normalizedPayload || repUrl.includes(normalizedPayload);
      }).length;
    } else {
      const snapshot = await db.collection('reports').get();
      snapshot.forEach(doc => {
        const r = doc.data();
        const repUrl = r.url?.toLowerCase() || '';
        const repUpi = r.upi?.toLowerCase() || '';
        if ((domain && repUrl.includes(domain)) || repUpi === normalizedPayload || repUrl.includes(normalizedPayload)) {
          count++;
        }
      });
    }
  } catch (error) {
    console.error('[Community Reports] Failed to fetch count:', error.message);
  }
  return count;
}

// POST /scan - Unified Threat Intelligence Pipeline
exports.createScan = async (req, res, next) => {
  console.log('[DIAGNOSTIC] SCAN_ROUTE_ENTERED');
  try {
    const { payload, city, latitude, longitude } = req.body;

    if (!payload) {
      return res.status(400).json({ success: false, message: 'Scan payload is required.' });
    }

    const userId = req.user ? req.user.uid : 'anonymous';
    const timestamp = new Date().toISOString();
    const dateStr = timestamp.split('T')[0];
    const finalCity = city || 'Unknown';
    const finalLat = parseFloat(latitude) || null;
    const finalLng = parseFloat(longitude) || null;

    // Detect and Normalize
    const qrType = detectQrType(payload);
    const normalizedPayload = payload.trim().toLowerCase();
    const domain = getDomainName(payload);
    const isUrl = qrType === 'Website' || qrType === 'PDF' || qrType === 'Play Store' || qrType === 'App Store' || qrType === 'Government' || qrType === 'Social';

    // 1. Check Cache First
    console.log('[DIAGNOSTIC] SCAN_ANALYSIS_STARTED');
    let cachedAnalysis = getCachedResult(normalizedPayload);
    let analysis;

    if (cachedAnalysis) {
      console.log('[Risk Engine] Loading results from cache.');
      analysis = cachedAnalysis;
    } else {
      console.log(`[Risk Engine] Running fresh analysis pipeline for payload type: ${qrType}`);
      
      // 2. Fetch all intelligence inputs in parallel (with retries and fallbacks)
      const [safeBrowsingRes, virusTotalRes, openRouterRes, communityCount] = await Promise.all([
        isUrl ? googleSafeBrowsing.checkUrl(payload) : Promise.resolve({ isSafe: true, threatType: 'Safe' }),
        isUrl ? virusTotal.checkUrl(payload) : Promise.resolve({ malicious: 0, suspicious: 0, harmless: 0, ratio: '0/0' }),
        openRouter.analyzePayload(payload),
        getCommunityReportsCount(normalizedPayload, domain)
      ]);

      // 3. Compute Risk Score using the evidence-fusion Risk Engine
      const evaluation = riskEngine.evaluate({
        payload,
        qrType,
        domain,
        safeBrowsingRes,
        virusTotalRes,
        openRouterRes,
        communityCount
      });

      analysis = {
        riskScore: evaluation.riskScore,
        confidence: openRouterRes.confidence || 85,
        threatLevel: evaluation.threatLevel,
        threatCategory: openRouterRes.threatCategory || (evaluation.riskScore <= 20 ? 'Safe' : 'Suspicious'),
        threatsDetected: evaluation.threatsDetected,
        reasoning: openRouterRes.reasoning || 'No immediate structural threats detected.',
        recommendation: evaluation.recommendation,
        technicalIndicators: evaluation.technicalIndicators,
        googleSafeBrowsing: safeBrowsingRes.isSafe ? 'Safe' : safeBrowsingRes.threatType,
        virusTotal: {
          malicious: virusTotalRes.malicious,
          suspicious: virusTotalRes.suspicious,
          harmless: virusTotalRes.harmless,
          ratio: virusTotalRes.ratio
        },
        communityReports: communityCount,
        riskBreakdown: evaluation.riskBreakdown,
        aiReasoning: evaluation.aiReasoning,
        aiObservations: evaluation.aiObservations
      };

      // Set Cache
      setCachedResult(normalizedPayload, analysis);
    }

    // 4. Formulate the Scan Record
    const scanId = 'scan-' + Date.now();
    const scanRecord = {
      scanId,
      userId,
      payload,
      qrType,
      riskScore: analysis.riskScore,
      status: getRiskStatus(analysis.riskScore),
      city: finalCity,
      latitude: finalLat,
      longitude: finalLng,
      timestamp,
      analysis // Store full explainable report parameters
    };

    // 5. Store in DB (Sandbox or Live Firestore)
    if (isSandbox) {
      sandboxDb.scans.unshift(scanRecord);
      sandboxDb.incrementAnalytics(dateStr, 'scan');
      if (scanRecord.status === 'Safe') sandboxDb.incrementAnalytics(dateStr, 'safe');
      if (scanRecord.status === 'Dangerous') sandboxDb.incrementAnalytics(dateStr, 'dangerous');
      
      const threatLvl = getThreatLevel(analysis.riskScore);
      if (threatLvl === 'High Risk') {
        sandboxDb.incrementAnalytics(dateStr, 'highRisk');
      } else if (threatLvl === 'Medium Risk') {
        sandboxDb.incrementAnalytics(dateStr, 'mediumRisk');
      } else if (threatLvl === 'Critical') {
        sandboxDb.incrementAnalytics(dateStr, 'criticalRisk');
      }

      // Update threats index in sandbox
      if (domain && (scanRecord.status === 'Dangerous' || analysis.riskScore >= 60)) {
        let threat = sandboxDb.threats.find(t => t.domain === domain);
        if (threat) {
          threat.timesDetected += 1;
          threat.lastSeen = timestamp;
          threat.severity = analysis.threatLevel;
        } else {
          sandboxDb.threats.push({
            domain,
            threatType: `${analysis.threatCategory} Link`,
            timesDetected: 1,
            lastSeen: timestamp,
            severity: analysis.threatLevel
          });
        }
      }
    } else {
      // Live Firestore Mode
      await db.collection('scans').doc(scanId).set(scanRecord);

      // Increment analytics atomically
      const analyticsDocRef = db.collection('analytics').doc(dateStr);
      await db.runTransaction(async (transaction) => {
        const doc = await transaction.get(analyticsDocRef);
        let data = { dailyScans: 0, safeScans: 0, dangerousScans: 0, highRisk: 0, mediumRisk: 0, criticalRisk: 0, reportsToday: 0 };
        if (doc.exists) data = doc.data();

        data.dailyScans = (data.dailyScans || 0) + 1;
        if (scanRecord.status === 'Safe') data.safeScans = (data.safeScans || 0) + 1;
        if (scanRecord.status === 'Dangerous') data.dangerousScans = (data.dangerousScans || 0) + 1;
        
        const threatLvl = getThreatLevel(analysis.riskScore);
        if (threatLvl === 'High Risk') data.highRisk = (data.highRisk || 0) + 1;
        if (threatLvl === 'Medium Risk') data.mediumRisk = (data.mediumRisk || 0) + 1;
        if (threatLvl === 'Critical') data.criticalRisk = (data.criticalRisk || 0) + 1;

        transaction.set(analyticsDocRef, data, { merge: true });
      });

      // Update threats collection in Firestore
      if (domain && (scanRecord.status === 'Dangerous' || analysis.riskScore >= 60)) {
        const threatDocRef = db.collection('threats').doc(domain.replace(/\./g, '_'));
        const doc = await threatDocRef.get();
        if (doc.exists) {
          const current = doc.data();
          await threatDocRef.update({
            timesDetected: (current.timesDetected || 0) + 1,
            lastSeen: timestamp,
            severity: analysis.threatLevel
          });
        } else {
          await threatDocRef.set({
            domain,
            threatType: `${analysis.threatCategory} imposter`,
            timesDetected: 1,
            lastSeen: timestamp,
            severity: analysis.threatLevel
          });
        }
      }
    }

    // 6. Return comprehensive analysis response to display on result page
    console.log('[DIAGNOSTIC] SCAN_RESPONSE_SENT');
    return res.status(201).json({
      success: true,
      message: 'Scan analyzed and logged successfully',
      scan: scanRecord
    });

  } catch (error) {
    console.error('[DIAGNOSTIC] SCAN_ERROR:', error.message);
    next(error);
  }
};

// GET /scans
exports.getScans = async (req, res, next) => {
  try {
    const userId = req.user.uid;

    if (isSandbox) {
      const userScans = sandboxDb.scans.filter(s => s.userId === userId);
      return res.status(200).json({
        success: true,
        scans: userScans
      });
    } else {
      const snapshot = await db.collection('scans')
        .where('userId', '==', userId)
        .orderBy('timestamp', 'desc')
        .get();

      const scansList = [];
      snapshot.forEach(doc => {
        scansList.push(doc.data());
      });

      return res.status(200).json({
        success: true,
        scans: scansList
      });
    }
  } catch (error) {
    next(error);
  }
};
