const { db, isSandbox } = require('../config/firebase');
const sandboxDb = require('../services/sandboxDb');
const googleSafeBrowsing = require('../services/googleSafeBrowsing');
const virusTotal = require('../services/virusTotal');
const openRouter = require('../services/openRouter');

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

      // 3. Compute Risk Score using the Weighted Risk Engine
      let calculatedScore = 0;
      const technicalIndicators = [];
      const threatsDetected = [];

      // Google Safe Browsing Hit (+40)
      if (isUrl && !safeBrowsingRes.isSafe) {
        calculatedScore += 40;
        threatsDetected.push('Malicious Web Link');
        technicalIndicators.push(`Google Safe Browsing Blocklist (${safeBrowsingRes.threatType})`);
      }

      // VirusTotal Malicious (+35)
      if (isUrl && virusTotalRes.malicious > 0) {
        calculatedScore += 35;
        threatsDetected.push('Malicious URL Detection');
        technicalIndicators.push(`VirusTotal Malicious Vendors (${virusTotalRes.ratio})`);
      }

      // VirusTotal Suspicious (+20)
      if (isUrl && virusTotalRes.suspicious > 0) {
        calculatedScore += 20;
        threatsDetected.push('Suspicious URL Detection');
        technicalIndicators.push('VirusTotal Suspicious Flag');
      }

      // AI Confidence Above 90% (+30)
      if (openRouterRes.confidence > 90 && openRouterRes.riskScore > 50) {
        calculatedScore += 30;
        technicalIndicators.push('AI High-Confidence Threat Flag');
      }

      // Community Reports (+20)
      if (communityCount > 0) {
        calculatedScore += 20;
        threatsDetected.push('Community Reported Phishing');
        technicalIndicators.push(`Scam Reported by ${communityCount} User(s)`);
      }

      // HTTP missing SSL (+15)
      const isHttp = isUrl && normalizedPayload.startsWith('http://');
      if (isHttp) {
        calculatedScore += 15;
        technicalIndicators.push('Insecure HTTP Connection');
      }

      // Short URL (+10)
      const URL_SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly", "adf.ly", "ow.ly", "rebrand.ly", "git.io", "tiny.cc", "t.ly"];
      const isShortened = isUrl && URL_SHORTENERS.some(short => domain === short || domain.endsWith('.' + short));
      if (isShortened) {
        calculatedScore += 10;
        threatsDetected.push('Short URL Redirection');
        technicalIndicators.push('URL Shortener Link');
      }

      // Parse threat indicator categories returned by AI response
      if (openRouterRes.threatsDetected && Array.isArray(openRouterRes.threatsDetected)) {
        openRouterRes.threatsDetected.forEach(threat => {
          const term = threat.toLowerCase();

          // Typosquatting (+20)
          if (term.includes('typo') || term.includes('look-alike')) {
            calculatedScore += 20;
            threatsDetected.push('Typosquatting');
            technicalIndicators.push('Typosquatting Look-alike Domain');
          }
          // Spoofed Domain (+20)
          if (term.includes('spoof')) {
            calculatedScore += 20;
            threatsDetected.push('Spoofed Domain');
            technicalIndicators.push('Spoofed Brand Domain');
          }
          // Unknown Domain (+10)
          if (term.includes('unknown domain') || term.includes('unrecognized')) {
            calculatedScore += 10;
            technicalIndicators.push('Unknown Domain Registry');
          }
          // Recently Registered (+20)
          if (term.includes('recent') || term.includes('newly registered')) {
            calculatedScore += 20;
            technicalIndicators.push('Recently Registered Domain');
          }
          // Redirect Chain (+15)
          if (term.includes('redirect') || term.includes('chain')) {
            calculatedScore += 15;
            technicalIndicators.push('Redirect Chain');
          }
          // Credential Harvesting (+30)
          if (term.includes('harvest') || term.includes('credential')) {
            calculatedScore += 30;
            threatsDetected.push('Credential Harvesting');
            technicalIndicators.push('Credential Harvesting forms');
          }
          // Financial Scam (+30)
          if (term.includes('financial') || term.includes('gateway') || term.includes('payment scam')) {
            calculatedScore += 30;
            threatsDetected.push('Financial Fraud Scam');
            technicalIndicators.push('Financial Scam indicators');
          }
          // Sticker Replacement (+20)
          if (term.includes('sticker') || term.includes('replacement')) {
            calculatedScore += 20;
            threatsDetected.push('Sticker Replacement');
            technicalIndicators.push('QR Sticker replacement possibility');
          }
          // Fake Banking (+25)
          if (term.includes('banking') || term.includes('fake bank')) {
            calculatedScore += 25;
            threatsDetected.push('Fake Banking Portal');
            technicalIndicators.push('Impersonation Banking Page');
          }
          // Fake UPI (+20)
          if (term.includes('fake upi') || term.includes('upi fraud')) {
            calculatedScore += 20;
            threatsDetected.push('Fake UPI VPA');
            technicalIndicators.push('UPI Payment Fraud Signature');
          }
          // OTP Scam (+25)
          if (term.includes('otp') || term.includes('one-time password')) {
            calculatedScore += 25;
            threatsDetected.push('OTP Fraud redirection');
            technicalIndicators.push('OTP Stealing forms');
          }
          // Identity Theft (+25)
          if (term.includes('identity') || term.includes('theft') || term.includes('kyc')) {
            calculatedScore += 25;
            threatsDetected.push('Identity Theft');
            technicalIndicators.push('KYC Identity Theft hooks');
          }
          // Malware (+35)
          if (term.includes('malware') || term.includes('apk') || term.includes('download')) {
            calculatedScore += 35;
            threatsDetected.push('Malware Payload');
            technicalIndicators.push('APK/Executable Malware link');
          }
        });
      }

      // Add other technical indicators from AI
      if (openRouterRes.technicalIndicators && Array.isArray(openRouterRes.technicalIndicators)) {
        openRouterRes.technicalIndicators.forEach(ind => {
          if (!technicalIndicators.includes(ind)) {
            technicalIndicators.push(ind);
          }
        });
      }

      // Ensure threat tags are unique
      const uniqueThreats = [...new Set(threatsDetected)];

      // Clamp risk score (0-100)
      const riskScore = Math.min(Math.max(calculatedScore, 0), 100);

      // Map Final Risk Level based on computed score
      let threatLevel = 'Safe';
      if (riskScore > 80) threatLevel = 'Critical';
      else if (riskScore > 60) threatLevel = 'High Risk';
      else if (riskScore > 40) threatLevel = 'Medium Risk';
      else if (riskScore > 20) threatLevel = 'Low Risk';

      // Recommendation matching
      let recommendation = openRouterRes.recommendation || 'Proceed';
      if (riskScore >= 60) {
        recommendation = 'Block';
      } else if (riskScore >= 40) {
        recommendation = 'Proceed Carefully';
      }

      analysis = {
        riskScore,
        confidence: openRouterRes.confidence || 85,
        threatLevel,
        threatCategory: openRouterRes.threatCategory || (riskScore <= 20 ? 'Safe' : 'Suspicious'),
        threatsDetected: uniqueThreats,
        reasoning: openRouterRes.reasoning || 'No immediate structural threats detected.',
        recommendation,
        technicalIndicators: technicalIndicators.length > 0 ? technicalIndicators : ['Safe Structural Format'],
        googleSafeBrowsing: safeBrowsingRes.isSafe ? 'Safe' : safeBrowsingRes.threatType,
        virusTotal: {
          malicious: virusTotalRes.malicious,
          suspicious: virusTotalRes.suspicious,
          harmless: virusTotalRes.harmless,
          ratio: virusTotalRes.ratio
        },
        communityReports: communityCount
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
      status: analysis.threatLevel === 'Safe' ? 'Safe' : (analysis.threatLevel === 'Low Risk' || analysis.threatLevel === 'Medium Risk' ? 'Suspicious' : 'Dangerous'),
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
      
      if (analysis.riskScore >= 75) {
        sandboxDb.incrementAnalytics(dateStr, 'highRisk');
      } else if (analysis.riskScore >= 30) {
        sandboxDb.incrementAnalytics(dateStr, 'mediumRisk');
      }
      if (analysis.riskScore >= 90) {
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
        if (analysis.riskScore >= 75) data.highRisk = (data.highRisk || 0) + 1;
        if (analysis.riskScore >= 30 && analysis.riskScore < 75) data.mediumRisk = (data.mediumRisk || 0) + 1;
        if (analysis.riskScore >= 90) data.criticalRisk = (data.criticalRisk || 0) + 1;

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
    return res.status(201).json({
      success: true,
      message: 'Scan analyzed and logged successfully',
      scan: scanRecord
    });

  } catch (error) {
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
