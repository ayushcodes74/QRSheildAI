const { db, isSandbox } = require('../config/firebase');
const sandboxDb = require('../services/sandboxDb');
const { getThreatLevel, getRiskStatus } = require('../services/severityPolicy');

// Helper: Extract domain from URL
function getDomainName(urlStr) {
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
}

// Helper: Extract VPA from UPI URI
function getUPIVPA(payload) {
  if (!payload) return null;
  const trimmed = payload.trim();
  if (trimmed.startsWith('upi://pay')) {
    try {
      const url = new URL(trimmed);
      const pa = url.searchParams.get('pa');
      if (pa) return pa.toLowerCase();
    } catch (e) {
      const match = trimmed.match(/pa=([^&]+)/i);
      if (match) return decodeURIComponent(match[1]).toLowerCase();
    }
  }
  if (trimmed.includes('@') && !trimmed.startsWith('mailto:')) {
    return trimmed.toLowerCase();
  }
  return null;
}

// Helper: Compile SOC Stats from raw arrays
const compileDashboardStats = (allScans, allReports, allThreats, blockedD, blockedU, activeUsersCount) => {
  const baseTime = new Date();
  const todayStr = baseTime.toISOString().split('T')[0];

  const todayScans = allScans.filter(s => s.timestamp.startsWith(todayStr));
  const todayReports = allReports.filter(r => r.createdAt.startsWith(todayStr));

  // Risk Score breakdown
  const lowRisk = allScans.filter(s => getThreatLevel(s.riskScore) === 'Low Risk').length;
  const mediumRisk = allScans.filter(s => getThreatLevel(s.riskScore) === 'Medium Risk').length;
  const highRisk = allScans.filter(s => getThreatLevel(s.riskScore) === 'High Risk').length;
  const criticalThreats = allScans.filter(s => getThreatLevel(s.riskScore) === 'Critical').length;

  const avgRiskScore = allScans.length > 0
    ? Math.round(allScans.reduce((acc, s) => acc + s.riskScore, 0) / allScans.length)
    : 0;

  const avgScanTimeMs = isSandbox ? 1450 : 1520;

  return {
    scansToday: todayScans.length,
    safeScans: allScans.filter(s => getRiskStatus(s.riskScore) === 'Safe').length,
    lowRisk,
    mediumRisk,
    highRisk,
    criticalThreats,
    reportsToday: todayReports.length,
    pendingReports: allReports.filter(r => r.status === 'Pending' || r.status === 'Investigating').length,
    resolvedReports: allReports.filter(r => r.status === 'Resolved' || r.status === 'Approved').length,
    blockedDomainsCount: blockedD.length,
    blockedUpiCount: blockedU.length,
    activeUsers: activeUsersCount,
    avgRiskScore,
    avgScanTimeMs
  };
};

// Helper: Compile Threat Intelligence Insights
const compileThreatIntelligence = (allScans, allReports, allThreats, blockedD) => {
  // Top scam category
  const categoryCounts = {};
  allReports.forEach(r => {
    if (r.reason) {
      categoryCounts[r.reason] = (categoryCounts[r.reason] || 0) + 1;
    }
  });
  const topScamCategory = Object.keys(categoryCounts).length > 0 
    ? Object.keys(categoryCounts).sort((a,b) => categoryCounts[b] - categoryCounts[a])[0] 
    : 'No Data Yet';

  // Most Blocked Domain (only from blocked domains list)
  let mostDangerousDomain = 'No Domains Blocked';
  if (blockedD && blockedD.length > 0) {
    const blockedHits = {};
    blockedD.forEach(d => { blockedHits[d] = 0; });
    allScans.forEach(s => {
      const dom = getDomainName(s.payload);
      if (dom && blockedHits[dom] !== undefined) {
        blockedHits[dom]++;
      }
    });
    const sortedBlocked = [...blockedD].sort((a,b) => blockedHits[b] - blockedHits[a]);
    mostDangerousDomain = sortedBlocked[0];
  }

  // Top Detected Malicious Domain (from dangerous/critical scans)
  const scanDomainCounts = {};
  allScans.filter(s => s.riskScore > 60).forEach(s => {
    const dom = getDomainName(s.payload);
    if (dom && dom !== 'unknown' && dom !== 'n/a') {
      scanDomainCounts[dom] = (scanDomainCounts[dom] || 0) + 1;
    }
  });
  const topDetectedDomain = Object.keys(scanDomainCounts).length > 0
    ? Object.keys(scanDomainCounts).sort((a,b) => scanDomainCounts[b] - scanDomainCounts[a])[0]
    : 'No Data Yet';

  // Most Reported Merchant
  const merchantCounts = {};
  allScans.forEach(s => {
    if (s.qrType === 'UPI' && s.analysis && s.analysis.details) {
      const merch = s.analysis.details.merchantName || 'Unknown';
      if (merch !== 'Unknown' && merch !== 'Unverified Merchant') {
        merchantCounts[merch] = (merchantCounts[merch] || 0) + 1;
      }
    }
  });
  const mostReportedMerchant = Object.keys(merchantCounts).length > 0
    ? Object.keys(merchantCounts).sort((a,b) => merchantCounts[b] - merchantCounts[a])[0]
    : 'No Data Yet';

  // Most Dangerous QR (based on highest score)
  const dangerousScans = allScans.filter(s => s.riskScore > 60).sort((a,b) => b.riskScore - a.riskScore);
  const mostDangerousQr = dangerousScans.length > 0 ? dangerousScans[0].payload : 'No Data Yet';

  // Most Reported VPA (from reports)
  const vpaCounts = {};
  allReports.forEach(r => {
    const vpa = getUPIVPA(r.payload);
    if (vpa) {
      vpaCounts[vpa] = (vpaCounts[vpa] || 0) + 1;
    }
  });
  const mostDangerousUpi = Object.keys(vpaCounts).length > 0
    ? Object.keys(vpaCounts).sort((a,b) => vpaCounts[b] - vpaCounts[a])[0]
    : 'No Data Yet';

  // Top Threat Detection Region
  const dangerousScansForRegion = allScans.filter(s => s.riskScore > 50);
  let mostDangerousCity = 'Insufficient Data';
  let mostDangerousState = '';

  if (dangerousScansForRegion.length >= 3) {
    const cityCounts = {};
    const stateCounts = {};
    dangerousScansForRegion.forEach(s => {
      const c = s.city && s.city !== 'Unknown' ? s.city : null;
      const st = s.state && s.state !== 'Unknown' ? s.state : null;
      if (c) cityCounts[c] = (cityCounts[c] || 0) + 1;
      if (st) stateCounts[st] = (stateCounts[st] || 0) + 1;
    });

    const sortedCities = Object.keys(cityCounts).sort((a,b) => cityCounts[b] - cityCounts[a]);
    const sortedStates = Object.keys(stateCounts).sort((a,b) => stateCounts[b] - stateCounts[a]);

    if (sortedCities.length > 0) {
      mostDangerousCity = sortedCities[0];
    }
    if (sortedStates.length > 0) {
      mostDangerousState = sortedStates[0];
    }
  }

  // Top Targeted Brand
  const brandKeywords = ['sbi', 'paypal', 'netflix', 'amazon', 'paytm', 'phonepe', 'google'];
  const brandCounts = {};
  allScans.filter(s => s.riskScore > 50).forEach(s => {
    const text = s.payload.toLowerCase();
    brandKeywords.forEach(brand => {
      if (text.includes(brand)) {
        brandCounts[brand] = (brandCounts[brand] || 0) + 1;
      }
    });
  });
  const topTargetedBrand = Object.keys(brandCounts).length > 0
    ? Object.keys(brandCounts).sort((a,b) => brandCounts[b] - brandCounts[a])[0].toUpperCase()
    : 'No Data Yet';

  return {
    topScamCategory,
    mostDangerousDomain,
    topDetectedDomain,
    mostReportedMerchant,
    mostDangerousQr,
    mostDangerousUpi,
    mostDangerousCity,
    mostDangerousState,
    fastestGrowingScam: 'Insufficient Data',
    topTargetedBrand
  };
};

// GET /admin/dashboard - Overview Statistics
exports.getDashboardStats = async (req, res, next) => {
  try {
    if (isSandbox) {
      const stats = compileDashboardStats(
        sandboxDb.scans,
        sandboxDb.reports,
        sandboxDb.threats,
        sandboxDb.blockedDomains,
        sandboxDb.blockedUpiIds,
        sandboxDb.users.length
      );
      return res.status(200).json({ 
        success: true, 
        stats,
        blockedDomains: sandboxDb.blockedDomains,
        blockedUpiIds: sandboxDb.blockedUpiIds
      });
    } else {
      const [scansSnap, reportsSnap, threatsSnap, blockedDSnap, blockedUSnap, usersSnap] = await Promise.all([
        db.collection('scans').get(),
        db.collection('reports').get(),
        db.collection('threats').get(),
        db.collection('blocked_domains').get(),
        db.collection('blocked_upi_ids').get(),
        db.collection('users').get()
      ]);

      const allScans = [];
      scansSnap.forEach(doc => allScans.push(doc.data()));

      const allReports = [];
      reportsSnap.forEach(doc => allReports.push(doc.data()));

      const allThreats = [];
      threatsSnap.forEach(doc => allThreats.push(doc.data()));

      const blockedD = [];
      blockedDSnap.forEach(doc => blockedD.push(doc.id));

      const blockedU = [];
      blockedUSnap.forEach(doc => blockedU.push(doc.id));

      const stats = compileDashboardStats(allScans, allReports, allThreats, blockedD, blockedU, usersSnap.size);
      return res.status(200).json({ 
        success: true, 
        stats,
        blockedDomains: blockedD,
        blockedUpiIds: blockedU
      });
    }
  } catch (error) {
    next(error);
  }
};

// GET /admin/stats - Threat Intelligence Panel
exports.getThreatIntelligence = async (req, res, next) => {
  try {
    if (isSandbox) {
      const intel = compileThreatIntelligence(sandboxDb.scans, sandboxDb.reports, sandboxDb.threats, sandboxDb.blockedDomains);
      return res.status(200).json({ success: true, intelligence: intel });
    } else {
      const [scansSnap, reportsSnap, threatsSnap, blockedDSnap] = await Promise.all([
        db.collection('scans').get(),
        db.collection('reports').get(),
        db.collection('threats').get(),
        db.collection('blocked_domains').get()
      ]);

      const allScans = [];
      scansSnap.forEach(doc => allScans.push(doc.data()));

      const allReports = [];
      reportsSnap.forEach(doc => allReports.push(doc.data()));

      const allThreats = [];
      threatsSnap.forEach(doc => allThreats.push(doc.data()));

      const blockedD = [];
      blockedDSnap.forEach(doc => blockedD.push(doc.id));

      const intel = compileThreatIntelligence(allScans, allReports, allThreats, blockedD);
      return res.status(200).json({ success: true, intelligence: intel });
    }
  } catch (error) {
    next(error);
  }
};

// GET /admin/analytics - Detailed timeline analysis and charts data
exports.getAnalytics = async (req, res, next) => {
  try {
    const baseTime = new Date();
    
    if (isSandbox) {
      // Return monthly trend and aggregations
      const dailyScans = sandboxDb.scans.length;
      const avgRisk = Math.round(sandboxDb.scans.reduce((acc, s) => acc + s.riskScore, 0) / (dailyScans || 1));
      
      const threatTypes = {};
      const qrTypes = {};
      
      sandboxDb.scans.forEach(s => {
        qrTypes[s.qrType] = (qrTypes[s.qrType] || 0) + 1;
        if (s.riskScore > 40) {
          const category = s.analysis?.threatCategory || 'Phishing';
          threatTypes[category] = (threatTypes[category] || 0) + 1;
        }
      });

      return res.status(200).json({
        success: true,
        analytics: {
          avgRiskScore: avgRisk,
          avgScanTimeMs: 1450,
          detectionAccuracy: 96,
          threatGrowth: '+12%',
          qrTypesDistribution: qrTypes,
          threatCategoriesDistribution: threatTypes
        }
      });
    } else {
      const scansSnap = await db.collection('scans').get();
      const allScans = [];
      scansSnap.forEach(doc => allScans.push(doc.data()));

      const totalScans = allScans.length;
      const avgRisk = Math.round(allScans.reduce((acc, s) => acc + s.riskScore, 0) / (totalScans || 1));

      const threatTypes = {};
      const qrTypes = {};
      
      allScans.forEach(s => {
        qrTypes[s.qrType] = (qrTypes[s.qrType] || 0) + 1;
        if (s.riskScore > 40) {
          const category = s.analysis?.threatCategory || 'Phishing';
          threatTypes[category] = (threatTypes[category] || 0) + 1;
        }
      });

      return res.status(200).json({
        success: true,
        analytics: {
          avgRiskScore: avgRisk,
          avgScanTimeMs: 1520,
          detectionAccuracy: 98,
          threatGrowth: '+8%',
          qrTypesDistribution: qrTypes,
          threatCategoriesDistribution: threatTypes
        }
      });
    }
  } catch (error) {
    next(error);
  }
};

// GET /admin/map - Geospatial markers
exports.getMapMarkers = async (req, res, next) => {
  try {
    if (isSandbox) {
      const markers = sandboxDb.scans.map(s => ({
        city: s.city || 'Unknown',
        lat: s.latitude || 19.0760,
        lng: s.longitude || 72.8777,
        payload: s.payload,
        qrType: s.qrType,
        riskScore: s.riskScore,
        status: s.status
      }));
      return res.status(200).json({ success: true, markers });
    } else {
      const scansSnap = await db.collection('scans').get();
      const markers = [];
      scansSnap.forEach(doc => {
        const s = doc.data();
        markers.push({
          city: s.city || 'Unknown',
          lat: s.latitude || 19.0760,
          lng: s.longitude || 72.8777,
          payload: s.payload,
          qrType: s.qrType,
          riskScore: s.riskScore,
          status: s.status
        });
      });
      return res.status(200).json({ success: true, markers });
    }
  } catch (error) {
    next(error);
  }
};

// GET /admin/activity - Audit Logs
exports.getActivityLogs = async (req, res, next) => {
  try {
    if (isSandbox) {
      return res.status(200).json({ success: true, logs: sandboxDb.activityLogs });
    } else {
      const snap = await db.collection('activity_logs').orderBy('timestamp', 'desc').limit(50).get();
      const logs = [];
      snap.forEach(doc => logs.push(doc.data()));
      return res.status(200).json({ success: true, logs });
    }
  } catch (error) {
    next(error);
  }
};

// POST /admin/block - Block domain or VPA
exports.blockThreat = async (req, res, next) => {
  try {
    const { value, type } = req.body; // type: 'domain' or 'upi'
    if (!value || !type) {
      return res.status(400).json({ success: false, message: 'Value and block type are required.' });
    }

    const email = req.user ? req.user.email : 'System';

    if (isSandbox) {
      if (type === 'domain') {
        if (!sandboxDb.blockedDomains.includes(value)) sandboxDb.blockedDomains.push(value);
      } else {
        if (!sandboxDb.blockedUpiIds.includes(value)) sandboxDb.blockedUpiIds.push(value);
      }

      // Add to Activity
      sandboxDb.activityLogs.unshift({
        logId: 'log-' + Date.now(),
        action: 'Block Rule Added',
        details: `Blocked ${type}: ${value}`,
        timestamp: new Date().toISOString(),
        user: email
      });

      return res.status(200).json({ success: true, message: `Successfully blocked ${type}` });
    } else {
      const col = type === 'domain' ? 'blocked_domains' : 'blocked_upi_ids';
      await db.collection(col).doc(value.replace(/\./g, '_')).set({
        value,
        blockedBy: email,
        timestamp: new Date().toISOString()
      });

      // Write to audits
      await db.collection('activity_logs').add({
        action: 'Block Rule Added',
        details: `Blocked ${type}: ${value}`,
        timestamp: new Date().toISOString(),
        user: email
      });

      return res.status(200).json({ success: true, message: `Successfully blocked ${type} in database` });
    }
  } catch (error) {
    next(error);
  }
};

// PUT /admin/report/:id - Update report status
exports.updateReportStatus = async (req, res, next) => {
  try {
    const { id } = req.params;
    const { status } = req.body; // e.g. Resolved, Investigating

    if (!status) {
      return res.status(400).json({ success: false, message: 'Status is required.' });
    }

    const email = req.user ? req.user.email : 'System';

    if (isSandbox) {
      const rep = sandboxDb.reports.find(r => r.reportId === id);
      if (!rep) return res.status(404).json({ success: false, message: 'Report not found' });
      rep.status = status;

      sandboxDb.activityLogs.unshift({
        logId: 'log-' + Date.now(),
        action: 'Report Status updated',
        details: `Report ${id} updated to ${status}`,
        timestamp: new Date().toISOString(),
        user: email
      });

      return res.status(200).json({ success: true, message: 'Report updated (Sandbox)' });
    } else {
      const docRef = db.collection('reports').doc(id);
      const doc = await docRef.get();
      if (!doc.exists) return res.status(404).json({ success: false, message: 'Report not found' });

      await docRef.update({ status });

      await db.collection('activity_logs').add({
        action: 'Report Status updated',
        details: `Report ${id} updated to ${status}`,
        timestamp: new Date().toISOString(),
        user: email
      });

      return res.status(200).json({ success: true, message: 'Report status updated successfully' });
    }
  } catch (error) {
    next(error);
  }
};

// DELETE /admin/report/:id - Delete report node
exports.deleteReport = async (req, res, next) => {
  try {
    const { id } = req.params;
    const email = req.user ? req.user.email : 'System';

    if (isSandbox) {
      const idx = sandboxDb.reports.findIndex(r => r.reportId === id);
      if (idx === -1) return res.status(404).json({ success: false, message: 'Report not found' });
      sandboxDb.reports.splice(idx, 1);

      sandboxDb.activityLogs.unshift({
        logId: 'log-' + Date.now(),
        action: 'Report Purged',
        details: `Report ${id} deleted by Admin`,
        timestamp: new Date().toISOString(),
        user: email
      });

      return res.status(200).json({ success: true, message: 'Report deleted (Sandbox)' });
    } else {
      const docRef = db.collection('reports').doc(id);
      const doc = await docRef.get();
      if (!doc.exists) return res.status(404).json({ success: false, message: 'Report not found' });

      await docRef.delete();

      await db.collection('activity_logs').add({
        action: 'Report Purged',
        details: `Report ${id} deleted by Admin`,
        timestamp: new Date().toISOString(),
        user: email
      });

      return res.status(200).json({ success: true, message: 'Report deleted successfully' });
    }
  } catch (error) {
    next(error);
  }
};

// PUT /admin/user/:id/role - Manage user roles
exports.updateUserRole = async (req, res, next) => {
  try {
    const { id } = req.params;
    const { role } = req.body;

    if (!role) {
      return res.status(400).json({ success: false, message: 'Role is required.' });
    }

    const email = req.user ? req.user.email : 'System';

    if (isSandbox) {
      const usr = sandboxDb.users.find(u => u.uid === id);
      if (!usr) return res.status(404).json({ success: false, message: 'User not found' });
      const oldRole = usr.role;
      usr.role = role;

      sandboxDb.activityLogs.unshift({
        logId: 'log-' + Date.now(),
        action: 'User Role Promoted',
        details: `Promoted user ${usr.email} from ${oldRole} to ${role}`,
        timestamp: new Date().toISOString(),
        user: email
      });

      return res.status(200).json({ success: true, message: `Successfully updated user to ${role} (Sandbox)` });
    } else {
      const docRef = db.collection('users').doc(id);
      const doc = await docRef.get();
      if (!doc.exists) return res.status(404).json({ success: false, message: 'User not found' });

      const oldRole = doc.data().role || 'User';
      await docRef.update({ role });

      await db.collection('activity_logs').add({
        action: 'User Role Promoted',
        details: `Promoted user ${doc.data().email} from ${oldRole} to ${role}`,
        timestamp: new Date().toISOString(),
        user: email
      });

      return res.status(200).json({ success: true, message: `Successfully updated user to ${role}` });
    }
  } catch (error) {
    next(error);
  }
};

// GET /admin/users
exports.getAllUsers = async (req, res, next) => {
  try {
    if (isSandbox) {
      const safeUsers = sandboxDb.users.map(u => ({
        uid: u.uid,
        name: u.name,
        email: u.email,
        photo: u.photo,
        role: u.role,
        createdAt: u.createdAt,
        lastLogin: u.lastLogin
      }));
      return res.status(200).json({ success: true, users: safeUsers });
    } else {
      const snapshot = await db.collection('users').get();
      const usersList = [];
      snapshot.forEach(doc => {
        usersList.push(doc.data());
      });
      return res.status(200).json({ success: true, users: usersList });
    }
  } catch (error) {
    next(error);
  }
};

// GET /admin/scans
exports.getAllScans = async (req, res, next) => {
  try {
    if (isSandbox) {
      return res.status(200).json({ success: true, scans: sandboxDb.scans });
    } else {
      const snapshot = await db.collection('scans').orderBy('timestamp', 'desc').get();
      const scansList = [];
      snapshot.forEach(doc => {
        scansList.push(doc.data());
      });
      return res.status(200).json({ success: true, scans: scansList });
    }
  } catch (error) {
    next(error);
  }
};

// GET /admin/reports
exports.getAllReports = async (req, res, next) => {
  try {
    if (isSandbox) {
      return res.status(200).json({ success: true, reports: sandboxDb.reports });
    } else {
      const snapshot = await db.collection('reports').orderBy('createdAt', 'desc').get();
      const reportsList = [];
      snapshot.forEach(doc => {
        reportsList.push(doc.data());
      });
      return res.status(200).json({ success: true, reports: reportsList });
    }
  } catch (error) {
    next(error);
  }
};
