// Sandbox In-Memory Database for Offline/Demo Mode
const bcrypt = require('bcryptjs');

const users = [];
const scans = [];
const reports = [];
const threats = [];
const analytics = {};
const settings = {
  maintenanceMode: false,
  minRiskScoreForAlert: 75,
  allowedDomainExtensions: ['.com', '.org', '.net', '.edu', '.gov', '.in']
};

// Newly added Blocked collections and Activity logs for SOC Showcase
const blockedDomains = ['sbi-login-verification.xyz', 'paypal-security-login.xyz', 'amaz0n-payment.xyz'];
const blockedUpiIds = ['fakebiz@paytm', 'scamseller@ybl', 'fakecashback@paytm'];
const activityLogs = [
  { logId: 'log-1', action: 'User Login', details: 'Inspector Cybercop (Police) authenticated successfully.', timestamp: new Date(Date.now() - 600000).toISOString(), user: 'police@qrshield.ai' },
  { logId: 'log-2', action: 'Threat Detection', details: 'Critical Typosquatting threat (100/100) identified on http://sbi-login-verification.xyz/secure', timestamp: new Date(Date.now() - 1200000).toISOString(), user: 'System' },
  { logId: 'log-3', action: 'Admin Action', details: 'Domain sbi-login-verification.xyz appended to Global Firewall Blocklist.', timestamp: new Date(Date.now() - 1800000).toISOString(), user: 'admin@qrshield.ai' },
  { logId: 'log-4', action: 'User Login', details: 'Cyber Chief Admin (Admin) logged in from command terminal.', timestamp: new Date(Date.now() - 2400000).toISOString(), user: 'admin@qrshield.ai' },
  { logId: 'log-5', action: 'Reports Audit', details: 'Phishing complaint rep-1 status updated to Investigating.', timestamp: new Date(Date.now() - 7200000).toISOString(), user: 'police@qrshield.ai' }
];

// Seed default users
const seedUsers = async () => {
  const adminPasswordHash = await bcrypt.hash('admin123', 10);
  const policePasswordHash = await bcrypt.hash('police123', 10);
  const userPasswordHash = await bcrypt.hash('user123', 10);

  users.push(
    {
      uid: 'mock-admin-uid',
      name: 'Cyber Chief Admin',
      email: 'admin@qrshield.ai',
      passwordHash: adminPasswordHash,
      photo: 'https://images.unsplash.com/photo-1535713875002-d1d0cf377fde?w=150',
      role: 'Admin',
      createdAt: new Date(Date.now() - 10 * 24 * 3600000).toISOString(),
      lastLogin: new Date().toISOString()
    },
    {
      uid: 'mock-police-uid',
      name: 'Inspector Cybercop',
      email: 'police@qrshield.ai',
      passwordHash: policePasswordHash,
      photo: 'https://images.unsplash.com/photo-1570295999919-56ceb5ecca61?w=150',
      role: 'Police',
      createdAt: new Date(Date.now() - 8 * 24 * 3600000).toISOString(),
      lastLogin: new Date().toISOString()
    },
    {
      uid: 'mock-user-uid',
      name: 'Ayush Kumar',
      email: 'user@qrshield.ai',
      passwordHash: userPasswordHash,
      photo: 'https://images.unsplash.com/photo-1494790108377-be9c29b29330?w=150',
      role: 'User',
      createdAt: new Date(Date.now() - 5 * 24 * 3600000).toISOString(),
      lastLogin: new Date().toISOString()
    }
  );
};

// Seed default scans
const seedScans = () => {
  const baseTime = Date.now();
  scans.push(
    {
      scanId: 'scan-1',
      userId: 'mock-user-uid',
      payload: 'https://github.com/ayushcodes74',
      qrType: 'Website',
      riskScore: 5,
      status: 'Safe',
      city: 'Mumbai',
      state: 'Maharashtra',
      latitude: 19.0760,
      longitude: 72.8777,
      timestamp: new Date(baseTime - 4 * 3600000).toISOString()
    },
    {
      scanId: 'scan-2',
      userId: 'mock-user-uid',
      payload: 'http://sbi-login-verification.xyz/secure/login.php',
      qrType: 'Website',
      riskScore: 100,
      status: 'Dangerous',
      city: 'Delhi',
      state: 'Delhi',
      latitude: 28.7041,
      longitude: 77.1025,
      timestamp: new Date(baseTime - 3 * 3600000).toISOString(),
      analysis: {
        riskScore: 100,
        confidence: 94,
        threatLevel: 'Critical',
        threatCategory: 'Phishing',
        threatsDetected: ['Phishing', 'Spoofed Domain', 'Suspicious TLD'],
        reasoning: 'Typosquatting site masquerading as online SBI login on untrusted domain extension (.xyz).',
        recommendation: 'Block',
        technicalIndicators: ['HTTPS Missing', 'Suspicious TLD', 'Typosquatting Domain'],
        googleSafeBrowsing: 'SOCIAL_ENGINEERING',
        virusTotal: { malicious: 5, suspicious: 2, harmless: 65, ratio: '5/72' },
        communityReports: 1
      }
    },
    {
      scanId: 'scan-3',
      userId: 'mock-user-uid',
      payload: 'upi://pay?pa=fakecashback@paytm&pn=FreeCashback&am=5000',
      qrType: 'UPI',
      riskScore: 60,
      status: 'Suspicious',
      city: 'Bangalore',
      state: 'Karnataka',
      latitude: 12.9716,
      longitude: 77.5946,
      timestamp: new Date(baseTime - 2 * 3600000).toISOString(),
      analysis: {
        riskScore: 60,
        confidence: 90,
        threatLevel: 'High Risk',
        threatCategory: 'UPI Fraud',
        threatsDetected: ['Fake Cashback', 'Fake Reward', 'Payment Gateway Scam'],
        reasoning: 'Prefilled transaction seeking funds using cashback/reward bait.',
        recommendation: 'Proceed Carefully',
        technicalIndicators: ['VPA Unverified', 'Cashback Bait'],
        googleSafeBrowsing: 'Safe',
        virusTotal: { malicious: 0, suspicious: 0, harmless: 0, ratio: '0/0' },
        communityReports: 1
      }
    },
    {
      scanId: 'scan-4',
      userId: 'mock-admin-uid',
      payload: 'WIFI:S:PublicAirportWifi;T:WPA;P:guest123;;',
      qrType: 'WiFi',
      riskScore: 15,
      status: 'Safe',
      city: 'Mumbai',
      state: 'Maharashtra',
      latitude: 19.0760,
      longitude: 72.8777,
      timestamp: new Date(baseTime - 1 * 3600000).toISOString()
    },
    {
      scanId: 'scan-5',
      userId: 'mock-user-uid',
      payload: 'https://netflix-free-premium.xyz/promo',
      qrType: 'Website',
      riskScore: 85,
      status: 'Dangerous',
      city: 'Pune',
      state: 'Maharashtra',
      latitude: 18.5204,
      longitude: 73.8567,
      timestamp: new Date(baseTime - 8 * 3600000).toISOString(),
      analysis: {
        riskScore: 85,
        confidence: 88,
        threatLevel: 'High Risk',
        threatCategory: 'Phishing',
        threatsDetected: ['Phishing', 'Free Premium Bait'],
        reasoning: 'Mimics official Netflix page using premium service bait to harvest credit card metrics.',
        recommendation: 'Block',
        technicalIndicators: ['Suspicious TLD', 'Bait language'],
        googleSafeBrowsing: 'SOCIAL_ENGINEERING',
        virusTotal: { malicious: 2, suspicious: 1, harmless: 69, ratio: '2/72' },
        communityReports: 0
      }
    }
  );
};

// Seed default threats
const seedThreats = () => {
  threats.push(
    {
      domain: 'sbi-login-verification.xyz',
      threatType: 'Phishing Impersonation',
      timesDetected: 5,
      lastSeen: new Date().toISOString(),
      severity: 'Critical'
    },
    {
      domain: 'paypal-security-login.xyz',
      threatType: 'Credential Harvesting',
      timesDetected: 3,
      lastSeen: new Date(Date.now() - 24 * 3600000).toISOString(),
      severity: 'Critical'
    },
    {
      domain: 'netflix-free-premium.xyz',
      threatType: 'Impersonation Phishing',
      timesDetected: 2,
      lastSeen: new Date(Date.now() - 8 * 3600000).toISOString(),
      severity: 'High'
    }
  );
};

// Seed default reports
const seedReports = () => {
  reports.push(
    {
      reportId: 'rep-1',
      userId: 'mock-user-uid',
      scanId: 'scan-2',
      payload: 'http://sbi-login-verification.xyz/secure/login.php',
      reason: 'Phishing Website',
      riskScore: 100,
      city: 'Delhi',
      state: 'Delhi',
      country: 'India',
      status: 'Pending',
      description: 'Pretends to be the official SBI online login portal. Asks for OTP and netbanking password.',
      createdAt: new Date(Date.now() - 3 * 3600000).toISOString()
    },
    {
      reportId: 'rep-2',
      userId: 'mock-user-uid',
      scanId: 'scan-3',
      payload: 'upi://pay?pa=fakecashback@paytm&pn=FreeCashback&am=5000',
      reason: 'UPI Fraud',
      riskScore: 60,
      city: 'Bangalore',
      state: 'Karnataka',
      country: 'India',
      status: 'Investigating',
      description: 'Scan requests a prefilled amount of 5,000 INR claiming to award cashback.',
      createdAt: new Date(Date.now() - 12 * 3600000).toISOString()
    }
  );
};

// Initialize seeding
seedUsers().then(() => {
  seedScans();
  seedThreats();
  seedReports();
});

// Helper functions for Sandbox interaction
module.exports = {
  users,
  scans,
  reports,
  threats,
  analytics,
  settings,
  blockedDomains,
  blockedUpiIds,
  activityLogs,
  
  getDailyAnalytics: (dateStr) => {
    if (!analytics[dateStr]) {
      // Calculate from scans and reports arrays
      const dateScans = scans.filter(s => s.timestamp.startsWith(dateStr));
      const dateReports = reports.filter(r => r.createdAt.startsWith(dateStr));
      
      analytics[dateStr] = {
        dailyScans: dateScans.length,
        safeScans: dateScans.filter(s => s.status === 'Safe').length,
        dangerousScans: dateScans.filter(s => s.status === 'Dangerous').length,
        highRisk: dateScans.filter(s => s.riskScore >= 75).length,
        mediumRisk: dateScans.filter(s => s.riskScore >= 30 && s.riskScore < 75).length,
        criticalRisk: dateScans.filter(s => s.riskScore >= 90).length,
        reportsToday: dateReports.length
      };
    }
    return analytics[dateStr];
  },
  
  incrementAnalytics: (dateStr, type) => {
    const daily = module.exports.getDailyAnalytics(dateStr);
    if (type === 'scan') {
      daily.dailyScans += 1;
    } else if (type === 'safe') {
      daily.safeScans += 1;
    } else if (type === 'dangerous') {
      daily.dangerousScans += 1;
    } else if (type === 'highRisk') {
      daily.highRisk += 1;
    } else if (type === 'mediumRisk') {
      daily.mediumRisk += 1;
    } else if (type === 'criticalRisk') {
      daily.criticalRisk += 1;
    } else if (type === 'report') {
      daily.reportsToday += 1;
    }
  }
};
