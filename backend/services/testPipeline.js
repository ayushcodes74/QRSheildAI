require('dotenv').config({ path: '../.env' });
const googleSafeBrowsing = require('./googleSafeBrowsing');
const virusTotal = require('./virusTotal');
const openRouter = require('./openRouter');

// Mock function mirroring scanController logic for offline validation
async function dryRunAnalysis(payload) {
  const qrType = payload.includes('upi://') ? 'UPI' : 'Website';
  const normalized = payload.toLowerCase();
  const domain = payload.includes('://') ? new URL(payload).hostname : '';

  console.log(`\n==================================================`);
  console.log(`DRY RUN SCAN: "${payload}" (${qrType})`);
  console.log(`==================================================`);

  // Concurrent checks
  const [safeBrowsingRes, virusTotalRes, openRouterRes] = await Promise.all([
    qrType === 'Website' ? googleSafeBrowsing.checkUrl(payload) : Promise.resolve({ isSafe: true, threatType: 'Safe' }),
    qrType === 'Website' ? virusTotal.checkUrl(payload) : Promise.resolve({ malicious: 0, suspicious: 0, harmless: 0, ratio: '0/0' }),
    openRouter.analyzePayload(payload)
  ]);

  console.log('• Google Safe Browsing:', safeBrowsingRes);
  console.log('• VirusTotal:', virusTotalRes);
  console.log('• OpenRouter AI Category:', openRouterRes.threatCategory);
  console.log('• OpenRouter AI Risk Score:', openRouterRes.riskScore);
  console.log('• OpenRouter AI Threats:', openRouterRes.threatsDetected);
  console.log('• OpenRouter AI Indicators:', openRouterRes.technicalIndicators);

  // Compute Risk
  let calculatedScore = 0;
  const technicalIndicators = [];
  const threatsDetected = [];

  if (qrType === 'Website' && !safeBrowsingRes.isSafe) {
    calculatedScore += 40;
    threatsDetected.push('Malicious Web Link');
    technicalIndicators.push(`Google Safe Browsing Blocklist (${safeBrowsingRes.threatType})`);
  }

  if (qrType === 'Website' && virusTotalRes.malicious > 0) {
    calculatedScore += 35;
    threatsDetected.push('Malicious URL Detection');
    technicalIndicators.push(`VirusTotal Malicious Vendors (${virusTotalRes.ratio})`);
  }

  if (qrType === 'Website' && virusTotalRes.suspicious > 0) {
    calculatedScore += 20;
    threatsDetected.push('Suspicious URL Detection');
    technicalIndicators.push('VirusTotal Suspicious Flag');
  }

  if (openRouterRes.confidence > 90 && openRouterRes.riskScore > 50) {
    calculatedScore += 30;
    technicalIndicators.push('AI High-Confidence Threat Flag');
  }

  const isHttp = qrType === 'Website' && normalized.startsWith('http://');
  if (isHttp) {
    calculatedScore += 15;
    technicalIndicators.push('Insecure HTTP Connection');
  }

  const URL_SHORTENERS = ["bit.ly", "tinyurl.com"];
  const isShortened = qrType === 'Website' && URL_SHORTENERS.some(short => domain.includes(short));
  if (isShortened) {
    calculatedScore += 10;
    threatsDetected.push('Short URL Redirection');
    technicalIndicators.push('URL Shortener Link');
  }

  if (openRouterRes.threatsDetected && Array.isArray(openRouterRes.threatsDetected)) {
    openRouterRes.threatsDetected.forEach(threat => {
      const term = threat.toLowerCase();
      if (term.includes('typo')) { calculatedScore += 20; threatsDetected.push('Typosquatting'); technicalIndicators.push('Typosquatting Domain'); }
      if (term.includes('spoof')) { calculatedScore += 20; threatsDetected.push('Spoofed Domain'); technicalIndicators.push('Spoofed Brand Domain'); }
      if (term.includes('harvest')) { calculatedScore += 30; threatsDetected.push('Credential Harvesting'); technicalIndicators.push('Harvesting Forms'); }
      if (term.includes('fake bank')) { calculatedScore += 25; threatsDetected.push('Fake Banking Portal'); technicalIndicators.push('Fake Bank Site'); }
      if (term.includes('fake upi')) { calculatedScore += 20; threatsDetected.push('Fake UPI VPA'); technicalIndicators.push('UPI Fraud'); }
      if (term.includes('malware')) { calculatedScore += 35; threatsDetected.push('Malware Payload'); technicalIndicators.push('Malicious Executable'); }
    });
  }

  const finalScore = Math.min(Math.max(calculatedScore, 0), 100);
  console.log(`\n▶ EVALUATED RISK SCORE: ${finalScore}/100`);
  let status = 'Safe';
  if (finalScore > 80) status = 'Critical';
  else if (finalScore > 60) status = 'High Risk';
  else if (finalScore > 40) status = 'Medium Risk';
  else if (finalScore > 20) status = 'Low Risk';
  console.log(`▶ STATUS LEVEL: ${status}`);
  console.log(`▶ REASONING: ${openRouterRes.reasoning}`);
  console.log(`▶ RECOMMENDATION: ${finalScore >= 60 ? 'Block' : finalScore >= 40 ? 'Proceed Carefully' : 'Proceed'}`);
}

async function run() {
  await dryRunAnalysis('https://google.com');
  await dryRunAnalysis('http://sbi-login-verification.xyz/secure');
  await dryRunAnalysis('upi://pay?pa=fakecashback@paytm&pn=FreeCashback&am=5000');
}

run();
