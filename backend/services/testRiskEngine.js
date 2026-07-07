const assert = require('assert').strict;
const riskEngine = require('./riskEngine');

console.log('Starting Risk Engine tests...\n');

let passedTestsCount = 0;

function runTestCase(name, fn) {
  try {
    fn();
    console.log(`\x1b[32m✔ PASS: ${name}\x1b[0m`);
    passedTestsCount++;
  } catch (err) {
    console.error(`\x1b[31m✘ FAIL: ${name}\x1b[0m`);
    console.error(err);
  }
}

// Helper default clean mock inputs
const cleanSafeBrowsing = { isSafe: true, threatType: 'Safe' };
const cleanVirusTotal = { malicious: 0, suspicious: 0, harmless: 70, undetected: 10, ratio: '0/80' };
const cleanOpenRouter = { riskScore: 0, confidence: 95, threatLevel: 'Safe', threatCategory: 'Safe', reasoning: 'Clean payload', threatsDetected: [], technicalIndicators: [] };
const cleanCommunityCount = 0;

// Test 1: Clean HTTPS URL with no threat intelligence hits
runTestCase('Clean HTTPS URL with no threat intelligence hits', () => {
  const result = riskEngine.evaluate({
    payload: 'https://google.com',
    qrType: 'Website',
    domain: 'google.com',
    safeBrowsingRes: cleanSafeBrowsing,
    virusTotalRes: cleanVirusTotal,
    openRouterRes: cleanOpenRouter,
    communityCount: cleanCommunityCount
  });

  assert.equal(result.riskScore, 0, 'Risk score should be 0');
  assert.equal(result.threatLevel, 'Safe');
  assert.equal(result.recommendation, 'Proceed');
  assert.deepEqual(result.threatsDetected, []);
  assert.deepEqual(result.technicalIndicators, ['Safe Structural Format']);
});

// Test 2: HTTP URL (structural +5)
runTestCase('HTTP URL', () => {
  const result = riskEngine.evaluate({
    payload: 'http://example.com',
    qrType: 'Website',
    domain: 'example.com',
    safeBrowsingRes: cleanSafeBrowsing,
    virusTotalRes: cleanVirusTotal,
    openRouterRes: cleanOpenRouter,
    communityCount: cleanCommunityCount
  });

  assert.equal(result.riskScore, 5, 'Risk score should be 5');
  assert.equal(result.threatLevel, 'Safe');
  assert.equal(result.recommendation, 'Proceed');
  assert.ok(result.technicalIndicators.includes('Insecure HTTP Connection'));
});

// Test 3: Known URL shortener (shortener +5, HTTP +5 = 10)
runTestCase('Known URL shortener', () => {
  const result = riskEngine.evaluate({
    payload: 'http://bit.ly/xyz',
    qrType: 'Website',
    domain: 'bit.ly',
    safeBrowsingRes: cleanSafeBrowsing,
    virusTotalRes: cleanVirusTotal,
    openRouterRes: cleanOpenRouter,
    communityCount: cleanCommunityCount
  });

  assert.equal(result.riskScore, 10, 'Risk score should be 10');
  assert.ok(result.threatsDetected.includes('Short URL Redirection'));
  assert.ok(result.technicalIndicators.includes('URL Shortener Link'));
  assert.ok(result.technicalIndicators.includes('Insecure HTTP Connection'));
});

// Test 4: Safe Browsing confirmed phishing URL (GSB +40, override to min 70)
runTestCase('Safe Browsing confirmed phishing URL', () => {
  const result = riskEngine.evaluate({
    payload: 'https://unsafe-phishing.com',
    qrType: 'Website',
    domain: 'unsafe-phishing.com',
    safeBrowsingRes: { isSafe: false, threatType: 'SOCIAL_ENGINEERING' },
    virusTotalRes: cleanVirusTotal,
    openRouterRes: cleanOpenRouter,
    communityCount: cleanCommunityCount
  });

  // GSB contribution is 40. Override rules: GSB SOCIAL_ENGINEERING confirms -> min score 70.
  assert.equal(result.riskScore, 70, 'Risk score must be at least 70');
  assert.equal(result.threatLevel, 'High Risk');
  assert.equal(result.recommendation, 'Block');
  assert.ok(result.threatsDetected.includes('Malicious Web Link'));
  assert.ok(result.technicalIndicators.includes('Google Safe Browsing Blocklist (SOCIAL_ENGINEERING)'));
});

// Test 5: VirusTotal with 1 malicious engine (VT +10)
runTestCase('VirusTotal with 1 malicious engine', () => {
  const result = riskEngine.evaluate({
    payload: 'https://example.com',
    qrType: 'Website',
    domain: 'example.com',
    safeBrowsingRes: cleanSafeBrowsing,
    virusTotalRes: { malicious: 1, suspicious: 0, harmless: 69, undetected: 10, ratio: '1/80' },
    openRouterRes: cleanOpenRouter,
    communityCount: cleanCommunityCount
  });

  assert.equal(result.riskScore, 10, 'Risk score should be 10');
  assert.ok(result.threatsDetected.includes('Suspicious URL Detection'));
  assert.ok(result.technicalIndicators.includes('VirusTotal Malicious Vendors (1/80)'));
});

// Test 6: VirusTotal with 10 malicious engines (VT +30, override to min 70)
runTestCase('VirusTotal with 10 malicious engines', () => {
  const result = riskEngine.evaluate({
    payload: 'https://example.com',
    qrType: 'Website',
    domain: 'example.com',
    safeBrowsingRes: cleanSafeBrowsing,
    virusTotalRes: { malicious: 10, suspicious: 0, harmless: 60, undetected: 10, ratio: '10/80' },
    openRouterRes: cleanOpenRouter,
    communityCount: cleanCommunityCount
  });

  assert.equal(result.riskScore, 70, 'Risk score should be at least 70');
  assert.equal(result.threatLevel, 'High Risk');
  assert.equal(result.recommendation, 'Block');
});

// Test 7: Safe Browsing threat + VirusTotal >= 5 malicious (GSB +40, VT +24, override to min 85)
runTestCase('Safe Browsing threat + VirusTotal >= 5 malicious', () => {
  const result = riskEngine.evaluate({
    payload: 'https://dangerous-site.com',
    qrType: 'Website',
    domain: 'dangerous-site.com',
    safeBrowsingRes: { isSafe: false, threatType: 'MALWARE' },
    virusTotalRes: { malicious: 5, suspicious: 0, harmless: 65, undetected: 10, ratio: '5/80' },
    openRouterRes: cleanOpenRouter,
    communityCount: cleanCommunityCount
  });

  assert.equal(result.riskScore, 85, 'Risk score should be overridden to 85');
  assert.equal(result.threatLevel, 'Critical');
  assert.equal(result.recommendation, 'Block');
  assert.ok(result.threatsDetected.includes('Malicious Web Link'));
  assert.ok(result.threatsDetected.includes('Malicious URL Detection'));
});

// Test 8: High AI risk but low AI confidence (confidence < 60 -> AI contribution = 0)
runTestCase('High AI risk but low AI confidence', () => {
  const result = riskEngine.evaluate({
    payload: 'https://example.com',
    qrType: 'Website',
    domain: 'example.com',
    safeBrowsingRes: cleanSafeBrowsing,
    virusTotalRes: cleanVirusTotal,
    openRouterRes: { riskScore: 95, confidence: 55, threatLevel: 'Critical', threatCategory: 'Phishing' },
    communityCount: cleanCommunityCount
  });

  assert.equal(result.riskScore, 0, 'Risk score should be 0 because AI confidence is low');
  assert.equal(result.riskBreakdown.aiContext.score, 0, 'AI contribution score should be 0');
});

// Test 9: High AI risk and high AI confidence (risk = 90, confidence = 85 -> (90/100)*(85/100)*15 = 11.475 -> rounded to 11)
runTestCase('High AI risk and high AI confidence', () => {
  const result = riskEngine.evaluate({
    payload: 'https://example.com',
    qrType: 'Website',
    domain: 'example.com',
    safeBrowsingRes: cleanSafeBrowsing,
    virusTotalRes: cleanVirusTotal,
    openRouterRes: { riskScore: 90, confidence: 85, threatLevel: 'Critical', threatCategory: 'Phishing' },
    communityCount: cleanCommunityCount
  });

  assert.equal(result.riskScore, 11, 'Risk score should be 11');
  assert.equal(result.riskBreakdown.aiContext.score, 11, 'AI contribution score should be 11');
});

// Test 10: Community reports scaling
runTestCase('Community reports scaling', () => {
  const evaluateReports = (count) => {
    return riskEngine.evaluate({
      payload: 'https://example.com',
      qrType: 'Website',
      domain: 'example.com',
      safeBrowsingRes: cleanSafeBrowsing,
      virusTotalRes: cleanVirusTotal,
      openRouterRes: cleanOpenRouter,
      communityCount: count
    }).riskScore;
  };

  assert.equal(evaluateReports(0), 0);
  assert.equal(evaluateReports(1), 2);
  assert.equal(evaluateReports(2), 4);
  assert.equal(evaluateReports(3), 4);
  assert.equal(evaluateReports(4), 7);
  assert.equal(evaluateReports(8), 7);
  assert.equal(evaluateReports(10), 10);
  assert.equal(evaluateReports(25), 10);
});

// Test 11: AI hallucinated "Sticker Replacement" must NOT become verified evidence
runTestCase('AI hallucinated "Sticker Replacement" must NOT become verified evidence', () => {
  const result = riskEngine.evaluate({
    payload: 'https://example.com',
    qrType: 'Website',
    domain: 'example.com',
    safeBrowsingRes: cleanSafeBrowsing,
    virusTotalRes: cleanVirusTotal,
    openRouterRes: {
      riskScore: 60,
      confidence: 80,
      threatLevel: 'Medium Risk',
      threatCategory: 'Phishing',
      threatsDetected: ['Sticker Replacement', 'Typosquatting'],
      technicalIndicators: ['VPA Unverified']
    },
    communityCount: cleanCommunityCount
  });

  // Verify it is not inside main threatsDetected or technicalIndicators
  assert.ok(!result.threatsDetected.includes('Sticker Replacement'), 'Should not verify Sticker Replacement');
  assert.ok(!result.threatsDetected.includes('Typosquatting'), 'Should not verify Typosquatting');
  assert.ok(!result.technicalIndicators.includes('VPA Unverified'), 'Should not verify VPA Unverified');

  // Verify it is stored in aiObservations
  assert.ok(result.aiObservations.threatsDetected.includes('Sticker Replacement'));
  assert.ok(result.aiObservations.threatsDetected.includes('Typosquatting'));
  assert.ok(result.aiObservations.technicalIndicators.includes('VPA Unverified'));
});

// Test 12: AI hallucinated "HTTPS Missing" for an HTTPS URL must NOT become a verified indicator
runTestCase('AI hallucinated "HTTPS Missing" for an HTTPS URL must NOT become a verified indicator', () => {
  const result = riskEngine.evaluate({
    payload: 'https://secure-site.com',
    qrType: 'Website',
    domain: 'secure-site.com',
    safeBrowsingRes: cleanSafeBrowsing,
    virusTotalRes: cleanVirusTotal,
    openRouterRes: {
      riskScore: 70,
      confidence: 90,
      threatLevel: 'High Risk',
      threatCategory: 'Phishing',
      threatsDetected: ['Phishing'],
      technicalIndicators: ['HTTPS Missing']
    },
    communityCount: cleanCommunityCount
  });

  // Verify HTTPS Missing is NOT in main technicalIndicators (since URL is https://)
  assert.ok(!result.technicalIndicators.includes('HTTPS Missing'), 'HTTPS Missing should not be verified');
  assert.ok(!result.technicalIndicators.includes('Insecure HTTP Connection'), 'Should not contain Insecure HTTP Connection');
  
  // Verify it is in aiObservations
  assert.ok(result.aiObservations.technicalIndicators.includes('HTTPS Missing'));
});

console.log(`\nTest Run Complete: ${passedTestsCount} / 12 passed.\n`);

if (passedTestsCount === 12) {
  console.log('All tests passed successfully.');
  process.exit(0);
} else {
  console.error('Some tests failed.');
  process.exit(1);
}
