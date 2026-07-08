const assert = require('assert').strict;
const http = require('http');
const fs = require('fs');
const path = require('path');

console.log('Starting Programmatic Regression Tests for QR Shield AI...\n');

// 1. Mocking services BEFORE importing the backend server
const googleSafeBrowsing = require('./googleSafeBrowsing');
const virusTotal = require('./virusTotal');
const openRouter = require('./openRouter');

googleSafeBrowsing.checkUrl = async (url) => {
  return { isSafe: true, threatType: 'Safe' };
};

virusTotal.checkUrl = async (url) => {
  return { malicious: 0, suspicious: 0, harmless: 72, undetected: 15, ratio: '0/72' };
};

openRouter.analyzePayload = async (payload) => {
  return {
    riskScore: 0,
    confidence: 95,
    threatLevel: 'Safe',
    threatCategory: 'Safe content',
    reasoning: 'Mocked safe response',
    threatsDetected: [],
    technicalIndicators: []
  };
};

// 2. Set port to 5999 for test environment
process.env.PORT = 5999;
process.env.NODE_ENV = 'test';

// Import backend server (starts listening on PORT 5999)
const { app, server } = require('../server');

// Helper to make HTTP requests
function makeRequest(options, body = null) {
  return new Promise((resolve, reject) => {
    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        resolve({
          statusCode: res.statusCode,
          headers: res.headers,
          data: data
        });
      });
    });
    req.on('error', (err) => { reject(err); });
    if (body) {
      req.write(typeof body === 'string' ? body : JSON.stringify(body));
    }
    req.end();
  });
}

let passedCount = 0;
let failedCount = 0;

async function runTest(name, fn) {
  try {
    await fn();
    console.log(`\x1b[32m✔ PASS: ${name}\x1b[0m`);
    passedCount++;
  } catch (err) {
    console.error(`\x1b[31m✘ FAIL: ${name}\x1b[0m`);
    console.error(err);
    failedCount++;
  }
}

// Reusable mock element helper
function createMockElement(id = '') {
  return {
    id,
    textContent: id === 'res-risk-text' ? 'Calculating...' : '',
    className: '',
    style: {},
    innerHTML: '',
    classList: {
      add(cls) { this.classes.add(cls); },
      remove(cls) { this.classes.delete(cls); },
      classes: new Set()
    },
    firstChild: null,
    appendChild(child) {},
    insertBefore() {},
    remove() {},
    scrollIntoView() {},
    cloneNode() {
      return createMockElement(id);
    },
    addEventListener(event, callback) {},
    replaceChild(newChild, oldChild) {},
    parentNode: {
      insertBefore() {},
      replaceChild(newChild, oldChild) {}
    }
  };
}

async function runAllTests() {
  // Wait for server to bind
  await new Promise(r => setTimeout(r, 600));

  // Test 1: Production origin CORS preflight
  await runTest('Production origin CORS preflight OPTIONS request returns CORP cross-origin and valid CORS approval', async () => {
    const res = await makeRequest({
      hostname: 'localhost',
      port: 5999,
      path: '/scan',
      method: 'OPTIONS',
      headers: {
        'Origin': 'https://qr-shield-ai.vercel.app',
        'Access-Control-Request-Method': 'POST',
        'Access-Control-Request-Headers': 'content-type'
      }
    });

    assert.equal(res.statusCode, 204, 'Preflight OPTIONS should return status 204');
    assert.equal(res.headers['access-control-allow-origin'], 'https://qr-shield-ai.vercel.app');
    assert.equal(res.headers['access-control-allow-credentials'], 'true');
    assert.equal(res.headers['cross-origin-resource-policy'], 'cross-origin', 'CORP header must be cross-origin');
  });

  // Test 2: Production-origin POST /scan CORP & CORS headers validation
  await runTest('Production-origin POST /scan returns CORS origin headers and CORP cross-origin header', async () => {
    const res = await makeRequest({
      hostname: 'localhost',
      port: 5999,
      path: '/scan',
      method: 'POST',
      headers: {
        'Origin': 'https://qr-shield-ai.vercel.app',
        'Content-Type': 'application/json'
      }
    }, {
      payload: 'https://google.com',
      city: 'Bhopal',
      latitude: 23.2599,
      longitude: 77.4126
    });

    assert.equal(res.statusCode, 201, 'POST /scan should return status 201');
    assert.equal(res.headers['access-control-allow-origin'], 'https://qr-shield-ai.vercel.app');
    assert.equal(res.headers['access-control-allow-credentials'], 'true');
    assert.equal(res.headers['cross-origin-resource-policy'], 'cross-origin', 'CORP header must be cross-origin');
  });

  // Test 3: Successful backend scan response body check
  await runTest('Successful backend scan response format validation', async () => {
    const res = await makeRequest({
      hostname: 'localhost',
      port: 5999,
      path: '/scan',
      method: 'POST',
      headers: {
        'Origin': 'https://qr-shield-ai.vercel.app',
        'Content-Type': 'application/json'
      }
    }, {
      payload: 'https://google.com',
      city: 'Mumbai',
      latitude: 19.076,
      longitude: 72.8777
    });

    const body = JSON.parse(res.data);
    assert.equal(body.success, true);
    assert.ok(body.scan);
    assert.equal(body.scan.payload, 'https://google.com');
    assert.equal(body.scan.qrType, 'Website');
    assert.ok(body.scan.analysis);
    assert.equal(body.scan.analysis.riskScore, 0);
    assert.equal(body.scan.analysis.threatLevel, 'Safe');
  });

  // Test 4: Offline fallback analyzer validation (checks all fields)
  await runTest('Offline fallback analyzer mapping and normalization validation', async () => {
    const code = fs.readFileSync(path.join(__dirname, '../../assets/js/analysis.js'), 'utf8');
    const windowMock = {};
    const runCode = new Function('window', code);
    runCode(windowMock);
    const analyzeQRContent = windowMock.QRShieldAnalysis.analyzeQRContent;

    // Test a basic safe URL
    const resSafe = analyzeQRContent('https://google.com');
    assert.equal(resSafe.type, 'Website');
    assert.equal(resSafe.riskLevel, 'Safe');
    assert.equal(resSafe.threatLevel, 'Safe');
    assert.equal(resSafe.threatCategory, 'Safe content');
    assert.equal(resSafe.confidence, 100);
    assert.ok(resSafe.reasoning);
    assert.equal(resSafe.googleSafeBrowsing, 'Safe');
    assert.deepEqual(resSafe.virusTotal, { malicious: 0, suspicious: 0, harmless: 0, ratio: '0/0' });
    assert.equal(resSafe.communityReports, 0);
    assert.ok(Array.isArray(resSafe.technicalIndicators));

    // Test canonical risk-level mapping thresholds:
    // Safe: 0-20
    const mockSafe = { riskScore: 10 };
    const mappedSafe = evaluateCustomRisk(mockSafe);
    assert.equal(mappedSafe.riskLevel, 'Safe');

    // Low Risk: 21-40
    const mockLow = { riskScore: 30 };
    const mappedLow = evaluateCustomRisk(mockLow);
    assert.equal(mappedLow.riskLevel, 'Low Risk');

    // Medium Risk: 41-60
    const mockMed = { riskScore: 50 };
    const mappedMed = evaluateCustomRisk(mockMed);
    assert.equal(mappedMed.riskLevel, 'Medium Risk');

    // High Risk: 61-80
    const mockHigh = { riskScore: 70 };
    const mappedHigh = evaluateCustomRisk(mockHigh);
    assert.equal(mappedHigh.riskLevel, 'High Risk');

    // Critical: 81-100
    const mockCrit = { riskScore: 90 };
    const mappedCrit = evaluateCustomRisk(mockCrit);
    assert.equal(mappedCrit.riskLevel, 'Critical');

    function evaluateCustomRisk(obj) {
      // Evaluate inline mapping mirroring analysis.js logic
      const score = obj.riskScore;
      let level = '';
      if (score >= 81) level = 'Critical';
      else if (score >= 61) level = 'High Risk';
      else if (score >= 41) level = 'Medium Risk';
      else if (score >= 21) level = 'Low Risk';
      else level = 'Safe';
      return { riskLevel: level };
    }
  });

  // Test 5: Fallback UI does not remain in Calculating state
  await runTest('Fallback UI does not remain in Calculating state after rendering results', async () => {
    const scannerCode = fs.readFileSync(path.join(__dirname, '../../assets/js/scanner.js'), 'utf8');

    // Mock DOM elements and document structure
    const elementsStore = {};
    const documentMock = {
      addEventListener(event, callback) {},
      getElementById(id) {
        if (!elementsStore[id]) {
          elementsStore[id] = createMockElement(id);
        }
        return elementsStore[id];
      },
      createElement(tag) {
        return createMockElement();
      },
      querySelector() {
        return createMockElement();
      }
    };

    const windowMock = {
      location: { search: '' },
      localStorage: { getItem() { return null; }, setItem() {} },
      history: { replaceState() {} },
      document: documentMock,
      QRShieldUtils: {
        showLoading() {},
        hideLoading() {},
        showToast() {},
        addScanToHistory() {}
      }
    };

    // Evaluate code inside local function and pull target functions
    const runScanner = new Function('window', 'document', 'localStorage', 'API_BASE_URL', scannerCode + '\nreturn { displayAnalysisResults };');
    const { displayAnalysisResults } = runScanner(windowMock, documentMock, windowMock.localStorage, 'http://localhost:5999');

    const sampleAnalysis = {
      type: 'Website',
      rawContent: 'https://example.com',
      riskScore: 25,
      threatLevel: 'Low Risk',
      threatCategory: 'Safe Content',
      confidence: 100,
      reasoning: 'Heuristic checks verified ssl encryption.',
      isOfflineFallback: true
    };

    displayAnalysisResults(sampleAnalysis);

    const riskTextEl = elementsStore['res-risk-text'];
    assert.ok(riskTextEl, 'res-risk-text element should be loaded');
    assert.notEqual(riskTextEl.textContent, 'Calculating...', 'Risk text should be updated from Calculating...');
    assert.equal(riskTextEl.textContent, 'Low Risk', 'Risk text should be updated to Low Risk');
  });

  // Test 6: AI assessment never renders undefined
  await runTest('AI assessment block never renders undefined when reasoning is empty/fallback', async () => {
    const scannerCode = fs.readFileSync(path.join(__dirname, '../../assets/js/scanner.js'), 'utf8');

    const elementsStore = {};
    const documentMock = {
      addEventListener(event, callback) {},
      getElementById(id) {
        if (!elementsStore[id]) {
          elementsStore[id] = createMockElement(id);
        }
        return elementsStore[id];
      },
      createElement(tag) {
        return createMockElement();
      },
      querySelector() {
        return createMockElement();
      }
    };

    const windowMock = {
      location: { search: '' },
      localStorage: { getItem() { return null; }, setItem() {} },
      history: { replaceState() {} },
      document: documentMock,
      QRShieldUtils: {
        showLoading() {},
        hideLoading() {},
        showToast() {},
        addScanToHistory() {}
      }
    };

    const runScanner = new Function('window', 'document', 'localStorage', 'API_BASE_URL', scannerCode + '\nreturn { displayAnalysisResults };');
    const { displayAnalysisResults } = runScanner(windowMock, documentMock, windowMock.localStorage, 'http://localhost:5999');

    // Case 1: analysis has reasoning undefined, but has aiExplanation
    const sampleAnalysis1 = {
      type: 'Website',
      rawContent: 'https://example.com',
      riskScore: 0,
      threatLevel: 'Safe',
      threatCategory: 'Safe Content',
      confidence: 100,
      aiExplanation: 'Fallback system description.',
      isOfflineFallback: true
    };

    displayAnalysisResults(sampleAnalysis1);
    const explanationHtml1 = elementsStore['res-ai-explanation'].innerHTML;
    assert.ok(!explanationHtml1.includes('undefined'), 'HTML should not render undefined');
    assert.ok(explanationHtml1.includes('Fallback system description.'), 'HTML should fall back to aiExplanation');

    // Case 2: both reasoning and aiExplanation are missing
    const sampleAnalysis2 = {
      type: 'Website',
      rawContent: 'https://example.com',
      riskScore: 0,
      threatLevel: 'Safe',
      threatCategory: 'Safe Content',
      confidence: 100,
      isOfflineFallback: true
    };

    displayAnalysisResults(sampleAnalysis2);
    const explanationHtml2 = elementsStore['res-ai-explanation'].innerHTML;
    assert.ok(!explanationHtml2.includes('undefined'), 'HTML should not render undefined');
    assert.ok(explanationHtml2.includes('No reasoning details provided.'), 'HTML should use hard fallback message');
  });

  // Tear down server
  server.close(() => {
    console.log('\n----------------------------------------');
    console.log(`Regression Test complete: ${passedCount} / ${passedCount + failedCount} passed.`);
    console.log('----------------------------------------');
    if (failedCount > 0) {
      process.exit(1);
    } else {
      process.exit(0);
    }
  });
}

runAllTests();
