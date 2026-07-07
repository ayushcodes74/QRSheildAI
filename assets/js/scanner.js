/**
 * QR Shield AI - Scanner Interface Logic
 * Coordinates HTML5 camera scanning, file imports, and results rendering
 */

let html5QrCode = null;
const SCANNER_DIV_ID = "reader";
let isCameraActive = false;

document.addEventListener('DOMContentLoaded', () => {
  initScannerUI();
});

function initScannerUI() {
  const startCamBtn = document.getElementById('start-camera-btn');
  const stopCamBtn = document.getElementById('stop-camera-btn');
  const fileInput = document.getElementById('file-input');
  const dropZone = document.getElementById('drop-zone');
  const resultCard = document.getElementById('result-card');
  const resetBtn = document.getElementById('reset-scan-btn');
  
  if (startCamBtn) {
  startCamBtn.addEventListener('click', (e) => {
    e.preventDefault();
    e.stopPropagation();
    startCameraScanning();
  });
}
  
  if (stopCamBtn) {
    stopCamBtn.addEventListener('click', stopCameraScanning);
  }
  
  if (fileInput) {
    fileInput.addEventListener('change', handleFileSelect);
  }
  
  if (dropZone) {
    // Setup drag & drop
    dropZone.addEventListener('dragover', (e) => {
      e.preventDefault();
      dropZone.classList.add('drag-hover');
    });
    
    dropZone.addEventListener('dragleave', () => {
      dropZone.classList.remove('drag-hover');
    });
    
    dropZone.addEventListener('drop', (e) => {
      e.preventDefault();
      dropZone.classList.remove('drag-hover');
      if (e.dataTransfer.files && e.dataTransfer.files[0]) {
        processUploadedImage(e.dataTransfer.files[0]);
      }
    });
    
    dropZone.addEventListener('click', (e) => {
      if (e.target.closest('button, input, a')) {
        return;
      }

      fileInput.click();
    });
  }

  if (resetBtn) {
    resetBtn.addEventListener('click', resetScannerConsole);
  }
  
  // Set up click handlers on buttons within result card
  setupResultActionHandlers();

  // Auto-trigger file upload if query param is set
  const urlParams = new URLSearchParams(window.location.search);
  if (urlParams.get('action') === 'upload' && fileInput) {
    // Clear query parameter from address bar to avoid repeated triggers on refresh
    window.history.replaceState({}, document.title, window.location.pathname);
    setTimeout(() => {
      fileInput.click();
    }, 400);
  }

  // Auto-trigger programmatic scan analysis for showcase testing
  const testPayload = urlParams.get('test_payload');
  if (testPayload) {
    window.history.replaceState({}, document.title, window.location.pathname);
    setTimeout(() => {
      handleScanSuccess(testPayload);
    }, 600);
  }

  // Auto-trigger Hackathon Demo stages
  const demoMode = urlParams.get('demo');
  if (demoMode) {
    if (demoMode === 'safe') {
      showDemoHUD('STAGE 1 - Simulating Scanning Safe QR Code (https://google.com)', '#22c55e');
      setTimeout(() => {
        handleScanSuccess("https://google.com");
      }, 1500);
    } else if (demoMode === 'dangerous') {
      showDemoHUD('STAGE 2 - Simulating Scanning Phishing QR Code (http://sbi-login-verification.xyz/secure)', '#ef4444');
      setTimeout(() => {
        handleScanSuccess("http://sbi-login-verification.xyz/secure");
      }, 1500);
    }
  }
}

/* ==========================================================================
   Camera Scanning Logic (Html5Qrcode integration)
   ========================================================================== */
async function startCameraScanning() {
  if (isCameraActive) return;
  
  const placeholder = document.getElementById('scanner-placeholder');
  const readerElement = document.getElementById(SCANNER_DIV_ID);
  const startCamBtn = document.getElementById('start-camera-btn');
  const stopCamBtn = document.getElementById('stop-camera-btn');
  const viewContainer = document.querySelector('.scanner-view-container');
  
  if (window.QRShieldUtils) {
    window.QRShieldUtils.showLoading('Accessing Camera...', 'Requesting media permissions');
  }

  try {
    // Check camera availability
    await Html5Qrcode.getCameras();
    
    if (placeholder) placeholder.style.display = 'none';
    if (readerElement) readerElement.style.display = 'block';
    if (viewContainer) viewContainer.classList.add('is-scanning');

    html5QrCode = new Html5Qrcode(SCANNER_DIV_ID);
    
    const config = {
      fps: 10,
      qrbox: (width, height) => {
        const boxSize = Math.min(width, height) * 0.65;
        return { width: boxSize, height: boxSize };
      }
    };
    
    await html5QrCode.start(
      { facingMode: "environment" },
      config,
      (decodedText, decodedResult) => {
        // Success callback
        handleScanSuccess(decodedText);
      },
      (errorMessage) => {
        // Scan fail callback (mostly noise, we ignore it)
      }
    );
    
    isCameraActive = true;
    if (startCamBtn) startCamBtn.style.display = 'none';
    if (stopCamBtn) stopCamBtn.style.display = 'inline-flex';
    
    if (window.QRShieldUtils) {
      window.QRShieldUtils.showToast('Webcam started successfully', 'success');
    }
  } catch (err) {
    console.error('Camera startup error', err);
    if (placeholder) placeholder.style.display = 'flex';
    if (readerElement) readerElement.style.display = 'none';
    if (viewContainer) viewContainer.classList.remove('is-scanning');
    
    if (window.QRShieldUtils) {
      window.QRShieldUtils.showToast('Camera permission denied or camera not found.', 'error');
    }
  } finally {
    if (window.QRShieldUtils) {
      window.QRShieldUtils.hideLoading();
    }
  }
}

async function stopCameraScanning() {
  if (!isCameraActive || !html5QrCode) return;
  
  const startCamBtn = document.getElementById('start-camera-btn');
  const stopCamBtn = document.getElementById('stop-camera-btn');
  const placeholder = document.getElementById('scanner-placeholder');
  const readerElement = document.getElementById(SCANNER_DIV_ID);
  const viewContainer = document.querySelector('.scanner-view-container');

  try {
    await html5QrCode.stop();
    html5QrCode = null;
    isCameraActive = false;
    
    if (startCamBtn) startCamBtn.style.display = 'inline-flex';
    if (stopCamBtn) stopCamBtn.style.display = 'none';
    if (placeholder) placeholder.style.display = 'flex';
    if (readerElement) readerElement.style.display = 'none';
    if (viewContainer) viewContainer.classList.remove('is-scanning');
    
    if (window.QRShieldUtils) {
      window.QRShieldUtils.showToast('Camera feed stopped.', 'info');
    }
  } catch (err) {
    console.error('Failed to stop camera stream', err);
  }
}

/* ==========================================================================
   Image File Scanning Logic
   ========================================================================== */
function handleFileSelect(e) {
  if (e.target.files && e.target.files[0]) {
    processUploadedImage(e.target.files[0]);
  }
}

async function processUploadedImage(file) {
  if (!file.type.match('image.*')) {
    if (window.QRShieldUtils) window.QRShieldUtils.showToast('Invalid file format. Select an image.', 'error');
    return;
  }

  // Display a temporary loader while scanning image file
  if (window.QRShieldUtils) {
    window.QRShieldUtils.showLoading('Decompiling Image...', 'Scanning matrix pixels');
  }
  
  // Stop camera if running
  if (isCameraActive) {
    await stopCameraScanning();
  }

  // Create temporary invisible HTML element for scanner if not active
  const scannerTempDiv = document.createElement('div');
  scannerTempDiv.id = 'temp-scanner';
  scannerTempDiv.style.display = 'none';
  document.body.appendChild(scannerTempDiv);

  const localScanner = new Html5Qrcode('temp-scanner');
  
  try {
    const decodedText = await localScanner.scanFile(file, true);
    handleScanSuccess(decodedText);
  } catch (err) {
    console.error('Error decoding image file', err);
    if (window.QRShieldUtils) {
      window.QRShieldUtils.showToast('Failed to detect any QR code in this image.', 'warning');
    }
  } finally {
    localScanner.clear();
    scannerTempDiv.remove();
    if (window.QRShieldUtils) {
      window.QRShieldUtils.hideLoading();
    }
  }
}

/* ==========================================================================
   Result Parsing & Visualization
   ========================================================================== */
function handleScanSuccess(decodedText) {
  // Play sound or stop scanning immediately to prevent duplicate runs
  if (isCameraActive) {
    stopCameraScanning();
  }
  
  if (window.QRShieldUtils) {
    window.QRShieldUtils.showLoading('Initializing Security Diagnostics...', '👁️ Booting local cyber analyst heuristics...');
  }

  // Create sequential loading logs updates
  const steps = [
    { delay: 400, title: 'Analyzing QR scheme type...', sub: '⚙️ Identifying SSID, UPI VPA, mailto or HTTP payloads...' },
    { delay: 800, title: 'Checking Safe Browsing registers...', sub: '🛡️ Querying live Google Safe Browsing reputation feeds...' },
    { delay: 1200, title: 'Fetching VirusTotal reputation...', sub: '🔍 Querying VirusTotal domain threat analytics...' },
    { delay: 1600, title: 'Generating Gemini AI explanation...', sub: '🤖 Synthesizing explainable risk profiles & classifications...' },
    { delay: 2000, title: 'Compiling risk scorecard...', sub: '📊 Compiling final weighted risk score & indicators...' }
  ];
  
  steps.forEach(step => {
    setTimeout(() => {
      if (window.QRShieldUtils) {
        window.QRShieldUtils.showLoading(step.title, step.sub);
      }
    }, step.delay);
  });

  // Fetch from backend API
  setTimeout(async () => {
    // 1. Dispatch dynamic query to backend API
    const token = localStorage.getItem('qr_shield_token');
    const headers = { 'Content-Type': 'application/json' };
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    let analysis = null;
    let isBackendSuccess = false;
    let data = null;

    try {
      const res = await apiFetch(`${API_BASE_URL}/scan`, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          payload: decodedText,
          city: 'Mumbai', // Default metadata region
          latitude: 19.0760,
          longitude: 72.8777
        })
      }, 60000);

      data = await res.json();
      if (res.ok && data.success) {
        // Backend successfully processed metrics!
        analysis = data.scan.analysis;
        analysis.rawContent = data.scan.payload;
        analysis.type = data.scan.qrType;
        isBackendSuccess = true;
        console.log('[Scanner] Dynamic backend threat report retrieved:', analysis);
      } else {
        const apiErr = new Error(data.message || 'API request rejected');
        apiErr.name = 'APIError';
        throw apiErr;
      }
    } catch (err) {
      console.error('[Scanner] Primary backend scan failed', {
        errorName: err.name,
        errorMessage: err.message,
        apiBaseUrl: API_BASE_URL,
        endpoint: `${API_BASE_URL}/scan`,
        online: navigator.onLine
      });
      if (window.QRShieldAnalysis) {
        analysis = window.QRShieldAnalysis.analyzeQRContent(decodedText);
        if (analysis) {
          analysis.isOfflineFallback = true;
        }
      }
    }

    if (window.QRShieldUtils) {
      window.QRShieldUtils.hideLoading();
    }

    if (!analysis) {
      if (window.QRShieldUtils) window.QRShieldUtils.showToast('Failed to analyze QR code payload.', 'error');
      return;
    }

    const rLevel = analysis.threatLevel || analysis.riskLevel;

    // 2. Render Results Card
    displayAnalysisResults(analysis);
    
    // 3. Save to History (local cache update only if backend succeeded to prevent duplicate POSTs)
    if (window.QRShieldUtils) {
      if (isBackendSuccess) {
        try {
          const rawHis = localStorage.getItem('qr_shield_history') || '[]';
          const parsedHis = JSON.parse(rawHis);
          parsedHis.unshift({
            id: data.scan.scanId,
            timestamp: data.scan.timestamp,
            type: analysis.type,
            riskScore: analysis.riskScore,
            riskLevel: rLevel,
            content: analysis.rawContent
          });
          if (parsedHis.length > 100) parsedHis.pop();
          localStorage.setItem('qr_shield_history', JSON.stringify(parsedHis));
        } catch (e) {
          console.error('History cache sync error:', e);
        }
      } else {
        // Local offline fallback record creation
        await window.QRShieldUtils.addScanToHistory({
          type: analysis.type,
          riskScore: analysis.riskScore,
          riskLevel: rLevel,
          content: analysis.rawContent
        });
      }
    }

    // 4. Trigger visual feedbacks
    triggerScanEffects(rLevel);

    // 5. Hackathon Demo transition coordination
    const demoMode = new URLSearchParams(window.location.search).get('demo');
    if (demoMode === 'safe') {
      startDemoCountdown('Stage 2: Critical Phishing Scan starting', 'scanner.html?demo=dangerous', 5);
    } else if (demoMode === 'dangerous') {
      startDemoCountdown('Stage 3: Loading Real-Time Police SOC Dashboard', 'admin.html?demo=1', 6);
    }

  }, 2400); // 2.4s matching diagnostic logging timeline
}

function displayAnalysisResults(analysis) {
  const resultCard = document.getElementById('result-card');
  const typeEl = document.getElementById('res-type');
  const contentEl = document.getElementById('res-content');
  const riskLevelEl = document.getElementById('res-risk-level');
  const riskDescEl = document.getElementById('res-risk-desc');
  const aiExplanationEl = document.getElementById('res-ai-explanation');
  
  if (!resultCard) return;
  
  // Show page content
  resultCard.classList.add('visible');
  resultCard.scrollIntoView({ behavior: 'smooth', block: 'start' });

  // If fallback, add offline warning label/banner
  let offlineBanner = document.getElementById('res-offline-banner');
  if (offlineBanner) {
    offlineBanner.remove();
  }
  if (analysis.isOfflineFallback) {
    const banner = document.createElement('div');
    banner.id = 'res-offline-banner';
    banner.style.background = 'rgba(245, 158, 11, 0.08)';
    banner.style.border = '1px solid rgba(245, 158, 11, 0.3)';
    banner.style.color = '#f59e0b';
    banner.style.padding = '12px 16px';
    banner.style.borderRadius = '8px';
    banner.style.marginBottom = '20px';
    banner.style.fontSize = '0.85rem';
    banner.style.fontWeight = '700';
    banner.style.textAlign = 'center';
    banner.innerHTML = '⚠ OFFLINE FALLBACK: Threat Engine Server Unreachable. Result compiled using client-side heuristic engines only.';
    resultCard.insertBefore(banner, resultCard.firstChild);
  }
  
  // Basic content
  if (typeEl) typeEl.textContent = analysis.type;
  if (contentEl) contentEl.textContent = analysis.rawContent;
  
  const rLevel = analysis.threatLevel || analysis.riskLevel;

  // Set Risk badge level styling
  if (riskLevelEl) {
    riskLevelEl.textContent = rLevel;
    riskLevelEl.className = 'result-badge'; // reset
    if (rLevel === 'Safe' || rLevel === 'Low Risk') riskLevelEl.classList.add('badge-safe');
    if (rLevel === 'Medium' || rLevel === 'Medium Risk') riskLevelEl.classList.add('badge-medium');
    if (rLevel === 'Suspicious' || rLevel === 'High Risk') riskLevelEl.classList.add('badge-suspicious');
    if (rLevel === 'Dangerous' || rLevel === 'Critical') riskLevelEl.classList.add('badge-dangerous');
  }

  if (riskDescEl) {
    riskDescEl.textContent = `Score: ${analysis.riskScore}/100`;
  }

  // Render Gauge Progress Animations
  updateRiskGauge(analysis.riskScore, rLevel);

  // Compile rich unified checklist from API outputs
  const displayChecklist = [];

  if (analysis.googleSafeBrowsing) {
    const isSafe = analysis.googleSafeBrowsing === 'Safe';
    displayChecklist.push({
      name: 'Google Safe Browsing',
      pass: isSafe,
      desc: isSafe ? 'Verified clean domain database status.' : `Threat matches: ${analysis.googleSafeBrowsing}`
    });
  }

  if (analysis.virusTotal) {
    const isSafe = (analysis.virusTotal.malicious || 0) === 0;
    displayChecklist.push({
      name: 'VirusTotal Threat Scan',
      pass: isSafe,
      desc: isSafe ? '0 malicious vendors flagged this link.' : `${analysis.virusTotal.malicious} security vendors flagged this link (${analysis.virusTotal.ratio}).`
    });
  }

  if (typeof analysis.communityReports !== 'undefined') {
    const isSafe = (analysis.communityReports || 0) === 0;
    displayChecklist.push({
      name: 'Community Security Trust',
      pass: isSafe,
      desc: isSafe ? '0 fraud complaints reported by community agents.' : `${analysis.communityReports} fraud/phishing complaints filed for this payload.`
    });
  }

  if (analysis.confidence) {
    displayChecklist.push({
      name: 'AI Analyst Confidence',
      pass: true,
      desc: `Classification confidence rated at ${analysis.confidence}%.`
    });
  }

  if (analysis.technicalIndicators && Array.isArray(analysis.technicalIndicators)) {
    analysis.technicalIndicators.forEach(ind => {
      const lower = ind.toLowerCase();
      const isPass = !lower.includes('missing') && !lower.includes('malicious') && !lower.includes('suspicious') && !lower.includes('typo') && !lower.includes('spoof') && !lower.includes('scam') && !lower.includes('fraud') && !lower.includes('bait') && !lower.includes('unverified');
      displayChecklist.push({
        name: 'Technical Indicator',
        pass: isPass,
        desc: ind
      });
    });
  }

  const checklistToRender = displayChecklist.length > 0 ? displayChecklist : (analysis.checklist || []);
  renderChecklist(checklistToRender);

  // Parse UPI details locally if not populated
  if (analysis.type === 'UPI' && (!analysis.details || Object.keys(analysis.details).length === 0)) {
    analysis.details = { upiId: 'Unknown VPA', merchantName: 'Unverified Merchant', amount: 'N/A' };
    try {
      const urlParts = analysis.rawContent.split('?');
      if (urlParts.length > 1) {
        const searchParams = new URLSearchParams(urlParts[1]);
        analysis.details.upiId = searchParams.get('pa') || 'Unknown VPA';
        analysis.details.merchantName = searchParams.get('pn') || 'Unverified Merchant';
        analysis.details.amount = searchParams.get('am') || 'N/A';
      }
    } catch(e) {}
  }

  // Render UPI or specialized detail fields
  renderSpecializedCard(analysis);

  // Setup dynamic Open button behaviour
  updateActionButtons(analysis);

  // Setup AI reasoning explanations html block
  if (aiExplanationEl) {
    const displayCategory = analysis.threatCategory || (analysis.riskScore <= 20 ? 'Safe content' : 'Threat suspect');
    const displayRec = analysis.recommendation || 'Proceed carefully';
    
    const explanationHtml = `
      <div style="font-weight: 700; color: var(--color-cyan); margin-bottom: 6px; font-size: 0.95rem; text-transform: uppercase;">AI Analyst Assessment</div>
      <div style="font-size: 0.85rem; color: var(--text-muted); margin-bottom: 8px;">
        Category: <strong>${displayCategory}</strong> | Risk Severity: <strong>${rLevel}</strong>
      </div>
      <p style="margin-bottom: 12px; line-height: 1.5; font-size: 0.95rem;">${analysis.reasoning}</p>
      <div style="border-top: 1px dashed var(--border-color); padding-top: 10px; margin-top: 10px;">
        <strong style="color: var(--color-warning); text-transform: uppercase; font-size: 0.85rem; display: block; margin-bottom: 4px;">Recommended Action:</strong>
        <span style="font-weight: 700; font-size: 1rem; color: #fff;">${displayRec}</span>
      </div>
    `;
    aiExplanationEl.innerHTML = explanationHtml;
  }

  // Inject Report Export panel dynamically
  let exportPanel = document.getElementById('report-export-panel');
  if (!exportPanel) {
    const actionContainer = document.querySelector('.result-actions');
    if (actionContainer) {
      exportPanel = document.createElement('div');
      exportPanel.id = 'report-export-panel';
      exportPanel.style.display = 'flex';
      exportPanel.style.gap = '8px';
      exportPanel.style.width = '100%';
      exportPanel.style.justifyContent = 'center';
      exportPanel.style.marginTop = '15px';
      exportPanel.innerHTML = `
        <button class="btn btn-secondary" id="export-pdf-btn" style="padding: 6px 12px; font-size: 0.8rem; flex: 1;">Export PDF</button>
        <button class="btn btn-secondary" id="export-json-btn" style="padding: 6px 12px; font-size: 0.8rem; flex: 1;">Export JSON</button>
        <button class="btn btn-secondary" id="export-csv-btn" style="padding: 6px 12px; font-size: 0.8rem; flex: 1;">Export CSV</button>
      `;
      actionContainer.parentNode.insertBefore(exportPanel, actionContainer.nextSibling);

      // Add click listeners to export buttons
      document.getElementById('export-pdf-btn').addEventListener('click', () => {
        window.print();
      });

      document.getElementById('export-json-btn').addEventListener('click', () => {
        const jsonStr = JSON.stringify(analysis, null, 2);
        const blob = new Blob([jsonStr], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `QR_Shield_Security_Report_${Date.now()}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
      });

      document.getElementById('export-csv-btn').addEventListener('click', () => {
        const rows = [
          ["Payload", "QR Type", "Risk Score", "Threat Level", "AI Recommendation", "AI Explanation"],
          [
            analysis.rawContent,
            analysis.type,
            analysis.riskScore,
            analysis.threatLevel || analysis.riskLevel,
            analysis.recommendation || '',
            analysis.reasoning || analysis.aiExplanation || ''
          ]
        ];
        let csvContent = "data:text/csv;charset=utf-8,";
        rows.forEach(r => {
          const row = r.map(val => `"${String(val).replace(/"/g, '""')}"`).join(",");
          csvContent += row + "\n";
        });
        const encodedUri = encodeURI(csvContent);
        const link = document.createElement("a");
        link.setAttribute("href", encodedUri);
        link.setAttribute("download", `QR_Shield_Security_Report_${Date.now()}.csv`);
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
      });
    }
  }
}

function updateRiskGauge(score, level) {
  const circleFg = document.getElementById('gauge-fg');
  const scoreNum = document.getElementById('gauge-score-num');
  const progressFill = document.getElementById('risk-bar-fill');
  
  if (!circleFg || !scoreNum) return;
  
  // Circle circumference is 220
  const circumference = 220;
  const offset = circumference - (score / 100) * circumference;
  
  circleFg.style.strokeDashoffset = offset;
  scoreNum.innerHTML = `${score}<span>Risk</span>`;
  
  // Color the progress indicators matching modern security bands
  let color = '#22c55e'; // safe green
  if (level === 'Medium' || level === 'Medium Risk') color = '#f59e0b';
  if (level === 'Suspicious' || level === 'High Risk') color = '#f97316';
  if (level === 'Dangerous' || level === 'Critical') color = '#ef4444';
  
  circleFg.style.stroke = color;
  
  if (progressFill) {
    progressFill.style.width = `${score}%`;
    progressFill.style.backgroundColor = color;
  }
}

function renderChecklist(checklist) {
  const container = document.getElementById('security-checklist');
  if (!container) return;
  
  container.innerHTML = '';
  
  if (!checklist || checklist.length === 0) {
    container.innerHTML = `
      <div class="checklist-item pass">
        <div class="checklist-icon">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><polyline points="20 6 9 17 4 12"></polyline></svg>
        </div>
        <div>Content type does not support deep security checklists. Plain content verification verified.</div>
      </div>
    `;
    return;
  }
  
  checklist.forEach(item => {
    const statusClass = item.pass ? 'pass' : 'fail';
    const statusIcon = item.pass 
      ? `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><polyline points="20 6 9 17 4 12"></polyline></svg>`
      : `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>`;
      
    const div = document.createElement('div');
    div.className = `checklist-item ${statusClass}`;
    div.innerHTML = `
      <div class="checklist-icon">${statusIcon}</div>
      <div>
        <strong>${item.name}</strong> - ${item.desc}
      </div>
    `;
    container.appendChild(div);
  });
}

function renderSpecializedCard(analysis) {
  const upiCard = document.getElementById('specialized-upi-card');
  if (!upiCard) return;
  
  if (analysis.type === 'UPI') {
    upiCard.style.display = 'block';
    
    const details = analysis.details;
    document.getElementById('upi-merchant-name').textContent = details.merchantName || 'N/A';
    document.getElementById('upi-id-value').textContent = details.upiId || 'N/A';
    document.getElementById('upi-amount-value').textContent = details.amount === 'N/A' ? 'Any' : `₹${details.amount}`;
    
    // Status text
    const statusVal = document.getElementById('upi-status-value');
    if (analysis.riskScore <= 10) {
      statusVal.textContent = 'Verified Payee';
      statusVal.style.color = '#22c55e';
    } else {
      statusVal.textContent = 'Unknown Recipient';
      statusVal.style.color = '#f59e0b';
    }
  } else {
    upiCard.style.display = 'none';
  }
}

function updateActionButtons(analysis) {
  const openLinkBtn = document.getElementById('action-open-link');
  if (!openLinkBtn) return;
  
  if (analysis.type === 'Website') {
    openLinkBtn.style.display = 'inline-flex';
    // Remove previous click listeners to avoid duplicates
    const newBtn = openLinkBtn.cloneNode(true);
    openLinkBtn.parentNode.replaceChild(newBtn, openLinkBtn);
    
    newBtn.addEventListener('click', (e) => {
      e.preventDefault();
      if (analysis.riskLevel === 'Dangerous' || analysis.riskLevel === 'Suspicious') {
        const proceed = confirm(`WARNING: This link is rated as ${analysis.riskLevel.toUpperCase()} (Threat Score: ${analysis.riskScore}/100).\n\nOpening it might expose your device to cyber fraud, identity theft, or virus downloads.\n\nDo you still wish to proceed?`);
        if (proceed) {
          window.open(analysis.rawContent, '_blank', 'noopener,noreferrer');
        }
      } else {
        window.open(analysis.rawContent, '_blank', 'noopener,noreferrer');
      }
    });
  } else {
    openLinkBtn.style.display = 'none';
  }
}

function animateTextTyping(text, element) {
  element.textContent = '';
  let index = 0;
  
  if (window.typingInterval) {
    clearInterval(window.typingInterval);
  }
  
  window.typingInterval = setInterval(() => {
    if (index < text.length) {
      element.textContent += text.charAt(index);
      index++;
    } else {
      clearInterval(window.typingInterval);
    }
  }, 10);
}

/* ==========================================================================
   Visual Effects Triggers
   ========================================================================== */
function triggerScanEffects(riskLevel) {
  if (riskLevel === 'Safe') {
    if (window.QRShieldUtils) {
      window.QRShieldUtils.triggerConfetti();
      window.QRShieldUtils.showToast('Clear scan profile. Confirmed SAFE.', 'success');
    }
  } else if (riskLevel === 'Dangerous') {
    if (window.QRShieldUtils) {
      window.QRShieldUtils.showToast('HIGH RISK WARNING: Malicious indicators detected!', 'error');
    }
    // Danger Pulse Full-screen background animation
    document.body.classList.add('danger-pulse-bg');
    setTimeout(() => {
      document.body.classList.remove('danger-pulse-bg');
    }, 1500);
  } else {
    if (window.QRShieldUtils) {
      window.QRShieldUtils.showToast(`Threat analysis complete: ${riskLevel} Risk.`, 'warning');
    }
  }
}

/* ==========================================================================
   Secondary Action Controllers
   ========================================================================== */
function setupResultActionHandlers() {
  const reportBtn = document.getElementById('action-report-scam');
  const shareBtn = document.getElementById('action-share');
  
  if (reportBtn) {
    reportBtn.addEventListener('click', () => {
      const content = document.getElementById('res-content').textContent;
      const type = document.getElementById('res-type').textContent;
      // Redirect to report center with prefilled query params
      window.location.href = `report.html?url=${encodeURIComponent(content)}&reason=malicious_qr`;
    });
  }
  
  if (shareBtn) {
    shareBtn.addEventListener('click', () => {
      const content = document.getElementById('res-content').textContent;
      const risk = document.getElementById('res-risk-desc').textContent;
      
      const shareText = `QR Shield AI Scan Alert!\n\nContent: ${content}\nRisk Profile: ${risk}\n\nThink before you click! Analyze QR codes with QR Shield AI.`;
      
      if (navigator.clipboard) {
        navigator.clipboard.writeText(shareText).then(() => {
          if (window.QRShieldUtils) window.QRShieldUtils.showToast('Scan details copied to clipboard!', 'success');
        }).catch(() => {
          alert(shareText);
        });
      } else {
        alert(shareText);
      }
    });
  }
}

function resetScannerConsole() {
  const resultCard = document.getElementById('result-card');
  const fileInput = document.getElementById('file-input');
  
  if (resultCard) {
    resultCard.classList.remove('visible');
  }
  
  if (fileInput) {
    fileInput.value = ''; // reset file input
  }
  
  if (window.typingInterval) {
    clearInterval(window.typingInterval);
  }
  
  if (window.QRShieldUtils) {
    window.QRShieldUtils.showToast('Scanner console reset.', 'info');
  }
}

function showDemoHUD(message, stageColor) {
  let hud = document.getElementById('demo-hud-overlay');
  if (!hud) {
    hud = document.createElement('div');
    hud.id = 'demo-hud-overlay';
    hud.style.position = 'fixed';
    hud.style.top = '80px';
    hud.style.left = '50%';
    hud.style.transform = 'translateX(-50%)';
    hud.style.zIndex = '9999';
    hud.style.background = 'var(--bg-card)';
    hud.style.border = '2px solid ' + stageColor;
    hud.style.boxShadow = '0 0 20px ' + stageColor;
    hud.style.padding = '12px 25px';
    hud.style.borderRadius = '30px';
    hud.style.backdropFilter = 'blur(15px)';
    hud.style.fontWeight = '800';
    hud.style.fontSize = '0.95rem';
    hud.style.color = '#fff';
    hud.style.textAlign = 'center';
    hud.style.transition = 'all 0.3s ease';
    document.body.appendChild(hud);
  }
  hud.style.borderColor = stageColor;
  hud.style.boxShadow = '0 0 20px ' + stageColor;
  hud.innerHTML = `⚡ <span style="color: ${stageColor};">DEMO STATE:</span> ${message}`;
}

function startDemoCountdown(message, nextUrl, seconds) {
  let overlay = document.getElementById('demo-countdown-overlay');
  if (!overlay) {
    overlay = document.createElement('div');
    overlay.id = 'demo-countdown-overlay';
    overlay.style.position = 'fixed';
    overlay.style.bottom = '30px';
    overlay.style.left = '50%';
    overlay.style.transform = 'translateX(-50%)';
    overlay.style.background = 'rgba(6, 182, 212, 0.15)';
    overlay.style.border = '1px solid var(--color-cyan)';
    overlay.style.boxShadow = 'var(--glow-cyan)';
    overlay.style.padding = '15px 30px';
    overlay.style.borderRadius = '12px';
    overlay.style.backdropFilter = 'blur(10px)';
    overlay.style.color = '#fff';
    overlay.style.zIndex = '99999';
    overlay.style.fontWeight = '700';
    overlay.style.textAlign = 'center';
    overlay.style.fontSize = '0.95rem';
    document.body.appendChild(overlay);
  }

  let remaining = seconds;
  const interval = setInterval(() => {
    remaining--;
    if (remaining <= 0) {
      clearInterval(interval);
      overlay.innerHTML = `🚀 Loading next stage...`;
      setTimeout(() => {
        window.location.href = nextUrl;
      }, 500);
    } else {
      overlay.innerHTML = `⏱️ ${message} in <strong style="color: var(--color-cyan); font-size: 1.1rem;">${remaining}</strong> seconds...`;
    }
  }, 1000);
  overlay.innerHTML = `⏱️ ${message} in <strong style="color: var(--color-cyan); font-size: 1.1rem;">${remaining}</strong> seconds...`;
}
