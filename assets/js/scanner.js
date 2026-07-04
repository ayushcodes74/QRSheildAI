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
    startCamBtn.addEventListener('click', startCameraScanning);
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
    
    dropZone.addEventListener('click', () => {
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
    window.QRShieldUtils.showLoading('Running Security Analysis...', 'Calculating threat vectors');
  }

  // Simulate server/AI logic delay for high-tech feeling
  setTimeout(() => {
    if (window.QRShieldUtils) {
      window.QRShieldUtils.hideLoading();
    }

    // 1. Run checks
    if (!window.QRShieldAnalysis) {
      console.error('Analysis engine not loaded');
      return;
    }
    
    const analysis = window.QRShieldAnalysis.analyzeQRContent(decodedText);
    
    // 2. Render Results
    displayAnalysisResults(analysis);
    
    // 3. Save to History
    if (window.QRShieldUtils) {
      window.QRShieldUtils.addScanToHistory({
        type: analysis.type,
        riskScore: analysis.riskScore,
        riskLevel: analysis.riskLevel,
        content: analysis.rawContent
      });
    }

    // 4. Trigger Feedbacks based on Risk
    triggerScanEffects(analysis.riskLevel);

  }, 1200);
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
  
  // Basic content
  if (typeEl) typeEl.textContent = analysis.type;
  if (contentEl) contentEl.textContent = analysis.rawContent;
  
  // Set Risk badge level styling
  if (riskLevelEl) {
    riskLevelEl.textContent = analysis.riskLevel;
    riskLevelEl.className = 'result-badge'; // reset
    if (analysis.riskLevel === 'Safe') riskLevelEl.classList.add('badge-safe');
    if (analysis.riskLevel === 'Medium') riskLevelEl.classList.add('badge-medium');
    if (analysis.riskLevel === 'Suspicious') riskLevelEl.classList.add('badge-suspicious');
    if (analysis.riskLevel === 'Dangerous') riskLevelEl.classList.add('badge-dangerous');
  }

  if (riskDescEl) {
    riskDescEl.textContent = `Score: ${analysis.riskScore}/100`;
  }

  // Render Gauge Progress Animations
  updateRiskGauge(analysis.riskScore, analysis.riskLevel);

  // Render Security Checklist Matrix
  renderChecklist(analysis.checklist);

  // Render UPI or specialized detail fields
  renderSpecializedCard(analysis);

  // Setup dynamic Open button behaviour
  updateActionButtons(analysis);

  // Render AI explanatory text typing speed animation
  if (aiExplanationEl) {
    animateTextTyping(analysis.aiExplanation, aiExplanationEl);
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
  
  // Color the progress indicators
  let color = '#22c55e'; // safe green
  if (level === 'Medium') color = '#f59e0b';
  if (level === 'Suspicious') color = '#f97316';
  if (level === 'Dangerous') color = '#ef4444';
  
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
