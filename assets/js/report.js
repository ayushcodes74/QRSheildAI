/**
 * QR Shield AI - Scam Reporting Hub
 * Manages scam reports, form validations, screenshot uploads, and localStorage saves
 */

document.addEventListener('DOMContentLoaded', () => {
  initReportForm();
  renderUserReports();
});

let attachedScreenshotBase64 = null;

function initReportForm() {
  const form = document.getElementById('report-scam-form');
  const fileInput = document.getElementById('report-file');
  const dropArea = document.getElementById('report-drop-area');
  const previewContainer = document.getElementById('report-preview-container');
  const previewImg = document.getElementById('report-preview-img');
  const previewName = document.getElementById('report-preview-name');
  const previewSize = document.getElementById('report-preview-size');
  
  // 1. Check query parameters to prefill the URL (if redirected from scanner result card)
  const urlParams = new URLSearchParams(window.location.search);
  const prefillUrl = urlParams.get('url');
  const prefillReason = urlParams.get('reason');
  
  const urlInput = document.getElementById('scam-url');
  const reasonSelect = document.getElementById('scam-reason');
  
  if (urlInput && prefillUrl) {
    urlInput.value = prefillUrl;
  }
  
  if (reasonSelect && prefillReason) {
    // Attempt match
    if (prefillReason === 'malicious_qr') {
      reasonSelect.value = 'Phishing Website';
    }
  }

  // 2. Drag & Drop interactions for screenshot attachment
  if (dropArea && fileInput) {
    dropArea.addEventListener('dragover', (e) => {
      e.preventDefault();
      dropArea.classList.add('dragover');
    });
    
    dropArea.addEventListener('dragleave', () => {
      dropArea.classList.remove('dragover');
    });
    
    dropArea.addEventListener('drop', (e) => {
      e.preventDefault();
      dropArea.classList.remove('dragover');
      if (e.dataTransfer.files && e.dataTransfer.files[0]) {
        handleScreenshotFile(e.dataTransfer.files[0]);
      }
    });
    
    dropArea.addEventListener('click', () => {
      fileInput.click();
    });
    
    fileInput.addEventListener('change', (e) => {
      if (e.target.files && e.target.files[0]) {
        handleScreenshotFile(e.target.files[0]);
      }
    });
  }

  // 3. Form submit validation
  if (form) {
    form.addEventListener('submit', handleFormSubmit);
  }
}

function handleScreenshotFile(file) {
  const previewContainer = document.getElementById('report-preview-container');
  const previewImg = document.getElementById('report-preview-img');
  const previewName = document.getElementById('report-preview-name');
  const previewSize = document.getElementById('report-preview-size');

  if (!file.type.match('image.*')) {
    if (window.QRShieldUtils) window.QRShieldUtils.showToast('Invalid file format. Select an image.', 'error');
    return;
  }

  // Render preview details
  if (previewName) previewName.textContent = file.name;
  if (previewSize) previewSize.textContent = `${(file.size / 1024).toFixed(1)} KB`;
  
  // Convert image to base64 for LocalStorage storage
  const reader = new FileReader();
  reader.onload = (e) => {
    attachedScreenshotBase64 = e.target.result;
    if (previewImg) previewImg.src = e.target.result;
    if (previewContainer) previewContainer.classList.add('active');
    
    if (window.QRShieldUtils) {
      window.QRShieldUtils.showToast('Screenshot attached successfully', 'success');
    }
  };
  reader.readAsDataURL(file);
}

function handleFormSubmit(e) {
  e.preventDefault();
  
  const urlInput = document.getElementById('scam-url');
  const reasonSelect = document.getElementById('scam-reason');
  const descTextarea = document.getElementById('scam-desc');
  
  const url = urlInput ? urlInput.value.trim() : '';
  const reason = reasonSelect ? reasonSelect.value : '';
  const description = descTextarea ? descTextarea.value.trim() : '';
  
  // Basic validation checks
  if (!url) {
    if (window.QRShieldUtils) window.QRShieldUtils.showToast('Please specify the malicious URL or UPI target.', 'warning');
    urlInput.focus();
    return;
  }
  
  if (!reason) {
    if (window.QRShieldUtils) window.QRShieldUtils.showToast('Please select a scam classification category.', 'warning');
    reasonSelect.focus();
    return;
  }
  
  if (description.length < 10) {
    if (window.QRShieldUtils) window.QRShieldUtils.showToast('Provide a brief details description (minimum 10 characters).', 'warning');
    descTextarea.focus();
    return;
  }

  // 4. Save to storage with loading screens
  if (window.QRShieldUtils) {
    window.QRShieldUtils.showLoading('Submitting Incident Report...', 'Uploading logs to local repository');
  }

  setTimeout(async () => {
    if (window.QRShieldUtils) {
      window.QRShieldUtils.hideLoading();
    }
    
    // Save report data
    const reportData = {
      url,
      category: reason,
      description,
      screenshot: attachedScreenshotBase64 // base64 string
    };
    
    if (window.QRShieldUtils && window.QRShieldUtils.saveScamReport) {
      await window.QRShieldUtils.saveScamReport(reportData);
      window.QRShieldUtils.showToast('Scam incident reported successfully!', 'success');
      
      // Reset form
      resetReportForm();
      
      // Re-render local user submission lists below
      await renderUserReports();
    }
  }, 1500);
}

function resetReportForm() {
  const form = document.getElementById('report-scam-form');
  const previewContainer = document.getElementById('report-preview-container');
  const previewImg = document.getElementById('report-preview-img');
  
  if (form) form.reset();
  if (previewContainer) previewContainer.classList.remove('active');
  if (previewImg) previewImg.src = '';
  attachedScreenshotBase64 = null;
}

async function renderUserReports() {
  const container = document.getElementById('user-reports-list');
  if (!container) return;
  
  let reports = [];
  if (window.QRShieldUtils && window.QRShieldUtils.getScamReports) {
    reports = await window.QRShieldUtils.getScamReports();
  }
  
  if (reports.length === 0) {
    container.innerHTML = `
      <div class="empty-state" style="padding: 30px 20px;">
        <h3>No Reports Filed Yet</h3>
        <p>Any malicious links or payment scams you report will be cataloged here for threat tracking.</p>
      </div>
    `;
    return;
  }
  
  container.innerHTML = '';
  
  reports.forEach(report => {
    const card = document.createElement('div');
    card.className = 'glass-card';
    card.style.padding = '20px';
    card.style.marginBottom = '15px';
    
    const formattedDate = new Date(report.timestamp).toLocaleString();
    
    // Screenshot section
    const imgHtml = report.screenshot 
      ? `<div style="margin-top: 15px;"><img src="${report.screenshot}" alt="Scam Verification Image" style="max-width: 120px; border-radius: 8px; border: 1px solid var(--border-color);" /></div>`
      : '';
      
    card.innerHTML = `
      <div style="display: flex; justify-content: space-between; align-items: start; border-bottom: 1px solid var(--border-color); padding-bottom: 10px; margin-bottom: 10px;">
        <div>
          <span class="result-badge badge-dangerous" style="font-size: 0.75rem; padding: 2px 8px; display: inline-block;">${escapeHTML(report.category)}</span>
          <h4 style="margin-top: 5px; font-family: 'Fira Code', monospace; font-size: 0.9rem; word-break: break-all;">Target: ${escapeHTML(report.url)}</h4>
        </div>
        <span style="font-size: 0.75rem; color: var(--text-muted);">${formattedDate}</span>
      </div>
      <p style="font-size: 0.9rem; color: var(--text-muted); line-height: 1.4;">${escapeHTML(report.description)}</p>
      ${imgHtml}
    `;
    container.appendChild(card);
  });
}

function escapeHTML(str) {
  if (!str) return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
