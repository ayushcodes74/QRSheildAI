/**
 * QR Shield AI - Utility Library
 * Common UI and Storage Helper Functions
 */

document.addEventListener('DOMContentLoaded', () => {
  initTheme();
  initMobileMenu();
  initSafetyTips();
  initAuthNavbar(); // Automatically sets up dynamic sign-in links in navbar
  initPWA();
});

function initPWA() {
  // Dynamically attach manifest link tag
  if (!document.querySelector('link[rel="manifest"]')) {
    const link = document.createElement('link');
    link.rel = 'manifest';
    link.href = 'manifest.json';
    document.head.appendChild(link);
  }

  // Register PWA Service Worker
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('service-worker.js')
      .then(reg => console.log('[PWA] Service Worker active scope:', reg.scope))
      .catch(err => console.error('[PWA] Service Worker register failure:', err));
  }
}

/* ==========================================================================
   Theme Management (Persistent Cyber Dark / Tech Light Toggle)
   ========================================================================== */
function initTheme() {
  const savedTheme = localStorage.getItem('qr-shield-theme') || 'dark';
  document.documentElement.setAttribute('data-theme', savedTheme);
  
  // Set initial icon for toggle buttons (if they exist)
  updateThemeToggleUI(savedTheme);
  
  // Listen for clicks on any theme toggles
  document.querySelectorAll('.theme-toggle-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const currentTheme = document.documentElement.getAttribute('data-theme');
      const newTheme = currentTheme === 'light' ? 'dark' : 'light';
      
      document.documentElement.setAttribute('data-theme', newTheme);
      localStorage.setItem('qr-shield-theme', newTheme);
      updateThemeToggleUI(newTheme);
      showToast(`Switched to Cyber ${newTheme === 'dark' ? 'Dark' : 'Light'} Mode`, 'info');
    });
  });
}

function updateThemeToggleUI(theme) {
  document.querySelectorAll('.theme-toggle-btn').forEach(btn => {
    if (theme === 'light') {
      btn.innerHTML = `
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path>
        </svg>
      `; // Moon icon (shows dark option)
    } else {
      btn.innerHTML = `
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <circle cx="12" cy="12" r="5"></circle>
          <line x1="12" y1="1" x2="12" y2="3"></line>
          <line x1="12" y1="21" x2="12" y2="23"></line>
          <line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line>
          <line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line>
          <line x1="1" y1="12" x2="3" y2="12"></line>
          <line x1="21" y1="12" x2="23" y2="12"></line>
          <line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line>
          <line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line>
        </svg>
      `; // Sun icon (shows light option)
    }
  });
}

/* ==========================================================================
   Mobile Responsive Navigation Menu Toggle
   ========================================================================== */
function initMobileMenu() {
  const menuBtn = document.querySelector('.mobile-menu-btn');
  const navLinks = document.querySelector('.nav-links');
  
  if (menuBtn && navLinks) {
    menuBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      navLinks.classList.toggle('active');
      const isActive = navLinks.classList.contains('active');
      
      menuBtn.innerHTML = isActive 
        ? `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="28" height="28" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>`
        : `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="28" height="28" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="3" y1="12" x2="21" y2="12"></line><line x1="3" y1="6" x2="21" y2="6"></line><line x1="3" y1="18" x2="21" y2="18"></line></svg>`;
    });
    
    // Close menu when clicking outside or resizing screen
    document.addEventListener('click', (e) => {
      if (!navLinks.contains(e.target) && !menuBtn.contains(e.target)) {
        navLinks.classList.remove('active');
        updateMenuButtonIcon(menuBtn, false);
      }
    });
    
    window.addEventListener('resize', () => {
      if (window.innerWidth > 768) {
        navLinks.classList.remove('active');
        updateMenuButtonIcon(menuBtn, false);
      }
    });
  }
}

function updateMenuButtonIcon(btn, isActive) {
  if (isActive) return;
  btn.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="28" height="28" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="3" y1="12" x2="21" y2="12"></line><line x1="3" y1="6" x2="21" y2="6"></line><line x1="3" y1="18" x2="21" y2="18"></line></svg>`;
}

/* ==========================================================================
   Set Active Link styling for current page
   ========================================================================== */
function initNavbarActiveLink() {
  const currentPath = window.location.pathname;
  const pageName = currentPath.substring(currentPath.lastIndexOf('/') + 1) || 'index.html';
  
  document.querySelectorAll('.nav-links a').forEach(link => {
    const href = link.getAttribute('href');
    if (href === pageName || (pageName === 'index.html' && href === './') || (pageName === '' && href === 'index.html')) {
      link.classList.add('active');
    } else {
      link.classList.remove('active');
    }
  });
}

/* ==========================================================================
   Toast Notification System (Interactive floating notification badges)
   ========================================================================== */
function showToast(message, type = 'info', duration = 4000) {
  // Ensure toast container exists
  let container = document.querySelector('.toast-container');
  if (!container) {
    container = document.createElement('div');
    container.className = 'toast-container';
    document.body.appendChild(container);
  }
  
  // Icon definitions based on type
  const icons = {
    success: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>`,
    error: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>`,
    warning: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>`,
    info: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>`
  };
  
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.innerHTML = `
    <div class="toast-icon">${icons[type] || icons.info}</div>
    <div class="toast-message">${message}</div>
  `;
  
  container.appendChild(toast);
  
  // Slide out and remove
  const removeTimeout = setTimeout(() => {
    dismissToast(toast);
  }, duration);
  
  toast.addEventListener('click', () => {
    clearTimeout(removeTimeout);
    dismissToast(toast);
  });
}

function dismissToast(toast) {
  toast.classList.add('removing');
  toast.addEventListener('animationend', () => {
    toast.remove();
    // Clean up container if empty
    const container = document.querySelector('.toast-container');
    if (container && container.children.length === 0) {
      container.remove();
    }
  });
}

/* ==========================================================================
   Loading Overlay (For simulating scan analysis engine)
   ========================================================================== */
function showLoading(title = 'Initializing Scan...', subtext = 'Analyzing payload structure') {
  let overlay = document.querySelector('.loading-overlay');
  if (!overlay) {
    overlay = document.createElement('div');
    overlay.className = 'loading-overlay';
    overlay.innerHTML = `
      <div class="shield-spinner">
        <div class="shield-spinner-circle"></div>
        <div class="shield-spinner-inner"></div>
        <div class="shield-spinner-icon">
          <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" stroke="currentColor" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>
          </svg>
        </div>
      </div>
      <div class="loading-text">Analyzing Content...</div>
      <div class="loading-subtext">Evaluating threat level vectors</div>
    `;
    document.body.appendChild(overlay);
  }
  
  overlay.querySelector('.loading-text').textContent = title;
  overlay.querySelector('.loading-subtext').textContent = subtext;
  overlay.classList.add('active');
}

function hideLoading() {
  const overlay = document.querySelector('.loading-overlay');
  if (overlay) {
    overlay.classList.remove('active');
  }
}

/* ==========================================================================
   Rotating Cybersecurity Safety Tips
   ========================================================================== */
const SAFETY_TIPS = [
  "Never scan QR codes found in public places or on unsolicited mailers without careful inspection.",
  "Always verify merchant details (merchant name, payment ID) before verifying payments on UPI apps.",
  "Avoid clicking shortened links (like bit.ly, tinyurl) decoded from unknown QR codes.",
  "Never share OTPs, UPI PINs, or account credentials with anyone demanding them via QR redirects.",
  "Check for HTTPS and scrutinize the spelling of domains before entering login credentials.",
  "Fake payment receipts can be linked to QR codes. Do not trust QR codes displaying 'Payment Approved' on random screens.",
  "Malicious QR codes can auto-configure Wi-Fi networks to redirect your data through snooping hotspots."
];

function initSafetyTips() {
  const tipsTextEl = document.querySelector('.tips-text');
  if (!tipsTextEl) return;
  
  let currentTipIndex = 0;
  tipsTextEl.textContent = SAFETY_TIPS[0];
  
  setInterval(() => {
    tipsTextEl.style.opacity = 0;
    setTimeout(() => {
      currentTipIndex = (currentTipIndex + 1) % SAFETY_TIPS.length;
      tipsTextEl.textContent = SAFETY_TIPS[currentTipIndex];
      tipsTextEl.style.opacity = 1;
    }, 500);
  }, 7000);
}

/* ==========================================================================
   Local Storage Management (Scan History & Reports)
   ========================================================================== */
const STORAGE_KEYS = {
  HISTORY: 'qr_shield_history',
  REPORTS: 'qr_shield_reports'
};

function initAuthNavbar() {
  const token = localStorage.getItem('qr_shield_token');
  const user = JSON.parse(localStorage.getItem('qr_shield_user') || '{}');
  const navMenu = document.getElementById('navbar-menu');
  if (!navMenu) return;
  
  let html = `
    <li><a href="index.html">Home</a></li>
    <li><a href="scanner.html">Scan QR</a></li>
    <li><a href="history.html">History</a></li>
    <li><a href="report.html">Report Scam</a></li>
    <li><a href="about.html">About</a></li>
  `;
  
  if (token && user.email) {
    if (user.role === 'Admin' || user.role === 'Police') {
      html += `<li><a href="admin.html">Admin Console</a></li>`;
    }
    html += `<li><a href="#" id="auth-logout-btn" style="color: var(--color-red); font-weight: 600;">Logout</a></li>`;
  } else {
    html += `<li><a href="login.html" style="color: var(--color-cyan); font-weight: 600;">Sign In</a></li>`;
  }
  
  navMenu.innerHTML = html;
  initNavbarActiveLink();
  
  const logoutBtn = document.getElementById('auth-logout-btn');
  if (logoutBtn) {
    logoutBtn.addEventListener('click', (e) => {
      e.preventDefault();
      localStorage.removeItem('qr_shield_token');
      localStorage.removeItem('qr_shield_user');
      showToast('Logged out successfully', 'info');
      setTimeout(() => {
        window.location.replace('index.html');
      }, 1000);
    });
  }
}

// Local Storage Fallback helpers
function getLocalScanHistory() {
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEYS.HISTORY)) || [];
  } catch (e) {
    return [];
  }
}

function getLocalScamReports() {
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEYS.REPORTS)) || [];
  } catch (e) {
    return [];
  }
}

// Generic fetch wrapper with timeout, cold start detection and user friendly error handling
async function apiFetch(endpoint, options = {}, timeoutMs = 15000) {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeoutMs);
  
  const finalOptions = {
    ...options,
    signal: controller.signal
  };
  
  const startTime = Date.now();
  try {
    const res = await fetch(endpoint, finalOptions);
    clearTimeout(id);
    
    if (!res.ok) {
      if (res.status === 401) {
        showToast('Session expired or Unauthorized. Please log in again.', 'warning');
      } else if (res.status === 403) {
        showToast('Forbidden: You do not have permission for this resource.', 'error');
      } else if (res.status === 429) {
        showToast('Too many requests. Please try again later.', 'warning');
      } else if (res.status === 500) {
        showToast('Internal Server Error. Please contact support.', 'error');
      } else {
        showToast(`Server returned status: ${res.status}`, 'error');
      }
      
      const httpErr = new Error(`HTTP ${res.status}: ${res.statusText}`);
      httpErr.name = 'HTTPError';
      httpErr.status = res.status;
      throw httpErr;
    }
    return res;
  } catch (err) {
    clearTimeout(id);
    const duration = Date.now() - startTime;
    
    if (err.name === 'HTTPError') {
      throw err;
    }
    
    if (err.name === 'AbortError') {
      showToast('Request timed out while contacting the threat intelligence server. Please check your network connection and try again.', 'warning');
    } else if (err.name === 'TypeError' || err.message === 'Failed to fetch') {
      if (duration > 8000) {
        showToast('Server is starting up (Render Cold Start). Please wait 15 seconds and try again.', 'info');
      } else {
        showToast('Network error: Unable to connect to backend server. Possible CORS or connectivity failure.', 'error');
      }
    } else {
      showToast(`Interface error: ${err.message}`, 'error');
    }
    throw err;
  }
}

// Async API-integrated Helpers
async function getScanHistory() {
  const token = localStorage.getItem('qr_shield_token');
  if (!token) {
    return getLocalScanHistory();
  }

  try {
    const res = await apiFetch(`${API_BASE_URL}/scans`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    const data = await res.json();
    if (res.ok && data.success) {
      return data.scans.map(s => ({
        id: s.scanId,
        timestamp: s.timestamp,
        type: s.qrType,
        riskScore: s.riskScore,
        riskLevel: s.status,
        content: s.payload
      }));
    }
  } catch (err) {
    console.error('Fetch scans error:', err);
  }
  return getLocalScanHistory();
}

async function addScanToHistory(scanRecord) {
  // Save local fallback
  const localHistory = getLocalScanHistory();
  const localRecord = {
    id: Date.now().toString(),
    timestamp: new Date().toISOString(),
    ...scanRecord
  };
  localHistory.unshift(localRecord);
  if (localHistory.length > 100) localHistory.pop();
  localStorage.setItem(STORAGE_KEYS.HISTORY, JSON.stringify(localHistory));

  return localRecord;
}

async function deleteScanFromHistory(id) {
  let history = getLocalScanHistory();
  history = history.filter(item => item.id !== id);
  localStorage.setItem(STORAGE_KEYS.HISTORY, JSON.stringify(history));
  return history;
}

function clearScanHistory() {
  localStorage.setItem(STORAGE_KEYS.HISTORY, JSON.stringify([]));
}

async function getScamReports() {
  const token = localStorage.getItem('qr_shield_token');
  if (!token) {
    return getLocalScamReports();
  }

  try {
    const res = await apiFetch(`${API_BASE_URL}/reports`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    const data = await res.json();
    if (res.ok && data.success) {
      return data.reports.map(r => ({
        id: r.reportId,
        timestamp: r.createdAt,
        url: r.payload,
        category: r.reason,
        description: r.description,
        screenshot: r.screenshot
      }));
    }
  } catch (err) {
    console.error('Fetch reports error:', err);
  }
  return getLocalScamReports();
}

async function saveScamReport(report) {
  // Save local fallback
  const localReports = getLocalScamReports();
  const localRecord = {
    id: Date.now().toString(),
    timestamp: new Date().toISOString(),
    ...report
  };
  localReports.unshift(localRecord);
  localStorage.setItem(STORAGE_KEYS.REPORTS, JSON.stringify(localReports));

  // Sync to server if authenticated
  const token = localStorage.getItem('qr_shield_token');
  if (!token) {
    console.warn('Anonymous reports not synced with server.');
    return localRecord;
  }

  try {
    await apiFetch(`${API_BASE_URL}/report`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify({
        payload: report.url,
        reason: report.category,
        description: report.description,
        screenshot: report.screenshot, // Base64 screenshot
        city: 'Mumbai',
        state: 'Maharashtra',
        country: 'India'
      })
    });
  } catch (err) {
    console.error('Failed to sync report with backend:', err);
  }

  return localRecord;
}

/* ==========================================================================
   Confetti Canvas Particle Engine (Visual feedback on Safe scans)
   ========================================================================== */
let confettiAnimationId = null;

function triggerConfetti() {
  let canvas = document.getElementById('confetti-canvas');
  if (!canvas) {
    canvas = document.createElement('canvas');
    canvas.id = 'confetti-canvas';
    document.body.appendChild(canvas);
  }
  
  const ctx = canvas.getContext('2d');
  canvas.width = window.innerWidth;
  canvas.height = window.innerHeight;
  canvas.style.display = 'block';
  
  const colors = ['#22c55e', '#3b82f6', '#06b6d4', '#f59e0b', '#ec4899'];
  const particles = [];
  
  for (let i = 0; i < 150; i++) {
    particles.push({
      x: canvas.width / 2,
      y: canvas.height + 20,
      size: Math.random() * 6 + 4,
      color: colors[Math.floor(Math.random() * colors.length)],
      angle: Math.random() * Math.PI - Math.PI, // shoot upwards
      speed: Math.random() * 15 + 10,
      gravity: 0.35,
      friction: 0.96,
      opacity: 1,
      rotation: Math.random() * 360,
      rotationSpeed: Math.random() * 10 - 5
    });
  }
  
  if (confettiAnimationId) {
    cancelAnimationFrame(confettiAnimationId);
  }
  
  function update() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    let activeParticles = 0;
    
    particles.forEach(p => {
      if (p.opacity <= 0) return;
      
      p.speed *= p.friction;
      p.x += Math.cos(p.angle) * p.speed;
      p.y += Math.sin(p.angle) * p.speed + p.gravity;
      p.gravity += 0.05;
      p.opacity -= 0.015;
      p.rotation += p.rotationSpeed;
      
      if (p.y < canvas.height && p.x > 0 && p.x < canvas.width && p.opacity > 0) {
        activeParticles++;
        ctx.save();
        ctx.translate(p.x, p.y);
        ctx.rotate((p.rotation * Math.PI) / 180);
        ctx.globalAlpha = p.opacity;
        ctx.fillStyle = p.color;
        
        // draw rectangles
        ctx.fillRect(-p.size / 2, -p.size / 2, p.size, p.size);
        ctx.restore();
      }
    });
    
    if (activeParticles > 0) {
      confettiAnimationId = requestAnimationFrame(update);
    } else {
      canvas.style.display = 'none';
      cancelAnimationFrame(confettiAnimationId);
      confettiAnimationId = null;
    }
  }
  
  update();
}

// Export utilities for availability across modular scripts
window.QRShieldUtils = {
  showToast,
  showLoading,
  hideLoading,
  getScanHistory,
  addScanToHistory,
  deleteScanFromHistory,
  clearScanHistory,
  getScamReports,
  saveScamReport,
  triggerConfetti
};
