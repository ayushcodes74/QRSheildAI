/**
 * QR Shield AI - Scan History Manager
 * Orchestrates logs loading, filtering, search index, deletion, and exports
 */

document.addEventListener('DOMContentLoaded', () => {
  initHistoryView();
});

async function initHistoryView() {
  const searchInput = document.getElementById('history-search');
  const typeFilter = document.getElementById('filter-type');
  const riskFilter = document.getElementById('filter-risk');
  const clearBtn = document.getElementById('clear-history-btn');
  const exportBtn = document.getElementById('export-history-btn');

  // Load and render history lists on launch
  await renderHistoryTable();

  // Search & Filter event binds
  if (searchInput) {
    searchInput.addEventListener('input', applyFilters);
  }
  if (typeFilter) {
    typeFilter.addEventListener('change', applyFilters);
  }
  if (riskFilter) {
    riskFilter.addEventListener('change', applyFilters);
  }

  // Clear logs bind
  if (clearBtn) {
    clearBtn.addEventListener('click', handleClearAllHistory);
  }

  // Export JSON logs bind
  if (exportBtn) {
    exportBtn.addEventListener('click', handleExportJSON);
  }
}

async function getStoredHistory() {
  if (window.QRShieldUtils && window.QRShieldUtils.getScanHistory) {
    return await window.QRShieldUtils.getScanHistory();
  }
  return [];
}

async function renderHistoryTable(filteredLogs = null) {
  const tableBody = document.getElementById('history-table-body');
  const emptyState = document.getElementById('history-empty-state');
  const tableContainer = document.getElementById('history-table-container');
  const clearBtn = document.getElementById('clear-history-btn');
  const exportBtn = document.getElementById('export-history-btn');
  
  if (!tableBody) return;

  const logs = filteredLogs !== null ? filteredLogs : await getStoredHistory();

  // Handle empty state layout updates
  if (logs.length === 0) {
    if (emptyState) emptyState.style.display = 'block';
    if (tableContainer) tableContainer.style.display = 'none';
    if (clearBtn) clearBtn.disabled = true;
    if (exportBtn) exportBtn.disabled = true;
    return;
  }

  if (emptyState) emptyState.style.display = 'none';
  if (tableContainer) tableContainer.style.display = 'block';
  if (clearBtn) clearBtn.disabled = false;
  if (exportBtn) exportBtn.disabled = false;

  tableBody.innerHTML = '';

  logs.forEach(log => {
    const row = document.createElement('tr');
    row.id = `history-row-${log.id}`;
    
    // Format Date
    const dateFormatted = formatDate(log.timestamp);
    
    // Format Risk Badge
    let badgeClass = 'badge-safe';
    if (log.riskLevel === 'Medium') badgeClass = 'badge-medium';
    if (log.riskLevel === 'Suspicious') badgeClass = 'badge-suspicious';
    if (log.riskLevel === 'Dangerous') badgeClass = 'badge-dangerous';
    
    // Determine target actions redirect (if url, can navigate)
    const isUrl = /^https?:\/\//i.test(log.content);
    const viewButton = isUrl 
      ? `<a href="${log.content}" target="_blank" rel="noopener noreferrer" class="table-btn" title="Open Link">
          <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"></path><polyline points="15 3 21 3 21 9"></polyline><line x1="10" y1="14" x2="21" y2="3"></line></svg>
         </a>`
      : `<button class="table-btn" onclick="alert('Decoded Value:\\n\\n${log.content.replace(/'/g, "\\'")}')" title="View Payload">
          <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>
         </button>`;

    row.innerHTML = `
      <td class="table-date">${dateFormatted}</td>
      <td><span class="result-badge ${badgeClass}" style="padding: 3px 10px; font-size: 0.75rem;">${log.type}</span></td>
      <td>
        <div style="display: flex; align-items: center; gap: 8px;">
          <span style="font-weight: 700; color: ${getRiskColor(log.riskLevel)}">${log.riskScore}</span>
          <div style="flex-grow: 1; width: 60px; height: 4px; background: rgba(255,255,255,0.05); border-radius: 4px; overflow: hidden;">
            <div style="width: ${log.riskScore}%; height: 100%; background: ${getRiskColor(log.riskLevel)};"></div>
          </div>
        </div>
      </td>
      <td class="table-content" title="${log.content}">${escapeHTML(log.content)}</td>
      <td class="table-actions">
        ${viewButton}
        <button class="table-btn table-btn-delete" onclick="handleDeleteHistoryItem('${log.id}')" title="Delete Entry">
          <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path><line x1="10" y1="11" x2="10" y2="17"></line><line x1="14" y1="11" x2="14" y2="17"></line></svg>
        </button>
      </td>
    `;
    tableBody.appendChild(row);
  });
}

async function applyFilters() {
  const searchInput = document.getElementById('history-search');
  const typeFilter = document.getElementById('filter-type');
  const riskFilter = document.getElementById('filter-risk');

  const query = searchInput ? searchInput.value.toLowerCase().trim() : '';
  const typeVal = typeFilter ? typeFilter.value : 'All';
  const riskVal = riskFilter ? riskFilter.value : 'All';

  const allLogs = await getStoredHistory();
  
  const filtered = allLogs.filter(log => {
    const matchesSearch = log.content.toLowerCase().includes(query) || log.type.toLowerCase().includes(query);
    const matchesType = typeVal === 'All' || log.type === typeVal;
    const matchesRisk = riskVal === 'All' || log.riskLevel === riskVal;
    
    return matchesSearch && matchesType && matchesRisk;
  });

  await renderHistoryTable(filtered);
}

window.handleDeleteHistoryItem = function(id) {
  if (confirm('Delete this record from security logs?')) {
    const row = document.getElementById(`history-row-${id}`);
    if (row) {
      // Fade out effect
      row.style.transition = 'opacity 0.3s, transform 0.3s';
      row.style.opacity = '0';
      row.style.transform = 'translateX(-20px)';
      
      setTimeout(() => {
        if (window.QRShieldUtils && window.QRShieldUtils.deleteScanFromHistory) {
          window.QRShieldUtils.deleteScanFromHistory(id);
          applyFilters(); // Re-render lists
          window.QRShieldUtils.showToast('Log entry removed.', 'info');
        }
      }, 300);
    }
  }
};

async function handleClearAllHistory() {
  if (confirm('Are you absolutely sure you want to clear your entire scanning history? This cannot be undone.')) {
    if (window.QRShieldUtils && window.QRShieldUtils.clearScanHistory) {
      window.QRShieldUtils.clearScanHistory();
      await renderHistoryTable();
      window.QRShieldUtils.showToast('All security scan records deleted.', 'warning');
    }
  }
}

function handleExportJSON() {
  const logs = getStoredHistory();
  if (logs.length === 0) return;
  
  try {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(logs, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `qr_shield_scan_history_${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
    
    if (window.QRShieldUtils) {
      window.QRShieldUtils.showToast('History exported successfully!', 'success');
    }
  } catch (e) {
    if (window.QRShieldUtils) {
      window.QRShieldUtils.showToast('Failed to export history logs.', 'error');
    }
  }
}

/* ==========================================================================
   Helper Utilities for Text Formatting
   ========================================================================== */
function formatDate(isoString) {
  try {
    const date = new Date(isoString);
    const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
    
    const day = date.getDate();
    const month = months[date.getMonth()];
    const year = date.getFullYear();
    
    let hours = date.getHours();
    const minutes = date.getMinutes().toString().padStart(2, '0');
    const ampm = hours >= 12 ? 'PM' : 'AM';
    hours = hours % 12;
    hours = hours ? hours : 12; // 0 should be 12
    
    return `${month} ${day}, ${year} ${hours}:${minutes} ${ampm}`;
  } catch (e) {
    return 'Invalid Date';
  }
}

function getRiskColor(level) {
  if (level === 'Safe') return '#22c55e';
  if (level === 'Medium') return '#f59e0b';
  if (level === 'Suspicious') return '#f97316';
  if (level === 'Dangerous') return '#ef4444';
  return '#f8fafc';
}

function escapeHTML(str) {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
