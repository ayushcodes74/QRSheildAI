/**
 * Canonical Risk Severity Policy
 * 0–20   = Safe
 * 21–40  = Low Risk
 * 41–60  = Medium Risk
 * 61–80  = High Risk
 * 81–100 = Critical
 */

function getThreatLevel(riskScore) {
  const score = parseInt(riskScore) || 0;
  if (score >= 81) return 'Critical';
  if (score >= 61) return 'High Risk';
  if (score >= 41) return 'Medium Risk';
  if (score >= 21) return 'Low Risk';
  return 'Safe';
}

function getRiskStatus(riskScore) {
  const score = parseInt(riskScore) || 0;
  if (score > 60) return 'Dangerous';
  if (score > 20) return 'Suspicious';
  return 'Safe';
}

function getRiskSeverityConfig(riskScore) {
  const level = getThreatLevel(riskScore);
  const status = getRiskStatus(riskScore);
  
  let color = '#22c55e'; // Green
  let badgeClass = 'badge-safe';
  
  if (level === 'Critical') {
    color = '#ef4444'; // Red
    badgeClass = 'badge-dangerous';
  } else if (level === 'High Risk') {
    color = '#f97316'; // Orange / Warning
    badgeClass = 'badge-suspicious';
  } else if (level === 'Medium Risk') {
    color = '#f59e0b'; // Amber
    badgeClass = 'badge-medium';
  } else if (level === 'Low Risk') {
    color = '#06b6d4'; // Cyan
    badgeClass = 'badge-low';
  }
  
  return {
    threatLevel: level,
    status,
    color,
    badgeClass
  };
}

module.exports = {
  getThreatLevel,
  getRiskStatus,
  getRiskSeverityConfig
};
