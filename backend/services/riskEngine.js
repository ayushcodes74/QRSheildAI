const net = require('net');
const { getThreatLevel } = require('./severityPolicy');

/**
 * Helper: Extract domain from URL (reused from controllers or custom logic to ensure safety)
 */
function getDomainName(urlStr) {
  try {
    let target = urlStr.trim();
    if (!/^https?:\/\//i.test(target)) {
      target = 'http://' + target;
    }
    const parsed = new URL(target);
    return parsed.hostname.toLowerCase();
  } catch (e) {
    return null;
  }
}

/**
 * Evidence-Fusion Risk Engine
 * Computes individual component scores, applies overrides, formats findings and filters AI hallucinations.
 * 
 * @param {Object} params Input parameters containing the payload, type, and API outputs
 * @param {string} params.payload Raw scanned QR text
 * @param {string} params.qrType Detected QR type category
 * @param {string} [params.domain] Pre-parsed URL domain (optional)
 * @param {Object} [params.safeBrowsingRes] Google Safe Browsing API response
 * @param {Object} [params.virusTotalRes] VirusTotal API response
 * @param {Object} [params.openRouterRes] OpenRouter AI assistant classification details
 * @param {number} [params.communityCount] Quantity of user community scam reports
 * @returns {Object} Structured analysis result
 */
function evaluate({ payload, qrType, domain, safeBrowsingRes, virusTotalRes, openRouterRes, communityCount }) {
  const normalizedPayload = (payload || '').trim().toLowerCase();
  const isUrl = qrType === 'Website' || qrType === 'PDF' || qrType === 'Play Store' || qrType === 'App Store' || qrType === 'Government' || qrType === 'Social';
  
  // If domain is not supplied, extract it
  const finalDomain = domain || (isUrl ? getDomainName(payload) : null);

  const threatsDetected = [];
  const technicalIndicators = [];

  // --- 1. GOOGLE SAFE BROWSING ---
  let safeBrowsingContribution = 0;
  let safeBrowsingStatus = "Safe";
  let safeBrowsingEvidence = "No threat detected by Google Safe Browsing.";

  if (!isUrl) {
    safeBrowsingStatus = "Not Applicable";
    safeBrowsingEvidence = "Not a URL payload.";
  } else if (safeBrowsingRes && safeBrowsingRes.error) {
    safeBrowsingStatus = "Unavailable";
    safeBrowsingEvidence = `API unavailable: ${safeBrowsingRes.error}`;
  } else if (safeBrowsingRes && !safeBrowsingRes.isSafe) {
    safeBrowsingContribution = 40;
    safeBrowsingStatus = safeBrowsingRes.threatType || "Malicious";
    safeBrowsingEvidence = `Confirmed threat match: ${safeBrowsingRes.threatType}`;
    
    threatsDetected.push('Malicious Web Link');
    technicalIndicators.push(`Google Safe Browsing Blocklist (${safeBrowsingRes.threatType})`);
  }

  // --- 2. VIRUSTOTAL ---
  let virusTotalContribution = 0;
  let virusTotalStatus = "Safe";
  let virusTotalEvidence = "No threat detected by VirusTotal.";
  let vtMalicious = 0;
  let vtSuspicious = 0;
  let vtHarmless = 0;
  let vtUndetected = 0;
  let vtTotal = 0;
  let vtRatio = '0/0';

  if (!isUrl) {
    virusTotalStatus = "Not Applicable";
    virusTotalEvidence = "Not a URL payload.";
  } else if (virusTotalRes && virusTotalRes.error) {
    virusTotalStatus = "Unavailable";
    virusTotalEvidence = `API unavailable: ${virusTotalRes.error}`;
  } else if (virusTotalRes) {
    vtMalicious = virusTotalRes.malicious || 0;
    vtSuspicious = virusTotalRes.suspicious || 0;
    vtHarmless = virusTotalRes.harmless || 0;
    vtUndetected = virusTotalRes.undetected || 0;
    vtTotal = vtMalicious + vtSuspicious + vtHarmless + vtUndetected;
    vtRatio = virusTotalRes.ratio || `${vtMalicious}/${vtTotal}`;

    const maliciousRatio = vtTotal > 0 ? vtMalicious / vtTotal : 0;
    const suspiciousRatio = vtTotal > 0 ? vtSuspicious / vtTotal : 0;

    // Evaluate malicious/suspicious thresholds securely without double stacking.
    if (vtMalicious >= 10 || maliciousRatio >= 0.10) {
      virusTotalContribution = 30;
      virusTotalStatus = "Dangerous";
    } else if (vtMalicious >= 5 || maliciousRatio >= 0.05) {
      virusTotalContribution = 24;
      virusTotalStatus = "Dangerous";
    } else if (vtMalicious >= 2) {
      virusTotalContribution = 18;
      virusTotalStatus = "Dangerous";
    } else if (vtMalicious === 1) {
      virusTotalContribution = 10;
      virusTotalStatus = "Suspicious";
    } else if (vtSuspicious >= 5 || suspiciousRatio >= 0.10) {
      virusTotalContribution = 8;
      virusTotalStatus = "Suspicious";
    } else if (vtSuspicious > 0) {
      virusTotalContribution = 4;
      virusTotalStatus = "Suspicious";
    } else {
      virusTotalContribution = 0;
      virusTotalStatus = "Safe";
    }
    
    virusTotalEvidence = `Found ${vtMalicious} malicious and ${vtSuspicious} suspicious detections out of ${vtTotal} engines.`;

    if (vtMalicious >= 2) {
      threatsDetected.push('Malicious URL Detection');
    } else if (vtMalicious === 1) {
      threatsDetected.push('Suspicious URL Detection');
    }
    if (vtMalicious > 0) {
      technicalIndicators.push(`VirusTotal Malicious Vendors (${vtRatio})`);
    }

    if (vtSuspicious >= 5) {
      threatsDetected.push('Suspicious URL Detection');
      technicalIndicators.push('VirusTotal Suspicious Flag');
    } else if (vtSuspicious > 0) {
      technicalIndicators.push('VirusTotal Suspicious Flag');
    }
  }

  // --- 3. STRUCTURAL URL/PAYLOAD SIGNALS ---
  let structuralContribution = 0;
  const signals = [];

  if (isUrl) {
    // A. HTTP instead of HTTPS
    const startsWithHttp = /^http:\/\//i.test(payload);
    const lacksHttps = !/^https:\/\//i.test(payload);
    if (startsWithHttp || lacksHttps) {
      structuralContribution += 5;
      signals.push("HTTP instead of HTTPS");
      technicalIndicators.push('Insecure HTTP Connection');
    }

    // B. Known URL shortener
    const URL_SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly", "adf.ly", "ow.ly", "rebrand.ly", "git.io", "tiny.cc", "t.ly", "shorturl.at", "v.gd", "tiny.one", "urlr.me"];
    const isShortened = finalDomain && URL_SHORTENERS.some(short => finalDomain === short || finalDomain.endsWith('.' + short));
    if (isShortened) {
      structuralContribution += 5;
      signals.push("Known URL shortener");
      threatsDetected.push('Short URL Redirection');
      technicalIndicators.push('URL Shortener Link');
    }

    // C. IP-address hostname
    const isIp = finalDomain && net.isIP(finalDomain);
    if (isIp) {
      structuralContribution += 5;
      signals.push("IP-address hostname");
      threatsDetected.push('IP Address Hostname');
      technicalIndicators.push('Host is IP Address');
    }

    // D. Punycode hostname
    const isPunycode = finalDomain && (/^xn--/i.test(finalDomain) || /\.xn--/i.test(finalDomain));
    if (isPunycode) {
      structuralContribution += 5;
      signals.push("Punycode hostname");
      threatsDetected.push('Punycode Hostname spoof possibility');
      technicalIndicators.push('Punycode Domain');
    }

    // E. Excessive subdomains (parts.length >= 5)
    const parts = finalDomain ? finalDomain.split('.') : [];
    if (parts.length >= 5) {
      structuralContribution += 3;
      signals.push("Excessive subdomains");
      technicalIndicators.push('Excessive Subdomains');
    }

    // F. Suspicious URL length (payload.length > 100)
    if (payload && payload.length > 100) {
      structuralContribution += 2;
      signals.push("Suspicious URL length");
      technicalIndicators.push('Suspicious URL Length');
    }
  } else {
    // Non-URL structural checks
    if (qrType === 'UPI') {
      const normalized = normalizedPayload;
      if (!normalized.includes('pa=')) {
        structuralContribution += 5;
        signals.push("Missing payee address (pa)");
        threatsDetected.push('Malformed UPI Payment Request');
        technicalIndicators.push('Missing UPI Payee Address');
      }
      if (!normalized.includes('pn=')) {
        structuralContribution += 3;
        signals.push("Missing payee name (pn)");
        technicalIndicators.push('Missing UPI Payee Name');
      }
      if (payload && payload.length > 200) {
        structuralContribution += 2;
        signals.push("Suspicious UPI payload length");
        technicalIndicators.push('Suspicious UPI payload length');
      }
      if (normalized.includes('reward') || normalized.includes('cashback') || normalized.includes('refund') || normalized.includes('free')) {
        structuralContribution += 5;
        signals.push("Suspicious payment keyword");
        threatsDetected.push('Financial Fraud Scam');
        technicalIndicators.push('UPI Cashback/Reward keyword');
      }
    } else if (qrType === 'Email') {
      const cleanPayload = payload ? payload.trim() : '';
      const mailtoMatch = cleanPayload.match(/^mailto:([^?]+)/i);
      const emailStr = mailtoMatch ? mailtoMatch[1] : cleanPayload;
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(emailStr)) {
        structuralContribution += 5;
        signals.push("Malformed email address");
        threatsDetected.push('Malformed Email Address');
        technicalIndicators.push('Invalid Email Format');
      }
      const lower = cleanPayload.toLowerCase();
      if (lower.includes('suspend') || lower.includes('verify') || lower.includes('alert') || lower.includes('security') || lower.includes('update')) {
        structuralContribution += 3;
        signals.push("Suspicious email keyword");
        threatsDetected.push('Phishing Attempt');
        technicalIndicators.push('Suspicious Email Keywords');
      }
    } else if (qrType === 'Phone' || qrType === 'SMS') {
      const cleanPayload = payload ? payload.trim() : '';
      const numMatch = cleanPayload.match(/^(tel|sms|smsto):([^?]+)/i);
      const numStr = numMatch ? numMatch[2] : cleanPayload;
      if (!numStr || numStr.length === 0) {
        structuralContribution += 5;
        signals.push("Missing phone number");
        technicalIndicators.push('Missing Phone Number');
      } else {
        const sanitized = numStr.replace(/^\+/, '');
        if (/[^\d\-\s()]/.test(sanitized)) {
          structuralContribution += 3;
          signals.push("Phone number contains non-numeric characters");
          technicalIndicators.push('Invalid Phone Number Format');
        }
      }
    }
  }

  structuralContribution = Math.min(structuralContribution, 15);

  // --- 4. COMMUNITY REPORTS ---
  let communityContribution = 0;
  const reportCount = communityCount || 0;
  if (reportCount === 0) {
    communityContribution = 0;
  } else if (reportCount === 1) {
    communityContribution = 2;
  } else if (reportCount <= 3) {
    communityContribution = 4;
  } else if (reportCount <= 9) {
    communityContribution = 7;
  } else {
    communityContribution = 10;
  }

  if (reportCount > 0) {
    threatsDetected.push('Community Reported Phishing');
    technicalIndicators.push(`Scam Reported by ${reportCount} User(s)`);
  }

  // --- 5. AI CONTEXT ANALYSIS ---
  let aiContribution = 0;
  let aiConfidence = 0;
  let aiRiskScore = 0;
  let aiCategory = "Safe";
  let aiReasoning = "No AI analysis available.";
  let aiObservations = { threatsDetected: [], technicalIndicators: [] };

  if (!openRouterRes || openRouterRes.error || typeof openRouterRes.confidence === 'undefined') {
    aiCategory = "Unavailable";
    aiReasoning = "AI service was unavailable.";
  } else {
    aiConfidence = openRouterRes.confidence || 0;
    aiRiskScore = openRouterRes.riskScore || 0;
    aiCategory = openRouterRes.threatCategory || "Safe";
    aiReasoning = openRouterRes.reasoning || "No immediate structural threats detected.";
    aiObservations = {
      threatsDetected: openRouterRes.threatsDetected || [],
      technicalIndicators: openRouterRes.technicalIndicators || []
    };

    if (aiConfidence >= 60) {
      const rawContribution = (aiRiskScore / 100) * (aiConfidence / 100) * 15;
      aiContribution = Math.round(rawContribution);
      aiContribution = Math.max(0, Math.min(aiContribution, 15));
    }
  }

  // --- FINAL SCORE CALCULATION & OVERRIDES ---
  let finalRiskScore = safeBrowsingContribution + virusTotalContribution + structuralContribution + communityContribution + aiContribution;

  // Apply Override Rules
  const safeBrowsingConfirmsMalwareOrSocial = isUrl && safeBrowsingRes && !safeBrowsingRes.error && !safeBrowsingRes.isSafe && 
    (safeBrowsingRes.threatType === 'MALWARE' || safeBrowsingRes.threatType === 'SOCIAL_ENGINEERING');

  const safeBrowsingConfirmsThreat = isUrl && safeBrowsingRes && !safeBrowsingRes.error && !safeBrowsingRes.isSafe;

  if (safeBrowsingConfirmsMalwareOrSocial) {
    finalRiskScore = Math.max(finalRiskScore, 70);
  }
  if (isUrl && vtMalicious >= 10) {
    finalRiskScore = Math.max(finalRiskScore, 70);
  }
  if (safeBrowsingConfirmsThreat && vtMalicious >= 5) {
    finalRiskScore = Math.max(finalRiskScore, 85);
  }

  // Clamp final score
  finalRiskScore = Math.max(0, Math.min(finalRiskScore, 100));

  // Threshold / Threat Level Mapping
  const threatLevel = getThreatLevel(finalRiskScore);

  // Recommendation Mapping
  let recommendation = "Proceed";
  if (finalRiskScore >= 61) recommendation = "Block";
  else if (finalRiskScore >= 41) recommendation = "Verify Manually";
  else if (finalRiskScore >= 21) recommendation = "Proceed Carefully";

  // Ensure unique elements and clean arrays
  const uniqueThreats = [...new Set(threatsDetected)];
  const uniqueIndicators = technicalIndicators.length > 0 ? [...new Set(technicalIndicators)] : ['Safe Structural Format'];

  return {
    riskScore: finalRiskScore,
    threatLevel,
    recommendation,
    threatsDetected: uniqueThreats,
    technicalIndicators: uniqueIndicators,
    aiReasoning,
    aiObservations,
    riskBreakdown: {
      googleSafeBrowsing: {
        score: safeBrowsingContribution,
        maxScore: 40,
        status: safeBrowsingStatus,
        evidence: safeBrowsingEvidence
      },
      virusTotal: {
        score: virusTotalContribution,
        maxScore: 30,
        status: virusTotalStatus,
        malicious: vtMalicious,
        suspicious: vtSuspicious,
        totalEvaluated: vtTotal,
        evidence: virusTotalEvidence
      },
      structuralSignals: {
        score: structuralContribution,
        maxScore: 15,
        signals
      },
      communityReports: {
        score: communityContribution,
        maxScore: 10,
        reportCount
      },
      aiContext: {
        score: aiContribution,
        maxScore: 15,
        confidence: aiConfidence,
        aiRiskScore: aiRiskScore,
        category: aiCategory
      }
    }
  };
}

module.exports = { evaluate };
