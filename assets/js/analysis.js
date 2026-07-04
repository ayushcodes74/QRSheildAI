/**
 * QR Shield AI - Analysis Engine
 * Threat Scoring, Phishing Database Matching, and AI Explanation Simulator
 */

// Offline Fallback Phishing Domains (loaded synchronously to prevent CORS issues on file:// access)
const LOCAL_PHISHING_DOMAINS = [
  "paypal-security-login.xyz",
  "amaz0n-payment.xyz",
  "sbi-login-verification.xyz",
  "upi-payment-confirm.xyz",
  "bit.ly/fakebank",
  "netflix-free-premium.xyz",
  "facebook-verify-account.co",
  "steam-promo-gift.ru",
  "crypto-giveaway-2026.xyz",
  "google-login-update.com.de"
];

// Common URL Shortener Domains
const URL_SHORTENERS = [
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly", 
  "adf.ly", "ow.ly", "rebrand.ly", "git.io", "tiny.cc", "t.ly"
];

// Whitelist of highly popular, trusted domains (to determine "unknown domain")
const TRUSTED_DOMAINS = [
  "google.com", "google.co.in", "github.com", "microsoft.com", "apple.com", 
  "youtube.com", "wikipedia.org", "amazon.com", "amazon.in", "netflix.com", 
  "facebook.com", "instagram.com", "twitter.com", "linkedin.com", "zoom.us", 
  "drive.google.com", "dropbox.com", "paytm.com", "phonepe.com", "paypal.com",
  "spotify.com", "stackoverflow.com", "reddit.com", "medium.com", "w3schools.com"
];

// Keywords commonly misused in phishing domains
const SUSPICIOUS_KEYWORDS = [
  "login", "verify", "secure", "signin", "update", "banking", "account", 
  "support", "billing", "free", "gift", "prize", "refund", "claim", "portal",
  "verification", "security", "wallet", "crypto", "pay", "payment"
];

// Known safe/verified merchants for UPI analysis
const VERIFIED_UPI_MERCHANTS = [
  "amazon", "google", "phonepe", "paytm", "netflix", "spotify", "steam", 
  "uber", "ola", "zomato", "swiggy", "flipkart", "irctc", "lic"
];

/**
 * Main analysis coordinator.
 * Identifies QR type and performs structural scanning.
 */
function analyzeQRContent(content) {
  const trimmed = content.trim();
  const result = {
    rawContent: trimmed,
    type: 'Text',
    riskScore: 0,
    riskLevel: 'Safe',
    checklist: [],
    details: {},
    aiExplanation: '',
    recommendation: 'No action required. This plain text appears safe to read.'
  };

  // 1. Detect QR Code Type
  if (trimmed.startsWith('upi://pay')) {
    result.type = 'UPI';
    analyzeUPILink(trimmed, result);
  } else if (/^https?:\/\//i.test(trimmed) || /^[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}(:[0-9]{1,5})?(\/.*)?$/i.test(trimmed)) {
    result.type = 'Website';
    // Ensure URL has protocol for parser
    let urlString = trimmed;
    if (!/^https?:\/\//i.test(trimmed)) {
      urlString = 'http://' + trimmed;
    }
    analyzeURL(urlString, result);
  } else if (trimmed.startsWith('WIFI:')) {
    result.type = 'WiFi';
    analyzeWiFi(trimmed, result);
  } else if (trimmed.startsWith('mailto:')) {
    result.type = 'Email';
    analyzeEmail(trimmed, result);
  } else if (trimmed.startsWith('tel:')) {
    result.type = 'Phone';
    analyzePhone(trimmed, result);
  } else if (trimmed.startsWith('sms:') || trimmed.startsWith('smsto:')) {
    result.type = 'SMS';
    analyzeSMS(trimmed, result);
  } else if (trimmed.startsWith('BEGIN:VCARD')) {
    result.type = 'Contact';
    analyzeContact(trimmed, result);
  } else {
    // Check if plain text looks like a suspicious link or VPA
    if (trimmed.includes('@') && !trimmed.includes(' ')) {
      // Could be raw VPA or Email
      if (trimmed.includes('@') && (trimmed.toLowerCase().endsWith('.vpa') || trimmed.toLowerCase().includes('upi') || trimmed.toLowerCase().includes('ybl') || trimmed.toLowerCase().includes('okaxis'))) {
        result.type = 'UPI';
        result.details = { upiId: trimmed, merchantName: 'Unknown entity', amount: 'N/A' };
        result.riskScore = 30; // Unknown plain UPI
        result.riskLevel = 'Medium';
        result.aiExplanation = "This QR code contains a raw UPI ID without full transaction details. Transferring funds to this VPA directly might be risky if you don't recognize the recipient.";
        result.recommendation = "Always double-check the recipient's name in your payment app before entering your UPI PIN.";
      }
    }
  }

  // Determine Overall Risk Level based on computed score
  if (result.riskScore <= 20) {
    result.riskLevel = 'Safe';
  } else if (result.riskScore <= 50) {
    result.riskLevel = 'Medium';
  } else if (result.riskScore <= 80) {
    result.riskLevel = 'Suspicious';
  } else {
    result.riskLevel = 'Dangerous';
  }

  return result;
}

/**
 * URL Threat Analysis engine.
 * Implements mathematical scoring criteria from standard rules.
 */
function analyzeURL(urlString, result) {
  let score = 0;
  let parsedUrl;
  
  try {
    parsedUrl = new URL(urlString);
  } catch (e) {
    // Handle invalid URL structures
    result.riskScore = 50;
    result.riskLevel = 'Suspicious';
    result.aiExplanation = "The URL syntax is malformed, which is a common trick used to evade automated link parsing and security filter detectors.";
    result.recommendation = "Do not attempt to load this link. Copying it to a browser might run malicious hidden scripts.";
    return;
  }

  const hostname = parsedUrl.hostname.toLowerCase();
  const protocol = parsedUrl.protocol.toLowerCase();
  
  // Checklist tracker
  const checklist = [];
  
  // Rule 1: HTTPS Connection Check (HTTPS missing +25)
  const isHttps = protocol === 'https:';
  const httpsScore = isHttps ? 0 : 25;
  score += httpsScore;
  checklist.push({
    name: 'HTTPS Encrypted Link',
    pass: isHttps,
    desc: isHttps ? 'Connection is secure and encrypted.' : 'Missing SSL encryption. Intercepted data is vulnerable.'
  });

  // Rule 2: Short URL check (Short URL +20)
  const isShortened = URL_SHORTENERS.some(short => hostname === short || hostname.endsWith('.' + short));
  const shortScore = isShortened ? 20 : 0;
  score += shortScore;
  checklist.push({
    name: 'Shortened Link Checker',
    pass: !isShortened,
    desc: isShortened ? 'Shortened URL detected. Hides the final destination path.' : 'Full transparent domain address.'
  });

  // Rule 3: Suspicious Keywords (+25)
  // Check if keywords are in domain name but it is not the legitimate domain
  let hasSuspiciousKeyword = false;
  let matchesLegitimate = false;
  
  // Identify if domain is pretending to be something else
  const domainParts = hostname.split('.');
  // Check if domain contains words like 'paypal', 'amazon', etc., while not being the official site
  const brandKeywords = ['paypal', 'amazon', 'netflix', 'steam', 'sbi', 'facebook', 'google'];
  
  brandKeywords.forEach(brand => {
    if (hostname.includes(brand)) {
      if (brand === 'paypal' && !hostname.endsWith('paypal.com')) hasSuspiciousKeyword = true;
      if (brand === 'amazon' && !hostname.endsWith('amazon.com') && !hostname.endsWith('amazon.in')) hasSuspiciousKeyword = true;
      if (brand === 'netflix' && !hostname.endsWith('netflix.com')) hasSuspiciousKeyword = true;
      if (brand === 'steam' && !hostname.endsWith('steampowered.com') && !hostname.endsWith('steamcommunity.com')) hasSuspiciousKeyword = true;
      if (brand === 'sbi' && !hostname.endsWith('onlinesbi.sbi') && !hostname.endsWith('sbi.co.in')) hasSuspiciousKeyword = true;
      if (brand === 'facebook' && !hostname.endsWith('facebook.com')) hasSuspiciousKeyword = true;
      if (brand === 'google' && !hostname.endsWith('google.com') && !hostname.endsWith('google.co.in')) hasSuspiciousKeyword = true;
    }
  });

  // Check general suspicious keywords
  SUSPICIOUS_KEYWORDS.forEach(keyword => {
    if (domainParts.some(part => part.includes(keyword) && part !== keyword)) {
      hasSuspiciousKeyword = true;
    }
  });

  const keywordScore = hasSuspiciousKeyword ? 25 : 0;
  score += keywordScore;
  checklist.push({
    name: 'Misleading Domain Keywords',
    pass: !hasSuspiciousKeyword,
    desc: hasSuspiciousKeyword ? 'Suspicious keywords (e.g. login, payment) found in the domain.' : 'No deceptive brand hijacking terms detected.'
  });

  // Rule 4: Known Phishing Database Check (Known phishing +40)
  // Combine custom JSON domains list
  let inPhishingDb = false;
  
  // Check if hostname matches any malicious entry in local database
  // Also try to check reports stored dynamically in localStorage
  const reportedScams = window.QRShieldUtils ? window.QRShieldUtils.getScamReports() : [];
  const dynamicBlacklist = reportedScams.map(r => {
    try {
      return new URL(r.url.startsWith('http') ? r.url : 'http://' + r.url).hostname.toLowerCase();
    } catch(e) {
      return r.url.toLowerCase();
    }
  });

  const fullBlacklist = [...LOCAL_PHISHING_DOMAINS, ...dynamicBlacklist];
  
  inPhishingDb = fullBlacklist.some(badDomain => {
    return hostname === badDomain || hostname.endsWith('.' + badDomain) || urlString.toLowerCase().includes(badDomain);
  });

  const dbScore = inPhishingDb ? 40 : 0;
  score += dbScore;
  checklist.push({
    name: 'Database Threat Comparison',
    pass: !inPhishingDb,
    desc: inPhishingDb ? 'Matches a known malicious domain in the anti-phishing registry!' : 'No entries found in blacklisted databases.'
  });

  // Rule 5: Unknown/Untrusted Domain (+10)
  const isTrusted = TRUSTED_DOMAINS.some(trusted => hostname === trusted || hostname.endsWith('.' + trusted));
  const isWellKnown = isTrusted;
  // If it's short link or already in bad DB, it's not a trusted site
  const domainScore = (!isWellKnown && !isShortened) ? 10 : 0;
  score += domainScore;
  checklist.push({
    name: 'Trust Factor Evaluation',
    pass: isWellKnown || isShortened, // shorteners handle redirect, so we pass this test and penalize shortener instead
    desc: isWellKnown ? 'Known trusted web domain.' : 'Unrecognized or newly registered domain authority.'
  });

  // Clamping score between 0 and 100
  result.riskScore = Math.min(Math.max(score, 0), 100);
  result.checklist = checklist;
  
  result.details = {
    protocol: protocol.replace(':', '').toUpperCase(),
    domain: hostname,
    path: parsedUrl.pathname,
    params: parsedUrl.search
  };

  // Generate Simulated AI Explanation and Recommendation
  generateAIExplanationForURL(result, isHttps, isShortened, hasSuspiciousKeyword, inPhishingDb, !isWellKnown);
}

/**
 * Custom AI sentence compiler for scanned links.
 */
function generateAIExplanationForURL(result, isHttps, isShortened, hasSuspiciousKeyword, inPhishingDb, isUnknown) {
  let sentences = [];
  let recommendations = [];

  if (inPhishingDb) {
    sentences.push(`ALERT: The scanned URL redirects to a domain listed in our phishing threat register (${result.details.domain}).`);
    sentences.push("This domain has been confirmed as a spoofed portal designed to steal sensitive account login or payment information.");
    recommendations.push("DO NOT click this link under any circumstances.");
    recommendations.push("Report this QR to local cybersecurity agencies or flag it in our scam database.");
  } else {
    if (isShortened) {
      sentences.push("This QR code uses a URL shortening redirection service.");
      sentences.push("Attackers frequently deploy shortened links to mask their final malicious destination domains and bypass automated firewall checks.");
      recommendations.push("Exercise extreme caution. Expand this URL using safe lookup services or do not open it.");
    }
    
    if (hasSuspiciousKeyword) {
      sentences.push("The domain structure contains misleading brand keywords or terms associated with authentication and finance.");
      sentences.push("This visual pattern closely mimics official bank login, social media, or utility pages to trick users into typing in credentials.");
      recommendations.push("If you open this page, inspect the browser address bar closely. Never enter login passwords or payment credentials.");
    }

    if (!isHttps) {
      sentences.push("The link does not utilize HTTPS (SSL) encryption protocol.");
      sentences.push("Any information transmitted over this connection (passwords, card numbers, forms) is exposed in cleartext and can be intercepted by hackers.");
      recommendations.push("Avoid inputting any details on this site. Enter web forms only over secure HTTPS connections.");
    }
    
    if (isUnknown && !isShortened && !hasSuspiciousKeyword && isHttps) {
      sentences.push("This domain has a valid HTTPS certificate, but it is not listed in our register of popular trusted web properties.");
      sentences.push("While not immediately flagged as malicious, newly registered or obscure websites can serve as temporary hosting sites for script attacks.");
      recommendations.push("Proceed with caution. Verify the origin of the QR code before interacting with the page content.");
    }
  }

  if (sentences.length === 0) {
    result.aiExplanation = "This URL displays a clean security profile. It is served over a secure, encrypted connection (HTTPS) and does not trigger any signature matches in our local blacklist or keyword threat lists.";
    result.recommendation = "You can proceed to open the link. As a best practice, verify the web layout once loaded.";
  } else {
    result.aiExplanation = "AI analysis warns: " + sentences.join(" ") + " We recommend staying vigilant.";
    result.recommendation = recommendations.join(" ");
  }
}

/**
 * UPI QR Analyst. Parses payee details, merchant name, VPA format, and verifies merchant registries.
 */
function analyzeUPILink(upiString, result) {
  const checklist = [];
  let score = 0;
  
  // Extract parameters from upi://pay?pa=address&pn=name&am=amount
  const params = {};
  try {
    const urlParts = upiString.split('?');
    if (urlParts.length > 1) {
      const searchParams = new URLSearchParams(urlParts[1]);
      params.upiId = searchParams.get('pa') || '';
      params.merchantName = searchParams.get('pn') || 'Unknown Merchant';
      params.amount = searchParams.get('am') || 'N/A';
      params.transactionRef = searchParams.get('tr') || 'N/A';
    } else {
      params.upiId = 'Unknown Address';
      params.merchantName = 'Unknown Merchant';
      params.amount = 'N/A';
    }
  } catch(e) {
    params.upiId = 'Parsing Error';
    params.merchantName = 'Unknown Merchant';
    params.amount = 'N/A';
  }

  // Validate VPA address structure (must contain @)
  const isVpaValid = params.upiId.includes('@');
  if (!isVpaValid) {
    score += 40;
    checklist.push({
      name: 'UPI Address (VPA) Format',
      pass: false,
      desc: 'Invalid UPI address format. Could be a corrupted payment payload.'
    });
  } else {
    checklist.push({
      name: 'UPI Address (VPA) Format',
      pass: true,
      desc: 'UPI identifier is syntactically valid.'
    });
  }

  // Verify Merchant against Whitelist
  const normalizedMerchant = params.merchantName.toLowerCase();
  const isVerifiedMerchant = VERIFIED_UPI_MERCHANTS.some(m => normalizedMerchant.includes(m));
  
  if (isVerifiedMerchant) {
    checklist.push({
      name: 'Merchant Registry Verification',
      pass: true,
      desc: `Merchant "${params.merchantName}" is registered and verified in our database.`
    });
  } else {
    score += 30; // Unknown merchant warning
    checklist.push({
      name: 'Merchant Registry Verification',
      pass: false,
      desc: 'Unregistered merchant. This transaction is targeting an unverified peer account.'
    });
  }

  // Detect suspicious payment demands (e.g. forced large amounts)
  const amountVal = parseFloat(params.amount);
  const hasForcedAmount = !isNaN(amountVal) && amountVal > 0;
  if (hasForcedAmount) {
    if (amountVal > 2000) {
      score += 15;
      checklist.push({
        name: 'Auto-Filled Amount Warning',
        pass: false,
        desc: `Scan requests a prefilled amount of ₹${params.amount}. High amount alert!`
      });
    } else {
      checklist.push({
        name: 'Auto-Filled Amount Check',
        pass: true,
        desc: `Scan requests a prefilled amount of ₹${params.amount}. Verify before payment.`
      });
    }
  } else {
    checklist.push({
      name: 'Flexible Amount Scan',
      pass: true,
      desc: 'No automated transaction amount is being requested. Enter amount manually.'
    });
  }

  result.riskScore = Math.min(score, 100);
  result.checklist = checklist;
  result.details = params;
  
  if (result.riskScore <= 10) {
    result.aiExplanation = `Verified Merchant Payment QR: This QR is a payment request for "${params.merchantName}" (${params.upiId}). It matches a registered trusted merchant directory.`;
    result.recommendation = "Safe to pay. Confirm the payment screen details matches in your UPI application.";
  } else {
    result.aiExplanation = `Unverified Payment Target: This QR requests a payment of ₹${params.amount || 'any amount'} targeting VPA address "${params.upiId}". The receiver is listed as "${params.merchantName}", which is NOT a registered merchant and could be a personal account masquerading as a corporate store.`;
    result.recommendation = "Caution! Ensure you know the payee before entering your UPI PIN. UPI PIN is only required to SEND money, never to RECEIVE money.";
  }
}

/**
 * WiFi QR configuration checks.
 */
function analyzeWiFi(wifiString, result) {
  const checklist = [];
  const details = { ssid: 'Unknown', encryption: 'None', hidden: 'No' };
  
  // WiFi format: WIFI:S:SSID;T:WPA;P:PASSWORD;H:true;;
  try {
    const ssidMatch = wifiString.match(/S:([^;]+);/);
    const typeMatch = wifiString.match(/T:([^;]+);/);
    const hiddenMatch = wifiString.match(/H:([^;]+);/);
    
    if (ssidMatch) details.ssid = ssidMatch[1];
    if (typeMatch) details.encryption = typeMatch[1];
    if (hiddenMatch) details.hidden = hiddenMatch[1] === 'true' ? 'Yes' : 'No';
  } catch (e) {}

  checklist.push({
    name: 'Encryption Security',
    pass: details.encryption !== 'nopass' && details.encryption !== 'None',
    desc: details.encryption !== 'nopass' ? `Uses ${details.encryption} encryption.` : 'Unencrypted network configuration (Open WiFi).'
  });

  const isNoPassword = details.encryption === 'nopass' || details.encryption === 'None';
  result.riskScore = isNoPassword ? 40 : 10;
  result.checklist = checklist;
  result.details = details;
  
  if (isNoPassword) {
    result.aiExplanation = `This QR is configured to connect your device automatically to an open, unencrypted Wi-Fi hotspot named "${details.ssid}". Attackers often use open Wi-Fi networks to launch "Man-in-the-Middle" attacks to spy on your online activities.`;
    result.recommendation = "We advise against connecting to this network. If you must connect, use a secure VPN.";
  } else {
    result.aiExplanation = `This QR is configured to connect your device to an encrypted Wi-Fi network named "${details.ssid}" using ${details.encryption} credentials.`;
    result.recommendation = "You can safely scan to connect, provided you trust the location hosting this QR code.";
  }
}

/**
 * Email QR checks.
 */
function analyzeEmail(emailString, result) {
  // mailto:support@paypal-secure.xyz?subject=Verify&body=Click%20here
  let score = 10;
  const checklist = [];
  const details = { recipient: '', subject: '', body: '' };
  
  try {
    const raw = emailString.replace('mailto:', '');
    const parts = raw.split('?');
    details.recipient = parts[0];
    
    if (parts.length > 1) {
      const searchParams = new URLSearchParams(parts[1]);
      details.subject = searchParams.get('subject') || '';
      details.body = searchParams.get('body') || '';
    }
  } catch(e) {}

  // Check if email domain is suspicious
  const emailDomain = details.recipient.split('@')[1] || '';
  const isSuspiciousEmail = LOCAL_PHISHING_DOMAINS.some(d => emailDomain.includes(d)) || 
                             SUSPICIOUS_KEYWORDS.some(k => emailDomain.includes(k) && !TRUSTED_DOMAINS.some(t => emailDomain.endsWith(t)));
  
  if (isSuspiciousEmail) {
    score += 50;
    checklist.push({
      name: 'Recipient Address Verification',
      pass: false,
      desc: 'Recipient address domain looks suspicious or resembles a phishing entity.'
    });
  } else {
    checklist.push({
      name: 'Recipient Address Verification',
      pass: true,
      desc: 'Recipient domain appears normal.'
    });
  }

  result.riskScore = score;
  result.checklist = checklist;
  result.details = details;
  
  if (score > 30) {
    result.aiExplanation = `Suspicious Email Target: This QR automates composing an email to "${details.recipient}". The destination address triggers a keyword alert or domain matches a known phishing site. Attackers use this to send automated confirmation templates.`;
    result.recommendation = "Do not send this email. It could verify your account existence or trigger a password reset attempt.";
  } else {
    result.aiExplanation = `Email Composer: This QR will open your email client to send a message to "${details.recipient}".`;
    result.recommendation = "Review the subject and body text in your email client before sending to ensure no sensitive details are exposed.";
  }
}

/**
 * Phone number QR config.
 */
function analyzePhone(phoneString, result) {
  const number = phoneString.replace('tel:', '');
  const isPremiumNumber = number.startsWith('+99') || number.startsWith('1900') || number.length < 5;
  
  result.riskScore = isPremiumNumber ? 30 : 10;
  result.details = { phoneNumber: number };
  result.checklist = [{
    name: 'Premium Toll Number Check',
    pass: !isPremiumNumber,
    desc: isPremiumNumber ? 'High-rate premium dialing prefix detected.' : 'Standard phone layout.'
  }];
  
  if (isPremiumNumber) {
    result.aiExplanation = `Toll Dialing Alert: This QR triggers a call dialer to "${number}". It contains prefixes associated with high-toll services or premium services that can charge you excessive fees.`;
    result.recommendation = "Do not initiate this call. Check if this is an official contact number first.";
  } else {
    result.aiExplanation = `Phone Dialer: This QR prompts you to call standard phone number "${number}".`;
    result.recommendation = "Safe to load in your phone dialer. Verify the contact person before making the call.";
  }
}

/**
 * SMS configuration checker.
 */
function analyzeSMS(smsString, result) {
  // sms:number?body=msg
  const details = { recipient: '', message: '' };
  try {
    const raw = smsString.replace(/sms(to)?:/i, '');
    const parts = raw.split('?');
    details.recipient = parts[0];
    
    if (parts.length > 1) {
      const searchParams = new URLSearchParams(parts[1]);
      details.message = searchParams.get('body') || '';
    }
  } catch(e) {}

  const isPremium = details.recipient.length < 6;
  const triggersAction = details.message.toLowerCase().includes('yes') || details.message.toLowerCase().includes('confirm') || details.message.toLowerCase().includes('otp');
  
  const score = (isPremium ? 20 : 10) + (triggersAction ? 20 : 0);
  
  result.riskScore = score;
  result.details = details;
  result.checklist = [
    {
      name: 'Shortcode Target Check',
      pass: !isPremium,
      desc: isPremium ? 'Targets a shortcode billing number.' : 'Targets standard phone contact.'
    },
    {
      name: 'Trigger Word Detection',
      pass: !triggersAction,
      desc: triggersAction ? 'Message attempts to send sensitive confirmation keywords (e.g. YES, OTP).' : 'Standard message body text.'
    }
  ];

  if (score >= 30) {
    result.aiExplanation = `Automated SMS Verification: This QR triggers a pre-filled SMS message text "${details.message}" sending to code "${details.recipient}". This is often used to subscribe you to paid services or confirm account hijacking attempts.`;
    result.recommendation = "Do not send this message. It could authenticate unsolicited subscriptions or actions.";
  } else {
    result.aiExplanation = `SMS Composer: This QR drafts a text to "${details.recipient}".`;
    result.recommendation = "Read and verify the message contents before hitting send.";
  }
}

/**
 * Contact card (VCard) structure scanner.
 */
function analyzeContact(contactString, result) {
  const details = { name: 'Unknown Contact', phone: 'N/A', url: '' };
  const checklist = [];
  
  try {
    const nameMatch = contactString.match(/FN:([^\n\r]+)/);
    const phoneMatch = contactString.match(/TEL[^\:]*\:([^\n\r]+)/);
    const urlMatch = contactString.match(/URL[^\:]*\:([^\n\r]+)/);
    
    if (nameMatch) details.name = nameMatch[1];
    if (phoneMatch) details.phone = phoneMatch[1];
    if (urlMatch) details.url = urlMatch[1];
  } catch(e) {}

  let score = 10;
  
  if (details.url) {
    // If contact contains URL, we analyze the URL!
    const subResult = { riskScore: 0, checklist: [] };
    let checkUrl = details.url;
    if (!/^https?:\/\//i.test(checkUrl)) checkUrl = 'http://' + checkUrl;
    
    analyzeURL(checkUrl, subResult);
    score += subResult.riskScore * 0.7; // Weigh URL threat in contact card heavily
    
    checklist.push({
      name: 'Embedded URL Security',
      pass: subResult.riskScore <= 30,
      desc: subResult.riskScore > 30 ? `Embedded contact website looks highly suspicious: ${details.url}` : `Contains safe-looking website: ${details.url}`
    });
  } else {
    checklist.push({
      name: 'Embedded Link Check',
      pass: true,
      desc: 'No hidden website URLs embedded in the contact card.'
    });
  }

  result.riskScore = Math.min(Math.round(score), 100);
  result.checklist = checklist;
  result.details = details;

  if (result.riskScore >= 40) {
    result.aiExplanation = `Suspicious Contact Card: Card imports a contact named "${details.name}" with phone "${details.phone}", but it embeds a suspicious web URL link "${details.url}". Spammers use this to preload bad links into address books.`;
    result.recommendation = "Do not save this contact, and do not click the embedded link.";
  } else {
    result.aiExplanation = `Contact Card Import: Card imports details for "${details.name}" with phone number "${details.phone}".`;
    result.recommendation = "You can safely save this contact card.";
  }
}

// Export functions to global scope
window.QRShieldAnalysis = {
  analyzeQRContent
};
