/**
 * QR Shield AI - Client Offline Fallback Parser
 * Provides parsing for QR types and lightweight heuristics when backend API is unreachable.
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
    aiExplanation: 'The system is operating in local fallback mode because the threat intelligence API is unreachable.',
    recommendation: 'Verify the payload details manually before proceeding.'
  };

  // Determine QR type and call corresponding sub-analyst
  if (trimmed.startsWith('upi://pay')) {
    result.type = 'UPI';
    parseOfflineUPI(trimmed, result);
  } else if (/^https?:\/\//i.test(trimmed) || /^[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}(:[0-9]{1,5})?(\/.*)?$/i.test(trimmed)) {
    result.type = 'Website';
    parseOfflineURL(trimmed, result);
  } else if (trimmed.startsWith('WIFI:')) {
    result.type = 'WiFi';
    parseOfflineWiFi(trimmed, result);
  } else if (trimmed.startsWith('mailto:')) {
    result.type = 'Email';
    parseOfflineEmail(trimmed, result);
  } else if (trimmed.startsWith('tel:')) {
    result.type = 'Phone';
    parseOfflinePhone(trimmed, result);
  } else if (trimmed.startsWith('sms:') || trimmed.startsWith('smsto:')) {
    result.type = 'SMS';
    parseOfflineSMS(trimmed, result);
  } else if (trimmed.startsWith('BEGIN:VCARD')) {
    result.type = 'Contact';
    parseOfflineContact(trimmed, result);
  } else {
    // Plain text or Raw UPI VPA
    if (trimmed.includes('@') && !trimmed.includes(' ')) {
      if (trimmed.toLowerCase().includes('upi') || trimmed.toLowerCase().includes('ybl') || trimmed.toLowerCase().includes('okaxis')) {
        result.type = 'UPI';
        result.details = { upiId: trimmed, merchantName: 'Unknown entity', amount: 'N/A' };
        result.riskScore = 25;
        result.riskLevel = 'Medium';
        result.aiExplanation = "This contains a raw UPI address. Transferring funds directly is unverified.";
      }
    }
  }

  // Adjust Risk Level mapping
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

function parseOfflineURL(urlString, result) {
  let score = 0;
  let parsedUrl;
  let target = urlString;

  if (!/^https?:\/\//i.test(target)) {
    target = 'http://' + target;
  }

  try {
    parsedUrl = new URL(target);
  } catch (e) {
    result.riskScore = 50;
    result.riskLevel = 'Suspicious';
    result.aiExplanation = "The URL syntax is malformed, preventing full inspection.";
    return;
  }

  const hostname = parsedUrl.hostname.toLowerCase();
  const protocol = parsedUrl.protocol.toLowerCase();
  const checklist = [];

  // Insecure protocol check
  const isHttps = protocol === 'https:';
  score += isHttps ? 0 : 20;
  checklist.push({
    name: 'HTTPS Encrypted Link',
    pass: isHttps,
    desc: isHttps ? 'Connection is secure and encrypted.' : 'Connection lacks SSL encryption.'
  });

  // Short URL heuristic (simple string lengths check)
  const isShortDomain = hostname.length < 8;
  score += isShortDomain ? 10 : 0;
  checklist.push({
    name: 'Shortened Domain Check',
    pass: !isShortDomain,
    desc: isShortDomain ? 'Extremely short domain detected (often used for link masking).' : 'Domain has standard structure length.'
  });

  result.riskScore = score;
  result.checklist = checklist;
  result.details = {
    protocol: protocol.replace(':', '').toUpperCase(),
    domain: hostname,
    path: parsedUrl.pathname
  };

  result.aiExplanation = `Local parsed link details: The URL points to "${hostname}" using ${protocol.replace(':', '').toUpperCase()} connection. Live cloud database checks are offline.`;
  result.recommendation = isHttps ? "Proceed with caution. Verify the domain looks correct in your browser." : "Insecure link. Do not enter any login credentials.";
}

function parseOfflineUPI(upiString, result) {
  const checklist = [];
  let score = 15;
  const params = { upiId: 'Unknown', merchantName: 'Unknown', amount: 'N/A' };

  try {
    const urlParts = upiString.split('?');
    if (urlParts.length > 1) {
      const searchParams = new URLSearchParams(urlParts[1]);
      params.upiId = searchParams.get('pa') || 'Unknown';
      params.merchantName = searchParams.get('pn') || 'Unknown Payee';
      params.amount = searchParams.get('am') || 'N/A';
    }
  } catch (e) {}

  const hasAt = params.upiId.includes('@');
  if (!hasAt) score += 30;

  checklist.push({
    name: 'UPI Address Format',
    pass: hasAt,
    desc: hasAt ? 'UPI identifier structure is valid.' : 'Invalid payment address.'
  });

  result.riskScore = score;
  result.checklist = checklist;
  result.details = params;
  result.aiExplanation = `UPI payment target: Address "${params.upiId}" for entity "${params.merchantName}".`;
  result.recommendation = "Always check the recipient name in your payment app before entering your UPI PIN.";
}

function parseOfflineWiFi(wifiString, result) {
  const details = { ssid: 'Unknown', encryption: 'None' };
  try {
    const ssidMatch = wifiString.match(/S:([^;]+);/);
    const typeMatch = wifiString.match(/T:([^;]+);/);
    if (ssidMatch) details.ssid = ssidMatch[1];
    if (typeMatch) details.encryption = typeMatch[1];
  } catch (e) {}

  const isNoPass = details.encryption === 'nopass' || details.encryption === 'None';
  result.riskScore = isNoPass ? 30 : 5;
  result.details = details;
  result.checklist = [{
    name: 'Encrypted network',
    pass: !isNoPass,
    desc: isNoPass ? 'Unencrypted public hotspot configuration.' : 'Requires network authentication credentials.'
  }];
  result.aiExplanation = `WiFi configuration: SSID: "${details.ssid}". Encryption: ${details.encryption}.`;
  result.recommendation = isNoPass ? "Open Wi-Fi networks can expose data. Avoid online banking over this link." : "Safe connection profiles.";
}

function parseOfflineEmail(emailString, result) {
  const details = { recipient: '' };
  try {
    details.recipient = emailString.replace('mailto:', '').split('?')[0];
  } catch (e) {}

  result.riskScore = 10;
  result.details = details;
  result.checklist = [{
    name: 'Standard Format',
    pass: true,
    desc: 'Triggers local email application.'
  }];
  result.aiExplanation = `Automates email composer to "${details.recipient}".`;
  result.recommendation = "Verify the recipient address before typing or sending messages.";
}

function parseOfflinePhone(phoneString, result) {
  const number = phoneString.replace('tel:', '');
  const isPremium = number.startsWith('+99') || number.length < 5;
  result.riskScore = isPremium ? 25 : 5;
  result.details = { phoneNumber: number };
  result.checklist = [{
    name: 'Standard Toll Check',
    pass: !isPremium,
    desc: isPremium ? 'Targets unverified premium-rate toll dialer.' : 'Standard phone format.'
  }];
  result.aiExplanation = `Automates dialing phone number "${number}".`;
  result.recommendation = "Verify call identity before dialing.";
}

function parseOfflineSMS(smsString, result) {
  const details = { recipient: '', message: '' };
  try {
    const parts = smsString.replace(/sms(to)?:/i, '').split('?');
    details.recipient = parts[0];
    if (parts.length > 1) {
      details.message = new URLSearchParams(parts[1]).get('body') || '';
    }
  } catch (e) {}

  result.riskScore = 15;
  result.details = details;
  result.checklist = [{
    name: 'SMS configuration',
    pass: true,
    desc: 'Targets standard cell carrier number.'
  }];
  result.aiExplanation = `Drafts text message content to "${details.recipient}".`;
  result.recommendation = "Do not share passwords, account verification numbers, or codes in prefilled SMS drafts.";
}

function parseOfflineContact(contactString, result) {
  const details = { name: 'Unknown', phone: 'N/A' };
  try {
    const fn = contactString.match(/FN:([^\n\r]+)/);
    const tel = contactString.match(/TEL[^\:]*\:([^\n\r]+)/);
    if (fn) details.name = fn[1];
    if (tel) details.phone = tel[1];
  } catch (e) {}

  result.riskScore = 5;
  result.details = details;
  result.checklist = [{
    name: 'Contact Format',
    pass: true,
    desc: 'Valid vCard structure.'
  }];
  result.aiExplanation = `Import contact card for "${details.name}" (${details.phone}).`;
  result.recommendation = "You can safely save this address card details to your local device.";
}

window.QRShieldAnalysis = {
  analyzeQRContent
};
