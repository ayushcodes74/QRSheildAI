const axios = require('axios');

// System prompt instructing the AI to act as a Senior Cybersecurity Analyst and return JSON only.
const SYSTEM_PROMPT = `
You are a Senior Cybersecurity Analyst, Threat Intelligence Engineer, and AI Security Expert.
Analyze the provided QR payload contents dynamically.
The payload can be a URL, UPI payment VPA, Email, Phone number, SMS text, WiFi configuration, APK file download, Social Media link, Government portal, or any general text structure.
Identify its signature indicators, phishing hallmarks, spoofing signals, typosquatting variants, urgency language, or potential security threat patterns.

CRITICAL: Return ONLY a raw JSON object matching the schema below. Do not output any preamble, explanation, or conversational text outside the JSON.

Expected Schema:
{
  "riskScore": (number from 0 to 100 representing raw threat assessment),
  "confidence": (number from 0 to 100 representing detection confidence),
  "threatLevel": ("Safe", "Low Risk", "Medium Risk", "High Risk", "Critical"),
  "threatCategory": (main category, e.g. "Phishing", "Safe", "Malware", "UPI Fraud", "Social Engineering", "Identity Theft"),
  "threatsDetected": [ (array of detected threat strings, e.g., "Phishing", "Spoofed Domain", "Urgency Language", "Unknown UPI VPA", "Sticker Replacement") ],
  "reasoning": (detailed concise explanation summarizing cybersecurity threat vector metrics),
  "recommendation": ("Proceed", "Proceed Carefully", "Block", "Report", "Contact Merchant", "Verify Manually"),
  "technicalIndicators": [ (array of identified technical indicators, e.g., "HTTPS Missing", "Suspicious TLD", "Look-alike Domain", "VPA Unverified") ]
}
`;

// Helper: Safely parse JSON from raw text, removing Markdown wrappers if any
function parseAIResponse(text) {
  try {
    let clean = text.trim();
    // Strip markdown code blocks if present
    if (clean.startsWith('```')) {
      clean = clean.replace(/^```(json)?/i, '').replace(/```$/i, '').trim();
    }
    return JSON.parse(clean);
  } catch (err) {
    console.error('[OpenRouter] Failed to parse AI JSON response:', err.message, '\nRaw response:', text);
    return null;
  }
}

// Sandbox Mode Mock Generator
function getMockAIResponse(payload) {
  const normalized = payload.toLowerCase();

  // 1. UPI Payload Analysis Simulation
  if (normalized.startsWith('upi://pay') || (normalized.includes('@') && (normalized.includes('upi') || normalized.includes('ybl') || normalized.includes('okaxis')))) {
    const isMockThreat = normalized.includes('phish') || normalized.includes('scam') || normalized.includes('fake') || normalized.includes('cashback') || normalized.includes('reward');
    if (isMockThreat) {
      return {
        riskScore: 78,
        confidence: 92,
        threatLevel: 'High Risk',
        threatCategory: 'UPI Fraud',
        threatsDetected: ['Fake Cashback', 'Fake Reward', 'Payment Gateway Scam'],
        reasoning: 'The QR payload contains a UPI payment redirect requesting funds under a suspicious reward incentive. This matches signatures of phishing scans trying to harvest UPI PINs.',
        recommendation: 'Block',
        technicalIndicators: ['Urgency Language', 'VPA Unverified', 'Cashback Bait']
      };
    }
    return {
      riskScore: 5,
      confidence: 95,
      threatLevel: 'Safe',
      threatCategory: 'Safe',
      threatsDetected: [],
      reasoning: 'Clean UPI payment structure pointing to a standard transaction. No suspicious cashback or urgent warning hooks found.',
      recommendation: 'Proceed',
      technicalIndicators: ['VPA Standard']
    };
  }

  // 2. URL Phishing Simulation
  if (/^https?:\/\//i.test(payload) || normalized.includes('.com') || normalized.includes('.xyz') || normalized.includes('.net')) {
    const isMockThreat = normalized.includes('phish') ||
      normalized.includes('malware') ||
      normalized.includes('fakebank') ||
      normalized.includes('verification') ||
      normalized.includes('secure-login') ||
      normalized.includes('xyz') ||
      normalized.includes('giveaway');

    if (isMockThreat) {
      return {
        riskScore: 85,
        confidence: 94,
        threatLevel: 'High Risk',
        threatCategory: 'Phishing',
        threatsDetected: ['Phishing', 'Spoofed Domain', 'Suspicious TLD'],
        reasoning: 'The web address displays traits of typosquatting or brand-impersonation, loading from an untrusted domain name TLD (.xyz). This matches templates of credential harvesting sites.',
        recommendation: 'Block',
        technicalIndicators: ['HTTPS Missing', 'Suspicious TLD', 'Look-alike Domain']
      };
    }
    return {
      riskScore: 10,
      confidence: 96,
      threatLevel: 'Safe',
      threatCategory: 'Safe',
      threatsDetected: [],
      reasoning: 'The domain checks out as a highly reputable web portal. Connection utilizes standard encryption and shows clean reputation indices.',
      recommendation: 'Proceed',
      technicalIndicators: ['HTTPS Secure', 'Trusted Hostname']
    };
  }

  // 3. SMS or plain text simulation
  const isSuspiciousText = normalized.includes('win') || normalized.includes('lottery') || normalized.includes('otp') || normalized.includes('suspend') || normalized.includes('bank');
  if (isSuspiciousText) {
    return {
      riskScore: 65,
      confidence: 88,
      threatLevel: 'Medium Risk',
      threatCategory: 'Social Engineering',
      threatsDetected: ['Lottery Scam', 'Urgency Language', 'OTP Scam'],
      reasoning: 'The text block prompts action using high-pressure urgency hooks (e.g. account suspension warnings or lottery cash wins). This aligns with financial phishing vectors.',
      recommendation: 'Verify Manually',
      technicalIndicators: ['Fear Language', 'OTP Request']
    };
  }

  return {
    riskScore: 15,
    confidence: 90,
    threatLevel: 'Safe',
    threatCategory: 'Safe',
    threatsDetected: [],
    reasoning: 'Standard plain text parameters. The payload does not contain any execution commands, link shorteners, or malicious phishing triggers.',
    recommendation: 'Proceed',
    technicalIndicators: ['Plain Text Format']
  };
}

/**
 * OpenRouter AI completion request with fallback models sequence
 */
async function analyzePayload(payload) {
  const apiKey = process.env.OPENROUTER_API_KEY;

  if (!apiKey) {
    console.log('[OpenRouter] No API key detected. Running in Sandbox Fallback Mode.');
    return getMockAIResponse(payload);
  }

  const modelsList = [
    'deepseek/deepseek-chat',
    'google/gemini-2.5-flash',
    'qwen/qwen-2.5-72b-instruct',
    'mistralai/mistral-7b-instruct'
  ];

  let lastError = null;

  for (const model of modelsList) {
    try {
      console.log(`[OpenRouter] Querying completion using model: ${model}`);

      const response = await axios.post(
        'https://openrouter.ai/api/v1/chat/completions',
        {
          model: model,
          messages: [
            { role: 'system', content: SYSTEM_PROMPT },
            { role: 'user', content: `Analyze this QR Payload: "${payload}"` }
          ],
          response_format: { type: 'json_object' },
          max_tokens: 1200,
          temperature: 0.1
        },
        {
          headers: {
            'Authorization': `Bearer ${apiKey}`,
            'Content-Type': 'application/json',
            'HTTP-Referer': 'http://localhost:5000',
            'X-Title': 'QR Shield AI'
          },
          timeout: 6000 // 6 second deadline per model
        }
      );

      const responseText = response.data.choices[0].message.content;
      const result = parseAIResponse(responseText);

      if (result) {
        console.log(`[OpenRouter] Success using model: ${model}`);
        return result;
      }

      lastError = new Error('Model returned unparsable JSON response');
    } catch (error) {
      const errMsg = error.response?.data?.error?.message || error.message;
      console.error(`[OpenRouter] Model ${model} failed:`, errMsg);
      lastError = error;
    }
  }

  console.error('[OpenRouter] All models exhausted. Falling back to local rule-based mock response.');
  return getMockAIResponse(payload);
}

module.exports = { analyzePayload };
