const axios = require('axios');

/**
 * Google Safe Browsing Lookup Integration
 * Checks URLs against the Google Safe Browsing list of threats.
 */
async function checkUrl(url, retryCount = 1) {
  const apiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;

  // Sandbox Mode Fallback
  if (!apiKey) {
    console.log('[Safe Browsing] No API key detected. Running in Sandbox Fallback Mode.');
    const normalized = url.toLowerCase();
    const isMockThreat = normalized.includes('phish') || 
                         normalized.includes('malware') || 
                         normalized.includes('fakebank') || 
                         normalized.includes('verification') || 
                         normalized.includes('secure-login') ||
                         normalized.includes('xyz') ||
                         normalized.includes('giveaway');

    if (isMockThreat) {
      return {
        isSafe: false,
        threatType: normalized.includes('malware') ? 'MALWARE' : 'SOCIAL_ENGINEERING',
        matches: [{
          threatType: normalized.includes('malware') ? 'MALWARE' : 'SOCIAL_ENGINEERING',
          platformType: 'ANY_PLATFORM',
          threatEntryType: 'URL',
          threat: { url }
        }]
      };
    }

    return { isSafe: true, threatType: 'Safe', matches: [] };
  }

  // Live Mode API Request
  const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`;
  const requestBody = {
    client: {
      clientId: 'qr-shield-ai',
      clientVersion: '1.0.0'
    },
    threatInfo: {
      threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
      platformTypes: ['ANY_PLATFORM'],
      threatEntryTypes: ['URL'],
      threatEntries: [{ url }]
    }
  };

  try {
    const response = await axios.post(endpoint, requestBody, { timeout: 4000 });
    const matches = response.data.matches;

    if (matches && matches.length > 0) {
      return {
        isSafe: false,
        threatType: matches[0].threatType, // e.g. MALWARE, SOCIAL_ENGINEERING
        matches: matches
      };
    }

    return { isSafe: true, threatType: 'Safe', matches: [] };
  } catch (error) {
    console.error(`[Safe Browsing] API query failed (retries left: ${retryCount}):`, error.message);
    if (retryCount > 0) {
      return await checkUrl(url, retryCount - 1);
    }
    // Fail safe to database metrics or return error status
    return { isSafe: true, threatType: 'Safe', error: error.message, matches: [] };
  }
}

module.exports = { checkUrl };
