const axios = require('axios');

/**
 * VirusTotal API v3 Integration
 * Queries URL details to count malicious, suspicious, and harmless vendor classifications.
 */
async function checkUrl(url, retryCount = 1) {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;

  // Sandbox Mode Fallback
  if (!apiKey) {
    console.log('[VirusTotal] No API key detected. Running in Sandbox Fallback Mode.');
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
        malicious: 5,
        suspicious: 2,
        harmless: 65,
        undetected: 15,
        ratio: '5/72'
      };
    }

    return {
      malicious: 0,
      suspicious: 0,
      harmless: 72,
      undetected: 15,
      ratio: '0/72'
    };
  }

  // Base64 encode the URL (VT URL identifier format: base64 without padding)
  const urlId = Buffer.from(url)
    .toString('base64')
    .replace(/=/g, '');

  const endpoint = `https://www.virustotal.com/api/v3/urls/${urlId}`;
  
  try {
    const response = await axios.get(endpoint, {
      headers: { 'x-apikey': apiKey },
      timeout: 4000
    });

    const stats = response.data.data.attributes.last_analysis_stats;
    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;
    const harmless = stats.harmless || 0;
    const undetected = stats.undetected || 0;
    const total = malicious + suspicious + harmless + undetected;

    return {
      malicious,
      suspicious,
      harmless,
      undetected,
      ratio: `${malicious}/${total}`
    };
  } catch (error) {
    // If the URL has not been scanned yet, VT might return a 404. 
    // In that case, we fall back to domain check which is highly reliable, or submit it.
    if (error.response && error.response.status === 404) {
      try {
        const domain = new URL(url).hostname;
        const domainEndpoint = `https://www.virustotal.com/api/v3/domains/${domain}`;
        const domResponse = await axios.get(domainEndpoint, {
          headers: { 'x-apikey': apiKey },
          timeout: 4000
        });

        const stats = domResponse.data.data.attributes.last_analysis_stats;
        const malicious = stats.malicious || 0;
        const suspicious = stats.suspicious || 0;
        const harmless = stats.harmless || 0;
        const undetected = stats.undetected || 0;
        const total = malicious + suspicious + harmless + undetected;

        return {
          malicious,
          suspicious,
          harmless,
          undetected,
          ratio: `${malicious}/${total}`
        };
      } catch (domErr) {
        console.error('[VirusTotal] Domain fallback query failed:', domErr.message);
      }
    }

    console.error(`[VirusTotal] API query failed (retries left: ${retryCount}):`, error.message);
    if (retryCount > 0) {
      return await checkUrl(url, retryCount - 1);
    }

    return {
      malicious: 0,
      suspicious: 0,
      harmless: 0,
      undetected: 0,
      ratio: '0/0',
      error: error.message
    };
  }
}

module.exports = { checkUrl };
