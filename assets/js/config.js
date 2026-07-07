// Central Frontend API Configuration for QR Shield AI
const API_BASE_URL = (function() {
  const host = window.location.hostname;
  const isLocal = host === 'localhost' || host === '127.0.0.1' || host.startsWith('192.168.');
  
  if (isLocal) {
    return 'http://localhost:5000';
  } else {
    return 'https://qrsheildai.onrender.com';
  }
})();

console.log(`[QR Shield Config] API Base URL configured as: ${API_BASE_URL}`);
