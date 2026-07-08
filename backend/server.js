const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const dotenv = require('dotenv');

// Load environment variables
dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

// ==========================================
// 1. Security Middlewares
// ==========================================
app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: true,
    directives: {
      "script-src": ["'self'", "'unsafe-inline'", "https://unpkg.com"],
      "connect-src": ["'self'", "https://identitytoolkit.googleapis.com", "*"],
      "img-src": ["'self'", "data:", "https://images.unsplash.com", "https://storage.googleapis.com", "*"]
    }
  },
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));



const allowedOrigins = [
  'http://127.0.0.1:5500',
  'http://localhost:5500',
  'https://qr-shield-ai.vercel.app'
];

app.use(cors({
  origin: (origin, callback) => {
    const accepted = !origin || allowedOrigins.includes(origin);
    console.log(`[DIAGNOSTIC] CORS_CHECK - Origin: ${origin || 'null'} - Accepted: ${accepted}`);
    
    if (accepted) {
      return callback(null, true);
    }

    console.error('[CORS] Blocked origin:', origin);
    return callback(new Error('Not allowed by CORS'));
  },
  credentials: true
}));

// Rate Limiting to prevent brute-force attacks and abuse
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 200, // Limit each IP to 200 requests per windowMs
  message: {
    success: false,
    message: 'Too many requests from this IP. Please try again after 15 minutes.'
  },
  standardHeaders: true,
  legacyHeaders: false,
});
app.use('/api/', limiter);
app.use('/auth/', limiter);

// Request parsing - increase payload limits for base64 screenshot uploads
app.use(express.json({ limit: '15mb' }));
app.use(express.urlencoded({ extended: true, limit: '15mb' }));
app.use(express.text({ type: 'text/plain', limit: '15mb' }));

// ==========================================
// 2. Logging Middleware
// ==========================================
app.use((req, res, next) => {
  const timestamp = new Date().toISOString();
  
  // Lifecycle logging for diagnostic paths and scan route
  const path = req.path;
  if (path === '/api/health' || path === '/api/echo' || path === '/scan') {
    console.log(`[DIAGNOSTIC] REQUEST_RECEIVED
Method: ${req.method}
Path: ${req.path}
Origin: ${req.headers.origin || 'null'}
Content-Type: ${req.headers['content-type'] || 'null'}
User-Agent: ${req.headers['user-agent'] || 'null'}
X-Forwarded-For: ${req.headers['x-forwarded-for'] || 'null'}
Timestamp: ${timestamp}`);
  }

  console.log(`[REQUEST] ${timestamp} - ${req.method} ${req.url} - IP: ${req.ip}`);
  
  // Hook response finish to log security events
  res.on('finish', () => {
    if (res.statusCode >= 400) {
      console.warn(`[SECURITY EVENT] ${timestamp} - Request Failed: ${req.method} ${req.url} - Status: ${res.statusCode}`);
    }
  });
  
  next();
});

// ==========================================
// 3. API Routes Mounting
// ==========================================
const authRoutes = require('./routes/authRoutes');
const scanRoutes = require('./routes/scanRoutes');
const reportRoutes = require('./routes/reportRoutes');
const adminRoutes = require('./routes/adminRoutes');

// Health Endpoint (public)
app.get('/health', (req, res) => {
  res.status(200).json({
    success: true,
    service: "QR Shield AI Backend",
    status: "healthy"
  });
});

// Diagnostic GET /api/health
app.get('/api/health', (req, res) => {
  const timestamp = new Date().toISOString();
  const origin = req.headers.origin || null;
  res.status(200).json({
    success: true,
    service: "qr-shield-backend",
    timestamp,
    origin
  });
});

// Diagnostic POST /api/echo
app.post('/api/echo', (req, res) => {
  const origin = req.headers.origin || null;
  res.status(200).json({
    success: true,
    body: req.body,
    origin,
    contentType: req.headers['content-type'] || null
  });
});

// Mount routes directly at root level as specified in REST API specifications
app.use(authRoutes);
app.use(scanRoutes);
app.use(reportRoutes);
app.use(adminRoutes);

// ==========================================
// 4. Static Frontend Assets Serving
// ==========================================
// Serve the static frontend folder (parent directory of backend)
const frontendPath = path.join(__dirname, '../');
app.use(express.static(frontendPath));

// Fallback for HTML routing
app.get('*', (req, res, next) => {
  // If request is for an API path, pass it through (will hit 404 handler)
  if (req.url.startsWith('/auth/') || req.url.startsWith('/user/') || req.url.startsWith('/scan') || req.url.startsWith('/report') || req.url.startsWith('/admin/')) {
    return next();
  }
  
  // Serve the index.html or requested static file
  res.sendFile(path.join(frontendPath, 'index.html'));
});

// ==========================================
// 5. Centralized Error Handling & 404s
// ==========================================

// Handle undefined REST API paths
app.use((req, res, next) => {
  res.status(404).json({
    success: false,
    message: `API endpoint '${req.originalUrl}' not found.`
  });
});

// Global Centralized Error Handling Middleware
app.use((err, req, res, next) => {
  const timestamp = new Date().toISOString();
  console.error(`[ERROR] ${timestamp} - Internal Server Error:`, err.stack);
  
  res.status(err.status || 500).json({
    success: false,
    message: err.message || 'An unexpected server error occurred.',
    error: process.env.NODE_ENV === 'development' ? err.stack : undefined
  });
});

const serverInstance = app.listen(PORT, () => {
  console.log(`==================================================`);
  console.log(`🛡 QR Shield AI - Backend Live at http://localhost:${PORT}`);
  console.log(`==================================================`);
});

module.exports = { app, server: serverInstance };
