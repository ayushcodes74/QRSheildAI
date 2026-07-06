const jwt = require('jsonwebtoken');

module.exports = (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        success: false,
        message: 'Access denied. No authorization token provided.'
      });
    }

    const token = authHeader.split(' ')[1];
    
    // Verify the JWT token
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'qr_shield_secret_key_2026_demo_key');
    
    // Attach decoded user info to the request object
    req.user = {
      uid: decoded.uid,
      email: decoded.email,
      role: decoded.role || 'User'
    };

    next();
  } catch (error) {
    console.error('[-] JWT validation error:', error.message);
    
    // Return unauthorized status if token is expired or invalid
    const message = error.name === 'TokenExpiredError' 
      ? 'Session expired. Please log in again.' 
      : 'Session verification failed. Invalid token.';
      
    return res.status(401).json({
      success: false,
      message
    });
  }
};
