module.exports = (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({
      success: false,
      message: 'Access denied. User session not authenticated.'
    });
  }

  const role = req.user.role;
  
  // Allow access only to Admin and Police roles
  if (role === 'Admin' || role === 'Police') {
    next();
  } else {
    return res.status(403).json({
      success: false,
      message: 'Forbidden. You do not have permission to access administrative resources.'
    });
  }
};
