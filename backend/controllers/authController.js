const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const axios = require('axios');
const { auth, db, isSandbox } = require('../config/firebase');
const sandboxDb = require('../services/sandboxDb');

// Helper: Generate Custom JWT Token
const generateToken = (uid, email, role) => {
  return jwt.sign(
    { uid, email, role },
    process.env.JWT_SECRET || 'qr_shield_secret_key_2026_demo_key',
    { expiresIn: '7d' }
  );
};

// Helper: Determine User Role on Signup based on email
const determineRole = (email) => {
  const normalized = email.toLowerCase();
  if (normalized.includes('admin@') || normalized.includes('admin')) {
    return 'Admin';
  } else if (normalized.includes('police@') || normalized.includes('police')) {
    return 'Police';
  }
  return 'User';
};

// POST /auth/signup
exports.signup = async (req, res, next) => {
  try {
    const { name, email, password, photo } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ success: false, message: 'Name, email, and password are required.' });
    }

    const role = determineRole(email);

    if (isSandbox) {
      // Sandbox Mode Signup
      const emailExists = sandboxDb.users.some(u => u.email.toLowerCase() === email.toLowerCase());
      if (emailExists) {
        return res.status(400).json({ success: false, message: 'Email address already registered.' });
      }

      const uid = 'mock-uid-' + Date.now();
      const passwordHash = await bcrypt.hash(password, 10);
      const newUser = {
        uid,
        name,
        email,
        passwordHash,
        photo: photo || 'https://images.unsplash.com/photo-1535713875002-d1d0cf377fde?w=150',
        role,
        createdAt: new Date().toISOString(),
        lastLogin: new Date().toISOString()
      };

      sandboxDb.users.push(newUser);
      
      // Seed to admins or police collections in sandbox if role matches
      if (role === 'Admin') sandboxDb.admins.push({ uid, email });
      if (role === 'Police') sandboxDb.police.push({ uid, email });

      const token = generateToken(uid, email, role);

      return res.status(201).json({
        success: true,
        message: 'Signup successful (Sandbox Mode)',
        token,
        user: { uid, name, email, photo: newUser.photo, role }
      });
    } else {
      // Real Firebase Mode Signup
      try {
        const userRecord = await auth.createUser({
          email,
          password,
          displayName: name,
          photoURL: photo || null
        });

        const userDoc = {
          uid: userRecord.uid,
          name,
          email,
          photo: photo || null,
          role,
          createdAt: new Date().toISOString(),
          lastLogin: new Date().toISOString()
        };

        // Write user metadata to firestore
        await db.collection('users').doc(userRecord.uid).set(userDoc);

        // Add to admins / police secondary collections if matching role
        if (role === 'Admin') {
          await db.collection('admins').doc(userRecord.uid).set({ uid: userRecord.uid, email, assignedAt: new Date().toISOString() });
        } else if (role === 'Police') {
          await db.collection('police').doc(userRecord.uid).set({ uid: userRecord.uid, email, assignedAt: new Date().toISOString() });
        }

        const token = generateToken(userRecord.uid, email, role);

        return res.status(201).json({
          success: true,
          message: 'Signup successful',
          token,
          user: userDoc
        });
      } catch (fbErr) {
        console.error('Firebase Auth signup error:', fbErr);
        return res.status(400).json({ success: false, message: fbErr.message });
      }
    }
  } catch (error) {
    next(error);
  }
};

// POST /auth/login
exports.login = async (req, res, next) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ success: false, message: 'Email and password are required.' });
    }

    if (isSandbox) {
      // Sandbox Password Verification
      const user = sandboxDb.users.find(u => u.email.toLowerCase() === email.toLowerCase());
      if (!user) {
        return res.status(401).json({ success: false, message: 'Invalid email credentials.' });
      }

      const isMatch = await bcrypt.compare(password, user.passwordHash);
      if (!isMatch) {
        return res.status(401).json({ success: false, message: 'Incorrect password entered.' });
      }

      user.lastLogin = new Date().toISOString();
      const token = generateToken(user.uid, user.email, user.role);

      return res.status(200).json({
        success: true,
        message: 'Login successful (Sandbox Mode)',
        token,
        user: {
          uid: user.uid,
          name: user.name,
          email: user.email,
          photo: user.photo,
          role: user.role
        }
      });
    } else {
      // Real Firebase Mode Login (using Firebase Client Identity Toolkit API on backend)
      try {
        const apiKey = process.env.FIREBASE_API_KEY;
        if (!apiKey) {
          return res.status(500).json({
            success: false,
            message: 'Firebase API key is missing. Add FIREBASE_API_KEY to your .env file.'
          });
        }

        const identityUrl = `https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${apiKey}`;
        const response = await axios.post(identityUrl, {
          email,
          password,
          returnSecureToken: true
        });

        const { localId, idToken } = response.data;

        // Fetch user role profile from Firestore
        const userDocRef = db.collection('users').doc(localId);
        const doc = await userDocRef.get();

        let userData = {};
        let role = 'User';

        if (doc.exists) {
          userData = doc.data();
          role = userData.role || 'User';
          
          // Update lastLogin timestamp
          await userDocRef.update({ lastLogin: new Date().toISOString() });
          userData.lastLogin = new Date().toISOString();
        } else {
          // If auth exists but firestore profile is missing, create it
          role = determineRole(email);
          userData = {
            uid: localId,
            name: email.split('@')[0],
            email,
            photo: null,
            role,
            createdAt: new Date().toISOString(),
            lastLogin: new Date().toISOString()
          };
          await userDocRef.set(userData);
        }

        const token = generateToken(localId, email, role);

        return res.status(200).json({
          success: true,
          message: 'Login successful',
          token,
          user: userData
        });
      } catch (fbErr) {
        console.error('Firebase Auth identity validation failed:', fbErr.response ? fbErr.response.data : fbErr.message);
        const errorMsg = fbErr.response && fbErr.response.data && fbErr.response.data.error
          ? fbErr.response.data.error.message
          : 'Authentication failed. Please verify credentials.';
        return res.status(401).json({ success: false, message: errorMsg });
      }
    }
  } catch (error) {
    next(error);
  }
};

// POST /auth/google
exports.googleLogin = async (req, res, next) => {
  try {
    const { idToken } = req.body;

    if (!idToken) {
      return res.status(400).json({ success: false, message: 'Google ID Token is required.' });
    }

    if (isSandbox || idToken.startsWith('mock-google-token')) {
      // Sandbox Mock Google Auth handler
      const email = idToken === 'mock-google-token-admin' ? 'admin@qrshield.ai' : 'user@qrshield.ai';
      const name = idToken === 'mock-google-token-admin' ? 'Mock Google Admin' : 'Mock Google User';
      const role = determineRole(email);
      const uid = 'google-uid-' + (idToken === 'mock-google-token-admin' ? 'admin' : 'user');

      let user = sandboxDb.users.find(u => u.uid === uid);
      if (!user) {
        user = {
          uid,
          name,
          email,
          passwordHash: 'oauth_sign_in',
          photo: 'https://images.unsplash.com/photo-1535713875002-d1d0cf377fde?w=150',
          role,
          createdAt: new Date().toISOString(),
          lastLogin: new Date().toISOString()
        };
        sandboxDb.users.push(user);
      } else {
        user.lastLogin = new Date().toISOString();
      }

      const token = generateToken(uid, email, role);

      return res.status(200).json({
        success: true,
        message: 'Google login successful (Sandbox Mode)',
        token,
        user: { uid, name, email, photo: user.photo, role }
      });
    } else {
      // Real Firebase Verification of Google ID Token
      try {
        const decodedToken = await auth.verifyIdToken(idToken);
        const { uid, email, name, picture } = decodedToken;

        const userDocRef = db.collection('users').doc(uid);
        const doc = await userDocRef.get();

        let userData = {};
        let role = 'User';

        if (doc.exists) {
          userData = doc.data();
          role = userData.role || 'User';
          await userDocRef.update({ lastLogin: new Date().toISOString() });
          userData.lastLogin = new Date().toISOString();
        } else {
          role = determineRole(email);
          userData = {
            uid,
            name: name || email.split('@')[0],
            email,
            photo: picture || null,
            role,
            createdAt: new Date().toISOString(),
            lastLogin: new Date().toISOString()
          };
          await userDocRef.set(userData);
          
          if (role === 'Admin') {
            await db.collection('admins').doc(uid).set({ uid, email, assignedAt: new Date().toISOString() });
          } else if (role === 'Police') {
            await db.collection('police').doc(uid).set({ uid, email, assignedAt: new Date().toISOString() });
          }
        }

        const token = generateToken(uid, email, role);

        return res.status(200).json({
          success: true,
          message: 'Google login successful',
          token,
          user: userData
        });
      } catch (fbErr) {
        console.error('Firebase verifyIdToken failed:', fbErr.message);
        return res.status(401).json({ success: false, message: 'Google Authentication token invalid: ' + fbErr.message });
      }
    }
  } catch (error) {
    next(error);
  }
};

// POST /auth/logout
exports.logout = (req, res) => {
  // Since JWT tokens are stateless, client side deletes localToken.
  return res.status(200).json({
    success: true,
    message: 'Session invalidated. Logged out successfully.'
  });
};

// GET /user/profile
exports.getUserProfile = async (req, res, next) => {
  try {
    const { uid } = req.user;

    if (isSandbox) {
      const user = sandboxDb.users.find(u => u.uid === uid);
      if (!user) {
        return res.status(404).json({ success: false, message: 'User profile not found.' });
      }
      return res.status(200).json({
        success: true,
        user: {
          uid: user.uid,
          name: user.name,
          email: user.email,
          photo: user.photo,
          role: user.role,
          createdAt: user.createdAt,
          lastLogin: user.lastLogin
        }
      });
    } else {
      const doc = await db.collection('users').doc(uid).get();
      if (!doc.exists) {
        return res.status(404).json({ success: false, message: 'User profile record missing in database.' });
      }
      return res.status(200).json({
        success: true,
        user: doc.data()
      });
    }
  } catch (error) {
    next(error);
  }
};
