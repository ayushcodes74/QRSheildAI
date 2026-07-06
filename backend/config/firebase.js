const admin = require('firebase-admin');
const dotenv = require('dotenv');
const path = require('path');

// Load environment variables from backend/.env
dotenv.config({ path: path.join(__dirname, '../.env') });

let isSandbox = false;
let auth = null;
let db = null;
let bucket = null;

const privateKey = process.env.FIREBASE_PRIVATE_KEY
  ? process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n')
  : null;

const hasCredentials =
  process.env.FIREBASE_PROJECT_ID &&
  process.env.FIREBASE_CLIENT_EMAIL &&
  privateKey;

if (hasCredentials) {
  try {
    if (!admin.apps.length) {
      admin.initializeApp({
        credential: admin.credential.cert({
          projectId: process.env.FIREBASE_PROJECT_ID,
          clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
          privateKey: privateKey,
        }),
        storageBucket: `${process.env.FIREBASE_PROJECT_ID}.appspot.com`
      });
      console.log('✔ Firebase Admin SDK initialized successfully.');
    }
    auth = admin.auth();
    db = admin.firestore();
    // Configure settings for firestore
    db.settings({ ignoreUndefinedProperties: true });
    
    try {
      bucket = admin.storage().bucket();
    } catch (err) {
      console.warn('⚠ Firebase Storage bucket could not be resolved. Storage features will fall back to data URIs.');
    }
  } catch (error) {
    console.error('❌ Error initializing Firebase Admin SDK:', error.message);
    console.warn('⚠ Falling back to Sandbox Mode (In-Memory database).');
    isSandbox = true;
  }
} else {
  console.warn('⚠ Firebase configuration credentials missing in .env.');
  console.warn('⚠ Running in Sandbox Mode (In-Memory database with local data persistence).');
  isSandbox = true;
}

module.exports = {
  admin,
  auth,
  db,
  bucket,
  isSandbox
};
