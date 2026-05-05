/**
 * Authentication Routes
 * Google OAuth + Standard Auth
 */

const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library');
const User = require('../models/User');

const JWT_SECRET = process.env.JWT_SECRET || 'haru-sora-secret-key-2024';
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '92817315946-uhm3r52gmlmf629439d9do6kqc2601cc.apps.googleusercontent.com';
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const GOOGLE_CALLBACK_URL = process.env.GOOGLE_CALLBACK_URL || 'http://localhost:4000/api/auth/google/callback';

const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_CALLBACK_URL);

async function findOrCreateGoogleUser({ email, name, picture, googleId }) {
  let user = await User.findOne({ email: email.toLowerCase() });

  if (!user) {
    user = await User.create({
      name,
      email: email.toLowerCase(),
      password: await bcrypt.hash(googleId + JWT_SECRET, 12),
      avatar: picture,
      googleId,
      isGoogleUser: true
    });
    console.log(`✅ New Google user created: ${email}`);
  } else if (!user.googleId) {
    user.googleId = googleId;
    user.avatar = user.avatar || picture;
    user.isGoogleUser = true;
    await user.save();
    console.log(`✅ Linked Google to existing account: ${email}`);
  }

  return user;
}

function buildGoogleAuthResponse(user) {
  const token = jwt.sign(
    { userId: user._id, email: user.email, role: user.role },
    JWT_SECRET,
    { expiresIn: '7d' }
  );

  return {
    message: 'Google login successful',
    token,
    user: {
      id: user._id,
      name: user.name,
      email: user.email,
      avatar: user.avatar,
      role: user.role,
      loyaltyPoints: user.loyaltyPoints
    }
  };
}

function buildGoogleSuccessHtml(payload) {
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Google Sign-In</title>
    <style>
      body { font-family: Arial, sans-serif; background: #fff8f1; color: #6f5648; display: grid; place-items: center; min-height: 100vh; margin: 0; }
      .card { background: white; border: 1px solid #ead9c9; border-radius: 16px; padding: 24px 28px; box-shadow: 0 10px 30px rgba(0,0,0,.06); text-align: center; max-width: 420px; }
    </style>
  </head>
  <body>
    <div class="card">
      <h2>Google sign-in successful</h2>
      <p>Redirecting you back to the home page...</p>
    </div>
    <script>
      (function() {
        const payload = ${JSON.stringify(payload)};
        localStorage.setItem('currentUser', JSON.stringify(payload.user));
        if (payload.token) localStorage.setItem('authToken', payload.token);
        localStorage.setItem('isLoggedIn', 'true');
        window.location.href = '/home';
      })();
    </script>
  </body>
</html>`;
}

async function exchangeGoogleCode(code, redirectUri) {
  const {tokens} = await googleClient.getToken({
    code,
    redirect_uri: redirectUri || GOOGLE_CALLBACK_URL
  });

  if (!tokens.id_token) {
    throw new Error('Google ID token missing from authorization code exchange');
  }

  const ticket = await googleClient.verifyIdToken({
    idToken: tokens.id_token,
    audience: GOOGLE_CLIENT_ID
  });

  const payload = ticket.getPayload();
  const { email, name, picture, sub: googleId } = payload;
  const user = await findOrCreateGoogleUser({ email, name, picture, googleId });

  return buildGoogleAuthResponse(user);
}

// POST /api/auth/google - Google OAuth login
router.post('/google', async (req, res) => {
  try {
    const { credential } = req.body;

    if (!credential) {
      return res.status(400).json({ message: 'Google credential is required' });
    }

    // Verify Google token
    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: GOOGLE_CLIENT_ID
    });

    const payload = ticket.getPayload();
    const { email, name, picture, sub: googleId } = payload;
    const user = await findOrCreateGoogleUser({ email, name, picture, googleId });

    res.json(buildGoogleAuthResponse(user));

  } catch (error) {
    console.error('Google auth error:', error);
    res.status(401).json({ message: 'Google authentication failed' });
  }
});

// POST /api/auth/google-code - Google OAuth login using authorization code exchange
router.post('/google-code', async (req, res) => {
  try {
    const { code, redirectUri } = req.body;

    if (!code) {
      return res.status(400).json({ message: 'Google authorization code is required' });
    }

    const result = await exchangeGoogleCode(code, redirectUri);

    res.json(result);
  } catch (error) {
    console.error('Google code auth error:', error);
    res.status(401).json({
      message: 'Google authorization code exchange failed',
      detail: error?.response?.data?.error_description || error?.response?.data?.error || error.message
    });
  }
});

// GET /api/auth/google/callback - Google OAuth callback redirect flow
router.get('/google/callback', async (req, res) => {
  try {
    const { code } = req.query;

    if (!code) {
      return res.status(400).send('Google authorization code is missing.');
    }

    const result = await exchangeGoogleCode(String(code), GOOGLE_CALLBACK_URL);
    res.send(buildGoogleSuccessHtml(result));
  } catch (error) {
    console.error('Google callback error:', error);
    res.status(401).send(`Google authorization code exchange failed: ${error?.response?.data?.error_description || error?.response?.data?.error || error.message}`);
  }
});

// POST /api/auth/login - Standard login with JWT
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    const token = jwt.sign(
      { userId: user._id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        avatar: user.avatar,
        role: user.role,
        loyaltyPoints: user.loyaltyPoints
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// GET /api/auth/me - Get current user from token
router.get('/me', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ message: 'No token provided' });
    }

    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    
    const user = await User.findById(decoded.userId).select('-password');
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json({ user });

  } catch (error) {
    res.status(401).json({ message: 'Invalid token' });
  }
});

// POST /api/auth/google-userinfo - Alternative Google login using userinfo
router.post('/google-userinfo', async (req, res) => {
  try {
    const { email, name, picture, googleId } = req.body;

    if (!email || !googleId) {
      return res.status(400).json({ message: 'Email and Google ID are required' });
    }

    const user = await findOrCreateGoogleUser({
      email,
      name: name || email.split('@')[0],
      picture,
      googleId
    });

    res.json(buildGoogleAuthResponse(user));

  } catch (error) {
    console.error('Google userinfo auth error:', error);
    res.status(500).json({ message: 'Server error during Google login' });
  }
});

module.exports = router;
