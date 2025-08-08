// auth-server.js
const express = require('express');
const session = require('express-session');
const cors = require('cors');
const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));
const { Issuer, generators } = require('openid-client');

const app = express();
const PORT = process.env.PORT || 4000;

/* ───────────────────────────────── ENV / CONSTANTES ───────────────────────────────── */

const IS_LOCAL = process.env.NODE_ENV !== 'production' || process.env.IS_OFFLINE === 'true';

const FRONTEND_URL   = IS_LOCAL ? 'http://localhost:3000'
                                : 'https://d10iaakzqzg2nu.cloudfront.net';

const AUTH_BASE_URL  = IS_LOCAL ? `http://localhost:${PORT}`
                                : 'https://auth-server-61ms.onrender.com';

const REDIRECT_URI   = `${AUTH_BASE_URL}/callback`;

// ⚠️ Vérifie bien ces valeurs (User Pool ID / Domain / Client ID/Secret)
const COGNITO_ISSUER = 'https://cognito-idp.ca-central-1.amazonaws.com/ca-central-1_0LywvRg65';
const COGNITO_DOMAIN = 'https://ca-central-10lywvrg65.auth.ca-central-1.amazoncognito.com';
const CLIENT_ID      = '9tg475st96qptbvefusar69nj';
const CLIENT_SECRET  = '19i56ejoqbutpgt9nsh51e6ca9t3b8jg62of4t3mk14rp0qt7qr'; 

const API_BASE = 'https://1irywxa5c3.execute-api.ca-central-1.amazonaws.com/prod';

/* ───────────────────────────────── MIDDLEWARES ───────────────────────────────── */

app.use((req, _res, next) => {
  console.log(`📥 ${req.method} ${req.url}`);
  next();
});

app.use(cors({
  origin: [FRONTEND_URL],
  credentials: true,
}));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// pour que secure cookies fonctionnent derrière un proxy (Render/ELB/NGINX)
app.set('trust proxy', 1);

app.use(session({
  name: 'connect.sid',               // nom explicite
  secret: 'your-secret',             // ⚠️ change ça et mets une vraie secret key via env
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: !IS_LOCAL,               // false en local, true en prod (https obligatoire)
    sameSite: IS_LOCAL ? 'lax' : 'none', // 'none' en prod pour autoriser cookies cross-site
    path: '/',
  },
}));

/* ─────────────────────────────── OPENID CLIENT ─────────────────────────────── */

let client;
let initializing = null;

async function initializeClient() {
  if (client) return;
  if (initializing) return initializing;

  initializing = (async () => {
    console.log('🔧 Découverte du provider OpenID...');
    const discoveredIssuer = await Issuer.discover(COGNITO_ISSUER);

    client = new discoveredIssuer.Client({
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      redirect_uris: [REDIRECT_URI],
      post_logout_redirect_uris: [FRONTEND_URL],
      response_types: ['code'],
    });

    console.log('✅ Client OpenID initialisé (redirect_uri =', REDIRECT_URI, ')');
  })();

  return initializing;
}

/* ─────────────────────────────────── ROUTES ─────────────────────────────────── */

app.get('/login', async (req, res) => {
  try {
    await initializeClient();

    const state = generators.state();
    const nonce = generators.nonce();
    req.session.state = state;
    req.session.nonce = nonce;

    const authUrl = client.authorizationUrl({
      scope: 'openid email profile phone',
      state,
      nonce,
      redirect_uri: REDIRECT_URI, // facultatif
    });

    console.log('➡️ Redirection vers:', authUrl);
    res.redirect(authUrl);
  } catch (err) {
    console.error('❌ /login:', err);
    res.status(500).json({ message: 'Erreur interne serveur /login' });
  }
});

app.get('/callback', async (req, res) => {
  try {
    await initializeClient();

    const params = client.callbackParams(req);
    const tokenSet = await client.callback(REDIRECT_URI, params, {
      state: req.session.state,
      nonce: req.session.nonce,
    });

    const userInfo = await client.userinfo(tokenSet.access_token);
    console.log('✅ userInfo reçu de Cognito:', userInfo);

    req.session.user = userInfo;

    // Sync DB
    const payload = {
      sub: userInfo.sub,
      email: userInfo.email,
      given_name: userInfo.given_name,
      family_name: userInfo.family_name,
      phone: userInfo.phone_number || null,
      user_type: userInfo.email === 'admin@knowmediq.com' ? 'admin' : 'professional',
    };

    const syncRes  = await fetch(`${API_BASE}/cognito-sync`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!syncRes.ok) console.error('❌ Erreur synchro DB:', await syncRes.text());

    // Récup profil complet
    const userRes  = await fetch(`${API_BASE}/users/email/${userInfo.email}`);
    const contentType = userRes.headers.get('content-type') || '';
    if (!userRes.ok || !contentType.includes('application/json')) {
      const rawText = await userRes.text();
      console.error('❌ /callback -> userRes non JSON:', rawText);
      return res.redirect(FRONTEND_URL);
    }
    const userData = await userRes.json();

    req.session.user_type = userData.user_type;
    req.session.profile_incomplete = userData.profile_incomplete || false;

    let redirectPath = '/';
    if (userData.user_type === 'admin')           redirectPath = '/admin/dashboard';
    else if (userData.user_type === 'professional') redirectPath = '/professional/dashboard';
    else if (userData.user_type === 'patient')      redirectPath = '/patient/dashboard';

    console.log(`✅ Redirection finale vers ${FRONTEND_URL}${redirectPath}`);
    res.redirect(`${FRONTEND_URL}${redirectPath}`);
  } catch (err) {
    console.error('❌ /callback:', err);
    res.redirect(FRONTEND_URL);
  }
});

/**
 * /logout pour les appels XHR (axios) depuis React :
 * - détruit la session
 * - efface le cookie
 * - renvoie du JSON (pas une redirection)
 */
// auth-server.js
app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('connect.sid', {
      path: '/',
      httpOnly: true,
      sameSite: IS_LOCAL ? 'lax' : 'none',
      secure: !IS_LOCAL,
    });

    const url =
      `${COGNITO_DOMAIN}/logout` +
      `?client_id=${CLIENT_ID}` +
      `&logout_uri=${encodeURIComponent(FRONTEND_URL)}` +
      `&v=${Date.now()}`; // évite le cache

    res.redirect(url);   // ✅ déconnexion Cognito + retour vers ton FRONTEND_URL
  });
});

/**
 * /logout-redirect pour une déconnexion "full" côté Cognito
 * (utile si tu veux *aussi* fermer la session côté hébergeur IdP).
 * À appeler si tu fais window.location.href au lieu d'axios.
 */
app.get('/logout-redirect', (_req, res) => {
  const url = `${COGNITO_DOMAIN}/logout?client_id=${CLIENT_ID}&logout_uri=${encodeURIComponent(FRONTEND_URL)}`;
  res.redirect(url);
});

app.get('/me', async (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Non authentifié' });

  try {
    const userRes = await fetch(`${API_BASE}/users/email/${req.session.user.email}`);
    const contentType = userRes.headers.get('content-type') || '';

    if (!userRes.ok || !contentType.includes('application/json')) {
      const rawText = await userRes.text();
      console.error('❌ /me -> userRes non JSON:', rawText);
      return res.status(500).json({ error: 'Erreur récupération utilisateur' });
    }

    const userData = await userRes.json();

    return res.json({
      ...req.session.user,
      user_id: userData.user_id,
      user_type: userData.user_type,
      profile_incomplete: userData.profile_incomplete || false,
      first_name: userData.first_name,
      last_name: userData.last_name,
    });
  } catch (err) {
    console.error('❌ /me:', err);
    return res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.get('/', (_req, res) => {
  res.send('✅ Serveur Cognito opérationnel');
});

/* ─────────────────────────────────── START ─────────────────────────────────── */

(async () => {
  await initializeClient();

  app.listen(PORT, () => {
    console.log(`🚀 Auth server sur ${IS_LOCAL ? `http://localhost:${PORT}` : `port ${PORT}`}`);
    console.log(`   FRONTEND_URL = ${FRONTEND_URL}`);
    console.log(`   REDIRECT_URI = ${REDIRECT_URI}`);
  });
})();

module.exports = app;