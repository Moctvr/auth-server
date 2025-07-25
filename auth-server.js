const express = require('express');
const session = require('express-session');
const cors = require('cors');
const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));
const { Issuer, generators } = require('openid-client');

console.log('lancement auth-server.js depuis', __dirname);

const app = express();
const PORT = 4000;

const API_BASE = 'https://1irywxa5c3.execute-api.ca-central-1.amazonaws.com/prod';

app.use((req, res, next) => {
  console.log(`📥 ${req.method} ${req.url}`);
  next();
});

app.use(cors({
  origin: [
    'https://d10iaakzqzg2nu.cloudfront.net',
    'http://localhost:3000'
  ],
  credentials: true
}));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.set('trust proxy', 1);

app.use(session({
  secret: 'your-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: true,
    sameSite: 'none'
  }
}));

let client;
let initializing = null;

async function initializeClient() {
  if (client) return;
  if (initializing) return initializing;

  initializing = (async () => {
    console.log('🔧 Découverte du provider OpenID...');
    const discoveredIssuer = await Issuer.discover('https://cognito-idp.ca-central-1.amazonaws.com/ca-central-1_0LywvRg65');

    client = new discoveredIssuer.Client({
      client_id: '9tg475st96qptbvefusar69nj',
      client_secret: '19i56ejoqbutpgt9nsh51e6ca9t3b8jg62of4t3mk14rp0qt7qr',
      redirect_uris: [
        'https://auth-server-61ms.onrender.com/callback',
        'http://localhost:4000/callback'
      ],
      response_types: ['code']
    });

    console.log('✅ Client OpenID initialisé');
  })();

  return initializing;
}

app.get('/login', async (req, res) => {
  try {
    if (!client) {
      await initializeClient();
    }

    const state = generators.state();
    const nonce = generators.nonce();
    req.session.state = state;
    req.session.nonce = nonce;

    const authUrl = client.authorizationUrl({
      scope: 'openid email profile phone',
      state,
      nonce,
    });

    console.log('➡️ Redirection vers:', authUrl);
    res.redirect(authUrl);
  } catch (err) {
    console.error('❌ Erreur dans /login:', err);
    res.status(500).json({ message: 'Erreur interne serveur /login' });
  }
});

app.get('/callback', async (req, res) => {
  const params = client.callbackParams(req);

  const baseRedirect = req.headers.host.includes('localhost')
    ? 'http://localhost:3000'
    : 'https://d10iaakzqzg2nu.cloudfront.net';

  const thisCallback = req.headers.host.includes('localhost')
    ? 'http://localhost:4000/callback'
    : 'https://auth-server-61ms.onrender.com/callback';

  try {
    const tokenSet = await client.callback(thisCallback, params, {
      state: req.session.state,
      nonce: req.session.nonce
    });

    const userInfo = await client.userinfo(tokenSet.access_token);
    console.log('✅ userInfo reçu de Cognito:', userInfo);

    req.session.user = userInfo;

    const payload = {
      sub: userInfo.sub,
      email: userInfo.email,
      given_name: userInfo.given_name,
      family_name: userInfo.family_name,
      phone: userInfo.phone_number || null,
      user_type: userInfo.email === 'admin@knowmediq.com' ? 'admin' : 'professional'
    };

    const syncRes = await fetch(`${API_BASE}/cognito-sync`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    const syncText = await syncRes.text();
    console.log(`📥 Réponse cognito-sync: ${syncRes.status} ${syncText}`);

    const userRes = await fetch(`${API_BASE}/users/email/${userInfo.email}`);
    const userData = await userRes.json();

    req.session.user_type = userData.user_type;
    req.session.profile_incomplete = userData.profile_incomplete || false;

    let redirectPath = '/';
    if (userData.user_type === 'admin') {
      redirectPath = '/admin/dashboard';
    } else if (userData.user_type === 'professional') {
      redirectPath = '/professional/dashboard';
    } else if (userData.user_type === 'patient') {
      redirectPath = '/patient/dashboard';
    }

    console.log(`✅ Redirection finale vers ${baseRedirect}${redirectPath}`);
    res.redirect(`${baseRedirect}${redirectPath}`);

  } catch (err) {
    console.error('❌ Erreur dans /callback:', err);
    res.redirect(baseRedirect);
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy();

  const logoutRedirect = req.headers.host.includes('localhost')
    ? 'http://localhost:3000'
    : 'https://d10iaakzqzg2nu.cloudfront.net';

  const logoutUrl = `https://ca-central-10lywvrg65.auth.ca-central-1.amazoncognito.com/logout?client_id=9tg475st96qptbvefusar69nj&logout_uri=${logoutRedirect}`;
  res.redirect(logoutUrl);
});

app.get('/me', async (req, res) => {
  console.log('📦 Accès à /me | Session =>', req.session);

  if (!req.session.user) {
    return res.status(401).json({ error: 'Non authentifié' });
  }

  try {
    const userEmail = req.session.user.email;
    const userRes = await fetch(`${API_BASE}/users/email/${userEmail}`);
    const userText = await userRes.text();

    if (!userRes.ok) {
      return res.status(500).json({ error: 'Erreur récupération utilisateur' });
    }

    let userData;
    try {
      userData = JSON.parse(userText);
    } catch (err) {
      return res.status(500).json({ error: 'Erreur parsing JSON' });
    }

    return res.json({
      ...req.session.user,
      user_id: userData.user_id,
      user_type: userData.user_type,
      profile_incomplete: userData.profile_incomplete || false,
      first_name: userData.first_name,
      last_name: userData.last_name
    });

  } catch (err) {
    return res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.get('/', (req, res) => {
  res.send('✅ Serveur Cognito opérationnel');
});

(async () => {
  await initializeClient();
  console.log('✅ Client OpenID initialisé et prêt');

  const isOffline = process.env.IS_OFFLINE === 'true';

  app.listen(PORT, () => {
    const env = isOffline || process.env.NODE_ENV === 'development'
      ? `http://localhost:${PORT}`
      : `port ${PORT} (Render ou autre)`;
    console.log(`🚀 Serveur auth lancé sur ${env}`);
  });
})();

module.exports = app;
