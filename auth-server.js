const express = require('express');
const session = require('express-session');
const RedisStore = require('connect-redis');
const { createClient } = require('redis');
const cors = require('cors');
const fetch = require('node-fetch');
const { Issuer, generators } = require('openid-client');

console.log('lancement auth-server.js depuis', __dirname);

const app = express();
const PORT = 4000;

const API_BASE = 'https://1irywxa5c3.execute-api.ca-central-1.amazonaws.com/prod';

// 🚀 Redis client setup
const redisClient = createClient({
  url: process.env.REDIS_URL // à définir dans Render, ex: redis://default:motdepasse@hostname:port
});
redisClient.connect().catch(console.error);

// ✅ Session avec Redis
app.use(session({
  store: new RedisStore({ client: redisClient }),
  secret: 'your-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false, // true si HTTPS (Render le force en général)
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000 // 1 jour
  }
}));

let client;
let initializing = null;

async function initializeClient() {
  if (client) return;
  if (initializing) return initializing;

  initializing = (async () => {
    try {
      console.log('🔧 Découverte du provider OpenID...');
      const discoveredIssuer = await Issuer.discover('https://cognito-idp.ca-central-1.amazonaws.com/ca-central-1_0LywvRg65');

      client = new discoveredIssuer.Client({
        client_id: '9tg475st96qptbvefusar69nj',
        client_secret: '19i56ejoqbutpgtbvefusar69nj',
        redirect_uris: ['https://d10iaakzqzg2nu.cloudfront.net/callback'],
        response_types: ['code']
      });

      console.log('✅ Client OpenID initialisé');
    } catch (err) {
      console.error('❌ Erreur découverte ou init OpenID:', err);
      throw err;
    }
  })();

  return initializing;
}

app.get('/login', async (req, res) => {
  try {
    if (!client) {
      console.log('⚠️ Client non initialisé, on initialise...');
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

  try {
    const tokenSet = await client.callback('https://d10iaakzqzg2nu.cloudfront.net/callback', params, {
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

    console.log('📦 Envoi à cognito-sync:', payload);

    const syncRes = await fetch(`${API_BASE}/cognito-sync`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    const syncText = await syncRes.text();
    console.log(`📥 Réponse cognito-sync: ${syncRes.status} ${syncText}`);

    if (!syncRes.ok) {
      console.error('❌ Erreur synchro DB:', syncRes.status, syncText);
    } else {
      console.log('✅ Synchro DB réussie');
    }

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

    console.log(`✅ Redirection finale vers ${redirectPath}`);
    res.redirect(`https://d10iaakzqzg2nu.cloudfront.net${redirectPath}`);

  } catch (err) {
    console.error('❌ Erreur dans /callback:', err);
    res.redirect('https://d10iaakzqzg2nu.cloudfront.net');
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy();
  const logoutUrl = `https://ca-central-10lywvrg65.auth.ca-central-1.amazoncognito.com/logout?client_id=9tg475st96qptbvefusar69nj&logout_uri=https://d10iaakzqzg2nu.cloudfront.net`;
  res.redirect(logoutUrl);
});

app.get('/me', async (req, res) => {
  console.log('📦 Accès à /me | Session =>', req.session);

  if (!req.session.user) {
    console.warn('❌ Aucune session utilisateur');
    return res.status(401).json({ error: 'Non authentifié' });
  }

  try {
    const userEmail = req.session.user.email;
    console.log('📧 Appel API /users/email avec:', userEmail);

    const userRes = await fetch(`${API_BASE}/users/email/${userEmail}`);
    const userText = await userRes.text();

    if (!userRes.ok) {
      console.error('❌ Erreur API /users/email:', userRes.status, userText);
      return res.status(500).json({ error: 'Erreur récupération utilisateur' });
    }

    let userData;
    try {
      userData = JSON.parse(userText);
    } catch (err) {
      console.error('❌ JSON invalide reçu:', err, ' | Texte:', userText);
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
    console.error('❌ Erreur générale dans /me:', err);
    return res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.get('/', (req, res) => {
  res.send('✅ Serveur Cognito opérationnel');
});

(async () => {
  await initializeClient();
  console.log('✅ Client OpenID initialisé et prêt');

  // Toujours lancer le serveur, sauf si explicitement désactivé
  const isOffline = process.env.IS_OFFLINE === 'true';

  if (isOffline) {
    app.listen(PORT, () => {
      console.log(`🚀 Serveur auth lancé en local sur http://localhost:${PORT}`);
    });
  } else {
    app.listen(PORT, () => {
      console.log(`🚀 Serveur auth lancé sur le port ${PORT} (Render ou autre)`);
    });
  }
})();

module.exports = app;
