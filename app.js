require('dotenv').config();
const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const path = require('path');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();

// -----------------------------
// Configuração básica
// -----------------------------
const app = express();
const PORT = process.env.PORT || 3000;
const BASE_URL = process.env.BASE_URL || `https://symmetrical-engine-r4v4w7q6w9xg2pwrw-3000.app.github.dev`;
const REDIRECT_URI = process.env.REDIRECT_URI || `${BASE_URL}/auth/callback`;

// Scopes (ajuste conforme o acesso do seu app no X)
const SCOPE = (process.env.X_SCOPES || [
  'tweet.read',
  'users.read',
  'follows.read',
  'like.read',
  'list.read',
  'bookmark.read',
  'offline.access'
].join(' '));

const TWITTER_ENDPOINTS = {
  AUTH_URL: 'https://twitter.com/i/oauth2/authorize',
  TOKEN_URL: 'https://api.twitter.com/2/oauth2/token',
  REVOKE_URL: 'https://api.twitter.com/2/oauth2/revoke',
  ME: 'https://api.twitter.com/2/users/me',
  USER_TWEETS: (id) => `https://api.twitter.com/2/users/${id}/tweets`,
  USER_MENTIONS: (id) => `https://api.twitter.com/2/users/${id}/mentions`,
  USER_LIKED: (id) => `https://api.twitter.com/2/users/${id}/liked_tweets`,
  USER_FOLLOWERS: (id) => `https://api.twitter.com/2/users/${id}/followers`,
  USER_FOLLOWING: (id) => `https://api.twitter.com/2/users/${id}/following`,
  USER_BOOKMARKS: (id) => `https://api.twitter.com/2/users/${id}/bookmarks`,
};

// -----------------------------
// Middlewares
// -----------------------------
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
  name: 'xapp.sid',
  secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: false, // defina true atrás de proxy HTTPS
    maxAge: 24 * 60 * 60 * 1000
  }
}));

// -----------------------------
// Banco de dados (SQLite)
// -----------------------------
const db = new sqlite3.Database(path.join(__dirname, 'x_app.db'));
db.serialize(() => {
  db.run(`PRAGMA journal_mode = WAL;`);
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT UNIQUE,
    username TEXT,
    name TEXT,
    description TEXT,
    avatar_url TEXT,
    location TEXT,
    url TEXT,
    verified INTEGER DEFAULT 0,
    followers_count INTEGER,
    following_count INTEGER,
    tweet_count INTEGER,
    listed_count INTEGER,
    created_at_twitter TEXT,
    access_token TEXT,
    refresh_token TEXT,
    token_type TEXT,
    scope TEXT,
    expires_in INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );`);

  db.run(`CREATE TABLE IF NOT EXISTS tweets (
    id TEXT PRIMARY KEY,
    user_id TEXT,
    text TEXT,
    created_at_twitter TEXT,
    conversation_id TEXT,
    in_reply_to_user_id TEXT,
    lang TEXT,
    source TEXT,
    reply_settings TEXT,
    retweet_count INTEGER DEFAULT 0,
    reply_count INTEGER DEFAULT 0,
    like_count INTEGER DEFAULT 0,
    quote_count INTEGER DEFAULT 0,
    bookmark_count INTEGER DEFAULT 0,
    impression_count INTEGER DEFAULT 0,
    possibly_sensitive INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (user_id)
  );`);
});

// -----------------------------
// Utilitários (PKCE, estado, etc.)
// -----------------------------
function generateState() {
  return crypto.randomBytes(24).toString('base64url');
}

function generatePKCE() {
  const codeVerifier = crypto.randomBytes(96).toString('base64url');
  const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
  return { codeVerifier, codeChallenge };
}

function buildAuthURL(state, codeChallenge) {
  const u = new URL(TWITTER_ENDPOINTS.AUTH_URL);
  u.searchParams.set('response_type', 'code');
  u.searchParams.set('client_id', process.env.CLIENT_ID);
  u.searchParams.set('redirect_uri', REDIRECT_URI);
  u.searchParams.set('scope', SCOPE);
  u.searchParams.set('state', state);
  u.searchParams.set('code_challenge', codeChallenge);
  u.searchParams.set('code_challenge_method', 'S256');
  return u.toString();
}

async function twitterGET(url, accessToken, params = {}) {
  const u = new URL(url);
  Object.entries(params).forEach(([k, v]) => {
    if (v !== undefined && v !== null) u.searchParams.set(k, v);
  });
  const res = await axios.get(u.toString(), {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'User-Agent': 'x-api-sample/1.0'
    }
  });
  return res.data;
}

function upsertUser(user, tokenPayload) {
  return new Promise((resolve, reject) => {
    const m = user.public_metrics || {};
    const stmt = db.prepare(`
      INSERT INTO users (
        user_id, username, name, description, avatar_url, location, url, verified,
        followers_count, following_count, tweet_count, listed_count, created_at_twitter,
        access_token, refresh_token, token_type, scope, expires_in, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
      ON CONFLICT(user_id) DO UPDATE SET
        username=excluded.username,
        name=excluded.name,
        description=excluded.description,
        avatar_url=excluded.avatar_url,
        location=excluded.location,
        url=excluded.url,
        verified=excluded.verified,
        followers_count=excluded.followers_count,
        following_count=excluded.following_count,
        tweet_count=excluded.tweet_count,
        listed_count=excluded.listed_count,
        created_at_twitter=excluded.created_at_twitter,
        access_token=excluded.access_token,
        refresh_token=excluded.refresh_token,
        token_type=excluded.token_type,
        scope=excluded.scope,
        expires_in=excluded.expires_in,
        updated_at=datetime('now')
    `);

    stmt.run([
      user.id,
      user.username,
      user.name,
      user.description || null,
      user.profile_image_url || null,
      user.location || null,
      user.url || null,
      user.verified ? 1 : 0,
      m.followers_count || 0,
      m.following_count || 0,
      m.tweet_count || 0,
      m.listed_count || 0,
      user.created_at || null,
      tokenPayload?.access_token || null,
      tokenPayload?.refresh_token || null,
      tokenPayload?.token_type || null,
      tokenPayload?.scope || SCOPE,
      tokenPayload?.expires_in || null
    ], (err) => {
      if (err) reject(err);
      else resolve(true);
    });
  });
}

function insertTweets(userId, tweets = []) {
  return new Promise((resolve, reject) => {
    if (!tweets.length) return resolve(0);
    const stmt = db.prepare(`
      INSERT OR REPLACE INTO tweets (
        id, user_id, text, created_at_twitter, conversation_id, in_reply_to_user_id, lang, source,
        reply_settings, retweet_count, reply_count, like_count, quote_count, bookmark_count,
        impression_count, possibly_sensitive
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    let count = 0;
    for (const t of tweets) {
      const pm = t.public_metrics || {};
      stmt.run([
        t.id,
        userId,
        t.text || '',
        t.created_at || null,
        t.conversation_id || null,
        t.in_reply_to_user_id || null,
        t.lang || null,
        t.source || null,
        t.reply_settings || null,
        pm.retweet_count || 0,
        pm.reply_count || 0,
        pm.like_count || 0,
        pm.quote_count || 0,
        t.public_bookmark_count || 0,
        t.impression_count || 0,
        t.possibly_sensitive ? 1 : 0
      ], (err) => {
        if (err) console.error('Erro ao inserir tweet', err.message);
        else count++;
      });
    }
    stmt.finalize((err) => err ? reject(err) : resolve(count));
  });
}

function requireAuth(req, res, next) {
  if (!req.session.accessToken) {
    return res.status(401).json({ error: 'Não autenticado' });
  }
  next();
}

// -----------------------------
// Rotas HTML simples
// -----------------------------
app.get('/', (req, res) => {
  const logged = !!req.session.accessToken;
  const username = req.session.username;
  res.send(`
    <!doctype html>
    <html lang="pt-br">
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>X OAuth App</title>
        <style>
          body{font-family:system-ui, -apple-system, Segoe UI, Roboto, Arial; background:#0f1419; color:#e6e9ec; margin:0; padding:40px}
          .card{max-width:700px; margin:0 auto; background:#17202a; padding:24px; border-radius:16px; box-shadow:0 8px 30px rgba(0,0,0,.25)}
          a.btn{display:inline-block; padding:12px 16px; border-radius:12px; text-decoration:none; background:#1da1f2; color:#001b2e; font-weight:700}
          .muted{color:#93a1af}
          .grid{display:grid; grid-template-columns:1fr 1fr; gap:12px}
          .chip{display:inline-block; padding:6px 10px; border:1px solid #2b3642; border-radius:999px; font-size:12px; margin:2px}
          footer{margin-top:20px; color:#93a1af; font-size:12px}
          pre{white-space:pre-wrap; word-break:break-word; background:#0b1016; padding:12px; border-radius:8px}
        </style>
      </head>
      <body>
        <div class="card">
          <h1>🚀 X (Twitter) OAuth 2.0 + SQLite</h1>
          <p class="muted">App de exemplo com login via X, salvando usuário e tweets no SQLite.</p>
          ${logged ? `
            <p>Autenticado como <strong>@${username}</strong></p>
            <div class="grid">
              <a class="btn" href="/dashboard">Abrir dashboard</a>
              <a class="btn" href="/auth/logout">Logout</a>
            </div>
          ` : `
            <a class="btn" href="/auth/login">Login com X</a>
          `}
          <hr style="margin:20px 0; border-color:#2b3642" />
          <p>Scopes:</p>
          <div>
            ${SCOPE.split(' ').map(s => `<span class="chip">${s}</span>`).join('')}
          </div>
          <footer>
            <p>Callback: <code>${REDIRECT_URI}</code></p>
          </footer>
        </div>
      </body>
    </html>
  `);
});

app.get('/dashboard', (req, res) => {
  if (!req.session.accessToken) return res.redirect('/');
  res.send(`
    <!doctype html>
    <html lang="pt-br">
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>Dashboard</title>
        <style>
          body{font-family:system-ui, -apple-system, Segoe UI, Roboto, Arial; background:#0f1419; color:#e6e9ec; margin:0; padding:40px}
          .wrap{max-width:1200px; margin:0 auto}
          .row{display:flex; gap:16px; flex-wrap:wrap}
          .card{flex:1 1 380px; background:#17202a; padding:20px; border-radius:16px; box-shadow:0 8px 30px rgba(0,0,0,.25)}
          a.btn{display:inline-block; padding:10px 14px; border-radius:12px; text-decoration:none; background:#1da1f2; color:#001b2e; font-weight:700}
          pre{white-space:pre-wrap; word-break:break-word; background:#0b1016; padding:12px; border-radius:8px; max-height:360px; overflow:auto}
        </style>
      </head>
      <body>
        <div class="wrap">
          <h1>📊 Dashboard</h1>
          <p>Autenticado como <strong>@${req.session.username}</strong> — <a class="btn" href="/auth/logout">Logout</a></p>
          <div class="row">
            <div class="card">
              <h3>👤 Meu perfil</h3>
              <p><a class="btn" href="/api/me">/api/me</a></p>
              <pre id="me">Carregue em /api/me</pre>
            </div>
            <div class="card">
              <h3>🧵 Meus tweets (salvos)</h3>
              <p>
                <a class="btn" href="/sync/tweets">Sincronizar tweets</a>
                <a class="btn" href="/api/tweets">/api/tweets</a>
              </p>
              <pre id="tweets">Carregue em /api/tweets</pre>
            </div>
          </div>
        </div>
      </body>
    </html>
  `);
});

// -----------------------------
// Fluxo OAuth
// -----------------------------
app.get('/auth/login', (req, res) => {
  if (!process.env.CLIENT_ID) {
    return res.status(500).send('CLIENT_ID não configurado (.env)');
  }
  const state = generateState();
  const { codeVerifier, codeChallenge } = generatePKCE();
  req.session.state = state;
  req.session.codeVerifier = codeVerifier;
  const url = buildAuthURL(state, codeChallenge);
  console.log('🔐 Redirecionando para autorização:', url);
  return res.redirect(url);
});

app.get('/auth/callback', async (req, res) => {
  try {
    const { code, state, error } = req.query;
    if (error) {
      return res.status(400).send(`Erro de autorização: ${error}`);
    }
    if (!code) return res.status(400).send('Código de autorização ausente');
    if (!req.session.state || state !== req.session.state) {
      return res.status(400).send('State inválido');
    }
    if (!req.session.codeVerifier) {
      return res.status(400).send('code_verifier ausente na sessão');
    }

    // Trocar code por tokens
    const form = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: REDIRECT_URI,
      client_id: process.env.CLIENT_ID,
      code_verifier: req.session.codeVerifier
    });

    const headers = { 'Content-Type': 'application/x-www-form-urlencoded' };
    // Para apps confidenciais, use Basic se CLIENT_SECRET estiver definido
    if (process.env.CLIENT_SECRET) {
      headers['Authorization'] = `Basic ${Buffer.from(`${process.env.CLIENT_ID}:${process.env.CLIENT_SECRET}`).toString('base64')}`;
    }

    const tokenRes = await axios.post(TWITTER_ENDPOINTS.TOKEN_URL, form, { headers });
    const tokens = tokenRes.data;

    req.session.accessToken = tokens.access_token;
    req.session.refreshToken = tokens.refresh_token;
    req.session.expiresIn = tokens.expires_in;

    // Buscar dados do usuário e salvar no banco
    const me = await twitterGET(TWITTER_ENDPOINTS.ME, tokens.access_token, {
      'user.fields': 'created_at,description,location,profile_image_url,public_metrics,verified,url'
    });

    if (me && me.data) {
      await upsertUser(me.data, tokens);
      req.session.userId = me.data.id;
      req.session.username = me.data.username;
    }

    return res.redirect('/dashboard');
  } catch (err) {
    console.error('Erro no callback:', err.response?.data || err.message);
    return res.status(500).send('Falha no callback');
  }
});

app.get('/auth/refresh', async (req, res) => {
  try {
    if (!req.session.refreshToken) {
      return res.status(400).json({ error: 'Refresh token ausente' });
    }
    const form = new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: req.session.refreshToken,
      client_id: process.env.CLIENT_ID
    });
    const headers = { 'Content-Type': 'application/x-www-form-urlencoded' };
    if (process.env.CLIENT_SECRET) {
      headers['Authorization'] = `Basic ${Buffer.from(`${process.env.CLIENT_ID}:${process.env.CLIENT_SECRET}`).toString('base64')}`;
    }
    const r = await axios.post(TWITTER_ENDPOINTS.TOKEN_URL, form, { headers });
    const t = r.data;
    req.session.accessToken = t.access_token;
    req.session.refreshToken = t.refresh_token || req.session.refreshToken;
    req.session.expiresIn = t.expires_in;
    return res.json({ ok: true, expires_in: t.expires_in, scope: t.scope });
  } catch (err) {
    console.error('Erro no refresh:', err.response?.data || err.message);
    return res.status(500).json({ error: 'Falha ao renovar token', details: err.response?.data || err.message });
  }
});

app.get('/auth/logout', async (req, res) => {
  try {
    if (req.session.accessToken) {
      try {
        const form = new URLSearchParams({
          token: req.session.accessToken,
          client_id: process.env.CLIENT_ID
        });
        const headers = { 'Content-Type': 'application/x-www-form-urlencoded' };
        if (process.env.CLIENT_SECRET) {
          headers['Authorization'] = `Basic ${Buffer.from(`${process.env.CLIENT_ID}:${process.env.CLIENT_SECRET}`).toString('base64')}`;
        }
        await axios.post(TWITTER_ENDPOINTS.REVOKE_URL, form, { headers });
      } catch (e) {
        console.warn('Aviso: falha ao revogar no servidor do X:', e.response?.data || e.message);
      }
    }
  } finally {
    req.session.destroy(() => res.redirect('/'));
  }
});

// -----------------------------
// APIs (dados do banco) + Sync
// -----------------------------
app.get('/api/me', requireAuth, (req, res) => {
  db.get(`SELECT * FROM users WHERE user_id = ?`, [req.session.userId], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    return res.json({ data: row });
  });
});

app.get('/sync/tweets', requireAuth, async (req, res) => {
  try {
    const params = {
      max_results: '100',
      'tweet.fields': 'created_at,public_metrics,conversation_id,in_reply_to_user_id,lang,source,reply_settings,possibly_sensitive',
      expansions: '',
    };
    const data = await twitterGET(TWITTER_ENDPOINTS.USER_TWEETS(req.session.userId), req.session.accessToken, params);
    const tweets = data?.data || [];
    const count = await insertTweets(req.session.userId, tweets);
    return res.json({ synced: count });
  } catch (err) {
    console.error('Erro ao sincronizar tweets:', err.response?.data || err.message);
    return res.status(500).json({ error: 'Falha ao sincronizar tweets', details: err.response?.data || err.message });
  }
});

app.get('/api/tweets', requireAuth, (req, res) => {
  db.all(`SELECT * FROM tweets WHERE user_id = ? ORDER BY datetime(created_at_twitter) DESC LIMIT 300`, [req.session.userId], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    return res.json({ count: rows.length, data: rows });
  });
});

// Healthcheck e config
app.get('/health', (req, res) => res.json({ ok: true, now: new Date().toISOString() }));
app.get('/config', (req, res) => res.json({
  base_url: BASE_URL,
  redirect_uri: REDIRECT_URI,
  scope: SCOPE.split(' '),
  has_client_secret: !!process.env.CLIENT_SECRET
}));

// -----------------------------
// Start
// -----------------------------
app.listen(PORT, () => {
  console.log(`✅ Server on ${BASE_URL}`);
  console.log(`➡️  OAuth callback: ${REDIRECT_URI}`);
});