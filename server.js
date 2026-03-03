'use strict';
require('dotenv').config();

const express    = require('express');
const { Pool }   = require('pg');
const Stripe     = require('stripe');
const nodemailer = require('nodemailer');
const crypto     = require('crypto');

const app  = express();
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes('render.com')
    ? { rejectUnauthorized: false }
    : false,
});

function getStripe() {
  if (!process.env.STRIPE_SECRET_KEY) throw new Error('STRIPE_SECRET_KEY não configurado');
  return new Stripe(process.env.STRIPE_SECRET_KEY);
}

// ─── Banco de dados ───────────────────────────────────────────────────────────

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id         SERIAL PRIMARY KEY,
      name       TEXT NOT NULL,
      email      TEXT UNIQUE NOT NULL,
      password   TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS licenses (
      id                SERIAL PRIMARY KEY,
      user_id           INTEGER REFERENCES users(id),
      key               TEXT UNIQUE NOT NULL,
      email             TEXT NOT NULL,
      plan              TEXT NOT NULL,
      plan_name         TEXT NOT NULL,
      status            TEXT DEFAULT 'active',
      stripe_session_id TEXT,
      created_at        TIMESTAMP DEFAULT NOW(),
      expires_at        TIMESTAMP,
      last_seen         TIMESTAMP,
      last_version      TEXT,
      last_mode         TEXT
    );

    CREATE TABLE IF NOT EXISTS telemetry (
      id                 SERIAL PRIMARY KEY,
      license_key        TEXT NOT NULL,
      balance_usdc       NUMERIC,
      balance_sol        NUMERIC,
      capital_base       NUMERIC,
      profit_accumulated NUMERIC,
      trades_total       INTEGER,
      trades_won         INTEGER,
      trades_today       INTEGER,
      profit_today       NUMERIC,
      is_running         BOOLEAN,
      mode               TEXT,
      bot_version        TEXT,
      rpc_status         TEXT,
      circuit_breaker    BOOLEAN,
      last_trade_at      TIMESTAMP,
      recorded_at        TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS activation_log (
      id          SERIAL PRIMARY KEY,
      license_key TEXT,
      action      TEXT,
      ip          TEXT,
      meta        TEXT,
      ts          TIMESTAMP DEFAULT NOW()
    );
  `);
  console.log('✅ Banco de dados inicializado');
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function generateKey() {
  const seg = () => crypto.randomBytes(2).toString('hex').toUpperCase();
  return `SARB-${seg()}-${seg()}-${seg()}-${seg()}`;
}

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

function hashPassword(password) {
  return crypto.createHash('sha256')
    .update(password + (process.env.PASS_SALT || 'solarb2025'))
    .digest('hex');
}

function expiresAt(plan) {
  if (plan === 'lifetime') return null;
  const d = new Date();
  if (plan === 'monthly')    d.setMonth(d.getMonth() + 1);
  if (plan === 'quarterly')  d.setMonth(d.getMonth() + 3);
  if (plan === 'semiannual') d.setMonth(d.getMonth() + 6);
  if (plan === 'annual')     d.setFullYear(d.getFullYear() + 1);
  return d;
}

function planName(plan) {
  return {
    monthly:    'Mensal',
    quarterly:  'Trimestral',
    semiannual: 'Semestral',
    annual:     'Anual',
    lifetime:   'Vitalício',
  }[plan] || plan;
}

function planFromPriceId(priceId) {
  return {
    [process.env.STRIPE_PRICE_MONTHLY]:    'monthly',
    [process.env.STRIPE_PRICE_QUARTERLY]:  'quarterly',
    [process.env.STRIPE_PRICE_SEMIANNUAL]: 'semiannual',
    [process.env.STRIPE_PRICE_ANNUAL]:     'annual',
    [process.env.STRIPE_PRICE_LIFETIME]:   'lifetime',
  }[priceId] || 'monthly';
}

function calcDaysLeft(exp) {
  if (!exp) return null;
  return Math.ceil((new Date(exp) - new Date()) / 86_400_000);
}

// Token store em memória — 24h
const tokenStore = new Map();

function createSession(userId) {
  const token = generateToken();
  tokenStore.set(token, userId);
  setTimeout(() => tokenStore.delete(token), 24 * 60 * 60 * 1000);
  return token;
}

async function sendKeyEmail(email, key, plan) {
  if (!process.env.SMTP_USER) {
    console.log(`📧 [SMTP não configurado] Key para ${email}: ${key}`);
    return;
  }
  const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST || 'smtp.gmail.com',
    port: Number(process.env.SMTP_PORT) || 587,
    secure: false,
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
  });
  const label   = planName(plan);
  const siteUrl = process.env.SITE_URL || 'https://cotam2.com';
  await transporter.sendMail({
    from: `SOL·ARB <${process.env.SMTP_USER}>`,
    to: email,
    subject: `🤖 Sua chave SOL·ARB — Plano ${label}`,
    html: `
      <div style="font-family:monospace;background:#0a0a0a;color:#00ff88;padding:32px;border-radius:12px;max-width:540px;margin:0 auto">
        <h2 style="margin:0 0 8px">SOL·ARB Arbitrage Bot</h2>
        <p style="color:#556677;margin:0 0 24px">Plano: <strong style="color:#fff">${label}</strong></p>
        <p style="color:#aabbcc;margin:0 0 8px">Sua chave de licença:</p>
        <div style="background:#111;border:1px solid #00ff88;border-radius:8px;padding:18px;font-size:22px;letter-spacing:3px;text-align:center;color:#00ff88">${key}</div>
        <div style="background:#0d2a1a;border:1px solid #00ff8830;border-radius:8px;padding:20px;margin:24px 0;color:#aabbcc;font-size:14px;line-height:2">
          <strong style="color:#00ff88">📥 Como ativar:</strong><br>
          1. Baixe o <strong style="color:#fff">SOLARB.exe</strong> no site<br>
          2. Crie um arquivo <strong style="color:#fff">.env</strong> na mesma pasta<br>
          3. Adicione <strong style="color:#fff">LICENSE_KEY=${key}</strong> no .env<br>
          4. Configure seu RPC e PRIVATE_KEY<br>
          5. Execute o SOLARB.exe 🚀<br>
          6. Painel: <a href="${siteUrl}/dashboard.html" style="color:#00ff88">${siteUrl}/dashboard.html</a>
        </div>
        <p style="color:#334455;font-size:12px">Suporte: <a href="${siteUrl}" style="color:#00ff88">${siteUrl}</a></p>
      </div>`,
  });
}

// ─── Middleware ───────────────────────────────────────────────────────────────

app.use('/api/stripe/webhook', express.raw({ type: 'application/json' }));
app.use(express.json());

app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Admin-Token');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer '))
    return res.status(401).json({ error: 'Token não fornecido' });
  const userId = tokenStore.get(header.slice(7));
  if (!userId) return res.status(401).json({ error: 'Token inválido ou expirado' });
  req.userId = userId;
  next();
}

function adminAuth(req, res, next) {
  if (req.headers['x-admin-token'] !== process.env.ADMIN_TOKEN)
    return res.status(401).json({ error: 'Unauthorized' });
  next();
}

// ─── Health ───────────────────────────────────────────────────────────────────

app.get('/health', (req, res) => res.json({ ok: true, ts: new Date().toISOString() }));

// ─── AUTH: Register ───────────────────────────────────────────────────────────

app.post('/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password)
      return res.status(400).json({ error: 'Preencha todos os campos' });
    if (password.length < 8)
      return res.status(400).json({ error: 'Senha deve ter mínimo 8 caracteres' });

    const existing = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (existing.rows.length > 0)
      return res.status(400).json({ error: 'Email já cadastrado' });

    const result = await pool.query(
      'INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING id',
      [name, email, hashPassword(password)]
    );
    const userId = result.rows[0].id;
    const token  = createSession(userId);

    // Vincula licença existente se comprou antes de criar conta
    const licResult = await pool.query(
      "SELECT * FROM licenses WHERE email = $1 AND status = 'active' ORDER BY created_at DESC LIMIT 1",
      [email]
    );
    const license = licResult.rows[0] || null;
    if (license && !license.user_id) {
      await pool.query('UPDATE licenses SET user_id = $1 WHERE id = $2', [userId, license.id]);
    }

    res.json({ token, user: { id: userId, name, email }, license });
  } catch (err) {
    console.error('Register error:', err.message);
    res.status(500).json({ error: 'Erro interno no servidor' });
  }
});

// ─── AUTH: Login ──────────────────────────────────────────────────────────────

app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ error: 'Preencha email e senha' });

    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user   = result.rows[0];
    if (!user || user.password !== hashPassword(password))
      return res.status(401).json({ error: 'Email ou senha incorretos' });

    const token = createSession(user.id);
    const licResult = await pool.query(
      "SELECT * FROM licenses WHERE (user_id = $1 OR email = $2) AND status = 'active' ORDER BY created_at DESC LIMIT 1",
      [user.id, email]
    );
    const license = licResult.rows[0] || null;

    res.json({ token, user: { id: user.id, name: user.name, email: user.email }, license });
  } catch (err) {
    console.error('Login error:', err.message);
    res.status(500).json({ error: 'Erro interno no servidor' });
  }
});

// ─── AUTH: Me ─────────────────────────────────────────────────────────────────

app.get('/auth/me', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, name, email FROM users WHERE id = $1', [req.userId]);
    const user   = result.rows[0];
    if (!user) return res.status(404).json({ error: 'Usuário não encontrado' });

    const licResult = await pool.query(
      "SELECT * FROM licenses WHERE (user_id = $1 OR email = $2) AND status = 'active' ORDER BY created_at DESC LIMIT 1",
      [user.id, user.email]
    );
    res.json({ user, license: licResult.rows[0] || null });
  } catch (err) {
    console.error('Me error:', err.message);
    res.status(500).json({ error: 'Erro interno no servidor' });
  }
});

// ─── TELEMETRY: My ───────────────────────────────────────────────────────────

app.get('/telemetry/my', authMiddleware, async (req, res) => {
  try {
    const userResult = await pool.query('SELECT email FROM users WHERE id = $1', [req.userId]);
    const user = userResult.rows[0];
    if (!user) return res.status(404).json({ error: 'Usuário não encontrado' });

    const licResult = await pool.query(
      "SELECT key FROM licenses WHERE (user_id = $1 OR email = $2) AND status = 'active' ORDER BY created_at DESC LIMIT 1",
      [req.userId, user.email]
    );
    const license = licResult.rows[0];
    if (!license) return res.json({ telemetry: null, history: [] });

    const telResult = await pool.query(
      'SELECT * FROM telemetry WHERE license_key = $1 ORDER BY recorded_at DESC LIMIT 1',
      [license.key]
    );
    const histResult = await pool.query(
      'SELECT balance_usdc, recorded_at FROM telemetry WHERE license_key = $1 ORDER BY recorded_at DESC LIMIT 360',
      [license.key]
    );

    res.json({
      telemetry: telResult.rows[0] || null,
      history:   histResult.rows.reverse(),
    });
  } catch (err) {
    console.error('Telemetry/my error:', err.message);
    res.status(500).json({ error: 'Erro interno no servidor' });
  }
});

// ─── LICENSE: Validate ────────────────────────────────────────────────────────

app.post('/license/validate', async (req, res) => {
  try {
    const { key, bot_version, mode } = req.body;
    if (!key) return res.json({ valid: false, error: 'Missing key' });

    const result = await pool.query('SELECT * FROM licenses WHERE key = $1', [key]);
    const lic    = result.rows[0];
    if (!lic) return res.json({ valid: false, error: 'Key not found' });
    if (lic.status !== 'active') return res.json({ valid: false, error: `License ${lic.status}` });

    if (lic.expires_at && new Date(lic.expires_at) < new Date()) {
      await pool.query("UPDATE licenses SET status = 'expired' WHERE key = $1", [key]);
      return res.json({ valid: false, error: 'License expired' });
    }

    await pool.query(
      'UPDATE licenses SET last_seen = NOW(), last_version = $1, last_mode = $2 WHERE key = $3',
      [bot_version || null, mode || null, key]
    );

    const days    = calcDaysLeft(lic.expires_at);
    const warning = days !== null && days <= 7
      ? `⚠️ Sua licença expira em ${days} dias. Renove em: ${process.env.SITE_URL}`
      : null;

    res.json({
      valid:      true,
      user:       { name: lic.email.split('@')[0], email: lic.email },
      plan:       { name: lic.plan_name || lic.plan, slug: lic.plan, max_capital_usdc: 999999 },
      expires_at: lic.expires_at,
      days_left:  days,
      warning,
    });
  } catch (err) {
    console.error('Validate error:', err.message);
    res.status(500).json({ valid: false, error: 'Erro interno' });
  }
});

// ─── LICENSE: Heartbeat ───────────────────────────────────────────────────────

app.post('/license/heartbeat', async (req, res) => {
  try {
    const { key } = req.body;
    if (!key) return res.json({ shutdown: false });

    const result = await pool.query('SELECT * FROM licenses WHERE key = $1', [key]);
    const lic    = result.rows[0];
    if (!lic || lic.status !== 'active') return res.json({ shutdown: true });

    if (lic.expires_at && new Date(lic.expires_at) < new Date()) {
      await pool.query("UPDATE licenses SET status = 'expired' WHERE key = $1", [key]);
      return res.json({ shutdown: true });
    }

    await pool.query('UPDATE licenses SET last_seen = NOW() WHERE key = $1', [key]);
    res.json({ shutdown: false });
  } catch (err) {
    res.json({ shutdown: false });
  }
});

// ─── TELEMETRY: Update ────────────────────────────────────────────────────────

app.post('/telemetry/update', async (req, res) => {
  try {
    const {
      key, balance_usdc, balance_sol, capital_base, profit_accumulated,
      trades_total, trades_won, trades_today, profit_today,
      is_running, mode, bot_version, rpc_status, circuit_breaker, last_trade_at,
    } = req.body;

    if (!key) return res.json({ ok: false, error: 'Missing key' });

    const licResult = await pool.query(
      "SELECT id FROM licenses WHERE key = $1 AND status = 'active'", [key]
    );
    if (licResult.rows.length === 0) return res.json({ ok: false, error: 'Invalid key' });

    await pool.query(`
      INSERT INTO telemetry
        (license_key, balance_usdc, balance_sol, capital_base, profit_accumulated,
         trades_total, trades_won, trades_today, profit_today,
         is_running, mode, bot_version, rpc_status, circuit_breaker, last_trade_at)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
    `, [
      key, balance_usdc, balance_sol, capital_base, profit_accumulated,
      trades_total, trades_won, trades_today, profit_today,
      is_running, mode, bot_version, rpc_status, circuit_breaker,
      last_trade_at || null,
    ]);

    // Mantém últimas 1440 entradas por key
    await pool.query(`
      DELETE FROM telemetry WHERE license_key = $1 AND id NOT IN (
        SELECT id FROM telemetry WHERE license_key = $1 ORDER BY recorded_at DESC LIMIT 1440
      )
    `, [key]);

    res.json({ ok: true });
  } catch (err) {
    console.error('Telemetry update error:', err.message);
    res.status(500).json({ ok: false });
  }
});

// ─── STRIPE: Checkout ────────────────────────────────────────────────────────

app.post('/api/stripe/checkout', async (req, res) => {
  try {
    const stripe = getStripe();
    const { plan } = req.body;
    const priceMap = {
      monthly:    process.env.STRIPE_PRICE_MONTHLY,
      quarterly:  process.env.STRIPE_PRICE_QUARTERLY,
      semiannual: process.env.STRIPE_PRICE_SEMIANNUAL,
      annual:     process.env.STRIPE_PRICE_ANNUAL,
      lifetime:   process.env.STRIPE_PRICE_LIFETIME,
    };
    if (!priceMap[plan]) return res.status(400).json({ error: 'Plano inválido' });

    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      mode: plan === 'lifetime' ? 'payment' : 'subscription',
      allow_promotion_codes: true,
      line_items: [{ price: priceMap[plan], quantity: 1 }],
      metadata: { price_id: priceMap[plan] },
      success_url: `${process.env.SITE_URL}/success.html`,
      cancel_url:  `${process.env.SITE_URL}/#planos`,
    });
    res.json({ url: session.url });
  } catch (err) {
    console.error('Stripe checkout error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ─── STRIPE: Webhook ─────────────────────────────────────────────────────────

app.post('/api/stripe/webhook', async (req, res) => {
  try {
    const stripe = getStripe();
    let event;
    try {
      event = stripe.webhooks.constructEvent(
        req.body, req.headers['stripe-signature'], process.env.STRIPE_WEBHOOK_SECRET
      );
    } catch (err) {
      return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    if (event.type === 'checkout.session.completed') {
      const session = event.data.object;
      const email   = session.customer_details?.email;
      const plan    = planFromPriceId(session.metadata?.price_id);
      const key     = generateKey();

      const dup = await pool.query('SELECT id FROM licenses WHERE stripe_session_id = $1', [session.id]);
      if (dup.rows.length > 0) return res.json({ received: true });

      const userResult = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
      const userId     = userResult.rows[0]?.id || null;

      await pool.query(
        'INSERT INTO licenses (user_id, key, email, plan, plan_name, expires_at, stripe_session_id) VALUES ($1,$2,$3,$4,$5,$6,$7)',
        [userId, key, email, plan, planName(plan), expiresAt(plan), session.id]
      );

      try {
        await sendKeyEmail(email, key, plan);
        console.log(`✅ Licença [${plan}] ${email} → ${key}`);
      } catch (e) {
        console.error(`❌ Email error: ${e.message}`);
      }
    }

    if (event.type === 'customer.subscription.deleted') {
      await pool.query(
        "UPDATE licenses SET status = 'suspended' WHERE stripe_session_id = $1",
        [event.data.object.id]
      );
    }

    res.json({ received: true });
  } catch (err) {
    console.error('Webhook error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ─── ADMIN ────────────────────────────────────────────────────────────────────

app.get('/api/admin/licenses', adminAuth, async (req, res) => {
  try { res.json((await pool.query('SELECT * FROM licenses ORDER BY created_at DESC')).rows); }
  catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/admin/users', adminAuth, async (req, res) => {
  try { res.json((await pool.query('SELECT id, name, email, created_at FROM users ORDER BY created_at DESC')).rows); }
  catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/admin/telemetry/:key', adminAuth, async (req, res) => {
  try { res.json((await pool.query('SELECT * FROM telemetry WHERE license_key = $1 ORDER BY recorded_at DESC LIMIT 200', [req.params.key])).rows); }
  catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/admin/logs', adminAuth, async (req, res) => {
  try { res.json((await pool.query('SELECT * FROM activation_log ORDER BY ts DESC LIMIT 500')).rows); }
  catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/admin/revoke', adminAuth, async (req, res) => {
  try {
    if (!req.body.key) return res.status(400).json({ error: 'Missing key' });
    await pool.query("UPDATE licenses SET status = 'suspended' WHERE key = $1", [req.body.key]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/admin/reactivate', adminAuth, async (req, res) => {
  try {
    if (!req.body.key) return res.status(400).json({ error: 'Missing key' });
    await pool.query("UPDATE licenses SET status = 'active' WHERE key = $1", [req.body.key]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/admin/create-manual', adminAuth, async (req, res) => {
  try {
    const { email, plan } = req.body;
    if (!email || !plan) return res.status(400).json({ error: 'Missing email or plan' });
    const key        = generateKey();
    const userResult = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    const userId     = userResult.rows[0]?.id || null;
    const exp        = expiresAt(plan);
    await pool.query(
      'INSERT INTO licenses (user_id, key, email, plan, plan_name, expires_at) VALUES ($1,$2,$3,$4,$5,$6)',
      [userId, key, email, plan, planName(plan), exp]
    );
    console.log(`🔧 Licença manual [${plan}] ${email} → ${key}`);
    res.json({ ok: true, key, expires_at: exp });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── Start ────────────────────────────────────────────────────────────────────

const PORT = Number(process.env.PORT) || 4000;

initDB().then(() => {
  app.listen(PORT, () => {
    console.log(`🔑 SOL·ARB Server na porta ${PORT}`);
    console.log(`   Site:   ${process.env.SITE_URL         || '⚠️  não configurado'}`);
    console.log(`   Stripe: ${process.env.STRIPE_SECRET_KEY ? '✅' : '❌ faltando'}`);
    console.log(`   Email:  ${process.env.SMTP_USER          ? '✅' : '❌ faltando'}`);
    console.log(`   Admin:  ${process.env.ADMIN_TOKEN         ? '✅' : '❌ faltando'}`);
    console.log(`   DB:     ${process.env.DATABASE_URL         ? '✅ PostgreSQL' : '❌ faltando'}`);
  });
}).catch(err => {
  console.error('❌ Falha ao inicializar banco:', err.message);
  process.exit(1);
});
