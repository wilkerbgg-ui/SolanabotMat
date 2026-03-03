'use strict';
require('dotenv').config();

const express    = require('express');
const Database   = require('better-sqlite3');
const Stripe     = require('stripe');
const nodemailer = require('nodemailer');
const crypto     = require('crypto');

const app    = express();
const db     = new Database('./licenses.db');
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

// ─── Banco de dados ───────────────────────────────────────────────────────────

db.exec(`
  CREATE TABLE IF NOT EXISTS licenses (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    key               TEXT UNIQUE NOT NULL,
    email             TEXT NOT NULL,
    plan              TEXT NOT NULL,
    status            TEXT DEFAULT 'active',
    stripe_session_id TEXT,
    created_at        TEXT DEFAULT (datetime('now')),
    expires_at        TEXT,
    last_seen         TEXT,
    last_version      TEXT,
    last_mode         TEXT
  );

  CREATE TABLE IF NOT EXISTS telemetry (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    license_key         TEXT NOT NULL,
    balance_usdc        REAL,
    balance_sol         REAL,
    capital_base        REAL,
    profit_accumulated  REAL,
    trades_total        INTEGER,
    trades_won          INTEGER,
    trades_today        INTEGER,
    profit_today        REAL,
    is_running          INTEGER,
    mode                TEXT,
    bot_version         TEXT,
    rpc_status          TEXT,
    circuit_breaker     INTEGER,
    last_trade_at       TEXT,
    ts                  TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS activation_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    license_key TEXT,
    action      TEXT,
    ip          TEXT,
    meta        TEXT,
    ts          TEXT DEFAULT (datetime('now'))
  );
`);

// ─── Helpers ──────────────────────────────────────────────────────────────────

function generateKey() {
  const seg = () => crypto.randomBytes(2).toString('hex').toUpperCase();
  return `SARB-${seg()}-${seg()}-${seg()}-${seg()}`;
}

function expiresAt(plan) {
  if (plan === 'lifetime') return null;
  const d = new Date();
  if (plan === 'monthly') d.setMonth(d.getMonth() + 1);
  if (plan === 'annual')  d.setFullYear(d.getFullYear() + 1);
  return d.toISOString();
}

function planFromPriceId(priceId) {
  return {
    [process.env.STRIPE_PRICE_MONTHLY]:  'monthly',
    [process.env.STRIPE_PRICE_ANNUAL]:   'annual',
    [process.env.STRIPE_PRICE_LIFETIME]: 'lifetime',
  }[priceId] || 'monthly';
}

function calcDaysLeft(expiresAt) {
  if (!expiresAt) return null;
  return Math.ceil((new Date(expiresAt) - new Date()) / 86_400_000);
}

async function sendKeyEmail(email, key, plan) {
  const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST || 'smtp.gmail.com',
    port: Number(process.env.SMTP_PORT) || 587,
    secure: false,
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
  });

  const label    = { monthly: 'Mensal', annual: 'Anual', lifetime: 'Vitalício' }[plan] || plan;
  const siteUrl  = process.env.SITE_URL || 'https://taurus.enduranceserver.com.br';

  await transporter.sendMail({
    from: `SOL·ARB <${process.env.SMTP_USER}>`,
    to: email,
    subject: `🤖 Sua chave SOL·ARB — Plano ${label}`,
    html: `
      <div style="font-family:monospace;background:#0a0a0a;color:#00ff88;padding:32px;border-radius:12px;max-width:540px;margin:0 auto">
        <h2 style="margin:0 0 8px">SOL·ARB Arbitrage Bot</h2>
        <p style="color:#556677;margin:0 0 24px">Plano: <strong style="color:#fff">${label}</strong></p>
        <p style="color:#aabbcc;margin:0 0 8px">Sua chave de licença:</p>
        <div style="background:#111;border:1px solid #00ff88;border-radius:8px;padding:18px;font-size:22px;letter-spacing:3px;text-align:center;color:#00ff88">
          ${key}
        </div>
        <div style="background:#0d2a1a;border:1px solid #00ff8830;border-radius:8px;padding:20px;margin:24px 0;color:#aabbcc;font-size:14px;line-height:2">
          <strong style="color:#00ff88">📥 Como ativar:</strong><br>
          1. Baixe o <strong style="color:#fff">SOLARB.exe</strong> no site<br>
          2. Crie um arquivo <strong style="color:#fff">.env</strong> na mesma pasta<br>
          3. Adicione <strong style="color:#fff">LICENSE_KEY=${key}</strong> no .env<br>
          4. Configure seu RPC e PRIVATE_KEY no .env<br>
          5. Execute o SOLARB.exe — o bot valida e inicia 🚀
        </div>
        <p style="color:#334455;font-size:12px;margin:0">
          Guarde esta chave em local seguro.<br>
          Suporte: <a href="${siteUrl}" style="color:#00ff88">${siteUrl}</a>
        </p>
      </div>
    `,
  });
}

// ─── Middleware ───────────────────────────────────────────────────────────────

app.use('/api/stripe/webhook', express.raw({ type: 'application/json' }));
app.use(express.json());

app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', process.env.SITE_URL || '*');
  res.header('Access-Control-Allow-Headers', 'Content-Type, X-Admin-Token');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

function adminAuth(req, res, next) {
  const token = req.headers['x-admin-token'];
  if (!token || token !== process.env.ADMIN_TOKEN) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

// ─── Health check ─────────────────────────────────────────────────────────────

app.get('/health', (req, res) => {
  res.json({ ok: true, ts: new Date().toISOString() });
});

// ─── /license/validate ───────────────────────────────────────────────────────

app.post('/license/validate', (req, res) => {
  const { key, bot_version, mode } = req.body;

  if (!key) return res.json({ valid: false, error: 'Missing key' });

  const lic = db.prepare('SELECT * FROM licenses WHERE key = ?').get(key);

  if (!lic) {
    db.prepare("INSERT INTO activation_log(license_key, action, ip, meta) VALUES(?,?,?,?)").run(key, 'validate_not_found', req.ip, null);
    return res.json({ valid: false, error: 'Key not found' });
  }

  if (lic.status !== 'active') {
    return res.json({ valid: false, error: `License ${lic.status}` });
  }

  if (lic.expires_at && new Date(lic.expires_at) < new Date()) {
    db.prepare("UPDATE licenses SET status='expired' WHERE key=?").run(key);
    return res.json({ valid: false, error: 'License expired' });
  }

  db.prepare('UPDATE licenses SET last_seen=datetime("now"), last_version=?, last_mode=? WHERE key=?')
    .run(bot_version || null, mode || null, key);

  db.prepare("INSERT INTO activation_log(license_key, action, ip, meta) VALUES(?,?,?,?)")
    .run(key, 'validated', req.ip, JSON.stringify({ bot_version, mode }));

  const days = calcDaysLeft(lic.expires_at);
  const warning = days !== null && days <= 7
    ? `⚠️ Sua licença expira em ${days} dias. Renove em: ${process.env.SITE_URL}`
    : null;

  res.json({
    valid:      true,
    user:       { name: lic.email.split('@')[0], email: lic.email },
    plan:       { name: lic.plan, slug: lic.plan, max_capital_usdc: 999999 },
    expires_at: lic.expires_at,
    days_left:  days,
    warning,
  });
});

// ─── /license/heartbeat ──────────────────────────────────────────────────────

app.post('/license/heartbeat', (req, res) => {
  const { key } = req.body;

  if (!key) return res.json({ shutdown: false });

  const lic = db.prepare('SELECT * FROM licenses WHERE key = ?').get(key);

  if (!lic || lic.status !== 'active') return res.json({ shutdown: true });

  if (lic.expires_at && new Date(lic.expires_at) < new Date()) {
    db.prepare("UPDATE licenses SET status='expired' WHERE key=?").run(key);
    return res.json({ shutdown: true });
  }

  db.prepare('UPDATE licenses SET last_seen=datetime("now") WHERE key=?').run(key);
  res.json({ shutdown: false });
});

// ─── /telemetry/update ───────────────────────────────────────────────────────

app.post('/telemetry/update', (req, res) => {
  const {
    key, balance_usdc, balance_sol, capital_base, profit_accumulated,
    trades_total, trades_won, trades_today, profit_today,
    is_running, mode, bot_version, rpc_status, circuit_breaker, last_trade_at,
  } = req.body;

  if (!key) return res.json({ ok: false, error: 'Missing key' });

  const lic = db.prepare('SELECT id FROM licenses WHERE key = ? AND status = "active"').get(key);
  if (!lic) return res.json({ ok: false, error: 'Invalid key' });

  db.prepare(`
    INSERT INTO telemetry
      (license_key, balance_usdc, balance_sol, capital_base, profit_accumulated,
       trades_total, trades_won, trades_today, profit_today,
       is_running, mode, bot_version, rpc_status, circuit_breaker, last_trade_at)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
  `).run(
    key, balance_usdc, balance_sol, capital_base, profit_accumulated,
    trades_total, trades_won, trades_today, profit_today,
    is_running ? 1 : 0, mode, bot_version, rpc_status,
    circuit_breaker ? 1 : 0, last_trade_at
  );

  // Mantém últimas 1440 entradas por key (~1 dia)
  db.prepare(`
    DELETE FROM telemetry WHERE license_key = ? AND id NOT IN (
      SELECT id FROM telemetry WHERE license_key = ? ORDER BY ts DESC LIMIT 1440
    )
  `).run(key, key);

  res.json({ ok: true });
});

// ─── Stripe: checkout ────────────────────────────────────────────────────────

app.post('/api/stripe/checkout', async (req, res) => {
  try {
    const { plan } = req.body;
    const priceMap = {
      monthly:  process.env.STRIPE_PRICE_MONTHLY,
      annual:   process.env.STRIPE_PRICE_ANNUAL,
      lifetime: process.env.STRIPE_PRICE_LIFETIME,
    };

    if (!priceMap[plan]) return res.status(400).json({ error: 'Plano inválido' });

    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      mode: plan === 'lifetime' ? 'payment' : 'subscription',
      line_items: [{ price: priceMap[plan], quantity: 1 }],
      metadata: { price_id: priceMap[plan] },
      success_url: `${process.env.SITE_URL}/success.html`,
      cancel_url:  `${process.env.SITE_URL}/#pricing`,
    });

    res.json({ url: session.url });
  } catch (err) {
    console.error('Stripe checkout error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ─── Stripe: webhook ─────────────────────────────────────────────────────────

app.post('/api/stripe/webhook', async (req, res) => {
  let event;

  try {
    event = stripe.webhooks.constructEvent(
      req.body,
      req.headers['stripe-signature'],
      process.env.STRIPE_WEBHOOK_SECRET
    );
  } catch (err) {
    console.error('Webhook signature error:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const email   = session.customer_details?.email;
    const plan    = planFromPriceId(session.metadata?.price_id);
    const key     = generateKey();

    const existing = db.prepare('SELECT id FROM licenses WHERE stripe_session_id = ?').get(session.id);
    if (existing) {
      console.log(`⚠️  Webhook duplicado ignorado: ${session.id}`);
      return res.json({ received: true });
    }

    db.prepare('INSERT INTO licenses (key, email, plan, expires_at, stripe_session_id) VALUES (?,?,?,?,?)')
      .run(key, email, plan, expiresAt(plan), session.id);

    try {
      await sendKeyEmail(email, key, plan);
      console.log(`✅ Licença criada [${plan}] ${email} → ${key}`);
    } catch (e) {
      console.error(`❌ Erro ao enviar email para ${email}:`, e.message);
    }
  }

  if (event.type === 'customer.subscription.deleted') {
    const sub = event.data.object;
    const lic = db.prepare("SELECT * FROM licenses WHERE stripe_session_id = ?").get(sub.id);
    if (lic) {
      db.prepare("UPDATE licenses SET status='suspended' WHERE key=?").run(lic.key);
      console.log(`⛔ Assinatura cancelada — licença suspensa: ${lic.key}`);
    }
  }

  res.json({ received: true });
});

// ─── Admin ────────────────────────────────────────────────────────────────────

app.get('/api/admin/licenses', adminAuth, (req, res) => {
  res.json(db.prepare('SELECT * FROM licenses ORDER BY created_at DESC').all());
});

app.get('/api/admin/telemetry/:key', adminAuth, (req, res) => {
  res.json(db.prepare('SELECT * FROM telemetry WHERE license_key = ? ORDER BY ts DESC LIMIT 200').all(req.params.key));
});

app.get('/api/admin/logs', adminAuth, (req, res) => {
  res.json(db.prepare('SELECT * FROM activation_log ORDER BY ts DESC LIMIT 500').all());
});

app.post('/api/admin/revoke', adminAuth, (req, res) => {
  if (!req.body.key) return res.status(400).json({ error: 'Missing key' });
  db.prepare("UPDATE licenses SET status='suspended' WHERE key=?").run(req.body.key);
  res.json({ ok: true });
});

app.post('/api/admin/reactivate', adminAuth, (req, res) => {
  if (!req.body.key) return res.status(400).json({ error: 'Missing key' });
  db.prepare("UPDATE licenses SET status='active' WHERE key=?").run(req.body.key);
  res.json({ ok: true });
});

app.post('/api/admin/create-manual', adminAuth, (req, res) => {
  const { email, plan } = req.body;
  if (!email || !plan) return res.status(400).json({ error: 'Missing email or plan' });
  const key = generateKey();
  db.prepare('INSERT INTO licenses (key, email, plan, expires_at) VALUES (?,?,?,?)').run(key, email, plan, expiresAt(plan));
  console.log(`🔧 Licença manual [${plan}] ${email} → ${key}`);
  res.json({ ok: true, key, expires_at: expiresAt(plan) });
});

// ─── Start ────────────────────────────────────────────────────────────────────

const PORT = Number(process.env.PORT) || 4000;
app.listen(PORT, () => {
  console.log(`🔑 SOL·ARB License Server na porta ${PORT}`);
  console.log(`   Site:   ${process.env.SITE_URL   || '⚠️  não configurado'}`);
  console.log(`   Stripe: ${process.env.STRIPE_SECRET_KEY ? '✅' : '❌ faltando'}`);
  console.log(`   Email:  ${process.env.SMTP_USER        ? '✅' : '❌ faltando'}`);
});
