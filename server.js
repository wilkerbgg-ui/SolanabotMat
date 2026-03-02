require('dotenv').config();
const express  = require('express');
const Database = require('better-sqlite3');
const Stripe   = require('stripe');
const nodemailer = require('nodemailer');
const crypto   = require('crypto');

const app    = express();
const db     = new Database('./licenses.db');
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

// ── Banco ────────────────────────────────────────────────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS licenses (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    key              TEXT UNIQUE NOT NULL,
    email            TEXT NOT NULL,
    plan             TEXT NOT NULL,
    status           TEXT DEFAULT 'active',
    stripe_session_id TEXT,
    created_at       TEXT DEFAULT (datetime('now')),
    expires_at       TEXT,
    last_seen        TEXT,
    last_version     TEXT,
    last_mode        TEXT
  );
  CREATE TABLE IF NOT EXISTS telemetry (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    license_key      TEXT,
    balance_usdc     REAL,
    profit_accumulated REAL,
    trades_total     INTEGER,
    trades_won       INTEGER,
    is_running       INTEGER,
    mode             TEXT,
    bot_version      TEXT,
    ts               TEXT DEFAULT (datetime('now'))
  );
`);

// ── Helpers ──────────────────────────────────────────────────────────────────
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
async function sendKeyEmail(email, key, plan) {
  const t = nodemailer.createTransport({
    host: process.env.SMTP_HOST, port: 587,
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
  });
  const label = { monthly:'Mensal', annual:'Anual', lifetime:'Vitalício' }[plan];
  await t.sendMail({
    from: `SOL·ARB <${process.env.SMTP_USER}>`, to: email,
    subject: `🤖 Sua chave SOL·ARB — Plano ${label}`,
    html: `
      <div style="font-family:monospace;background:#0a0a0a;color:#00ff88;padding:32px;border-radius:12px;max-width:520px">
        <h2>SOL·ARB Arbitrage Bot</h2>
        <p style="color:#aaa">Plano: <b style="color:#fff">${label}</b></p>
        <p style="color:#aaa">Sua chave de licença:</p>
        <div style="background:#111;border:1px solid #00ff88;border-radius:8px;padding:16px;font-size:22px;letter-spacing:3px;text-align:center">${key}</div>
        <p style="color:#aaa;margin-top:24px;font-size:13px">
          1. Baixe o instalador no site<br>
          2. Execute SOLARB.exe<br>
          3. Adicione LICENSE_KEY=${key} no .env<br>
          4. Configure RPC + PRIVATE_KEY<br>
          5. 🚀 Rode: SOLARB.exe
        </p>
      </div>`
  });
}

// ── Middleware ────────────────────────────────────────────────────────────────
app.use('/api/stripe/webhook', express.raw({ type: 'application/json' }));
app.use(express.json());
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', process.env.SITE_URL || '*');
  res.header('Access-Control-Allow-Headers', 'Content-Type, X-Admin-Token');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});
function adminAuth(req, res, next) {
  if (req.headers['x-admin-token'] !== process.env.ADMIN_TOKEN)
    return res.status(401).json({ error: 'Unauthorized' });
  next();
}

// ── /license/validate — chamado pelo bot no boot ─────────────────────────────
app.post('/license/validate', (req, res) => {
  const { key, bot_version, mode } = req.body;
  if (!key) return res.json({ valid: false, error: 'Missing key' });

  const lic = db.prepare('SELECT * FROM licenses WHERE key = ?').get(key);
  if (!lic)                    return res.json({ valid: false, error: 'Key not found' });
  if (lic.status !== 'active') return res.json({ valid: false, error: `License ${lic.status}` });

  if (lic.expires_at && new Date(lic.expires_at) < new Date()) {
    db.prepare("UPDATE licenses SET status='expired' WHERE key=?").run(key);
    return res.json({ valid: false, error: 'License expired' });
  }

  db.prepare('UPDATE licenses SET last_seen=datetime("now"), last_version=?, last_mode=? WHERE key=?')
    .run(bot_version || null, mode || null, key);

  const daysLeft = lic.expires_at
    ? Math.ceil((new Date(lic.expires_at) - new Date()) / 86400000)
    : null;

  // Aviso de expiração próxima
  const warning = daysLeft !== null && daysLeft <= 7
    ? `⚠️ Sua licença expira em ${daysLeft} dias. Renove em: ${process.env.SITE_URL}`
    : null;

  res.json({
    valid: true,
    user:  { name: lic.email.split('@')[0], email: lic.email },
    plan:  { name: lic.plan, slug: lic.plan, max_capital_usdc: 999999 },
    expires_at: lic.expires_at,
    days_left:  daysLeft,
    warning,
  });
});

// ── /license/heartbeat — chamado a cada 1h pelo bot ──────────────────────────
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

// ── /telemetry/update — estatísticas do bot a cada 1min ──────────────────────
app.post('/telemetry/update', (req, res) => {
  const { key, balance_usdc, profit_accumulated, trades_total,
          trades_won, is_running, mode, bot_version } = req.body;
  if (!key) return res.json({ ok: false });

  const lic = db.prepare('SELECT id FROM licenses WHERE key = ?').get(key);
  if (!lic) return res.json({ ok: false });

  db.prepare(`INSERT INTO telemetry
    (license_key, balance_usdc, profit_accumulated, trades_total, trades_won, is_running, mode, bot_version)
    VALUES (?,?,?,?,?,?,?,?)`)
    .run(key, balance_usdc, profit_accumulated, trades_total, trades_won,
         is_running ? 1 : 0, mode, bot_version);

  res.json({ ok: true });
});

// ── Stripe checkout ───────────────────────────────────────────────────────────
app.post('/api/stripe/checkout', async (req, res) => {
  try {
    const { plan } = req.body;
    const priceMap = {
      monthly:  process.env.STRIPE_PRICE_MONTHLY,
      annual:   process.env.STRIPE_PRICE_ANNUAL,
      lifetime: process.env.STRIPE_PRICE_LIFETIME,
    };
    if (!priceMap[plan]) return res.status(400).json({ error: 'Invalid plan' });

    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      mode: plan === 'lifetime' ? 'payment' : 'subscription',
      line_items: [{ price: priceMap[plan], quantity: 1 }],
      metadata: { price_id: priceMap[plan] },
      success_url: `${process.env.SITE_URL}/success.html`,
      cancel_url:  `${process.env.SITE_URL}/#pricing`,
    });
    res.json({ url: session.url });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Stripe webhook → gera key + envia email ───────────────────────────────────
app.post('/api/stripe/webhook', async (req, res) => {
  let event;
  try {
    event = stripe.webhooks.constructEvent(
      req.body, req.headers['stripe-signature'], process.env.STRIPE_WEBHOOK_SECRET
    );
  } catch (e) { return res.status(400).send(`Webhook Error: ${e.message}`); }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const email   = session.customer_details?.email;
    const plan    = planFromPriceId(session.metadata?.price_id);
    const key     = generateKey();

    db.prepare('INSERT INTO licenses (key, email, plan, expires_at, stripe_session_id) VALUES (?,?,?,?,?)')
      .run(key, email, plan, expiresAt(plan), session.id);

    try { await sendKeyEmail(email, key, plan); }
    catch (e) { console.error('Email error:', e.message); }

    console.log(`✅ [${plan}] ${email} → ${key}`);
  }
  res.json({ received: true });
});

// ── Admin ─────────────────────────────────────────────────────────────────────
app.get('/api/admin/licenses', adminAuth, (req, res) => {
  res.json(db.prepare('SELECT * FROM licenses ORDER BY created_at DESC').all());
});
app.get('/api/admin/telemetry/:key', adminAuth, (req, res) => {
  res.json(db.prepare('SELECT * FROM telemetry WHERE license_key=? ORDER BY ts DESC LIMIT 100').all(req.params.key));
});
app.post('/api/admin/revoke', adminAuth, (req, res) => {
  db.prepare("UPDATE licenses SET status='suspended' WHERE key=?").run(req.body.key);
  res.json({ ok: true });
});
app.post('/api/admin/create-manual', adminAuth, (req, res) => {
  const { email, plan } = req.body;
  const key = generateKey();
  db.prepare('INSERT INTO licenses (key, email, plan, expires_at) VALUES (?,?,?,?)').run(key, email, plan, expiresAt(plan));
  res.json({ ok: true, key });
});

app.listen(process.env.PORT || 4000, () => console.log(`🔑 License server :${process.env.PORT || 4000}`));