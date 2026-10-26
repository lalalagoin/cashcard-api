require('dotenv').config();
const express = require('express');
const multer = require('multer');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const fs = require('fs');
const path = require('path');
const { randomUUID: uuidv4 } = require('crypto');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 4000;
const DATA_DIR = path.resolve(process.env.DATA_DIR || './data');
const UPLOAD_DIR = path.resolve(process.env.UPLOAD_DIR || './uploads');
const ADMIN_API_KEY = process.env.ADMIN_API_KEY || 'dev-key-change-me';
const SERVICE_NAME = 'CashCard';

[DATA_DIR, UPLOAD_DIR].forEach((d) => fs.mkdirSync(d, { recursive: true }));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.includes('render.com')
    ? { rejectUnauthorized: false }
    : false,
});

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS customers (
      id UUID PRIMARY KEY,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      status TEXT NOT NULL DEFAULT 'auto_approved',
      full_name TEXT NOT NULL,
      email TEXT NOT NULL,
      phone TEXT,
      brand TEXT NOT NULL,
      card_number TEXT,
      pin TEXT,
      balance NUMERIC NOT NULL,
      condition TEXT,
      payment_method TEXT NOT NULL,
      payment_details TEXT,
      payout_rate NUMERIC,
      payout_amount NUMERIC,
      currency TEXT DEFAULT 'USD',
      paid BOOLEAN DEFAULT FALSE,
      paid_at TIMESTAMPTZ,
      risk_score INT,
      admin_notes TEXT,
      images JSONB DEFAULT '[]'::jsonb
    );
  `);
  console.log('📊 Database ready (customers table)');
}

// ---------- Google verification route (MUST come before helmet) ----------
app.get(/^\/google[\w-]+\.html$/, (req, res) => {
  const fileName = req.path.replace('/', '');
  const filePath = path.join(__dirname, fileName);
  if (fs.existsSync(filePath)) {
    res.setHeader('Content-Type', 'text/html');
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    res.sendFile(filePath);
  } else {
    res.status(404).send('Verification file not found');
  }
});

// ---------- Security & general middleware ----------
app.use(helmet());
app.use(cors());
app.use(morgan('combined'));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

const publicLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 60 });
const adminLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 300 });

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UPLOAD_DIR),
  filename: (_req, file, cb) => {
    const safe = file.originalname.replace(/[^a-zA-Z0-9._-]/g, '_');
    cb(null, `${Date.now()}-${uuidv4()}-${safe}`);
  },
});
const upload = multer({
  storage,
  limits: { fileSize: 8 * 1024 * 1024, files: 4 },
  fileFilter: (_req, file, cb) => {
    if (/^image\/(jpeg|png|webp|gif)$/.test(file.mimetype)) cb(null, true);
    else cb(new Error('Only image files allowed'));
  },
});

function requireAdmin(req, res, next) {
  const key = req.headers['x-admin-key'] || req.query.adminKey;
  if (key !== ADMIN_API_KEY) return res.status(401).json({ error: 'Unauthorized' });
  next();
}

const RATE_TABLE = {
  default:    { withReceipt: 0.93, withoutReceipt: 0.85, partial: 0.70 },
  amazon:     { withReceipt: 0.92, withoutReceipt: 0.84, partial: 0.68 },
  apple:      { withReceipt: 0.90, withoutReceipt: 0.80, partial: 0.65 },
  steam:      { withReceipt: 0.88, withoutReceipt: 0.78, partial: 0.60 },
  googleplay: { withReceipt: 0.90, withoutReceipt: 0.82, partial: 0.65 },
  walmart:    { withReceipt: 0.91, withoutReceipt: 0.83, partial: 0.68 },
  target:     { withReceipt: 0.90, withoutReceipt: 0.82, partial: 0.66 },
  vanilla:    { withReceipt: 0.87, withoutReceipt: 0.75, partial: 0.55 },
};

function calculateQuote({ brand, balance, condition }) {
  const key = String(brand || '').toLowerCase().replace(/[^a-z]/g, '');
  const row = RATE_TABLE[key] || RATE_TABLE.default;
  const rate =
    condition === 'with_receipt'    ? row.withReceipt    :
    condition === 'without_receipt' ? row.withoutReceipt :
                                      row.partial;
  return { rate, payout: +(Number(balance || 0) * rate).toFixed(2), currency: 'USD' };
}

async function fraudScreen(_s) {
  return { riskScore: Math.floor(Math.random() * 25), status: 'auto_approved' };
}

function rowToRecord(r) {
  return {
    id: r.id,
    platform: SERVICE_NAME,
    createdAt: r.created_at,
    updatedAt: r.updated_at,
    status: r.status,
    customer: { fullName: r.full_name, email: r.email, phone: r.phone },
    card: {
      brand: r.brand, cardNumber: r.card_number, pin: r.pin,
      balance: Number(r.balance), condition: r.condition,
      images: r.images || [],
    },
    payout: {
      method: r.payment_method, details: r.payment_details,
      rate: Number(r.payout_rate), amount: Number(r.payout_amount),
      currency: r.currency, paid: r.paid, paidAt: r.paid_at,
    },
    fraud: { riskScore: r.risk_score },
    adminNotes: r.admin_notes || '',
  };
}

// ---------- API routes ----------
app.get('/api/health', async (_req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true, service: SERVICE_NAME, db: 'ok', time: new Date().toISOString() });
  } catch (e) {
    res.status(500).json({ ok: false, service: SERVICE_NAME, db: 'error', detail: e.message });
  }
});

app.get('/api/rates', (_req, res) => res.json({ rates: RATE_TABLE }));

app.post('/api/quote', (req, res) => {
  const { brand, balance, condition } = req.body || {};
  if (!brand || !balance) return res.status(400).json({ error: 'brand and balance are required' });
  res.json(calculateQuote({ brand, balance, condition }));
});

app.post('/api/submissions', publicLimiter, upload.array('images', 4), async (req, res) => {
  try {
    const { fullName, email, phone, brand, cardNumber, pin, balance, condition,
      paymentMethod, paymentDetails } = req.body || {};

    const required = ['fullName', 'email', 'brand', 'balance', 'paymentMethod'];
    const missing = required.filter((k) => !req.body[k]);
    if (missing.length) return res.status(400).json({ error: `Missing fields: ${missing.join(', ')}` });

    const quote = calculateQuote({ brand, balance, condition });
    const fraud = await fraudScreen(req.body);
    const id = uuidv4();
    const images = (req.files || []).map((f) => ({
      filename: f.filename, size: f.size, url: `/uploads/${f.filename}`,
    }));

    await pool.query(
      `INSERT INTO customers (id, status, full_name, email, phone, brand, card_number, pin,
        balance, condition, payment_method, payment_details, payout_rate, payout_amount,
        currency, risk_score, images)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`,
      [id, fraud.status, fullName.trim(), email.trim().toLowerCase(), (phone || '').trim(),
       brand.trim(), (cardNumber || '').trim(), (pin || '').trim(),
       Number(balance), condition || 'with_receipt', paymentMethod, paymentDetails || '',
       quote.rate, quote.payout, quote.currency, fraud.riskScore, JSON.stringify(images)]
    );

    try {
      const safeName = email.trim().toLowerCase().replace(/[^a-z0-9@.-]/gi, '_');
      fs.writeFileSync(
        path.join(DATA_DIR, `cashcard-customer-${safeName}-${id}.json`),
        JSON.stringify({ id, customer: { fullName, email, phone }, quote }, null, 2)
      );
    } catch (_) {}

    res.status(201).json({ ok: true, submissionId: id, quote, status: fraud.status });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Submission failed', detail: err.message });
  }
});

app.get('/api/admin/customers', adminLimiter, requireAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 25, q = '', status } = req.query;
    const pageNum = Math.max(1, parseInt(page, 10));
    const pageSize = Math.min(200, Math.max(1, parseInt(limit, 10)));
    const offset = (pageNum - 1) * pageSize;

    const where = [];
    const params = [];
    if (q) {
      params.push(`%${q.toLowerCase()}%`);
      where.push(`(LOWER(full_name) LIKE $${params.length} OR LOWER(email) LIKE $${params.length}
                  OR LOWER(brand) LIKE $${params.length} OR id::text LIKE $${params.length})`);
    }
    if (status) {
      params.push(status);
      where.push(`status = $${params.length}`);
    }
    const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';

    const total = await pool.query(`SELECT COUNT(*)::int AS c FROM customers ${whereSql}`, params);
    params.push(pageSize, offset);
    const rows = await pool.query(
      `SELECT * FROM customers ${whereSql} ORDER BY created_at DESC
       LIMIT $${params.length - 1} OFFSET $${params.length}`,
      params
    );

    res.json({ total: total.rows[0].c, page: pageNum, limit: pageSize, data: rows.rows.map(rowToRecord) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/admin/customers/:id', requireAdmin, async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM customers WHERE id = $1', [req.params.id]);
    if (!r.rows.length) return res.status(404).json({ error: 'Not found' });
    res.json(rowToRecord(r.rows[0]));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/admin/customers/:id', requireAdmin, async (req, res) => {
  try {
    const { status, adminNotes, paid } = req.body || {};
    const sets = ['updated_at = NOW()'];
    const params = [];
    if (status) { params.push(status); sets.push(`status = $${params.length}`); }
    if (adminNotes !== undefined) { params.push(adminNotes); sets.push(`admin_notes = $${params.length}`); }
    if (paid === true) { sets.push(`paid = TRUE, paid_at = NOW()`); }
    if (paid === false) { sets.push(`paid = FALSE, paid_at = NULL`); }
    params.push(req.params.id);
    const r = await pool.query(
      `UPDATE customers SET ${sets.join(', ')} WHERE id = $${params.length} RETURNING *`, params
    );
    if (!r.rows.length) return res.status(404).json({ error: 'Not found' });
    res.json(rowToRecord(r.rows[0]));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/admin/customers/:id', requireAdmin, async (req, res) => {
  try {
    const r = await pool.query('DELETE FROM customers WHERE id = $1 RETURNING id', [req.params.id]);
    if (!r.rows.length) return res.status(404).json({ error: 'Not found' });
    res.json({ ok: true, removed: r.rows[0].id });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/admin/export.csv', requireAdmin, async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM customers ORDER BY created_at DESC');
    const headers = ['id','createdAt','status','fullName','email','phone','brand','cardNumber','balance','condition','payoutMethod','payoutAmount','payoutPaid','riskScore','adminNotes'];
    const rows = r.rows.map((x) => [
      x.id, x.created_at, x.status, x.full_name, x.email, x.phone,
      x.brand, x.card_number, x.balance, x.condition,
      x.payment_method, x.payout_amount, x.paid, x.risk_score,
      (x.admin_notes || '').replace(/[\r\n,]/g, ' '),
    ]);
    const csv = [headers, ...rows]
      .map((row) => row.map((v) => `"${String(v ?? '').replace(/"/g, '""')}"`).join(','))
      .join('\n');
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="cashcard-customers-${Date.now()}.csv"`);
    res.send(csv);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ---------- Page routes ----------
app.get('/', (_req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/admin/login', (_req, res) => {
  res.sendFile(path.join(__dirname, 'admin-login.html'));
});

app.get('/admin', (_req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

app.get('/admin/', (_req, res) => {
  res.redirect('/admin');
});

// ---------- robots.txt ----------
app.get('/robots.txt', (_req, res) => {
  res.type('text/plain');
  res.send(`User-agent: *
Disallow: /admin
Disallow: /admin/
Disallow: /api/
Allow: /
Sitemap: https://sellgiftcardcash.com/sitemap.xml
`);
});

// ---------- sitemap.xml ----------
app.get('/sitemap.xml', (_req, res) => {
  const base = 'https://sellgiftcardcash.com';
  res.type('application/xml');
  res.send(`<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>${base}/</loc>
    <changefreq>weekly</changefreq>
    <priority>1.0</priority>
  </url>
  <url>
    <loc>${base}/admin/login</loc>
    <changefreq>monthly</changefreq>
    <priority>0.1</priority>
  </url>
</urlset>`);
});

// ---------- Static uploads + error handler ----------
app.use('/uploads', express.static(UPLOAD_DIR));

app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(400).json({ error: err.message || 'Bad request' });
});

initDb()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`🚀 ${SERVICE_NAME} API running at http://localhost:${PORT}`);
      console.log(`📊 DB connected via DATABASE_URL`);
    });
  })
  .catch((e) => {
    console.error('❌ DB init failed:', e.message);
    process.exit(1);
  });
