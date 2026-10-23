require('dotenv').config();
const express = require('express');
const multer = require('multer');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 4000;
const DATA_DIR = path.resolve(process.env.DATA_DIR || './data');
const UPLOAD_DIR = path.resolve(process.env.UPLOAD_DIR || './uploads');
const ADMIN_API_KEY = process.env.ADMIN_API_KEY || 'dev-key-change-me';
const SERVICE_NAME = 'CashCard';

[DATA_DIR, UPLOAD_DIR].forEach((d) => fs.mkdirSync(d, { recursive: true }));
const CUSTOMERS_FILE = path.join(DATA_DIR, 'cashcard-customers.json');
if (!fs.existsSync(CUSTOMERS_FILE)) fs.writeFileSync(CUSTOMERS_FILE, '[]', 'utf8');

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

function readCustomers() {
  try {
    return JSON.parse(fs.readFileSync(CUSTOMERS_FILE, 'utf8') || '[]');
  } catch {
    return [];
  }
}
function writeCustomers(list) {
  const tmp = `${CUSTOMERS_FILE}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(list, null, 2), 'utf8');
  fs.renameSync(tmp, CUSTOMERS_FILE);
}

function requireAdmin(req, res, next) {
  const key = req.headers['x-admin-key'] || req.query.adminKey;
  if (key !== ADMIN_API_KEY) {
    return res.status(401).json({ error: 'Unauthorized: invalid admin key' });
  }
  next();
}

const RATE_TABLE = {
  default:     { withReceipt: 0.93, withoutReceipt: 0.85, partial: 0.70 },
  amazon:      { withReceipt: 0.92, withoutReceipt: 0.84, partial: 0.68 },
  apple:       { withReceipt: 0.90, withoutReceipt: 0.80, partial: 0.65 },
  steam:       { withReceipt: 0.88, withoutReceipt: 0.78, partial: 0.60 },
  googleplay:  { withReceipt: 0.90, withoutReceipt: 0.82, partial: 0.65 },
  walmart:     { withReceipt: 0.91, withoutReceipt: 0.83, partial: 0.68 },
  target:      { withReceipt: 0.90, withoutReceipt: 0.82, partial: 0.66 },
  vanilla:     { withReceipt: 0.87, withoutReceipt: 0.75, partial: 0.55 },
};

function calculateQuote({ brand, balance, condition }) {
  const key = String(brand || '').toLowerCase().replace(/[^a-z]/g, '');
  const row = RATE_TABLE[key] || RATE_TABLE.default;
  const rate =
    condition === 'with_receipt'    ? row.withReceipt    :
    condition === 'without_receipt' ? row.withoutReceipt :
                                      row.partial;
  const payout = +(Number(balance || 0) * rate).toFixed(2);
  return { rate, payout, currency: 'USD' };
}

async function fraudScreen(_submission) {
  return { riskScore: Math.floor(Math.random() * 25), status: 'auto_approved' };
}

app.get('/api/health', (_req, res) =>
  res.json({ ok: true, service: SERVICE_NAME, time: new Date().toISOString() })
);

app.get('/api/rates', (_req, res) => res.json({ rates: RATE_TABLE }));

app.post('/api/quote', (req, res) => {
  const { brand, balance, condition } = req.body || {};
  if (!brand || !balance) {
    return res.status(400).json({ error: 'brand and balance are required' });
  }
  res.json(calculateQuote({ brand, balance, condition }));
});

app.post(
  '/api/submissions',
  publicLimiter,
  upload.array('images', 4),
  async (req, res) => {
    try {
      const {
        fullName, email, phone,
        brand, cardNumber, pin, balance, condition,
        paymentMethod, paymentDetails,
      } = req.body || {};

      const required = ['fullName', 'email', 'brand', 'balance', 'paymentMethod'];
      const missing = required.filter((k) => !req.body[k]);
      if (missing.length) {
        return res.status(400).json({ error: `Missing fields: ${missing.join(', ')}` });
      }

      const quote = calculateQuote({ brand, balance, condition });
      const fraud = await fraudScreen(req.body);

      const id = uuidv4();
      const images = (req.files || []).map((f) => ({
        filename: f.filename,
        size: f.size,
        url: `/uploads/${f.filename}`,
      }));

      const record = {
        id,
        platform: SERVICE_NAME,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        status: fraud.status,
        customer: {
          fullName: String(fullName).trim(),
          email: String(email).trim().toLowerCase(),
          phone: (phone || '').trim(),
        },
        card: {
          brand: String(brand).trim(),
          cardNumber: (cardNumber || '').trim(),
          pin: (pin || '').trim(),
          balance: Number(balance),
          condition: condition || 'with_receipt',
          images,
        },
        payout: {
          method: paymentMethod,
          details: paymentDetails || '',
          rate: quote.rate,
          amount: quote.payout,
          currency: quote.currency,
          paid: false,
          paidAt: null,
        },
        fraud: { riskScore: fraud.riskScore },
        adminNotes: '',
      };

      const all = readCustomers();
      all.push(record);
      writeCustomers(all);

      const safeName = record.customer.email.replace(/[^a-z0-9@.-]/gi, '_');
      const perFile = path.join(DATA_DIR, `cashcard-customer-${safeName}-${id}.json`);
      fs.writeFileSync(perFile, JSON.stringify(record, null, 2), 'utf8');

      res.status(201).json({ ok: true, submissionId: id, quote, status: record.status });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Submission failed', detail: err.message });
    }
  }
);

app.get('/api/admin/customers', adminLimiter, requireAdmin, (req, res) => {
  const { page = 1, limit = 25, q = '', status } = req.query;
  let list = readCustomers();

  if (q) {
    const needle = String(q).toLowerCase();
    list = list.filter((r) =>
      r.customer.fullName.toLowerCase().includes(needle) ||
      r.customer.email.toLowerCase().includes(needle) ||
      r.card.brand.toLowerCase().includes(needle) ||
      r.id.toLowerCase().includes(needle)
    );
  }
  if (status) list = list.filter((r) => r.status === status);

  list.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

  const pageNum = Math.max(1, parseInt(page, 10));
  const pageSize = Math.min(200, Math.max(1, parseInt(limit, 10)));
  const start = (pageNum - 1) * pageSize;
  const pageItems = list.slice(start, start + pageSize);

  res.json({ total: list.length, page: pageNum, limit: pageSize, data: pageItems });
});

app.get('/api/admin/customers/:id', requireAdmin, (req, res) => {
  const list = readCustomers();
  const rec = list.find((r) => r.id === req.params.id);
  if (!rec) return res.status(404).json({ error: 'Not found' });
  res.json(rec);
});

app.patch('/api/admin/customers/:id', requireAdmin, (req, res) => {
  const list = readCustomers();
  const idx = list.findIndex((r) => r.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Not found' });

  const rec = list[idx];
  const { status, adminNotes, paid } = req.body || {};

  if (status) rec.status = status;
  if (adminNotes !== undefined) rec.adminNotes = adminNotes;
  if (paid === true)  { rec.payout.paid = true;  rec.payout.paidAt = new Date().toISOString(); }
  if (paid === false) { rec.payout.paid = false; rec.payout.paidAt = null; }
  rec.updatedAt = new Date().toISOString();

  list[idx] = rec;
  writeCustomers(list);

  const safeName = rec.customer.email.replace(/[^a-z0-9@.-]/gi, '_');
  fs.writeFileSync(
    path.join(DATA_DIR, `cashcard-customer-${safeName}-${rec.id}.json`),
    JSON.stringify(rec, null, 2),
    'utf8'
  );

  res.json(rec);
});

app.delete('/api/admin/customers/:id', requireAdmin, (req, res) => {
  const list = readCustomers();
  const idx = list.findIndex((r) => r.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  const [removed] = list.splice(idx, 1);
  writeCustomers(list);
  res.json({ ok: true, removed: removed.id });
});

app.get('/api/admin/export.csv', requireAdmin, (req, res) => {
  const list = readCustomers();
  const headers = [
    'id','createdAt','status','fullName','email','phone',
    'brand','cardNumber','balance','condition',
    'payoutMethod','payoutAmount','payoutPaid','riskScore','adminNotes',
  ];
  const rows = list.map((r) => [
    r.id, r.createdAt, r.status,
    r.customer.fullName, r.customer.email, r.customer.phone,
    r.card.brand, r.card.cardNumber, r.card.balance, r.card.condition,
    r.payout.method, r.payout.amount, r.payout.paid,
    r.fraud.riskScore, (r.adminNotes || '').replace(/[\r\n,]/g, ' '),
  ]);
  const csv = [headers, ...rows]
    .map((row) => row.map((v) => `"${String(v ?? '').replace(/"/g, '""')}"`).join(','))
    .join('\n');

  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', `attachment; filename="cashcard-customers-${Date.now()}.csv"`);
  res.send(csv);
});

app.use('/uploads', express.static(UPLOAD_DIR));

app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(400).json({ error: err.message || 'Bad request' });
});

app.listen(PORT, () => {
  console.log(`🚀 ${SERVICE_NAME} API running at http://localhost:${PORT}`);
  console.log(`📁 Data dir: ${DATA_DIR}`);
  console.log(`📁 Uploads:  ${UPLOAD_DIR}`);
});