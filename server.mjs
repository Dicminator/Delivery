// server.mjs
import pkg from 'pg';
const { Pool } = pkg;

import express from 'express';
import http from 'http';
import path from 'path';
import { fileURLToPath } from 'url';
import bodyParser from 'body-parser';
import dotenv from 'dotenv';
import { Server as SocketIOServer } from 'socket.io';
import multer from 'multer';
import fs from 'fs';
import { exec } from 'child_process';
import os from 'os';
import crypto from 'crypto';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import iconv from 'iconv-lite';
import QRCode from 'qrcode';
import nodemailer from 'nodemailer';

dotenv.config();

/* Crash guards */
process.on('unhandledRejection', (r) => console.error('[unhandledRejection]', r));
process.on('uncaughtException', (e) => console.error('[uncaughtException]', e));

/* ---------------- AUTH CONFIG ---------------- */
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
const COOKIE_NAME = 'token';
const COOKIE_OPTIONS = {
  httpOnly: true,
  sameSite: 'lax',
  secure: String(process.env.NODE_ENV).toLowerCase() === 'production'
};
const PAGE_OPEN_FRESH_SECONDS = parseInt(process.env.PAGE_OPEN_FRESH_SECONDS || '3600', 10);
const SESSION_TTL_SECONDS     = parseInt(process.env.SESSION_TTL_SECONDS || '7200', 10);

/* ------------------- PIX CONFIG ------------------- */
const PIX_KEY           = (process.env.PIX_KEY || '').trim();
const PIX_MERCHANT_NAME = (process.env.PIX_MERCHANT_NAME || 'COMERCIO').trim();
const PIX_MERCHANT_CITY = (process.env.PIX_MERCHANT_CITY || 'CIDADE').trim();

/* ------------------- PATH/APP ------------------- */
const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);

const app    = express();
const server = http.createServer(app);
app.set('trust proxy', 1); // cookies secure atrás de proxy (Koyeb)

/* ------------------- PERSISTÊNCIA (uploads em disco p/ logo) ------------------- */
const DATA_DIR    = process.env.DATA_DIR || __dirname;
const UPLOADS_DIR = process.env.UPLOADS_DIR || path.join(DATA_DIR, 'uploads');

try {
  if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });
} catch (e) {
  console.warn('[UPLOADS_DIR] não pôde criar diretório:', UPLOADS_DIR, e?.message || e);
}
app.use('/uploads', express.static(UPLOADS_DIR));

/* ------------------- CORS/IO --------------- */
const ALLOWED = [
  'https://di-fernandes.shop',
  'https://www.di-fernandes.shop',
  'https://api.di-fernandes.shop',
  'http://localhost:3000',
  'http://127.0.0.1:3000'
];
// Permite injetar origens extras via env: CORS_ORIGINS="https://app.koyeb.app,https://admin.exemplo.com"
const EXTRA = (process.env.CORS_ORIGINS || '')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);
ALLOWED.push(...EXTRA);

app.use(cors({
  origin: (origin, cb) => cb(null, !origin || ALLOWED.includes(origin)),
  methods: ['GET','POST','PUT','PATCH','DELETE','OPTIONS'],
  credentials: true,
  allowedHeaders: ['Content-Type','Authorization']
}));

const io = new SocketIOServer(server, {
  cors: {
    origin: (origin, cb) => cb(null, !origin || ALLOWED.includes(origin)),
    methods: ['GET','POST'],
    credentials: true
  }
});

/* ------------------- PRINT/DEVICE CONFIG ------------------- */
// Koyeb está checando 8000; se não houver PORT no ambiente, cai para 8000.
const PORT                    = parseInt(process.env.PORT || '8000', 10);

// se quiser travar impressão off, troque a linha abaixo por: const PRINT_ENABLED = false;
const PRINT_ENABLED = false;

const PRINTER_NAME            = (process.env.PRINTER_NAME || 'VID').trim(); // (não usado, mas mantido)
const PRINTER_SHARE           = (process.env.PRINTER_SHARE || '\\\\DESKTOP\\VID').trim();
const PRINTER_HOST            = process.env.PRINTER_HOST || '192.168.0.50';
const PRINTER_PORT            = parseInt(process.env.PRINTER_PORT || '9100', 10);
const PRINTER_ENCODING        = process.env.PRINTER_ENCODING || 'GB18030';
const PRINTER_TEXT_CODEPAGE   = (process.env.PRINTER_TEXT_CODEPAGE || 'cp1252').toLowerCase();
const PRINT_AGENT_URL_ENV     = process.env.PRINT_AGENT_URL || '';
const PRINT_AGENT_TOKEN       = process.env.PRINT_AGENT_TOKEN || '';

/* ------------------- E-MAIL CONFIG (SMTP + Resend) ------------------- */
const EMAIL_ENABLED    = (process.env.EMAIL_ENABLED || 'false').toLowerCase() === 'true';
const EMAIL_PROVIDER   = (process.env.EMAIL_PROVIDER || 'smtp').toLowerCase(); // 'smtp' | 'resend'
const EMAIL_FROM       = (process.env.EMAIL_FROM || 'Pedidos <no-reply@example.com>').trim();
const EMAIL_TO_DEFAULT = (process.env.EMAIL_TO || '').trim();

const SMTP_HOST   = process.env.SMTP_HOST || '';
const SMTP_PORT   = parseInt(process.env.SMTP_PORT || '587', 10);
const SMTP_SECURE = (process.env.SMTP_SECURE || 'false').toLowerCase() === 'true';
const SMTP_USER   = process.env.SMTP_USER || '';
const SMTP_PASS   = process.env.SMTP_PASS || '';

let mailer = null;
if (EMAIL_ENABLED && EMAIL_PROVIDER === 'smtp') {
  mailer = nodemailer.createTransport({
    host: SMTP_HOST,
    port: SMTP_PORT,
    secure: SMTP_SECURE,
    auth: SMTP_USER && SMTP_PASS ? { user: SMTP_USER, pass: SMTP_PASS } : undefined,
    requireTLS: SMTP_SECURE ? false : true,
    tls: { minVersion: 'TLSv1.2', servername: SMTP_HOST }
  });
}

const RESEND_API_KEY = process.env.RESEND_API_KEY || '';
async function sendEmailResend({ from, to, subject, html, text }) {
  if (!RESEND_API_KEY) throw new Error('RESEND_API_KEY não configurada');
  const resp = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${RESEND_API_KEY}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      from,
      to: Array.isArray(to) ? to : [to],
      subject,
      html,
      text
    })
  });
  if (!resp.ok) {
    const body = await resp.text().catch(() => '');
    throw new Error(`Resend HTTP ${resp.status} – ${body.slice(0, 300)}`);
  }
  return await resp.json();
}

/* ===== Helpers PIX (EMV) ===== */
function normalizeAscii(str, maxLen = undefined) {
  let s = (str || '').normalize('NFD').replace(/[\u0300-\u036f]/g, '');
  s = s.replace(/[^A-Za-z0-9 .,\-@_]/g, '');
  if (maxLen) s = s.slice(0, maxLen);
  return s;
}
function tlv(id, value) {
  const v = String(value ?? '');
  const len = v.length.toString().padStart(2, '0');
  return `${id}${len}${v}`;
}
function crc16(payload) {
  let crc = 0xFFFF;
  for (let i = 0; i < payload.length; i++) {
    crc ^= (payload.charCodeAt(i) << 8);
    for (let j = 0; j < 8; j++) {
      if ((crc & 0x8000) !== 0) crc = (crc << 1) ^ 0x1021;
      else crc <<= 1;
      crc &= 0xFFFF;
    }
  }
  return crc.toString(16).toUpperCase().padStart(4, '0');
}
function buildPixPayload({ pixKey, merchantName, merchantCity, amount, txid = 'ORDER' }) {
  const gui  = tlv('00', 'BR.GOV.BCB.PIX');
  const key  = tlv('01', pixKey);
  const mai  = tlv('26', gui + key);
  const mcc  = tlv('52', '0000');
  const cur  = tlv('53', '986');
  const amt  = amount != null ? tlv('54', Number(amount).toFixed(2)) : '';
  const cc   = tlv('58', 'BR');
  const name = tlv('59', normalizeAscii(merchantName, 25));
  const city = tlv('60', normalizeAscii(merchantCity, 15));
  const add  = tlv('62', tlv('05', normalizeAscii(txid, 25)));

  const payloadNoCRC =
    tlv('00', '01') +
    tlv('01', '12') +
    mai + mcc + cur + amt + cc + name + city + add +
    '6304';

  const crc = crc16(payloadNoCRC);
  return payloadNoCRC + crc;
}

/* ------------------- PostgreSQL (pool + helpers) ------------------- */
// Preferir DATABASE_URL (Koyeb) – ex.: postgres://user:pass@host:5432/db?sslmode=require
const DB_URL = process.env.DATABASE_URL || '';
const pool = DB_URL
  ? new Pool({ connectionString: DB_URL, ssl: { rejectUnauthorized: false } })
  : new Pool({
      host: process.env.DB_HOST,
      port: parseInt(process.env.DB_PORT || '5432', 10),
      user: process.env.DB_USER,
      password: process.env.DB_PASS,
      database: process.env.DB_NAME,
      ssl: { rejectUnauthorized: false }
    });

/* Logs úteis do DB (para deploy) */
try {
  if (DB_URL) {
    const u = new URL(DB_URL);
    console.log('[DB] usando DATABASE_URL host=%s db=%s sslmode=%s',
      u.hostname, u.pathname.slice(1), u.searchParams.get('sslmode') || '');
  } else {
    console.log('[DB] usando variáveis separadas host=%s db=%s port=%s',
      process.env.DB_HOST, process.env.DB_NAME, process.env.DB_PORT || '5432');
  }
} catch (e) {
  console.warn('[DB] não foi possível parsear URL:', e?.message || e);
}
pool.on('error', (err) => console.error('[PG POOL ERROR]', err?.message || err));

async function run(sql, params = []) {
  const res = await pool.query(sql, params);
  return res; // res.rows, res.rowCount
}
async function all(sql, params = []) {
  const res = await pool.query(sql, params);
  return res.rows;
}
async function get(sql, params = []) {
  const res = await pool.query(sql, params);
  return res.rows?.[0] || null;
}

/* Pequeno util para construir placeholders $1,$2,... */
function placeholders(n, start = 1) {
  return Array.from({ length: n }, (_, i) => `$${i + start}`).join(',');
}

/* ------------------- INIT DB (PostgreSQL) ------------------- */
async function initDb() {
  // menu_items
  await run(`
    CREATE TABLE IF NOT EXISTS menu_items (
      id          integer GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
      name        varchar(255) NOT NULL,
      price       numeric(10,2) NOT NULL,
      category    varchar(120),
      image_url   varchar(500),
      image_blob  bytea,
      image_mime  varchar(100)
    )`);

  // orders
  await run(`
    CREATE TABLE IF NOT EXISTS orders (
      id              integer GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
      customer_name   varchar(255),
      phone           varchar(60),
      address         varchar(500),
      payment_method  varchar(60),
      notes           text,
      subtotal        numeric(10,2),
      delivery_fee    numeric(10,2),
      total           numeric(10,2),
      status          varchar(60) NOT NULL DEFAULT 'Pedido Novo',
      created_at      timestamp   NOT NULL DEFAULT now()
    )`);

  // order_items
  await run(`
    CREATE TABLE IF NOT EXISTS order_items (
      id        integer GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
      order_id  integer NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
      item_name varchar(255) NOT NULL,
      qty       integer NOT NULL,
      price     numeric(10,2) NOT NULL
    )`);
  await run(`CREATE INDEX IF NOT EXISTS idx_order_items_order_id ON order_items(order_id)`);

  // users
  await run(`
    CREATE TABLE IF NOT EXISTS users (
      id             integer GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
      username       varchar(100)  NOT NULL UNIQUE,
      password_hash  varchar(255)  NOT NULL,
      role           varchar(30)   NOT NULL DEFAULT 'user'
    )`);

  // settings
  await run(`
    CREATE TABLE IF NOT EXISTS settings (
      key   varchar(100) PRIMARY KEY,
      value text
    )`);

  // delivery_zones
  await run(`
    CREATE TABLE IF NOT EXISTS delivery_zones (
      id   integer GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
      name varchar(100) NOT NULL,
      fee  numeric(10,2) NOT NULL
    )`);

  // Seeds
  const menuCount = await get('SELECT COUNT(*)::int AS c FROM menu_items');
  if (!menuCount || Number(menuCount.c) === 0) {
    const items = [
      ['ESFIHA - CARNE', 8.00, 'Esfihas'],
      ['ESFIHA - CARNE/MUSSARELA ', 8.00, 'Esfihas'],
      ['ESFIHA - CARNE/QUEIJO BRANCO ', 8.00, 'Esfihas'],
      ['ESFIHA - FRANGO', 8.00, 'Esfihas'],
      ['ESFIHA - FRANGO/CATUPIRY', 8.00, 'Esfihas'],
      ['ESFIHA - FRANGO/QUEIJO BRANCO', 8.00, 'Esfihas'],
      ['ESFIHA - PRESUNTO', 8.00, 'Esfihas'],
      ['ESFIHA - PRESUNTO/CATUPIRY', 8.00, 'Esfihas'],
      ['ESFIHA - PRESUNTO/MUSSARELA ', 8.00, 'Esfihas'],
      ['ESFIHA - PRESUNTO/QUEIJO', 8.00, 'Esfihas'],
      ['ESFIHA - PIZZA - (Presunto, Mussarela e Orégano)', 8.00, 'Esfihas'],
      ['ESFIHA - CALABRESA', 8.00, 'Esfihas'],
      ['ESFIHA - CALABRESA/MUSSARELA', 8.00, 'Esfihas'],
      ['ESFIHA - CALABRESA/QUEIJO BRANCO', 8.00, 'Esfihas'],
      ['ESFIHA - CALABRESA/CATUPIRY', 8.00, 'Esfihas'],
      ['ESFIHA - MUSSARELA', 8.00, 'Esfihas'],
      ['ESFIHA - MUSSARELA/PALMITO', 8.00, 'Esfihas'],
      ['ESFIHA - ITALIANA - (Mussarela, Salame, Parmesão e Orégano)', 8.00, 'Esfihas'],
      ['ESFIHA - MODA DA CASA - (Mussarela e alho frito)', 8.00, 'Esfihas'],
      ['ESFIHA - BACON', 8.00, 'Esfihas'],
      ['ESFIHA - TOSCANA - (Mussarela, Calabresa em fatia Cebola)', 8.00, 'Esfihas'],
      ['ESFIHA - DOCE - SENSAÇÃO', 10.00, 'Esfihas'],
      ['ESFIHA - DOCE - BRIGADEIRO', 10.00, 'Esfihas'],
      ['REFRIGERANTE - COCA - COLA 2 L', 10.00, 'Esfihas'],
      ['REFRIGERANTE - TUBAINA - 2 L', 10.00, 'Esfihas']
    ];
    const valuesPlace = items.map((_, i) => `(${placeholders(3, i*3+1)})`).join(',');
    const flat = items.flat();
    await run(`INSERT INTO menu_items (name, price, category) VALUES ${valuesPlace}`, flat);
    console.log('Seed: menu_items criado.');
  }

  const fee = await get('SELECT value FROM settings WHERE key=$1', ['delivery_fee_default']);
  if (!fee) {
    await run('INSERT INTO settings (key, value) VALUES ($1,$2) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value', ['delivery_fee_default', '8']);
  }

  const zcount = await get('SELECT COUNT(*)::int AS c FROM delivery_zones');
  if (!zcount || Number(zcount.c) === 0) {
    const zones = [['Centro', 8], ['Jardins', 10], ['Vila Nova', 12]];
    const valuesPlace = zones.map((_, i) => `(${placeholders(2, i*2+1)})`).join(',');
    await run(`INSERT INTO delivery_zones (name, fee) VALUES ${valuesPlace}`, zones.flat());
    console.log('Seed: delivery_zones criado.');
  }

  const ucount = await get('SELECT COUNT(*)::int AS c FROM users');
  if (!ucount || Number(ucount.c) === 0) {
    const u = process.env.ADMIN_USER || 'admin';
    const p = process.env.ADMIN_PASS || 'admin123';
    const hash = await bcrypt.hash(p, 10);
    await run('INSERT INTO users (username, password_hash, role) VALUES ($1,$2,$3)', [u, hash, 'admin']);
    console.log(`[users] admin criado: ${u}/${p}`);
  }

  console.log('[DB] init ok (PostgreSQL)');
}

/* ------------------- MIDDLEWARE ------------------- */
app.use(bodyParser.json());
app.use(cookieParser());

function verifyToken(req, res, next) {
  const token = req.cookies?.[COOKIE_NAME];
  if (!token) return next();
  jwt.verify(token, JWT_SECRET, (err, payload) => {
    if (!err) req.user = payload;
    next();
  });
}
app.use(verifyToken);

/* 🔒 Bloquear arquivos sensíveis */
const DENY = ['/server.mjs', '/server.js', '/package.json', '/package-lock.json', '/.env', '/app.db'];
app.get(DENY, (req, res) => res.sendStatus(404));

/* ---------- Guard especial das telas ---------- */
function isFreshLogin(payload){
  if (!payload?.iat) return false;
  const now = Math.floor(Date.now()/1000);
  return (now - payload.iat) <= PAGE_OPEN_FRESH_SECONDS;
}
function sendFileGuarded(fileName) {
  return (req, res) => {
    if (!req.user || !isFreshLogin(req.user)) {
      res.type('text/html; charset=utf-8');
      return res.sendFile(path.join(__dirname, 'login.html'));
    }
    res.type('text/html; charset=utf-8');
    res.sendFile(path.join(__dirname, fileName));
  };
}

/* ------------------- PIX ENDPOINT ------------------- */
app.get('/api/pix', async (req, res) => {
  try {
    if (!PIX_KEY) return res.status(500).json({ ok:false, error: 'PIX_KEY não configurada no .env' });

    const amount = Number(req.query.amount);
    if (!Number.isFinite(amount) || amount <= 0) {
      return res.status(400).json({ ok:false, error: 'amount inválido' });
    }
    const txid = (req.query.txid || `ORD${Date.now()}`).toString().slice(0,25);

    const payload = buildPixPayload({
      pixKey: PIX_KEY,
      merchantName: PIX_MERCHANT_NAME,
      merchantCity: PIX_MERCHANT_CITY,
      amount,
      txid
    });

    const qrDataUrl = await QRCode.toDataURL(payload, { errorCorrectionLevel: 'M', margin: 1, scale: 6 });
    res.json({ ok:true, payload, amount: Number(amount.toFixed(2)), qrDataUrl, txid });
  } catch (e) {
    console.error('[GET /api/pix] erro:', e);
    res.status(500).json({ ok:false, error: 'Falha ao gerar PIX' });
  }
});

/* protege as telas */
app.get('/admin.html', sendFileGuarded('admin.html'));
app.get('/store.html', sendFileGuarded('store.html'));

/* ✅ Estáticos raiz */
app.use(express.static(__dirname, {
  index: 'index.html',
  extensions: ['html'],
  dotfiles: 'ignore',
  setHeaders: (res, filePath) => {
    if (filePath.endsWith('.html')) res.setHeader('Content-Type', 'text/html; charset=utf-8');
    else if (filePath.endsWith('.js'))   res.setHeader('Content-Type', 'application/javascript; charset=utf-8');
    else if (filePath.endsWith('.css'))  res.setHeader('Content-Type', 'text/css; charset=utf-8');
    else if (filePath.endsWith('.json')) res.setHeader('Content-Type', 'application/json; charset=utf-8');
    else if (filePath.endsWith('.txt'))  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  }
}));

/* ------------------- UPLOADS ------------------- */
/* Logo → disco */
const diskStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS_DIR),
  filename: (req, file, cb) => {
    const ext  = path.extname(file.originalname) || '.png';
    const base = path.basename(file.originalname, ext).replace(/[^a-z0-9_-]/gi,'_').toLowerCase();
    cb(null, `${base}-${Date.now()}${ext}`);
  }
});
function imageFilter(req, file, cb){
  const ok = /image\/(jpeg|jpg|png)/i.test(file.mimetype);
  if (!ok) return cb(new Error('Tipo de arquivo não permitido (use JPG/PNG)'));
  cb(null, true);
}
const uploadDisk = multer({ storage: diskStorage, fileFilter: imageFilter, limits: { fileSize: 5 * 1024 * 1024 } });

/* Itens → BLOB (memória) */
const uploadMem = multer({
  storage: multer.memoryStorage(),
  fileFilter: imageFilter,
  limits: { fileSize: 5 * 1024 * 1024 }
});

/* upload genérico */
app.post('/api/upload', uploadDisk.single('image'), (req, res) => {
  if (!req.file) return res.status(400).json({ ok:false, error: 'Arquivo não enviado' });
  const rel = '/uploads/' + req.file.filename;
  console.log('[UPLOAD] salvo em', rel);
  res.json({ ok: true, path: rel });
});

/* upload logo (copia para /uploads/logo.png e grava setting) */
app.post('/api/upload-logo', uploadDisk.single('logo'), async (req, res) => {
  if (!req.file) return res.status(400).json({ ok:false, error: 'Arquivo não enviado' });
  try {
    const newPath = path.join(UPLOADS_DIR, 'logo.png');
    fs.copyFileSync(req.file.path, newPath);
    await run(
      "INSERT INTO settings (key, value) VALUES ('logo_path', '/uploads/logo.png') ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value"
    );
    console.log('[UPLOAD-LOGO] logo atualizada em /uploads/logo.png');
    res.json({ ok:true, path: '/uploads/logo.png' });
  } catch (e) {
    console.error('[UPLOAD-LOGO] erro:', e);
    res.status(500).json({ ok:false, error: 'Falha ao salvar logo' });
  }
});

/* ------------------- AUTH ------------------- */
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ ok:false, error:'Credenciais obrigatórias' });

  try {
    const u = await get('SELECT id, username, password_hash, role FROM users WHERE username = $1', [username]);
    if (!u)   return res.status(401).json({ ok:false, error:'Usuário ou senha inválidos' });

    const ok = await bcrypt.compare(password, u.password_hash);
    if (!ok)  return res.status(401).json({ ok:false, error:'Usuário ou senha inválidos' });

    const token = jwt.sign(
      { id: u.id, username: u.username, role: u.role },
      JWT_SECRET,
      { expiresIn: `${SESSION_TTL_SECONDS}s` }
    );

    res.cookie(COOKIE_NAME, token, { ...COOKIE_OPTIONS, maxAge: SESSION_TTL_SECONDS * 1000 });
    res.json({ ok:true, user: { id: u.id, username: u.username, role: u.role }, ttl: SESSION_TTL_SECONDS });
  } catch (err) {
    res.status(500).json({ ok:false, error:'DB error' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie(COOKIE_NAME, COOKIE_OPTIONS);
  res.json({ ok:true });
});

app.get('/api/me', (req, res) => {
  if (!req.user) return res.status(401).json({ ok:false });
  res.json({ ok:true, user: req.user });
});

/* ------------------- HEALTH/DEBUG ------------------- */
app.get('/healthz', (req,res) => res.json({ ok: true, time: new Date().toISOString() }));

app.get('/debug/db-ping', async (req, res) => {
  try {
    const rows = await all('SELECT 1 AS ok');
    res.json({ ok: true, rows });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

/* ------------------- PRINT: Status & Teste ------------------- */
app.get('/print/status', (req, res) => {
  const isWin = process.platform === 'win32';
  res.json({
    ok: true,
    printEnabled: PRINT_ENABLED,
    platform: process.platform,
    mode: (PRINTER_SHARE ? 'windows-unc' : (PRINTER_HOST ? 'escpos-tcp' : 'desconhecido')),
    PRINTER_SHARE,
    PRINTER_HOST,
    PRINTER_PORT,
    isWin
  });
});

app.post('/print/test', async (req, res) => {
  if (!PRINT_ENABLED) return res.status(400).json({ ok:false, error:'PRINT_ENABLED=false' });
  try {
    const fake = {
      id: Math.floor(Date.now()/1000),
      created_at: new Date(),
      customer_name: 'Teste',
      phone: '11999999999',
      address: 'Rua Exemplo, 123',
      payment_method: 'Dinheiro',
      notes: 'Ticket de teste',
      items: [
        { item_name: 'ESFIHA - CARNE', qty: 2, price: 8.00 },
        { item_name: 'REFRIGERANTE 2L', qty: 1, price: 10.00 },
      ],
      subtotal: 26.00,
      delivery_fee: 8.00,
      total: 34.00,
      status: 'Em preparo'
    };
    await printOrder(fake);
    return res.json({ ok:true });
  } catch (e) {
    console.error('[print/test] erro:', e?.message || e);
    return res.status(500).json({ ok:false, error: String(e?.message || e) });
  }
});

/* ------------------- MENU ------------------- */
app.get('/api/menu', async (req, res) => {
  try {
    const { category } = req.query;
    let sql = `
      SELECT
        id,
        name,
        price,
        category,
        CASE
          WHEN image_url IS NOT NULL AND image_url <> '' THEN image_url
          WHEN image_blob IS NOT NULL THEN '/images/' || id
          ELSE NULL
        END AS image_url
      FROM menu_items`;
    const params = [];
    if (category && String(category).trim() !== '') {
      params.push(String(category));
      sql += ` WHERE LOWER(TRIM(category)) = LOWER(TRIM($${params.length}))`;
    }
    sql += ' ORDER BY id';

    const rows = await all(sql, params);
    res.json(rows);
  } catch (e) {
    console.error('[GET /api/menu] error:', e);
    res.status(500).json({ error: 'Internal error' });
  }
});

app.post('/api/menu', async (req, res) => {
  const { name, price, category, image_url } = req.body || {};
  if (!name || price == null) return res.status(400).json({ error:'name e price são obrigatórios' });
  try {
    const r = await run(
      'INSERT INTO menu_items (name, price, category, image_url) VALUES ($1,$2,$3,$4) RETURNING id',
      [name, Number(price), category || null, image_url || null]
    );
    const newId = r.rows[0].id;
    res.json({ id: newId, name, price:Number(price), category:category||null, image_url:image_url||null });
  } catch (err) {
    res.status(500).json({ error:'Erro ao incluir item' });
  }
});

app.put('/api/menu/:id', async (req, res) => {
  const id = Number(req.params.id);
  const { name, price, category, image_url } = req.body || {};
  const sql = `
    UPDATE menu_items SET
      name      = COALESCE($1, name),
      price     = COALESCE($2, price),
      category  = COALESCE($3, category),
      image_url = COALESCE($4, image_url)
    WHERE id = $5`;
  try {
    const params = [name ?? null, price != null ? Number(price) : null, category ?? null, image_url ?? null, id];
    const r = await run(sql, params);
    return res.json({ ok:true, changes: r.rowCount });
  } catch (err) {
    return res.status(500).json({ ok:false, error: String(err?.message || err) });
  }
});

app.delete('/api/menu/:id', async (req, res) => {
  const id = Number(req.params.id);
  try {
    const r = await run('DELETE FROM menu_items WHERE id = $1', [id]);
    res.json({ ok: true, changes: r.rowCount });
  } catch (err) {
    res.status(500).json({ error: 'Erro ao apagar item' });
  }
});

/* ===== Imagem do item → salva no BLOB e seta /images/:id ===== */
app.post('/api/menu/:id/image', uploadMem.single('image'), async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isFinite(id) || id <= 0) {
      return res.status(400).json({ ok:false, error:'id inválido' });
    }
    if (!req.file) {
      return res.status(400).json({ ok:false, error:'Arquivo não enviado (campo "image")' });
    }

    const mime = String(req.file.mimetype || '').toLowerCase();
    if (!/^image\/(png|jpe?g)$/.test(mime)) {
      return res.status(400).json({ ok:false, error:'Tipo de arquivo não permitido (use JPG/PNG)' });
    }

    const it = await get('SELECT id FROM menu_items WHERE id=$1', [id]);
    if (!it) return res.status(404).json({ ok:false, error:'Item não encontrado' });

    await run(
      'UPDATE menu_items SET image_blob=$1, image_mime=$2, image_url=$3 WHERE id=$4',
      [req.file.buffer, mime, `/images/${id}`, id]
    );

    return res.json({ ok:true, image_url: `/images/${id}` });
  } catch (e) {
    console.error('[POST /api/menu/:id/image] error:', e);
    return res.status(500).json({ ok:false, error:'Falha ao salvar imagem' });
  }
});

/* Desvincular imagem do item (limpa BLOB/URL) */
app.delete('/api/menu/:id/image', async (req, res) => {
  const id = Number(req.params.id);
  try {
    await run('UPDATE menu_items SET image_blob=NULL, image_mime=NULL, image_url=NULL WHERE id=$1', [id]);
    res.json({ ok:true });
  } catch (e) {
    res.status(500).json({ ok:false, error:'Falha ao desvincular imagem' });
  }
});

/* ------------------- SETTINGS ------------------- */
app.get('/api/settings/:key', async (req, res) => {
  try {
    const row = await get('SELECT value FROM settings WHERE key = $1', [req.params.key]);
    res.json({ key: req.params.key, value: row ? row.value : null });
  } catch {
    res.status(500).json({ error: 'DB error' });
  }
});
app.put('/api/settings/:key', async (req, res) => {
  const { value } = req.body || {};
  try {
    await run(
      'INSERT INTO settings (key, value) VALUES ($1,$2) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value',
      [req.params.key, String(value)]
    );
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: 'DB error' });
  }
});

/* ------------------- DELIVERY ZONES ------------------- */
app.get('/api/delivery-zones', async (req, res) => {
  try {
    const rows = await all('SELECT id, name, fee FROM delivery_zones ORDER BY name');
    res.json(rows);
  } catch {
    res.status(500).json({ error: 'DB error' });
  }
});
app.post('/api/delivery-zones', async (req, res) => {
  const { name, fee } = req.body || {};
  if (!name || fee == null) return res.status(400).json({ error: 'name e fee são obrigatórios' });
  try {
    const r = await run('INSERT INTO delivery_zones (name, fee) VALUES ($1,$2) RETURNING id', [name, Number(fee)]);
    res.json({ id: r.rows[0].id, name, fee: Number(fee) });
  } catch {
    res.status(500).json({ error: 'Erro ao incluir zona' });
  }
});
app.put('/api/delivery-zones/:id', async (req, res) => {
  const id = Number(req.params.id);
  const { name, fee } = req.body || {};
  try {
    const r = await run(
      'UPDATE delivery_zones SET name = COALESCE($1, name), fee = COALESCE($2, fee) WHERE id = $3',
      [name ?? null, fee != null ? Number(fee) : null, id]
    );
    res.json({ ok: true, changes: r.rowCount });
  } catch {
    res.status(500).json({ error: 'Erro ao atualizar zona' });
  }
});
app.delete('/api/delivery-zones/:id', async (req, res) => {
  const id = Number(req.params.id);
  try {
    const r = await run('DELETE FROM delivery_zones WHERE id = $1', [id]);
    res.json({ ok: true, changes: r.rowCount });
  } catch {
    res.status(500).json({ error: 'Erro ao apagar zona' });
  }
});

/* ------------------- ORDERS ------------------- */
app.post('/api/order', async (req, res) => {
  const { customer_name, phone, address, payment_method, notes, items, delivery_fee } = req.body || {};
  if (!items || !Array.isArray(items) || items.length === 0) {
    return res.status(400).json({ error: 'Itens do pedido são obrigatórios' });
  }

  const subtotal = items.reduce((acc, it) => acc + (Number(it.price) * Number(it.qty)), 0);
  const delivery = Number(delivery_fee || 0);
  const total = subtotal + delivery;

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const ins = await client.query(
      `INSERT INTO orders (customer_name, phone, address, payment_method, notes, subtotal, delivery_fee, total, status)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
       RETURNING id`,
      [customer_name || '', phone || '', address || '', payment_method || '', notes || '', subtotal, delivery, total, 'Pedido Novo']
    );
    const orderId = ins.rows[0].id;

    const values = [];
    const chunks = [];
    let idx = 1;
    for (const it of items) {
      const itemName = it.name ?? it.item_name ?? '';
      chunks.push(`($${idx},$${idx+1},$${idx+2},$${idx+3})`);
      values.push(orderId, itemName, Number(it.qty), Number(it.price));
      idx += 4;
    }
    await client.query(
      `INSERT INTO order_items (order_id, item_name, qty, price) VALUES ${chunks.join(',')}`,
      values
    );

    await client.query('COMMIT');

    const orderItems = (await all('SELECT item_name, qty, price FROM order_items WHERE order_id = $1', [orderId]));

    const order = {
      id: orderId,
      customer_name, phone, address, payment_method, notes,
      subtotal, delivery_fee: delivery, total,
      status: 'Pedido Novo',
      items: orderItems
    };

    io.emit('new-order', order);
    res.json({ ok: true, order_id: orderId });
  } catch (err) {
    try { await client.query('ROLLBACK'); } catch {}
    console.error('[POST /api/order] error:', err);
    res.status(500).json({ error: 'Erro ao salvar pedido' });
  } finally {
    client.release();
  }
});

app.get('/api/orders', async (req, res) => {
  try {
    const { on } = req.query; // formato esperado: YYYY-MM-DD
    let sql = 'SELECT id, customer_name, total, status, created_at FROM orders';
    const params = [];
    if (on) {
      sql += ' WHERE created_at >= $1::date AND created_at < ($1::date + interval \'1 day\')';
      params.push(String(on));
    }
    sql += ' ORDER BY id DESC';
    const rows = await all(sql, params);
    res.json(rows);
  } catch (e) {
    res.status(500).json({ error: 'DB error' });
  }
});

app.get('/api/orders/:id', async (req, res) => {
  const id = Number(req.params.id);
  try {
    const ord = await get('SELECT * FROM orders WHERE id = $1', [id]);
    if (!ord) return res.status(404).json({ ok:false, error:'Pedido não encontrado' });
    const items = await all('SELECT item_name, qty, price FROM order_items WHERE order_id = $1', [id]);
    res.json({ ok:true, order: { ...ord, items } });
  } catch {
    res.status(500).json({ ok:false, error:'Erro ao carregar itens' });
  }
});

/* --------- Helpers do agente ---------- */
function ensurePrintPath(url) {
  if (!url) return '';
  const base = String(url).replace(/\/+$/, '');
  if (/\/print\/?$/.test(url)) return url;
  return base + '/print';
}
async function resolveAgentUrl() {
  if (PRINT_AGENT_URL_ENV && String(PRINT_AGENT_URL_ENV).trim() !== '') {
    return ensurePrintPath(PRINT_AGENT_URL_ENV.trim());
  }
  const row = await get("SELECT value FROM settings WHERE key='PRINT_AGENT_URL'");
  const v = row?.value ? String(row.value).trim() : '';
  return ensurePrintPath(v);
}
function toAgentPayload(order) {
  return {
    id: order.id,
    dataHora: new Date(order.created_at || Date.now()).toLocaleString('pt-BR', { timeZone: 'America/Sao_Paulo' }),
    cliente:  order.customer_name || '',
    telefone: String(order.phone || '').replace(/\D+/g, '').slice(0, 11),
    endereco: order.address || '',
    complemento: '',
    pagamento: order.payment_method || '',
    itens: (order.items || []).map(i => ({
      qtd: Number(i.qty),
      nome: i.item_name,
      preco: Number(i.price) * Number(i.qty)
    })),
    subtotal: Number(order.subtotal || 0),
    entrega:  Number(order.delivery_fee || 0),
    total:    Number(order.total || 0),
    status:   order.status || 'Em preparo'
  };
}
async function notifyAgentPrint(order) {
  const url   = await resolveAgentUrl();
  const token = process.env.PRINT_AGENT_TOKEN || PRINT_AGENT_TOKEN || '';
  if (!url || !token) throw new Error('PRINT_AGENT_URL/TOKEN não configurados');
  const ctrl  = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 10_000);
  const idemKey = String(order.id);
  let resp, body = '';
  try {
    resp = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Auth': token,
        'X-Idempotency-Key': idemKey
      },
      body: JSON.stringify({ type: 'DELIVERY_ORDER', payload: toAgentPayload(order) }),
      signal: ctrl.signal
    });
    body = await resp.text().catch(() => '');
  } catch (e) {
    clearTimeout(timer);
    console.error('[AGENT FETCH ERROR]', e?.message || e, 'URL=', url);
    throw e;
  }
  clearTimeout(timer);
  if (!resp.ok) {
    console.error('[AGENT RESP]', resp.status, 'URL=', url, 'BODY=', body.slice(0,300));
    throw new Error(`Agente HTTP ${resp.status} – ${body.slice(0,300)}`);
  }
}

/* ------------------- STATUS PEDIDO ------------------- */
app.patch('/api/orders/:id/status', async (req, res) => {
  const id = Number(req.params.id);
  const { status } = req.body || {};
  const allowed = ['Pedido Novo','Em preparo','Saiu para entrega','Concluido'];
  if (!allowed.includes(status)) return res.status(400).json({ error: 'Status inválido' });
  try {
    const r = await run('UPDATE orders SET status = $1 WHERE id = $2', [status, id]);
    io.emit('order-status', { id, status });
    res.json({ ok: true, changes: r.rowCount });
  } catch {
    res.status(500).json({ error: 'DB error' });
  }
});

/* ------------------- IMPRESSÃO (local-first) ------------------- */
function padRight(s, n) { s = String(s ?? ''); return s + ' '.repeat(Math.max(0, n - s.length)); }
function padLeft(s, n)  { s = String(s ?? ''); return ' '.repeat(Math.max(0, n - s.length)) + s; }

function buildPlainTicket(order) {
  const L = 42;
  const lines = [];
  const dt = new Date(order.created_at || Date.now()).toLocaleString('pt-BR', { timeZone: 'America/Sao_Paulo' });

  lines.push('PEDIDO DELIVERY');
  lines.push(`Pedido #${order.id}   ${dt}`);
  lines.push('-'.repeat(L));
  if (order.customer_name)  lines.push(`Cliente: ${order.customer_name}`);
  if (order.phone)          lines.push(`Telefone: ${order.phone}`);
  if (order.address)        lines.push(`Endereço: ${order.address}`);
  if (order.payment_method) lines.push(`Pagamento: ${order.payment_method}`);
  if (order.notes)          lines.push(`Obs: ${order.notes}`);
  lines.push('-'.repeat(L));

  for (const it of (order.items || [])) {
    const total = (Number(it.qty) * Number(it.price)).toFixed(2);
    const left  = `${it.qty}x ${it.item_name}`.slice(0, L - 10);
    const right = `R$ ${total}`;
    lines.push(padRight(left, L - right.length) + right);
  }

  lines.push('-'.repeat(L));
  lines.push(padRight('Subtotal:', 12) + padLeft(`R$ ${Number(order.subtotal||0).toFixed(2)}`, L-12));
  lines.push(padRight('Entrega:', 12)  + padLeft(`R$ ${Number(order.delivery_fee||0).toFixed(2)}`, L-12));
  lines.push(padRight('TOTAL:', 12)    + padLeft(`R$ ${Number(order.total||0).toFixed(2)}`, L-12));
  if (order.status) lines.push(`Status: ${order.status}`);
  lines.push('-'.repeat(L));
  lines.push('\n\n\n');
  return lines.join('\r\n');
}

async function printOrder(order) {
  if (!PRINT_ENABLED) return;
  const isWin = process.platform === 'win32';

  if (isWin && PRINTER_SHARE) {
    const text     = buildPlainTicket(order);
    const tmpDir   = os.tmpdir();
    const filename = `ticket_${Date.now()}_${crypto.randomBytes(4).toString('hex')}.txt`;
    const fullPath = path.join(tmpDir, filename);

    const buf = iconv.encode(text, PRINTER_TEXT_CODEPAGE);
    fs.writeFileSync(fullPath, buf);

    console.log('[PRINT CFG] ENABLED=', PRINT_ENABLED, ' SHARE=', PRINTER_SHARE);

    const runCmd = (cmd) => new Promise((resolve, reject) => {
      console.log('[PRINT CMD]', cmd);
      exec(cmd, { windowsHide: true }, (err, stdout, stderr) => {
        if (stdout) console.log('[PRINT OUT]', stdout.toString().trim());
        if (stderr) console.log('[PRINT ERR]', stderr.toString().trim());
        return err ? reject(err) : resolve();
      });
    });

    try {
      await runCmd(`PRINT /D:"${PRINTER_SHARE}" "${fullPath}"`);
      console.log(`[PRINT] Enviado via PRINT para "${PRINTER_SHARE}"`);
    } catch (e1) {
      console.warn('[PRINT] PRINT falhou, fallback COPY /B...', e1?.message || e1);
      try {
        await runCmd(`COPY /B "${fullPath}" ${PRINTER_SHARE}`);
        console.log(`[PRINT] Enviado via COPY /B para "${PRINTER_SHARE}"`);
      } catch (e2) {
        console.error('[PRINT] Falhou PRINT e COPY /B. Tentando ESC/POS em rede…');
        try { fs.unlinkSync(fullPath); } catch(e){}
        return await printEscPosNetwork(order);
      }
    }
    try { fs.unlinkSync(fullPath); } catch(e){}
    return;
  }

  return await printEscPosNetwork(order);
}

async function printEscPosNetwork(order) {
  return new Promise((resolve, reject) => {
    import('escpos').then(escposModule => {
      const escpos = escposModule.default || escposModule;
      import('escpos-network').then(netModule => {
        const Network = (netModule.default || netModule);
        const device = new Network(PRINTER_HOST, PRINTER_PORT);
        const options = { encoding: PRINTER_ENCODING };
        const printer = new escpos.Printer(device, options);

        device.open(() => {
          try {
            printer
              .align('CT').style('B').size(1,1)
              .text('PEDIDO DELIVERY')
              .style('NORMAL')
              .text(`Pedido #${order.id}`)
              .text(new Date().toLocaleString('pt-BR'))
              .drawLine()
              .align('LT');

            if (order.customer_name)  printer.text(`Cliente: ${order.customer_name}`);
            if (order.phone)          printer.text(`Telefone: ${order.phone}`);
            if (order.address)        printer.text(`Endereço: ${order.address}`);
            if (order.payment_method) printer.text(`Pagamento: ${order.payment_method}`);
            if (order.notes)          printer.text(`Obs: ${order.notes}`);

            printer.drawLine();
            order.items.forEach(i => {
              printer.text(`${i.qty}x ${i.item_name} ..... R$ ${(Number(i.price)).toFixed(2)}`);
            });
            printer.drawLine();
            printer.text(`Subtotal: R$ ${Number(order.subtotal).toFixed(2)}`);
            printer.text(`Entrega:  R$ ${Number(order.delivery_fee).toFixed(2)}`);
            printer.style('B').text(`TOTAL:    R$ ${Number(order.total).toFixed(2)}`).style('NORMAL');
            if (order.status) printer.text(`Status: ${order.status}`);
            printer.drawLine().feed(3).cut().close();

            resolve();
          } catch (err) {
            reject(err);
          }
        });
      }).catch(reject);
    }).catch(reject);
  });
}

/* ------------------- /images/:id (BLOB) ------------------- */
app.get('/images/:id', async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isFinite(id) || id <= 0) return res.sendStatus(400);

    const row = await get('SELECT image_blob, image_mime FROM menu_items WHERE id=$1', [id]);
    if (!row || !row.image_blob) return res.sendStatus(404);

    const mime = row.image_mime || 'image/png';
    res.setHeader('Content-Type', mime);
    res.setHeader('Cache-Control', 'public, max-age=86400');
    return res.end(row.image_blob);
  } catch (e) {
    console.error('[GET /images/:id] error:', e);
    return res.sendStatus(500);
  }
});

/* ------------------- SPA FALLBACK ------------------- */
app.get(/^(?!\/(api|uploads|images|healthz|debug|print)(\/|$)).*/, (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

/* ------------------- START: sobe HTTP primeiro ------------------- */
server.listen(PORT, '0.0.0.0', async () => {
  console.log(`Servidor rodando em http://localhost:${PORT}`);
  console.log(`Home:  http://localhost:${PORT}/index.html`);
  console.log(`Loja:  http://localhost:${PORT}/store.html`);
  console.log(`Admin: http://localhost:${PORT}/admin.html`);
  console.log(`Impressão: ${PRINT_ENABLED ? (PRINTER_SHARE ? `Windows/UNC ${PRINTER_SHARE}` : `rede ${PRINTER_HOST}:${PRINTER_PORT}`) : 'desabilitada'}`);
  const emailState = EMAIL_ENABLED ? `habilitado (provider=${EMAIL_PROVIDER})` : 'desabilitado';
  console.log(`E-mail: ${emailState}`);
  console.log(`UPLOADS_DIR=${UPLOADS_DIR}`);
  console.log(`PAGE_OPEN_FRESH_SECONDS = ${PAGE_OPEN_FRESH_SECONDS}s  |  SESSION_TTL_SECONDS = ${SESSION_TTL_SECONDS}s`);

  if (EMAIL_ENABLED && EMAIL_PROVIDER === 'smtp' && mailer) {
    try {
      await mailer.verify();
      console.log('[MAILER] SMTP OK');
    } catch (e) {
      console.warn('[MAILER] Falha ao verificar SMTP:', e?.message || e);
    }
  }
});

/* ====== Inicializa DB em background (não bloqueia boot/health) ====== */
(async () => {
  try {
    await initDb();
  } catch (e) {
    console.error('[DB INIT FAILED]', e?.message || e);
    // não finaliza o processo — mantém o HTTP vivo para o healthcheck
  }
})();

/* ---------- Shutdown gracioso ---------- */
function shutdown(sig) {
  console.log(`[SHUTDOWN] sinal ${sig} recebido. Encerrando...`);
  server.close(async () => {
    try { await pool.end(); } catch {}
    process.exit(0);
  });
}
['SIGINT','SIGTERM'].forEach(s => process.on(s, () => shutdown(s)));
