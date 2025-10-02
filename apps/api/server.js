// API: auth com JWT, dados por usuário em arquivos e sessão WhatsApp (whatsapp-web.js).
// Rotas: /auth/signup, /auth/login
//        /api/power, /api/message, /api/groups, /api/schedule
//        /api/qr, /api/qr/status, /api/logout, /api/qr/reset
// Health: /health

const express = require('express');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const QRCode = require('qrcode');
const { Client, LocalAuth } = require('whatsapp-web.js');

const app = express();

const PORT        = process.env.PORT || 8080;
const ROOT_DATA   = process.env.DATA_DIR || path.join(__dirname, '..', '..', 'data');
const USERS_DIR   = path.join(ROOT_DATA, 'users');
const JWT_SECRET  = process.env.JWT_SECRET || 'troque-este-segredo';
const CORS_ORIGIN = process.env.CORS_ORIGIN || '*';

// FS base
fs.mkdirSync(USERS_DIR, { recursive: true });

// Middlewares
app.use(express.json({ limit: '1mb' }));
app.use(cors({ origin: CORS_ORIGIN === '*' ? true : CORS_ORIGIN }));

// Utils
function normalize(u){ return String(u || '').trim().toLowerCase(); }
function safeName(u){ return normalize(u).replace(/[^a-z0-9_.-]/gi, '_'); }
function userDir(u){
  const d = path.join(USERS_DIR, safeName(u));
  fs.mkdirSync(d, { recursive: true });
  return d;
}
function readJSON(p, fallback){
  try{ return JSON.parse(fs.readFileSync(p,'utf8')); } catch{ return fallback; }
}
function writeJSON(p, obj){
  fs.writeFileSync(p, JSON.stringify(obj, null, 2));
}

// Auth middleware
function auth(req, res, next){
  const m = (req.headers.authorization || '').match(/^Bearer\s+(.+)$/i);
  if(!m) return res.status(401).json({ error: 'token' });
  try{
    const payload = jwt.verify(m[1], JWT_SECRET);
    req.user = normalize(payload.u);
    if(!req.user) return res.status(401).json({ error:'token' });
    next();
  }catch{
    return res.status(401).json({ error: 'token' });
  }
}

// ---------- Auth ----------
app.post('/auth/signup', (req, res) => {
  let { username, password } = req.body || {};
  username = normalize(username);
  if(!username || !password) return res.status(400).json({ error: 'campos' });

  const d    = userDir(username);
  const prof = path.join(d, 'profile.json');
  if(fs.existsSync(prof)) return res.status(409).json({ error: 'existe' }); // impede duplicação por caixa alta

  const hash = bcrypt.hashSync(password, 10);
  writeJSON(prof, { username, hash, createdAt: new Date().toISOString() });
  fs.writeFileSync(path.join(d,'message.txt'), 'Olá, mundo!');
  fs.writeFileSync(path.join(d,'schedule.txt'), '09:00, 14:00');
  fs.writeFileSync(path.join(d,'groups.json'), '[]');

  const token = jwt.sign({ u: username }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ ok:true, token, username });
});

app.post('/auth/login', (req, res) => {
  let { username, password } = req.body || {};
  username = normalize(username);
  if(!username || !password) return res.status(400).json({ error: 'campos' });

  const d    = userDir(username);
  const prof = path.join(d, 'profile.json');
  if(!fs.existsSync(prof)) return res.status(404).json({ error: 'naoexist' });

  const profile = readJSON(prof, {});
  if(!bcrypt.compareSync(password, profile.hash)) return res.status(401).json({ error:'senha' });

  const token = jwt.sign({ u: username }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ ok:true, token, username });
});

// ---------- Power ----------
app.post('/api/power', auth, (req, res) => {
  const d = userDir(req.user);
  const p = path.join(d, 'disabled.json');
  const on = !!(req.body && req.body.on);
  writeJSON(p, { global: !on, at: new Date().toISOString() });
  res.json({ ok:true, disabled: !on });
});

app.get('/api/power', auth, (req, res) => {
  const d = userDir(req.user);
  const p = path.join(d, 'disabled.json');
  let disabled = false;
  try{ disabled = JSON.parse(fs.readFileSync(p,'utf8')).global === true; }catch{}
  res.json({ disabled });
});

// ---------- Dados ----------
app.get('/api/message', auth, (req, res) => {
  const d = userDir(req.user);
  const p = path.join(d,'message.txt');
  res.type('text/plain').send(fs.existsSync(p) ? fs.readFileSync(p,'utf8') : '');
});
app.post('/api/message', auth, (req, res) => {
  const d = userDir(req.user);
  fs.writeFileSync(path.join(d,'message.txt'), String((req.body && req.body.text) || ''));
  res.json({ ok:true });
});

app.get('/api/groups', auth, (req, res) => {
  const d = userDir(req.user);
  const p = path.join(d,'groups.json');
  res.type('application/json').send(fs.existsSync(p) ? fs.readFileSync(p,'utf8') : '[]');
});
app.post('/api/groups', auth, (req, res) => {
  const d = userDir(req.user);
  const arr = Array.isArray(req.body) ? req.body : [];
  fs.writeFileSync(path.join(d,'groups.json'), JSON.stringify(arr, null, 2));
  res.json({ ok:true });
});

app.get('/api/schedule', auth, (req, res) => {
  const d = userDir(req.user);
  const p = path.join(d,'schedule.txt');
  res.type('text/plain').send(fs.existsSync(p) ? fs.readFileSync(p,'utf8') : '');
});
app.post('/api/schedule', auth, (req, res) => {
  const d = userDir(req.user);
  const text = String((req.body && req.body.text) || '');
  fs.writeFileSync(path.join(d,'schedule.txt'), text);
  res.json({ ok:true });
});

// ---------- WhatsApp (whatsapp-web.js) ----------
const sessions = new Map(); // user -> { client, status, lastQR, lastErr, startedAt }

async function startSession(user){
  const d = userDir(user);
  const authBase = path.join(d, 'wwjs-auth'); // cada user tem sua pasta

  const client = new Client({
    authStrategy: new LocalAuth({ dataPath: authBase }),
    puppeteer: {
      headless: true,
      args: ['--no-sandbox','--disable-setuid-sandbox']
    }
  });

  const s = { client, status: 'connecting', lastQR: null, lastErr: null, startedAt: Date.now() };
  sessions.set(user, s);

  client.on('qr', (qr) => { s.lastQR = qr; s.status = 'waiting_qr'; });
  client.on('authenticated', () => { s.status = 'connecting'; });
  client.on('ready', () => { s.status = 'connected'; });
  client.on('auth_failure', (msg) => { s.status = 'closed'; s.lastErr = String(msg); });
  client.on('disconnected', (reason) => { s.status = 'closed'; s.lastErr = String(reason); });

  client.initialize();
  return s;
}
async function ensureSession(user){
  return sessions.get(user) || startSession(user);
}

app.get('/api/qr', auth, async (req, res) => {
  try{
    const s = await ensureSession(req.user);
    if(s.status === 'connected') return res.status(204).end();
    if(!s.lastQR) return res.status(202).json({ status: s.status || 'connecting' });
    const png = await QRCode.toBuffer(s.lastQR, { type: 'png', width: 256, margin: 1 });
    res.type('image/png').send(png);
  }catch(e){
    res.status(500).json({ error:'qr', msg:String(e.message||e) });
  }
});

app.get('/api/qr/status', auth, async (req, res) => {
  try{
    const s = await ensureSession(req.user);
    res.json({ status: s.status || 'connecting', reason: s.lastErr || null });
  }catch{
    res.json({ status: 'connecting', reason: null });
  }
});

app.post('/api/logout', auth, async (req, res) => {
  const s = sessions.get(req.user);
  try{ await s?.client?.logout(); }catch{}
  try{ await s?.client?.destroy(); }catch{}
  sessions.delete(req.user);
  res.json({ ok:true });
});

app.post('/api/qr/reset', auth, async (req, res) => {
  try{
    const s = sessions.get(req.user);
    try{ await s?.client?.destroy(); }catch{}
    sessions.delete(req.user);

    const d = userDir(req.user);
    const authBase = path.join(d, 'wwjs-auth');
    try{ fs.rmSync(authBase, { recursive:true, force:true }); }catch{}

    await startSession(req.user);
    res.json({ ok:true });
  }catch(e){
    res.status(500).json({ error:'reset', msg:String(e.message||e) });
  }
});

// ---------- Health ----------
app.get('/health', (_, res) => res.json({ ok:true, ts: Date.now() }));

// ---------- Estático local (opcional) ----------
const WEB_DIR = path.join(__dirname, '..', 'web');
if(fs.existsSync(WEB_DIR)){
  app.use('/', express.static(WEB_DIR));
}

// Start
app.listen(PORT, () => console.log('API :' + PORT));
