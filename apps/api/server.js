// API simples: cadastro/login com JWT e dados por usuário em arquivos.
// Rotas protegidas: /api/message, /api/groups, /api/schedule, /api/power
// Healthcheck: /health

const express = require('express');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 8080;
const DATA = process.env.DATA_DIR || path.join(__dirname, '..', '..', 'data');
const USERS = path.join(DATA, 'users');
const JWT_SECRET = process.env.JWT_SECRET || 'troque-este-segredo';
const CORS_ORIGIN = process.env.CORS_ORIGIN || '*';

fs.mkdirSync(USERS, { recursive: true });
app.use(express.json({ limit: '1mb' }));
app.use(cors({ origin: CORS_ORIGIN === '*' ? true : CORS_ORIGIN }));

function userDir(u) {
  const safe = String(u || '').replace(/[^a-z0-9_\-\.]/gi, '_');
  const d = path.join(USERS, safe);
  fs.mkdirSync(d, { recursive: true });
  return d;
}
function readJSON(p, f) { try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch { return f; } }

function auth(req, res, next) {
  const m = (req.headers.authorization || '').match(/^Bearer\s+(.+)$/i);
  if (!m) return res.status(401).json({ error: 'token' });
  try {
    const payload = jwt.verify(m[1], JWT_SECRET);
    req.user = payload.u;
    next();
  } catch {
    return res.status(401).json({ error: 'token' });
  }
}

// ----- Auth -----
app.post('/auth/signup', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'campos' });
  const d = userDir(username), prof = path.join(d, 'profile.json');
  if (fs.existsSync(prof)) return res.status(409).json({ error: 'existe' });
  const hash = bcrypt.hashSync(password, 10);
  fs.writeFileSync(prof, JSON.stringify({ username, hash, createdAt: new Date().toISOString() }, null, 2));
  fs.writeFileSync(path.join(d, 'message.txt'), 'Olá, mundo!');
  fs.writeFileSync(path.join(d, 'schedule.txt'), '09:00, 14:00');
  fs.writeFileSync(path.join(d, 'groups.json'), '[]');
  const token = jwt.sign({ u: username }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ ok: true, token, username });
});

app.post('/auth/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'campos' });
  const d = userDir(username), prof = path.join(d, 'profile.json');
  if (!fs.existsSync(prof)) return res.status(404).json({ error: 'naoexist' });
  const profile = readJSON(prof, {});
  if (!bcrypt.compareSync(password, profile.hash)) return res.status(401).json({ error: 'senha' });
  const token = jwt.sign({ u: username }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ ok: true, token, username });
});

// ----- Power (liga/desliga) -----
app.post('/api/power', auth, (req, res) => {
  const d = userDir(req.user);
  const p = path.join(d, 'disabled.json');
  const on = !!(req.body && req.body.on);
  fs.writeFileSync(p, JSON.stringify({ global: !on, at: new Date().toISOString() }, null, 2));
  res.json({ ok: true, disabled: !on });
});

app.get('/api/power', auth, (req, res) => {
  const d = userDir(req.user);
  const p = path.join(d, 'disabled.json');
  let disabled = false;
  try { disabled = JSON.parse(fs.readFileSync(p, 'utf8')).global === true; } catch {}
  res.json({ disabled });
});

// ----- Dados -----
app.get('/api/message', auth, (req, res) => {
  const d = userDir(req.user);
  const p = path.join(d, 'message.txt');
  res.type('text/plain').send(fs.existsSync(p) ? fs.readFileSync(p, 'utf8') : '');
});

app.post('/api/message', auth, (req, res) => {
  const d = userDir(req.user);
  fs.writeFileSync(path.join(d, 'message.txt'), String((req.body && req.body.text) || ''));
  res.json({ ok: true });
});

app.get('/api/groups', auth, (req, res) => {
  const d = userDir(req.user);
  const p = path.join(d, 'groups.json');
  res.type('application/json').send(fs.existsSync(p) ? fs.readFileSync(p, 'utf8') : '[]');
});

app.post('/api/groups', auth, (req, res) => {
  const d = userDir(req.user);
  const arr = Array.isArray(req.body) ? req.body : [];
  fs.writeFileSync(path.join(d, 'groups.json'), JSON.stringify(arr, null, 2));
  res.json({ ok: true });
});

// ----- Healthcheck (para Render/Koyeb acordar) -----
app.get('/health', (_, res) => res.json({ ok: true, ts: Date.now() }));

// (Opcional) servir a web localmente
const WEB = path.join(__dirname, '..', 'web');
if (fs.existsSync(WEB)) app.use('/', express.static(WEB));

app.listen(PORT, () => console.log('API :' + PORT));
