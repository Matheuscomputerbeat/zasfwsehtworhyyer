// WhatsApp Web JS + API REST + SQLite + usuário único (admin).
// Endpoints:
//  POST /auth/signup {username,password}   -> cria admin se não existir
//  POST /auth/login  {username,password}   -> JWT
//  GET  /api/power                       -> {disabled:bool}
//  POST /api/power {on:true|false}
//  GET  /api/message  (text/plain)
//  POST /api/message {text:string}
//  GET  /api/groups   (json array)
//  POST /api/groups   (json array de IDs @g.us)
//  GET  /api/schedule (text/plain)
//  POST /api/schedule {text:string}
//  GET  /api/qr        -> 204 conectado | 202 aguardando | PNG
//  GET  /api/qr/status -> {status}
//  POST /api/bot/restart
//  GET  /health

const path = require("path");
const fs = require("fs");
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");
const QRCode = require("qrcode");
const { Client, LocalAuth } = require("whatsapp-web.js");

const app = express();

// ----- ENV -----
const PORT = process.env.PORT || 8080;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "..", "..", "data");
const DB_FILE = path.join(DATA_DIR, "app.db");
const JWT_SECRET = process.env.JWT_SECRET || "troque-este-segredo";
const CORS_ORIGIN = process.env.CORS_ORIGIN || "*";
const ADMIN_USER_ENV = process.env.ADMIN_USER || "";
const ADMIN_PASS_ENV = process.env.ADMIN_PASS || "";

fs.mkdirSync(DATA_DIR, { recursive: true });

// ----- DB -----
const db = new Database(DB_FILE);

function setSetting(key, value) {
  db.prepare(`INSERT INTO settings(key,value) VALUES(?,?)
              ON CONFLICT(key) DO UPDATE SET value=excluded.value`).run(key, value);
}
function getSetting(key, fallback = "") {
  const r = db.prepare("SELECT value FROM settings WHERE key=?").get(key);
  return r ? r.value : fallback;
}

function migrate() {
  db.prepare(`CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    passhash TEXT NOT NULL,
    created_at TEXT NOT NULL
  )`).run();

  db.prepare(`CREATE TABLE IF NOT EXISTS settings(
    key TEXT PRIMARY KEY,
    value TEXT
  )`).run();

  db.prepare(`CREATE TABLE IF NOT EXISTS groups(
    id TEXT PRIMARY KEY
  )`).run();

  if (!getSetting("message")) setSetting("message", "Olá, mundo!");
  if (!getSetting("schedule")) setSetting("schedule", "09:00, 14:00");
  if (!getSetting("powerDisabled")) setSetting("powerDisabled", "false");

  const userCount = db.prepare("SELECT COUNT(1) as c FROM users").get().c;
  if (userCount === 0 && ADMIN_USER_ENV && ADMIN_PASS_ENV) {
    const hash = bcrypt.hashSync(ADMIN_PASS_ENV, 10);
    db.prepare("INSERT INTO users(username, passhash, created_at) VALUES(?,?,datetime('now'))")
      .run(ADMIN_USER_ENV, hash);
    console.log("[seed] admin criado via env:", ADMIN_USER_ENV);
  }
}

// ----- MIDDLEWARE -----
app.use(express.json({ limit: "1mb" }));
app.use(cors({ origin: CORS_ORIGIN === "*" ? true : CORS_ORIGIN }));

// ----- AUTH -----
function auth(req, res, next) {
  try {
    const m = (req.headers.authorization || "").match(/^Bearer\s+(.+)$/i);
    if (!m) return res.status(401).json({ error: "token" });
    const payload = jwt.verify(m[1], JWT_SECRET);
    req.user = payload.u;
    next();
  } catch {
    return res.status(401).json({ error: "token" });
  }
}

// usuário único
app.post("/auth/signup", (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: "campos" });

    const r = db.prepare("SELECT COUNT(1) as c FROM users").get();
    if (r.c > 0) return res.status(409).json({ error: "existe" });

    const hash = bcrypt.hashSync(password, 10);
    db.prepare("INSERT INTO users(username, passhash, created_at) VALUES(?,?,datetime('now'))")
      .run(username, hash);

    const token = jwt.sign({ u: username }, JWT_SECRET, { expiresIn: "7d" });
    res.json({ ok: true, token, username });
  } catch (e) {
    res.status(500).json({ error: "signup" });
  }
});

app.post("/auth/login", (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: "campos" });

    const u = db.prepare("SELECT * FROM users WHERE username=?").get(username);
    if (!u) return res.status(404).json({ error: "naoexist" });
    if (!bcrypt.compareSync(password, u.passhash)) return res.status(401).json({ error: "senha" });

    const token = jwt.sign({ u: username }, JWT_SECRET, { expiresIn: "7d" });
    res.json({ ok: true, token, username });
  } catch (e) {
    res.status(500).json({ error: "login" });
  }
});

// ----- WhatsApp -----
const WA_DIR = path.join(DATA_DIR, "wwebjs_auth");
fs.mkdirSync(WA_DIR, { recursive: true });

let wa = { client: null, status: "idle", lastQR: null };

function startWhatsApp() {
  if (wa.client) return wa.client;

  wa.status = "connecting";
  wa.lastQR = null;

  const client = new Client({
    authStrategy: new LocalAuth({ dataPath: WA_DIR, clientId: "bot" }),
    puppeteer: { headless: true, args: ["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage"] }
  });

  client.on("qr", (qr) => { wa.lastQR = qr; wa.status = "waiting_qr"; console.log("[WA] QR gerado"); });
  client.on("authenticated", () => { wa.status = "connecting"; console.log("[WA] authenticated"); });
  client.on("ready", () => { wa.status = "connected"; wa.lastQR = null; console.log("[WA] ready"); });
  client.on("auth_failure", (msg) => { wa.status = "error"; console.error("[WA] auth_failure:", msg); });
  client.on("disconnected", (reason) => {
    console.warn("[WA] disconnected:", reason);
    wa.status = "closed"; wa.client = null;
    setTimeout(() => { try { startWhatsApp(); } catch {} }, 3000);
  });

  client.initialize().catch((e) => { wa.status = "error"; console.error("[WA] init error:", e); });

  wa.client = client;
  return client;
}

function ensureWhatsApp() { if (!wa.client) startWhatsApp(); }

// ----- POWER -----
app.get("/api/power", auth, (_req, res) => res.json({ disabled: getSetting("powerDisabled", "false") === "true" }));
app.post("/api/power", auth, (req, res) => {
  const on = !!(req.body && req.body.on);
  setSetting("powerDisabled", on ? "false" : "true");
  if (on) ensureWhatsApp();
  else { try { wa.client?.destroy(); } catch {} wa.client = null; wa.status = "closed"; }
  res.json({ ok: true, disabled: !on });
});

// ----- DADOS -----
app.get("/api/message", auth, (_req, res) => res.type("text/plain").send(getSetting("message", "")));
app.post("/api/message", auth, (req, res) => { setSetting("message", String(req.body?.text || "")); res.json({ ok: true }); });

app.get("/api/schedule", auth, (_req, res) => res.type("text/plain").send(getSetting("schedule", "")));
app.post("/api/schedule", auth, (req, res) => { setSetting("schedule", String(req.body?.text || "")); res.json({ ok: true }); });

app.get("/api/groups", auth, (_req, res) => {
  const rows = db.prepare("SELECT id FROM groups ORDER BY id").all();
  res.json(rows.map((r) => r.id));
});
app.post("/api/groups", auth, (req, res) => {
  const arr = Array.isArray(req.body) ? req.body : [];
  db.prepare("DELETE FROM groups").run();
  const stmt = db.prepare("INSERT OR IGNORE INTO groups(id) VALUES(?)");
  const insertMany = db.transaction((groups) => { for (const g of groups) stmt.run(String(g)); });
  insertMany(arr);
  res.json({ ok: true });
});

// ----- QR -----
app.get("/api/qr", auth, async (_req, res) => {
  try {
    ensureWhatsApp();
    if (wa.status === "connected") return res.status(204).end();
    if (!wa.lastQR) return res.status(202).json({ status: wa.status || "connecting" });
    const png = await QRCode.toBuffer(wa.lastQR, { type: "png", width: 256, margin: 1 });
    res.type("image/png").send(png);
  } catch (e) { console.error("[QR] error:", e); res.status(500).json({ error: "qr" }); }
});
app.get("/api/qr/status", auth, (_req, res) => res.json({ status: wa.status || "connecting" }));

// ----- BOT RESTART -----
app.post("/api/bot/restart", auth, (_req, res) => {
  try {
    if (wa.client) { try { wa.client.destroy(); } catch {} wa.client = null; }
    wa.status = "idle"; startWhatsApp(); res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: "restart" }); }
});

// ----- HEALTH -----
app.get("/health", (_req, res) => res.json({ ok: true, ts: Date.now() }));

// ----- BOOT -----
(() => {
  migrate();
  if (getSetting("powerDisabled", "false") !== "true") ensureWhatsApp();
  app.listen(PORT, () => console.log("[API] porta:", PORT));
})();
