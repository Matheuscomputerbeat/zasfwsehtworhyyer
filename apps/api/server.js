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
const sqlite3 = require("sqlite3").verbose();
const QRCode = require("qrcode");
const { Client, LocalAuth } = require("whatsapp-web.js");

const app = express();

// ----- ENV -----
const PORT = process.env.PORT || 8080;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "..", "..", "data");
const DB_FILE = path.join(DATA_DIR, "app.db");
const JWT_SECRET = process.env.JWT_SECRET || "troque-este-segredo";
const CORS_ORIGIN = process.env.CORS_ORIGIN || "*";
const ADMIN_USER_ENV = process.env.ADMIN_USER || ""; // opcional
const ADMIN_PASS_ENV = process.env.ADMIN_PASS || ""; // opcional

fs.mkdirSync(DATA_DIR, { recursive: true });

// ----- MIDDLEWARE -----
app.use(express.json({ limit: "1mb" }));
app.use(cors({ origin: CORS_ORIGIN === "*" ? true : CORS_ORIGIN }));

// ----- DB -----
const db = new sqlite3.Database(DB_FILE);
function run(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) { if (err) reject(err); else resolve(this); });
  });
}
function get(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => (err ? reject(err) : resolve(row)));
  });
}
function all(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => (err ? reject(err) : resolve(rows)));
  });
}

async function migrate() {
  await run(`CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    passhash TEXT NOT NULL,
    created_at TEXT NOT NULL
  )`);

  await run(`CREATE TABLE IF NOT EXISTS settings(
    key TEXT PRIMARY KEY,
    value TEXT
  )`);

  await run(`CREATE TABLE IF NOT EXISTS groups(
    id TEXT PRIMARY KEY
  )`);

  // defaults
  const msg = await get(`SELECT value FROM settings WHERE key='message'`);
  if (!msg) await run(`INSERT INTO settings(key,value) VALUES('message','Olá, mundo!')`);
  const sch = await get(`SELECT value FROM settings WHERE key='schedule'`);
  if (!sch) await run(`INSERT INTO settings(key,value) VALUES('schedule','09:00, 14:00')`);
  const pow = await get(`SELECT value FROM settings WHERE key='powerDisabled'`);
  if (!pow) await run(`INSERT INTO settings(key,value) VALUES('powerDisabled','false')`);

  // seed admin via env se não existir
  const userCount = await get(`SELECT COUNT(1) as c FROM users`);
  if (userCount.c === 0 && ADMIN_USER_ENV && ADMIN_PASS_ENV) {
    const hash = bcrypt.hashSync(ADMIN_PASS_ENV, 10);
    await run(
      `INSERT INTO users(username, passhash, created_at) VALUES(?,?,datetime('now'))`,
      [ADMIN_USER_ENV, hash]
    );
    console.log("[seed] admin criado via env:", ADMIN_USER_ENV);
  }
}
function setSetting(key, value) {
  return run(`INSERT INTO settings(key,value) VALUES(?,?)
              ON CONFLICT(key) DO UPDATE SET value=excluded.value`, [key, value]);
}
async function getSetting(key, fallback = "") {
  const r = await get(`SELECT value FROM settings WHERE key=?`, [key]);
  return r ? r.value : fallback;
}

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

// usuário único: só permite signup se tabela estiver vazia
app.post("/auth/signup", async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: "campos" });
    const r = await get(`SELECT COUNT(1) as c FROM users`);
    if (r.c > 0) return res.status(409).json({ error: "existe" }); // já existe alguém
    const hash = bcrypt.hashSync(password, 10);
    await run(
      `INSERT INTO users(username, passhash, created_at) VALUES(?,?,datetime('now'))`,
      [username, hash]
    );
    const token = jwt.sign({ u: username }, JWT_SECRET, { expiresIn: "7d" });
    res.json({ ok: true, token, username });
  } catch (e) {
    res.status(500).json({ error: "signup" });
  }
});

app.post("/auth/login", async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: "campos" });
    const u = await get(`SELECT * FROM users WHERE username=?`, [username]);
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

let wa = {
  client: null,
  status: "idle", // idle | connecting | waiting_qr | connected | closed | error
  lastQR: null,
};

function startWhatsApp() {
  if (wa.client) return wa.client;

  wa.status = "connecting";
  wa.lastQR = null;

  const client = new Client({
    authStrategy: new LocalAuth({ dataPath: WA_DIR, clientId: "bot" }),
    puppeteer: {
      headless: true,
      args: ["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage"]
    }
  });

  client.on("qr", (qr) => {
    wa.lastQR = qr;
    wa.status = "waiting_qr";
    console.log("[WA] QR gerado");
  });

  client.on("authenticated", () => {
    wa.status = "connecting";
    console.log("[WA] authenticated");
  });

  client.on("ready", () => {
    wa.status = "connected";
    wa.lastQR = null;
    console.log("[WA] ready");
  });

  client.on("auth_failure", (msg) => {
    wa.status = "error";
    console.error("[WA] auth_failure:", msg);
  });

  client.on("disconnected", (reason) => {
    console.warn("[WA] disconnected:", reason);
    wa.status = "closed";
    wa.client = null;
    // auto-restart
    setTimeout(() => {
      try { startWhatsApp(); } catch {}
    }, 3000);
  });

  client.initialize().catch((e) => {
    wa.status = "error";
    console.error("[WA] initialize error:", e);
  });

  wa.client = client;
  return client;
}

async function ensureWhatsApp() {
  if (!wa.client) startWhatsApp();
}

// ----- POWER -----
app.get("/api/power", auth, async (_req, res) => {
  const disabled = (await getSetting("powerDisabled", "false")) === "true";
  res.json({ disabled });
});

app.post("/api/power", auth, async (req, res) => {
  const on = !!(req.body && req.body.on);
  await setSetting("powerDisabled", on ? "false" : "true");
  if (on) {
    ensureWhatsApp();
  } else {
    try { await wa.client?.destroy(); } catch {}
    wa.client = null;
    wa.status = "closed";
  }
  res.json({ ok: true, disabled: !on });
});

// ----- DADOS -----
app.get("/api/message", auth, async (_req, res) => {
  res.type("text/plain").send(await getSetting("message", ""));
});

app.post("/api/message", auth, async (req, res) => {
  const text = String((req.body && req.body.text) || "");
  await setSetting("message", text);
  res.json({ ok: true });
});

app.get("/api/schedule", auth, async (_req, res) => {
  res.type("text/plain").send(await getSetting("schedule", ""));
});

app.post("/api/schedule", auth, async (req, res) => {
  const text = String((req.body && req.body.text) || "");
  await setSetting("schedule", text);
  res.json({ ok: true });
});

app.get("/api/groups", auth, async (_req, res) => {
  const rows = await all(`SELECT id FROM groups ORDER BY id`);
  res.json(rows.map((r) => r.id));
});

app.post("/api/groups", auth, async (req, res) => {
  const arr = Array.isArray(req.body) ? req.body : [];
  await run("DELETE FROM groups");
  const stmt = db.prepare("INSERT OR IGNORE INTO groups(id) VALUES(?)");
  await new Promise((resolve, reject) => {
    db.serialize(() => {
      arr.forEach((g) => stmt.run([String(g)]));
      stmt.finalize((e) => (e ? reject(e) : resolve()));
    });
  });
  res.json({ ok: true });
});

// ----- QR -----
app.get("/api/qr", auth, async (_req, res) => {
  try {
    await ensureWhatsApp();
    if (wa.status === "connected") return res.status(204).end();
    if (!wa.lastQR) return res.status(202).json({ status: wa.status || "connecting" });
    const png = await QRCode.toBuffer(wa.lastQR, { type: "png", width: 256, margin: 1 });
    res.type("image/png").send(png);
  } catch (e) {
    console.error("[QR] error:", e);
    res.status(500).json({ error: "qr" });
  }
});

app.get("/api/qr/status", auth, async (_req, res) => {
  try {
    await ensureWhatsApp();
    res.json({ status: wa.status || "connecting" });
  } catch {
    res.json({ status: "connecting" });
  }
});

// ----- BOT RESTART -----
app.post("/api/bot/restart", auth, async (_req, res) => {
  try {
    if (wa.client) {
      try { await wa.client.destroy(); } catch {}
      wa.client = null;
    }
    wa.status = "idle";
    startWhatsApp();
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: "restart" });
  }
});

// ----- HEALTH -----
app.get("/health", (_req, res) => res.json({ ok: true, ts: Date.now() }));

// (opcional) servir web local em dev
const WEB = path.join(__dirname, "..", "web");
if (fs.existsSync(WEB)) app.use("/", express.static(WEB));

// ----- BOOT -----
(async () => {
  await migrate();
  // auto-start se não estiver desligado
  const disabled = (await getSetting("powerDisabled", "false")) === "true";
  if (!disabled) ensureWhatsApp();

  app.listen(PORT, () => console.log("[API] porta:", PORT));
})();
