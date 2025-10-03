// WhatsApp Web JS + API REST + SQLite (+ backup criptografado em arquivo).
// Rotas principais:
//  POST /auth/signup {username,password}  -> cria admin se não existir (apenas 1x)
//  POST /auth/login  {username,password}  -> JWT
//  GET  /api/power                       -> {disabled:bool}
//  POST /api/power {on:true|false}
//  GET  /api/message  (text/plain)       /  POST /api/message {text}
//  GET  /api/groups   (json array)       /  POST /api/groups (json array)
//  GET  /api/schedule (text/plain)       /  POST /api/schedule {text}
//  GET  /api/qr -> 204 conectado | 202 aguardando | PNG do QR
//  GET  /api/qr/status -> {status}
//  POST /api/state/backup  -> gera backup criptografado (state/state.enc)
//  GET  /api/state/download -> baixa o backup
//  GET  /health

const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");
const QRCode = require("qrcode");
const tar = require("tar");
const { Client, LocalAuth } = require("whatsapp-web.js");

const app = express();

// ---------- ENV ----------
const PORT = process.env.PORT || 8080;
const DATA_DIR = process.env.DATA_DIR || "/tmp/data";
const DB_FILE = path.join(DATA_DIR, "app.db");
const STATE_DIR = path.join(__dirname, "..", "..", "state"); // no repo
const STATE_ENC = path.join(STATE_DIR, "state.enc");          // arquivo criptografado commitável
const JWT_SECRET = process.env.JWT_SECRET || "troque-este-segredo";
const CORS_ORIGIN = process.env.CORS_ORIGIN || "*";
const STATE_KEY = process.env.STATE_KEY || ""; // chave hex 32 bytes (64 hex)

fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(STATE_DIR, { recursive: true });

app.use(express.json({ limit: "1mb" }));
app.use(cors({ origin: CORS_ORIGIN === "*" ? true : CORS_ORIGIN }));

// ---------- DB ----------
const db = new Database(DB_FILE);
db.pragma("journal_mode = WAL");

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

  // defaults
  const hasMsg = db.prepare("SELECT 1 FROM settings WHERE key='message'").get();
  if (!hasMsg) db.prepare("INSERT INTO settings(key,value) VALUES('message','Olá, mundo!')").run();
  const hasSch = db.prepare("SELECT 1 FROM settings WHERE key='schedule'").get();
  if (!hasSch) db.prepare("INSERT INTO settings(key,value) VALUES('schedule','09:00, 14:00')").run();
  const hasPow = db.prepare("SELECT 1 FROM settings WHERE key='powerDisabled'").get();
  if (!hasPow) db.prepare("INSERT INTO settings(key,value) VALUES('powerDisabled','false')").run();
}
function setSetting(key, value) {
  db.prepare(`INSERT INTO settings(key,value) VALUES(?,?)
              ON CONFLICT(key) DO UPDATE SET value=excluded.value`).run(key, value);
}
function getSetting(key, fallback = "") {
  const r = db.prepare("SELECT value FROM settings WHERE key=?").get(key);
  return r ? r.value : fallback;
}

// ---------- AUTH ----------
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

// Signup único
app.post("/auth/signup", (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: "campos" });
    const c = db.prepare("SELECT COUNT(1) c FROM users").get().c;
    if (c > 0) return res.status(409).json({ error: "existe" });
    const hash = bcrypt.hashSync(password, 10);
    db.prepare("INSERT INTO users(username, passhash, created_at) VALUES(?,?,datetime('now'))")
      .run(username, hash);
    const token = jwt.sign({ u: username }, JWT_SECRET, { expiresIn: "7d" });
    res.json({ ok: true, token, username });
  } catch {
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
  } catch {
    res.status(500).json({ error: "login" });
  }
});

// ---------- WhatsApp ----------
const WA_DIR = path.join(DATA_DIR, "wwebjs_auth");
fs.mkdirSync(WA_DIR, { recursive: true });

let wa = { client: null, status: "idle", lastQR: null };

function startWhatsApp() {
  if (wa.client) return wa.client;
  wa.status = "connecting"; wa.lastQR = null;

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
  client.on("authenticated", () => { wa.status = "connecting"; });
  client.on("ready", () => { wa.status = "connected"; wa.lastQR = null; console.log("[WA] ready"); });
  client.on("auth_failure", (m) => { wa.status = "error"; console.error("[WA] auth_failure:", m); });
  client.on("disconnected", (reason) => {
    console.warn("[WA] disconnected:", reason);
    wa.status = "closed"; try { wa.client?.destroy(); } catch {}
    wa.client = null; setTimeout(() => { try { startWhatsApp(); } catch{} }, 3000);
  });

  client.initialize().catch((e) => { wa.status = "error"; console.error("[WA] init error:", e); });
  wa.client = client; return client;
}
function ensureWhatsApp() { if (!wa.client) startWhatsApp(); }

// ---------- POWER ----------
app.get("/api/power", auth, (_req, res) => {
  const disabled = getSetting("powerDisabled", "false") === "true";
  res.json({ disabled });
});
app.post("/api/power", auth, (req, res) => {
  const on = !!(req.body && req.body.on);
  setSetting("powerDisabled", on ? "false" : "true");
  if (on) ensureWhatsApp();
  else { try { wa.client?.destroy(); } catch {} wa.client = null; wa.status = "closed"; }
  res.json({ ok: true, disabled: !on });
});

// ---------- DADOS ----------
app.get("/api/message", auth, (_req, res) => {
  res.type("text/plain").send(getSetting("message", ""));
});
app.post("/api/message", auth, (req, res) => {
  setSetting("message", String((req.body && req.body.text) || ""));
  res.json({ ok: true });
});

app.get("/api/schedule", auth, (_req, res) => {
  res.type("text/plain").send(getSetting("schedule", ""));
});
app.post("/api/schedule", auth, (req, res) => {
  setSetting("schedule", String((req.body && req.body.text) || ""));
  res.json({ ok: true });
});

app.get("/api/groups", auth, (_req, res) => {
  const rows = db.prepare("SELECT id FROM groups ORDER BY id").all();
  res.json(rows.map(r => r.id));
});
app.post("/api/groups", auth, (req, res) => {
  const arr = Array.isArray(req.body) ? req.body : [];
  const tx = db.transaction(() => {
    db.prepare("DELETE FROM groups").run();
    const ins = db.prepare("INSERT OR IGNORE INTO groups(id) VALUES(?)");
    arr.forEach(g => ins.run(String(g)));
  });
  tx();
  res.json({ ok: true });
});

// ---------- QR ----------
app.get("/api/qr", auth, async (_req, res) => {
  try {
    ensureWhatsApp();
    if (wa.status === "connected") return res.status(204).end();
    if (!wa.lastQR) return res.status(202).json({ status: wa.status || "connecting" });
    const png = await QRCode.toBuffer(wa.lastQR, { type: "png", width: 256, margin: 1 });
    res.type("image/png").send(png);
  } catch (e) { console.error("[QR] error:", e); res.status(500).json({ error: "qr" }); }
});
app.get("/api/qr/status", auth, (_req, res) => {
  ensureWhatsApp(); res.json({ status: wa.status || "connecting" });
});

// ---------- BACKUP CRIPTO (estado + sessão) ----------
function aesEncrypt(buffer, keyHex) {
  const key = Buffer.from(keyHex, "hex");
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const enc = Buffer.concat([cipher.update(buffer), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([Buffer.from("v1"), iv, tag, enc]); // [v1|12b iv|16b tag|payload]
}
function aesDecrypt(buffer, keyHex) {
  if (buffer.slice(0,2).toString() !== "v1") throw new Error("versao");
  const key = Buffer.from(keyHex, "hex");
  const iv = buffer.slice(2, 14);
  const tag = buffer.slice(14, 30);
  const payload = buffer.slice(30);
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(payload), decipher.final()]);
}
async function packState(toFile) {
  const tmpTar = path.join(DATA_DIR, "_state.tar");
  await tar.c({ file: tmpTar, cwd: DATA_DIR }, ["." ]);
  const gz = zlibDeflate(fs.readFileSync(tmpTar));
  fs.unlinkSync(tmpTar);
  if (!STATE_KEY) throw new Error("STATE_KEY ausente");
  const enc = aesEncrypt(gz, STATE_KEY);
  fs.writeFileSync(toFile, enc);
}
async function unpackState(fromFile) {
  if (!fs.existsSync(fromFile)) return;
  if (!STATE_KEY) throw new Error("STATE_KEY ausente");
  const enc = fs.readFileSync(fromFile);
  const gz = aesDecrypt(enc, STATE_KEY);
  const tarBuf = zlibInflate(gz);
  const tmpTar = path.join(DATA_DIR, "_restore.tar");
  fs.writeFileSync(tmpTar, tarBuf);
  await tar.x({ file: tmpTar, cwd: DATA_DIR });
  fs.unlinkSync(tmpTar);
}
// zlib helpers (sem deps externas)
function zlibDeflate(buf){ return crypto.deflateSync ? crypto.deflateSync(buf) : require("zlib").deflateSync(buf); }
function zlibInflate(buf){ return crypto.inflateSync ? crypto.inflateSync(buf) : require("zlib").inflateSync(buf); }

app.post("/api/state/backup", auth, async (_req, res) => {
  try { await packState(STATE_ENC); res.json({ ok:true, file:"state/state.enc" }); }
  catch(e){ console.error("[state/backup]", e); res.status(500).json({ error:"backup"}); }
});
app.get("/api/state/download", auth, (req, res) => {
  if (!fs.existsSync(STATE_ENC)) return res.status(404).json({ error:"no-backup" });
  res.setHeader("Content-Disposition", 'attachment; filename="state.enc"');
  res.type("application/octet-stream").send(fs.readFileSync(STATE_ENC));
});

// ---------- HEALTH ----------
app.get("/health", (_req, res) => res.json({ ok: true, ts: Date.now() }));

// (dev) servir web se existir
const WEB = path.join(__dirname, "..", "web");
if (fs.existsSync(WEB)) app.use("/", express.static(WEB));

// ---------- BOOT ----------
(async () => {
  // restaura do arquivo criptografado no repo (se existir)
  try { await unpackState(STATE_ENC); } catch(e){ console.warn("[state] restore falhou:", e.message); }
  migrate();
  const disabled = getSetting("powerDisabled", "false") === "true";
  if (!disabled) ensureWhatsApp();
  app.listen(PORT, () => console.log("[API] porta:", PORT));
})();

// ao encerrar: tenta salvar backup
function graceful(){ try{ packState(STATE_ENC).catch(()=>{}); }catch{} process.exit(0); }
process.on("SIGINT", graceful); process.on("SIGTERM", graceful);
