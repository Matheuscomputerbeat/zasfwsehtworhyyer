const path = require("path");
const fs = require("fs");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcryptjs");

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "..", "..", "..", "data");
const DB_FILE = path.join(DATA_DIR, "app.db");
fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new sqlite3.Database(DB_FILE);
function run(sql, p=[]) { return new Promise((res,rej)=>db.run(sql,p,function(e){e?rej(e):res(this)})); }
function get(sql, p=[]) { return new Promise((res,rej)=>db.get(sql,p,(e,r)=>e?rej(e):res(r))); }

(async () => {
  try {
    const u = process.env.ADMIN_USER || "admin";
    const p = process.env.ADMIN_PASS || "admin123";
    const exists = await get(`SELECT 1 FROM users LIMIT 1`);
    if (exists) { console.log("users já existe. nada a fazer."); process.exit(0); }
    const hash = bcrypt.hashSync(p, 10);
    await run(`INSERT INTO users(username, passhash, created_at) VALUES(?,?,datetime('now'))`, [u, hash]);
    console.log("admin criado:", u);
    process.exit(0);
  } catch (e) {
    console.error("ERR: seed", e);
    process.exit(1);
  }
})();
