const path = require("path");
const fs = require("fs");
const sqlite3 = require("sqlite3").verbose();

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "..", "..", "..", "data");
const DB_FILE = path.join(DATA_DIR, "app.db");
fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new sqlite3.Database(DB_FILE);

function run(sql) {
  return new Promise((resolve, reject) => db.run(sql, (e) => (e ? reject(e) : resolve())));
}

(async () => {
  try {
    await run(`CREATE TABLE IF NOT EXISTS users(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      passhash TEXT NOT NULL,
      created_at TEXT NOT NULL
    )`);
    await run(`CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT)`);
    await run(`CREATE TABLE IF NOT EXISTS groups(id TEXT PRIMARY KEY)`);

    console.log("OK: migrate");
    process.exit(0);
  } catch (e) {
    console.error("ERR: migrate", e);
    process.exit(1);
  }
})();
