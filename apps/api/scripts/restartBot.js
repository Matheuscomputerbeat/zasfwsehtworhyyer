// Reinicia o bot chamando a API local/remota.
// Env: API_URL (ex: http://localhost:8080), TOKEN (JWT)
const { fetch } = require("undici");

const API = process.env.API_URL || "http://localhost:8080";
const TOKEN = process.env.TOKEN || "";

(async () => {
  try {
    const r = await fetch(`${API}/api/bot/restart`, {
      method: "POST",
      headers: { "Authorization": `Bearer ${TOKEN}`, "Content-Type": "application/json" }
    });
    const j = await r.json().catch(()=> ({}));
    console.log(r.status, j);
  } catch (e) {
    console.error("ERR", e);
    process.exit(1);
  }
})();
