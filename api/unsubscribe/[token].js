import crypto from "crypto";
import pg from "pg";

const {
  UNSUB_SECRET = "",
  CONFIRM_URL = "https://appshaiskn.com/pages/unsubscribe",
  DATABASE_URL = ""
} = process.env;

const pool = DATABASE_URL
  ? new pg.Pool({ connectionString: DATABASE_URL, ssl: { require: true, rejectUnauthorized: false } })
  : null;

// base64url( rawJSON . HMAC-SHA256(rawJSON, secret) )
function parseToken(token) {
  if (!token) throw new Error("missing_token");
  if (!UNSUB_SECRET) throw new Error("missing_secret");
  const pad = "=".repeat((4 - (token.length % 4)) % 4);
  const buf = Buffer.from(token + pad, "base64url");
  const dot = buf.lastIndexOf(46); // "."
  if (dot < 0) throw new Error("format");
  const raw = buf.subarray(0, dot);
  const sig = buf.subarray(dot + 1);
  const expSig = crypto.createHmac("sha256", UNSUB_SECRET).update(raw).digest();
  if (sig.length !== expSig.length || !crypto.timingSafeEqual(sig, expSig)) throw new Error("signature");
  const payload = JSON.parse(raw.toString("utf8"));
  if (!payload.email || !payload.email.includes("@")) throw new Error("email");
  if (payload.exp && payload.exp < Math.floor(Date.now()/1000)) throw new Error("expired");
  return payload.email;
}

async function suppress(email, reason="user_unsubscribe", source="one_click") {
  if (!pool) return;
  const sql = `
    CREATE TABLE IF NOT EXISTS suppression(
      email TEXT PRIMARY KEY,
      reason TEXT,
      source TEXT,
      ts TIMESTAMPTZ DEFAULT now()
    );
    INSERT INTO suppression(email, reason, source)
    VALUES($1,$2,$3)
    ON CONFLICT (email) DO UPDATE
      SET reason = EXCLUDED.reason,
          source = EXCLUDED.source,
          ts     = now();
  `;
  const c = await pool.connect();
  try { await c.query("BEGIN"); await c.query(sql, [email, reason, source]); await c.query("COMMIT"); }
  catch (e) { await c.query("ROLLBACK"); console.error("DB suppress error:", e?.message || e); }
  finally { c.release(); }
}

export default async function handler(req, res) {
  const { token } = req.query;
  try {
    const email = parseToken(token);
    await suppress(email);

    if (req.method === "POST") return res.status(200).end(); // Gmail/Yahoo one-click
    const url = new URL(CONFIRM_URL); // human redirect
    url.searchParams.set("email", email);
    return res.status(302).setHeader("Location", url.toString()).end();

  } catch (e) {
    console.error("Unsubscribe error:", e?.message || e);
    if (req.method === "POST") return res.status(200).end();
    return res.status(400).send(e?.message || "Invalid or expired link.");
  }
}
export const config = { runtime: "nodejs" };
