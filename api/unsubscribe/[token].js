// pages/api/unsubscribe/[token].js
import crypto from "crypto";
import pg from "pg";
const { Pool } = pg;

// --- secrets / env ---
const UNSUB_SECRET =
  process.env.UNSUB_SECRET ||
  "3ExsYR4nlnttgnHxpDDKM5V0JNQpJKlR3JuvqyOXTAM"; // keep env in Vercel; fallback stays for convenience
const DATABASE_URL = process.env.DATABASE_URL;

// --- pg pool (singleton across hot-reloads) ---
let pool = globalThis.__unsub_pool;
if (!pool && DATABASE_URL) {
  pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: { rejectUnauthorized: false },
    max: 1,
  });
  globalThis.__unsub_pool = pool;
}

// --- helpers ---
function base64urlToBuffer(b64url) {
  const pad = 4 - (b64url.length % 4 || 4);
  const b64 =
    b64url.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat(pad === 4 ? 0 : pad);
  return Buffer.from(b64, "base64");
}

function safeEqual(a, b) {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

function esc(s) {
  return String(s).replace(/[&<>"']/g, (m) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[m])
  );
}

async function saveSuppression(email, source) {
  if (!pool) return; // no DB configured; still continue (unsub shouldn't fail)
  await pool.query(
    `INSERT INTO suppression (email, source, reason)
     VALUES ($1, $2, 'user-request')
     ON CONFLICT (email) DO UPDATE
       SET source = EXCLUDED.source,
           reason = EXCLUDED.reason,
           ts = now()`,
    [email, source]
  );
}

// --- handler ---
export default async function handler(req, res) {
  if (req.method !== "GET" && req.method !== "POST") {
    res.setHeader("Allow", "GET, POST");
    return res.status(405).end("Method Not Allowed");
  }

  const { token } = req.query;
  if (!token || typeof token !== "string") {
    return res.status(400).send("missing token");
  }

  let raw, sig;
  try {
    const buf = base64urlToBuffer(token);
    const dot = buf.lastIndexOf(46); // "."
    if (dot < 1) throw new Error("bad token");
    raw = buf.subarray(0, dot);
    sig = buf.subarray(dot + 1);
  } catch {
    return res.status(400).send("bad token");
  }

  const expected = crypto.createHmac("sha256", UNSUB_SECRET).update(raw).digest();
  if (!safeEqual(expected, sig)) {
    return res.status(400).send("signature");
  }

  let payload;
  try {
    payload = JSON.parse(raw.toString("utf8"));
  } catch {
    return res.status(400).send("payload");
  }

  if (!payload.email || !payload.exp) {
    return res.status(400).send("payload");
  }
  if (Date.now() / 1000 > Number(payload.exp)) {
    return res.status(400).send("expired");
  }

  const email = String(payload.email).trim().toLowerCase();

  try {
    // record suppression; POST is machine one-click, GET is human click
    await saveSuppression(email, req.method === "POST" ? "one-click" : "web");
  } catch (e) {
    console.error("suppression save failed:", e); // don't break UX
  }

  if (req.method === "POST") {
    // For Gmail/Yahoo one-click: no body needed
    return res.status(204).end();
  }

  // Human confirmation page
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  return res.status(200).send(`<!doctype html>
<html><head><meta charset="utf-8"><title>Unsubscribed</title></head>
<body style="font-family:Arial,Helvetica,sans-serif;padding:24px;">
  <h1 style="margin:0 0 8px;">You're unsubscribed</h1>
  <p style="margin:0 0 10px;">${esc(email)} was removed successfully.</p>
  <p style="margin:0;color:#6b7280;font-size:12px;">You won't receive further emails from us. If this was a mistake, reply to any previous email and we'll re-add you.</p>
</body></html>`);
}
