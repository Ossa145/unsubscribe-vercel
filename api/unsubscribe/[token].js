import crypto from "crypto";

const {
  UNSUB_SECRET = "",
  CONFIRM_URL = "https://appshaiskn.com/pages/unsubscribe",
} = process.env;

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
  if (sig.length !== expSig.length || !crypto.timingSafeEqual(sig, expSig)) {
    throw new Error("signature");
  }

  const payload = JSON.parse(raw.toString("utf8"));
  if (!payload.email || !payload.email.includes("@")) throw new Error("email");
  if (payload.exp && payload.exp < Math.floor(Date.now()/1000)) throw new Error("expired");
  return payload.email;
}

export default async function handler(req, res) {
  const { token } = req.query;
  try {
    const email = parseToken(token);

    // For GET: redirect to your page (we'll re-add DB after)
    if (req.method === "POST") return res.status(200).end();
    const url = new URL(CONFIRM_URL);
    url.searchParams.set("email", email);
    return res.status(302).setHeader("Location", url.toString()).end();

  } catch (e) {
    console.error("Unsub error:", e?.message || e);
    if (req.method === "POST") return res.status(200).end();
    return res.status(400).send(e?.message || "Invalid or expired link.");
  }
}

export const config = { runtime: "nodejs" };
