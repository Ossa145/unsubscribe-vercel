import crypto from "crypto";

const {
  UNSUB_SECRET = "change-me",
  CONFIRM_URL = "https://appshaiskn.com/pages/unsubscribe"
} = process.env;

// Token is base64url( rawJSON . HMAC )
function parseToken(token) {
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

    // TODO: add this email to your suppression DB here (we’ll wire later).

    if (req.method === "POST") {
      // Gmail/Yahoo one-click: return 200 OK, no body.
      return res.status(200).end();
    }

    // Human GET click → redirect to Shopify confirmation page + email param.
    const url = new URL(CONFIRM_URL);
    url.searchParams.set("email", email);
    return res.status(302).setHeader("Location", url.toString()).end();

  } catch (e) {
    // Be permissive for POST; show error only on GET
    if (req.method === "POST") return res.status(200).end();
    return res.status(400).send("Invalid or expired link.");
  }
}

export const config = { runtime: "nodejs" };

