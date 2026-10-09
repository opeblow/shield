import { createHmac, randomUUID, timingSafeEqual } from "node:crypto";

export type Verdict = "safe" | "caution" | "likely_scam" | "scam";

export type CertificatePayload = {
  certificate_id: string;
  scan_id: string;
  verdict: Verdict;
  risk_score: number;
  scam_types: string[];
  message: string;
  checked_at: string;
  expires_at: string;
  issuer: string;
  note?: string;
};

export const CERTIFICATE_TTL_SECONDS = 7 * 24 * 60 * 60;

function escapeHtml(value: string): string {
  return value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

export function issueCertificate(input: { scanId: string; verdict: Verdict; riskScore: number; scamTypes: string[]; message: string; issuer: string; note?: string; secret: Buffer; now?: Date }): string {
  const now = input.now ?? new Date();
  const payload: CertificatePayload = {
    certificate_id: randomUUID(),
    scan_id: input.scanId,
    verdict: input.verdict,
    risk_score: input.riskScore,
    scam_types: input.scamTypes,
    message: input.message,
    checked_at: now.toISOString(),
    expires_at: new Date(now.getTime() + CERTIFICATE_TTL_SECONDS * 1000).toISOString(),
    issuer: input.issuer,
    ...(input.note ? { note: input.note } : {})
  };
  return seal(payload, input.secret);
}

function seal(payload: CertificatePayload, secret: Buffer): string {
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signature = createHmac("sha256", secret).update(body).digest("hex");
  return `${body}.${signature}`;
}

export function verifyCertificate(token: string, secret: Buffer, nowMs = Date.now()): CertificatePayload | null {
  if (typeof token !== "string" || token.length > 4096) return null;
  const separator = token.lastIndexOf(".");
  if (separator <= 0) return null;
  const body = token.slice(0, separator);
  const signature = token.slice(separator + 1);
  if (!/^[0-9a-f]{64}$/.test(signature)) return null;
  const expected = createHmac("sha256", secret).update(body).digest();
  let provided: Buffer;
  try { provided = Buffer.from(signature, "hex"); } catch { return null; }
  if (provided.length !== expected.length || !timingSafeEqual(provided, expected)) return null;
  try {
    const payload = JSON.parse(Buffer.from(body, "base64url").toString("utf8")) as CertificatePayload;
    if (!payload || payload.verdict === undefined || typeof payload.risk_score !== "number" || typeof payload.message !== "string" || typeof payload.expires_at !== "string") return null;
    if (new Date(payload.expires_at).getTime() <= nowMs) return null;
    return payload;
  } catch {
    return null;
  }
}

function verdictBadge(verdict: Verdict): string {
  const map: Record<Verdict, { label: string; className: string }> = {
    safe: { label: "No scam signs found", className: "safe" },
    caution: { label: "Pause and check", className: "caution" },
    likely_scam: { label: "Likely scam", className: "likely-scam" },
    scam: { label: "Strong scam signs", className: "scam" }
  };
  const entry = map[verdict] ?? map.caution!;
  return `<span class="verdict verdict-${entry.className}">${entry.label}</span>`;
}

export function certificateCardHtml(payload: CertificatePayload): string {
  const date = new Date(payload.checked_at);
  const displayDate = new Intl.DateTimeFormat("en", { dateStyle: "medium", timeStyle: "short", timeZone: "UTC" }).format(date);
  const signaturePreview = createHmac("sha256", Buffer.from("certificate-display")).update(payload.certificate_id).digest("hex").slice(0, 16).toUpperCase();
  const message = escapeHtml(payload.message);
  const note = payload.note ? `<p class="cert-note">${escapeHtml(payload.note)}</p>` : "";
  const verdictLabel = verdictBadge(payload.verdict);
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <meta name="robots" content="noindex">
    <title>Shield check — ${displayDate}</title>
    <style>
      *{box-sizing:border-box}body{margin:0;background:#eef3e6;font:15px/1.6 system-ui,sans-serif;color:#18362d;display:grid;place-items:center;min-height:100vh;padding:24px}.cert{width:min(520px,100%);background:#fff;border-radius:24px;box-shadow:0 24px 70px rgba(24,54,44,.14);overflow:hidden}.cert-top{background:#0d2925;color:#f4f8f1;padding:22px 26px;display:flex;align-items:center;gap:14px}.cert-top .mark{width:44px;height:44px;flex:none;border-radius:12px;display:grid;place-items:center;background:#c8f36a;color:#0d2925;font-weight:800}.cert-top h1{font-size:17px;margin:0;letter-spacing:-.2px}.cert-top p{margin:2px 0 0;font-size:12px;color:#c7d6cd}.cert-body{padding:26px}.verdict{display:inline-block;padding:8px 14px;border-radius:999px;font-weight:700;font-size:13px}.verdict-safe{background:#dff2e3;color:#1e6b37}.verdict-caution{background:#f5eecb;color:#7a611a}.verdict-likely-scam,.verdict-scam{background:#f8d9d9;color:#9c2626}.cert-message{margin:18px 0;padding:14px 16px;background:#f4f6f1;border-left:4px solid #c8f36a;border-radius:10px;white-space:pre-wrap;word-break:break-word;color:#2c4a3f;font-size:13.5px}.cert-meta{display:grid;grid-template-columns:1fr 1fr;gap:10px 18px;font-size:12.5px;color:#5a6b62;margin:4px 0 0}.cert-meta b{color:#18362d}.cert-note{margin:16px 0 0;padding:12px 14px;background:#eef3e6;border-radius:10px;font-size:13px}.cert-foot{padding:16px 26px 20px;border-top:1px solid #e4eae0;font-size:11.5px;color:#7a8780}.cert-foot b{color:#0d2925}.cert-seal{display:flex;align-items:center;gap:10px;margin-top:14px;color:#4d6b5e;font-size:11px}
      .cert-seal .shield{width:26px;height:26px;flex:none}
    </style>
  </head>
  <body>
    <main class="cert">
      <header class="cert-top"><span class="mark" aria-hidden="true">S</span><div><h1>shield<span style="color:#c8f36a">.</span> verifiable check</h1><p>Signs shown are guidance, never proof.</p></div></header>
      <div class="cert-body">
        ${verdictLabel}
        <p class="cert-message">${message}</p>
        ${note}
        <dl class="cert-meta">
          <div><dt>Checked</dt><dd><b>${displayDate} UTC</b></dd></div>
          <div><dt>Risk score</dt><dd><b>${payload.risk_score} / 100</b></dd></div>
          <div><dt>Categories</dt><dd><b>${payload.scam_types.length ? payload.scam_types.join(", ") : "None identified"}</b></dd></div>
          <div><dt>Reference</dt><dd><b>${payload.certificate_id.slice(0, 8)}…</b></dd></div>
        </dl>
      </div>
      <footer class="cert-foot">
        <p>This card was issued by <b>Shield</b> and is valid until <b>${new Date(payload.expires_at).toISOString()}</b>. The content above is sealed; tampering breaks the signature.</p>
        <div class="cert-seal">
          <svg class="shield" viewBox="0 0 512 512" aria-hidden="true"><rect width="512" height="512" rx="128" fill="#0d2925"/><path d="M256 78 398 133v111c0 91-56 151-142 191-86-40-142-100-142-191V133z" fill="none" stroke="#c8f36a" stroke-width="24"/><path d="m196 254 43 43 82-91" fill="none" stroke="#f7f8f4" stroke-width="25" stroke-linecap="round" stroke-linejoin="round"/></svg>
          <span>Signed at issue · ${signaturePreview}</span>
        </div>
      </footer>
    </main>
  </body>
</html>`;
}