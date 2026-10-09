import { timingSafeEqual } from "node:crypto";
import { verifySignature } from "../../shared/src/crypto.js";
import { scanText } from "../../risk-engine/src/scan.js";
import type { Language, ScanResult } from "../../risk-engine/src/types.js";

export type WhatsAppMessage = { from: string; messageId: string; text: string; language: Language };
export type WhatsAppReply = { recipient: string; messageId: string; result: ScanResult };

export function verifyMetaSignature(rawBody: Buffer, signatureHeader: string | undefined, appSecret: string): boolean {
  const supplied = /^sha256=([a-f\d]{64})$/i.exec(signatureHeader ?? "")?.[1];
  if (!supplied) return false;
  return verifySignature(rawBody, supplied, Buffer.from(appSecret));
}

export function verifyMetaChallenge(mode: string | null, token: string | null, challenge: string | null, configuredToken: string): string | null {
  if (mode !== "subscribe" || !token || !challenge) return null;
  const supplied = Buffer.from(token);
  const expected = Buffer.from(configuredToken);
  if (supplied.length !== expected.length || !timingSafeEqual(supplied, expected)) return null;
  return challenge;
}

export interface WhatsAppAdapter { sendText(recipient: string, text: string): Promise<void> }

export class MetaCloudApiAdapter implements WhatsAppAdapter {
  constructor(private readonly token: string, private readonly phoneNumberId: string, private readonly apiVersion: string) {
    if (!/^v\d+\.\d+$/.test(apiVersion)) throw new Error("A supported WhatsApp Graph API version must be configured");
  }

  async sendText(recipient: string, text: string): Promise<void> {
    const response = await fetch(`https://graph.facebook.com/${this.apiVersion}/${encodeURIComponent(this.phoneNumberId)}/messages`, {
      method: "POST", headers: { authorization: `Bearer ${this.token}`, "content-type": "application/json" },
      body: JSON.stringify({ messaging_product: "whatsapp", recipient_type: "individual", to: recipient, type: "text", text: { preview_url: false, body: text } }),
      signal: AbortSignal.timeout(5_000)
    });
    if (!response.ok) throw new Error(`WhatsApp delivery failed with status ${response.status}`);
  }
}

export class WhatsAppSimulator {
  async receive(message: WhatsAppMessage): Promise<WhatsAppReply> {
    const result = await scanText(message.text, { language: message.language });
    return { recipient: message.from, messageId: message.messageId, result };
  }
}
