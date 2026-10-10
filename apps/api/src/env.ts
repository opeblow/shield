const requiredInProduction = ["AUTH_SECRET", "CERTIFICATE_SECRET", "FIELD_KEK", "BLIND_INDEX_PEPPER", "API_KEY_PEPPER", "COMMUNITY_MODERATION_TOKEN"] as const;

export type AppEnv = { nodeEnv: string; port: number; databaseUrl?: string; redisUrl?: string; openAiKey?: string; openAiModel?: string; openAiBaseUrl?: string; openAiVisionModel?: string; openAiTranscribeModel?: string; openAiTtsModel?: string; fieldKek?: string; blindPepper?: string; apiKeyPepper?: string; communityModerationToken?: string; authSecret?: string; certificateSecret?: string };

export function loadEnv(source: NodeJS.ProcessEnv = process.env): AppEnv {
  const nodeEnv = source.NODE_ENV ?? "development";
  if (nodeEnv === "production") {
    const required = [...requiredInProduction, "DATABASE_URL", "REDIS_URL"] as const;
    const missing = required.filter((key) => !source[key]);
    if (missing.length) throw new Error(`Missing required production configuration: ${missing.join(", ")}`);
    if (source.FIELD_KEK === "development-only-key-change-me") throw new Error("Development KEK is forbidden in production");
  }
  if (source.COMMUNITY_MODERATION_TOKEN && Buffer.byteLength(source.COMMUNITY_MODERATION_TOKEN) < 32) throw new Error("COMMUNITY_MODERATION_TOKEN must contain at least 32 bytes");
  if (source.AUTH_SECRET && Buffer.byteLength(source.AUTH_SECRET) < 32) throw new Error("AUTH_SECRET must contain at least 32 bytes");
  if (source.CERTIFICATE_SECRET && Buffer.byteLength(source.CERTIFICATE_SECRET) < 32) throw new Error("CERTIFICATE_SECRET must contain at least 32 bytes");
  const port = Number(source.PORT ?? "3001");
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("PORT must be a valid TCP port");
  return {
    nodeEnv,
    port,
    ...(source.DATABASE_URL ? { databaseUrl: source.DATABASE_URL } : {}),
    ...(source.REDIS_URL ? { redisUrl: source.REDIS_URL } : {}),
    ...(source.OPENAI_API_KEY ? { openAiKey: source.OPENAI_API_KEY } : {}),
    ...(source.OPENAI_MODEL ? { openAiModel: source.OPENAI_MODEL } : {}),
    ...(source.OPENAI_BASE_URL ? { openAiBaseUrl: source.OPENAI_BASE_URL } : {}),
    ...(source.OPENAI_VISION_MODEL ? { openAiVisionModel: source.OPENAI_VISION_MODEL } : {}),
    ...(source.OPENAI_TRANSCRIBE_MODEL ? { openAiTranscribeModel: source.OPENAI_TRANSCRIBE_MODEL } : {}),
    ...(source.OPENAI_TTS_MODEL ? { openAiTtsModel: source.OPENAI_TTS_MODEL } : {}),
    ...(source.FIELD_KEK ? { fieldKek: source.FIELD_KEK } : {}),
    ...(source.BLIND_INDEX_PEPPER ? { blindPepper: source.BLIND_INDEX_PEPPER } : {}),
    ...(source.API_KEY_PEPPER ? { apiKeyPepper: source.API_KEY_PEPPER } : {}),
    ...(source.COMMUNITY_MODERATION_TOKEN ? { communityModerationToken: source.COMMUNITY_MODERATION_TOKEN } : {}),
    ...(source.AUTH_SECRET ? { authSecret: source.AUTH_SECRET } : {}),
    ...(source.CERTIFICATE_SECRET ? { certificateSecret: source.CERTIFICATE_SECRET } : {})
  };
}
