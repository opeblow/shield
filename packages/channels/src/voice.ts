import type { Language } from "../../risk-engine/src/types.js";

export type Transcription = { text: string; language?: Language };
export type Speech = { mimeType: string; audio: Buffer };

export interface SpeechProvider {
  transcribe(audio: Buffer, options?: { language?: Language; mimeType?: string }): Promise<Transcription>;
  speak(text: string, language: Language): Promise<Speech>;
}

/** Selector over named speech providers so synthesis can be swapped per request (pluggable TTS). */
export class SpeechProviderRegistry {
  private readonly providers = new Map<string, SpeechProvider>();

  register(name: string, provider: SpeechProvider): this {
    this.providers.set(name, provider);
    return this;
  }

  names(): string[] {
    return [...this.providers.keys()];
  }

  get(name: string): SpeechProvider | null {
    return this.providers.get(name) ?? null;
  }

  /** Resolves "auto" to the preferred provider, a literal name, or null when unknown. */
  resolve(preferred = "simulated"): { name: string; provider: SpeechProvider } | null {
    if (preferred !== "auto") {
      const provider = this.providers.get(preferred);
      if (provider) return { name: preferred, provider };
      return null;
    }
    const name = this.providers.has("simulated") ? "simulated" : ([...this.providers.keys()][0] ?? null);
    if (!name) return null;
    return { name, provider: this.providers.get(name)! };
  }
}

/** Deterministic provider used by the local simulators and tests; never calls a network. */
export class SimulatedSpeechProvider implements SpeechProvider {
  constructor(private readonly transcript = "") {}
  async transcribe(audio: Buffer): Promise<Transcription> {
    return { text: this.transcript || `[simulated transcript of ${audio.length} bytes]` };
  }
  async speak(text: string, language: Language): Promise<Speech> {
    return { mimeType: "audio/mpeg", audio: Buffer.from(`${language}:${text}`) };
  }
}

/** OpenAI transcription and text-to-speech behind the same interface as the simulator. */
export class OpenAiSpeechProvider implements SpeechProvider {
  constructor(private readonly apiKey: string, private readonly transcribeModel: string, private readonly ttsModel: string, private readonly voice = "alloy", private readonly timeoutMs = 10_000) {
    if (!apiKey || !transcribeModel || !ttsModel) throw new Error("OpenAI speech provider requires an API key and both model names");
  }

  async transcribe(audio: Buffer, options: { language?: Language; mimeType?: string } = {}): Promise<Transcription> {
    const form = new FormData();
    const bytes = audio.buffer.slice(audio.byteOffset, audio.byteOffset + audio.byteLength) as ArrayBuffer;
    form.append("file", new Blob([bytes], { type: options.mimeType ?? "audio/ogg" }), "voice-note.ogg");
    form.append("model", this.transcribeModel);
    if (options.language) form.append("language", options.language);
    const response = await fetch("https://api.openai.com/v1/audio/transcriptions", { method: "POST", headers: { authorization: `Bearer ${this.apiKey}` }, body: form, signal: AbortSignal.timeout(this.timeoutMs) });
    if (!response.ok) throw new Error(`Transcription failed with status ${response.status}`);
    const body = await response.json() as { text?: string };
    if (!body.text) throw new Error("Transcription returned no text");
    return { text: body.text, ...(options.language ? { language: options.language } : {}) };
  }

  async speak(text: string, language: Language): Promise<Speech> {
    const response = await fetch("https://api.openai.com/v1/audio/speech", {
      method: "POST", headers: { authorization: `Bearer ${this.apiKey}`, "content-type": "application/json" },
      body: JSON.stringify({ model: this.ttsModel, voice: this.voice, input: text, response_format: "mp3", metadata: { language } }),
      signal: AbortSignal.timeout(this.timeoutMs)
    });
    if (!response.ok) throw new Error(`Speech synthesis failed with status ${response.status}`);
    return { mimeType: "audio/mpeg", audio: Buffer.from(await response.arrayBuffer()) };
  }
}
