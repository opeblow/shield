import { scanText } from "../../risk-engine/src/scan.js";
import type { Language, ScanResult } from "../../risk-engine/src/types.js";

export interface ChannelAdapter<I, O> { receive(input: I): Promise<O> }
export type ChannelResponse = { text: string; result: ScanResult };

export class SmsSimulator implements ChannelAdapter<{ from: string; text: string; language?: Language }, ChannelResponse> {
  async receive(input: { from: string; text: string; language?: Language }): Promise<ChannelResponse> {
    const result = await scanText(input.text, input.language ? { language: input.language } : {});
    return { text: `${result.verdict.toUpperCase()}: ${result.customer_message.text}`, result };
  }
}

export class UssdSimulator {
  private state: "language" | "message" | "done" = "language";
  private language: Language = "en";
  async receive(input: string): Promise<string> {
    if (this.state === "language") {
      const choices: Record<string, Language> = { "1": "en", "2": "pcm", "3": "yo", "4": "ha", "5": "ig" };
      const language = choices[input.trim()];
      if (!language) return "CON Choose language: 1 English 2 Pidgin 3 Yoruba 4 Hausa 5 Igbo";
      this.language = language;
      this.state = "message";
      return "CON Enter suspicious message (up to 160 characters):";
    }
    if (this.state === "message") {
      if (input.trim().length < 2 || input.length > 160) return "CON Enter 2 to 160 characters:";
      const result = await scanText(input, { language: this.language });
      this.state = "done";
      return `END ${result.verdict.toUpperCase()}: ${result.customer_message.text}`;
    }
    return "END Session ended. Dial again to scan another message.";
  }
}

export class IvrSimulator implements ChannelAdapter<{ transcript: string; language: Language }, ChannelResponse> {
  async receive(input: { transcript: string; language: Language }): Promise<ChannelResponse> {
    const result = await scanText(input.transcript, { language: input.language });
    return { text: result.customer_message.text, result };
  }
}
