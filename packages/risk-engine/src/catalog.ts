import type { Language, Verdict } from "./types.js";

export const catalog: Record<Language, Record<Verdict, string>> = {
  en: { safe: "No scam signs found. Confirm the details in your bank app before acting.", caution: "Pause and verify this message using an official number or app.", likely_scam: "This is likely a scam. Do not send money or share codes.", scam: "This has strong scam signs. Do not pay, click, or share personal details." },
  pcm: { safe: "We no see scam sign. Check am for your bank app before you do anything.", caution: "Hold on small. Confirm am with official number or app.", likely_scam: "E fit be scam. No send money or share code.", scam: "This one get strong scam sign. No pay, click link, or share your details." },
  yo: { safe: "A kò rí àmì ẹ̀tàn. Ṣàyẹ̀wò rẹ̀ nínú app bank rẹ kí o tó ṣe ohunkóhun.", caution: "Dúró kí o sì jẹ́rìí rẹ̀ nípasẹ̀ nọ́mbà tàbí app òṣìṣẹ́.", likely_scam: "Ó ṣeé ṣe kí ó jẹ́ ẹ̀tàn. Má ṣe fi owó ránṣẹ́ tàbí pín kóòdù.", scam: "Àwọn àmì ẹ̀tàn tó lágbára wà. Má sanwó, má tẹ link, má sì pín àlàyé ara ẹni." },
  ha: { safe: "Ba mu ga alamar zamba ba. Ka tabbatar da bayanin a manhajar bankinka kafin ka yi komai.", caution: "Dakata ka tabbatar ta lambar waya ko manhajar hukuma.", likely_scam: "Wannan na iya zama zamba. Kada ka tura kudi ko ka raba lambar sirri.", scam: "Akwai alamun zamba sosai. Kada ka biya, ka bude link, ko ka bada bayanan sirri." },
  ig: { safe: "Anyị ahụghị akara aghụghọ. Lelee ya na ngwa ụlọ akụ gị tupu i mee ihe.", caution: "Kwụsịtụ ma jiri nọmba ma ọ bụ ngwa gọọmentị nyochaa ya.", likely_scam: "O nwere ike ịbụ aghụghọ. Ezipụla ego ma ọ bụ koodu.", scam: "E nwere akara aghụghọ siri ike. Akwụla ụgwọ, pịa link, ma ọ bụ nye ozi nkeonwe." }
};

export function verdictMessage(language: Language, verdict: Verdict): string { return catalog[language][verdict]; }
