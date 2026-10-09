import type { Language } from "./types.js";

const brands = ["Access Bank", "GTBank", "Guaranty Trust Bank", "Zenith Bank", "FirstBank", "UBA", "OPay", "PalmPay", "CBN", "NELFUND", "NYSC", "NIMC"];
export function extractEntities(text: string): { urls: string[]; phones: string[]; accounts: string[]; amounts: string[]; brands: string[] } {
  const urls = [...new Set(text.match(/(?:https?:\/\/|www\.)[^\s<>()]+/gi) ?? [])];
  const phones = [...new Set(text.match(/(?<!\w)(?:\+?234|0)\s*\d(?:[\s-]?\d){9}(?!\w)/g) ?? [])];
  const accounts = [...new Set([...text.matchAll(/\b(?:account|acct|a\/c)\s*(?:number|no\.?|#|:)?\s*(\d{10})\b/gi)].map((m) => m[1]!).filter(Boolean))];
  const amounts = [...new Set(text.match(/(?:₦|NGN|N\s*)\s?\d[\d,]*(?:\.\d{1,2})?|\b\d+(?:\.\d+)?\s?(?:k|million|m)\b/gi) ?? [])];
  const normalized = text.normalize("NFC").toLocaleLowerCase();
  return { urls, phones, accounts, amounts, brands: brands.filter((brand) => normalized.includes(brand.toLocaleLowerCase())) };
}

function detectLanguageLegacy(text: string): Language {
  const value = text.normalize("NFC").toLocaleLowerCase();
  if (/\b(dem don|abeg|wetin|oga|no send|dey|wahala)\b/.test(value)) return "pcm";
  if (/\b(ẹ jọ̀ọ́|ẹ̀tàn|firanse|jẹri)\b/.test(value)) return "yo";
  if (/\b(kuɗi|kudi|zamba|aiko da|lambar sirri|don Allah)\b/.test(value) || /[ƙɗɓ]/.test(value)) return "ha";
  if (/\b(biko|ego|zipu|nye m|aghụghọ|ụlọ akụ)\b/.test(value)) return "ig";
  if (/[ịụṅ]/.test(value)) return "ig";
  if (/[ẹọṣ]/.test(value)) return "yo";
  return "en";
}

export function detectLanguage(text: string): Language {
  const value = text.normalize("NFC").toLocaleLowerCase();
  const plain = value.normalize("NFD").replace(/[\u0300-\u036f]/g, "");
  const hasAny = (markers: string[]) => markers.some((marker) => plain.includes(marker));
  if (hasAny(["dem don", "abeg", "wetin", "oga", "no send", "dey", "wahala", "make i", "na so"])) return "pcm";
  if (hasAny(["firanse", "bayii", "jeri", "akole", "san owo", "ebun", "kiakia", "e ku oriire", "jowo"])) return "yo";
  if (hasAny(["lambar sirri", "lambar", "asusun", "yanzu", "aiko da", "tabbatar", "manhaja", "tura", "kudin", "biya", "karbar"])) return "ha";
  if (hasAny(["zipu", "ugbu a", "akauntu", "ulo aku", "kwuo", "onyinye", "mgbazinye", "ndebanye", "ekwenyela", "nnata", "ngwa", "biko", "ego"])) return "ig";
  return detectLanguageLegacy(text);
}
