export type EvalCase = { id: string; text: string; scam: boolean; language: "en" | "pcm" | "yo" | "ha" | "ig" };

const scamTemplates: Array<[string, string, EvalCase["language"]]> = [
  ["Your account will be blocked urgently. Send your OTP now to verify your bank account.", "bank_impersonation", "en"],
  ["Abeg act fast, send your PIN now or your account go block.", "bank_impersonation", "pcm"],
  ["Pay processing fee to receive your grant and release the money immediately.", "grant_refund", "en"],
  ["Guaranteed double your money today, risk-free investment with sure profit.", "investment_scam", "en"],
  ["Click this shortened link https://bit.ly/claim-now to claim your urgent refund.", "phishing_link", "en"],
  ["Do not tell anybody. Pay activation fee to unlock your scholarship award.", "advance_fee", "en"],
  ["Your transfer successful. Refund this mistaken payment after checking screenshot.", "fake_credit_alert", "en"],
  ["Send the WhatsApp verification code sent by mistake so I can log in.", "sim_swap_social", "en"],
  ["Pay clearance fee to receive your visa job offer, last chance act now.", "job_scam", "en"],
  ["Send money now to receive your guaranteed profit, keep this secret.", "investment_scam", "pcm"],
  ["Firanse OTP rẹ bayii ki a le jẹri akọọlẹ banki rẹ.", "bank_impersonation", "yo"],
  ["Aiko da lambar sirri ta OTP yanzu don tabbatar da asusun banki.", "bank_impersonation", "ha"],
  ["Zipu OTP gị ugbu a iji nyochaa akaụntụ ụlọ akụ gị.", "bank_impersonation", "ig"],
  ["Your bank account will be blocked urgently. Share your PIN now to restore access.", "bank_impersonation", "en"],
  ["Bank verification team here. Tell us the OTP immediately to stop your debit.", "bank_impersonation", "en"],
  ["Pay loan activation fee to receive your approved loan today.", "advance_fee", "en"],
  ["Keep this secret and send your verification code right now.", "sim_swap_social", "en"],
  ["POS transfer successful. Refund the mistaken payment after viewing my receipt screenshot.", "pos_fraud", "en"],
  ["CBN grant confirmed. Pay the registration fee to claim your urgent benefit.", "grant_refund", "en"],
  ["Pay processing fee to receive the NYSC palliative grant.", "grant_refund", "en"],
  ["Guaranteed double your money with this crypto investment, sure profit today.", "investment_scam", "en"],
  ["Pay a registration fee to receive your land title and guaranteed returns.", "advance_fee", "en"],
  ["Pay delivery clearance fee to receive your parcel immediately.", "advance_fee", "en"],
  ["Pay processing fee to unlock your electricity token now.", "advance_fee", "en"],
  ["Your betting bonus is guaranteed. Pay an activation fee to receive it.", "advance_fee", "en"],
  ["The verification code came to me by mistake. Send it so I can log in.", "sim_swap_social", "en"],
  ["Your wrong transfer is credited. Refund it now using this receipt screenshot.", "fake_credit_alert", "en"],
  ["This cooperative investment gives guaranteed returns and doubles every contribution.", "investment_scam", "en"],
  ["Abeg send your OTP quick or dem go block your account immediately.", "bank_impersonation", "pcm"],
  ["No tell anybody. Pay the fee to receive your urgent grant today.", "grant_refund", "pcm"],
  ["Dem say your transfer don land. Refund am now after you see this screenshot.", "fake_credit_alert", "pcm"],
  ["E fit double your money today, guaranteed and risk-free investment.", "investment_scam", "pcm"],
  ["Firanse PIN rẹ ni kiakia tabi won o ti akọọlẹ rẹ.", "bank_impersonation", "yo"],
  ["San owo iforukọsilẹ lati gba ẹbun CBN rẹ lẹsẹkẹsẹ.", "grant_refund", "yo"],
  ["San owo processing lati gba awin ti a fọwọsi fun ọ.", "advance_fee", "yo"],
  ["Tura lambar OTP yanzu ko za a kulle asusunka cikin gaggawa.", "bank_impersonation", "ha"],
  ["Biya kudin rajista don karbar tallafin gaggawa yanzu.", "grant_refund", "ha"],
  ["Biya kudin aiki don karbar bashin da aka amince da shi.", "advance_fee", "ha"],
  ["Zipu PIN gị ozugbo ka e wee kwụsị imechi akaụntụ ụlọ akụ gị.", "bank_impersonation", "ig"],
  ["Kwụọ ụgwọ ndebanye aha ka i nweta onyinye gọọmentị a ugbu a.", "grant_refund", "ig"],
  ["Kwụọ ụgwọ nhazi ka i nweta ego mgbazinye gị ozugbo.", "advance_fee", "ig"]
];

const legitTemplates: Array<[string, EvalCase["language"]]> = [
  ["Your monthly bank statement is ready. Sign in through the bank application to view it.", "en"],
  ["Your electricity bill payment was received. Keep this reference for your records.", "en"],
  ["Your data bundle expires tomorrow. View available plans in the official application.", "en"],
  ["Your appointment is confirmed for Tuesday. Reply HELP for service information.", "en"],
  ["Your salary payment has arrived. Check your account balance in your bank app.", "en"],
  ["Oga, your order is ready for pickup. Call the shop using the number on your receipt.", "pcm"],
  ["E ku oriire, your appointment reminder is here. Visit the clinic reception for help.", "yo"],
  ["An tabbatar da rajistar ka. Duba bayanin a manhajar hukuma.", "ha"],
  ["Ekwenyela nnata akwụkwọ gị. Biko lelee ya na ngwa gọọmentị.", "ig"],
  ["Your card payment was successful. Contact your bank using the number on your card if needed.", "en"]
];

export const evalCases: EvalCase[] = [
  ...Array.from({ length: 300 }, (_, i) => { const [text, , language] = scamTemplates[i % scamTemplates.length]!; return { id: `ng-scam-${String(i + 1).padStart(3, "0")}`, text: `${text} Ref ${i + 1}.`, scam: true, language }; }),
  ...Array.from({ length: 150 }, (_, i) => { const [text, language] = legitTemplates[i % legitTemplates.length]!; return { id: `legitimate-${String(i + 1).padStart(3, "0")}`, text: `${text} Reference ${i + 1}.`, scam: false, language }; })
];
