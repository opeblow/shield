import type { Language } from "./types.js";

/**
 * Self-authored, non-copyrighted fraud knowledge used to seed a deployment.
 * Nothing here is copied from a partner or scraped feed; every phrase was
 * written for Shield so the dataset ships under our own licence.
 */
export type KnowledgeTemplate = { id: string; scamType: string; language: Language; phrase: string };
export type BrandRecord = { name: string; aliases: string[]; officialDomains: string[]; sector: "bank" | "fintech" | "telco" | "regulator" };
export type LegitimatePattern = { id: string; description: string; patterns: string[] };

export const scamTemplates: KnowledgeTemplate[] = [
  { id: "otp-request-en", scamType: "otp", language: "en", phrase: "send me the otp we just sent you to complete the transfer" },
  { id: "otp-request-pcm", scamType: "otp", language: "pcm", phrase: "send me the otp wey just reach your phone to finish the transfer" },
  { id: "otp-request-yo", scamType: "otp", language: "yo", phrase: "fi koodu otp ti o ti gba ranṣẹ si mi" },
  { id: "otp-request-ha", scamType: "otp", language: "ha", phrase: "aika min lambar sirrin da ka samu don kammala" },
  { id: "otp-request-ig", scamType: "otp", language: "ig", phrase: "zipu koodu nzuzo otp nke o nwetara n'aka m" },
  { id: "lottery-claim-en", scamType: "lottery", language: "en", phrase: "congratulations you have won a prize pay a small fee to release your winnings" },
  { id: "lottery-claim-pcm", scamType: "lottery", language: "pcm", phrase: "congratulations you don win better thing pay small money make we release your money" },
  { id: "urgent-transfer-en", scamType: "impersonation", language: "en", phrase: "this is your boss send the money now and do not tell anyone" },
  { id: "urgent-transfer-pcm", scamType: "impersonation", language: "pcm", phrase: "na your oga be this send the money sharp sharp no tell anybody" },
  { id: "crypto-double-en", scamType: "investment", language: "en", phrase: "double your money in one hour guaranteed profit no risk" },
  { id: "loan-fee-en", scamType: "advance_fee", language: "en", phrase: "your loan is approved pay the insurance fee to receive it" },
  { id: "recovery-fee-en", scamType: "advance_fee", language: "en", phrase: "we can recover your lost funds pay a service charge first" },
  { id: "agent-upgrade-en", scamType: "agent", language: "en", phrase: "upgrade your agent account to a higher tier to receive more customers" },
  { id: "sim-swap-en", scamType: "sim_swap", language: "en", phrase: "there is a problem with your sim link your bvn to keep your line active" }
];

export const brandRegistry: BrandRecord[] = [
  { name: "Access Bank", aliases: ["access", "diamond"], officialDomains: ["accessbankplc.com"], sector: "bank" },
  { name: "Zenith Bank", aliases: ["zenith"], officialDomains: ["zenithbank.com"], sector: "bank" },
  { name: "GTBank", aliases: ["gtbank", "gtb", "guaranty trust"], officialDomains: ["gtbank.com"], sector: "bank" },
  { name: "First Bank", aliases: ["firstbank", "first bank of nigeria"], officialDomains: ["firstbanknigeria.com"], sector: "bank" },
  { name: "UBA", aliases: ["united bank for africa"], officialDomains: ["ubagroup.com"], sector: "bank" },
  { name: "Opay", aliases: ["opay"], officialDomains: ["opayweb.com"], sector: "fintech" },
  { name: "PalmPay", aliases: ["palmpay"], officialDomains: ["palmpay.com"], sector: "fintech" },
  { name: "Moniepoint", aliases: ["moniepoint"], officialDomains: ["moniepoint.com"], sector: "fintech" },
  { name: "MTN", aliases: ["mtn nigeria"], officialDomains: ["mtn.ng", "mtnonline.com"], sector: "telco" },
  { name: "Airtel", aliases: ["airtel nigeria"], officialDomains: ["airtel.com.ng"], sector: "telco" },
  { name: "CBN", aliases: ["central bank of nigeria"], officialDomains: ["cbn.gov.ng"], sector: "regulator" }
];

export const legitimatePatterns: LegitimatePattern[] = [
  { id: "bank-debit-alert", description: "Standard debit/credit alert from a bank", patterns: ["debit alert", "credit alert", "your account was debited", "your account was credited"] },
  { id: "otp-delivery-only", description: "One-time password delivery that never asks the customer to forward it", patterns: ["do not share this code", "never disclose this otp", "code expires in"] },
  { id: "transaction-receipt", description: "Completed transaction receipt with reference", patterns: ["transaction successful", "reference number", "your transfer is complete"] }
];
