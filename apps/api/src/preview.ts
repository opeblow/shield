import { analyzeUrl } from "../../../packages/risk-engine/src/url-analysis.js";
import { fetchUrlSafely, type SafeFetchDeps } from "../../../packages/risk-engine/src/url-fetch.js";

export type LinkPreview = {
  url: string;
  status: number;
  content_type: string;
  bytes: number;
  truncated: boolean;
  title: string | null;
  description: string | null;
  signals: { code: string; text: string; evidence: string }[];
};

function extractMeta(body: string): { title: string | null; description: string | null } {
  const titleMatch = /<title[^>]*>([\s\S]*?)<\/title>/i.exec(body);
  const title = titleMatch ? titleMatch[1]!.replace(/\s+/g, " ").trim().slice(0, 200) : null;
  const descriptionPattern = /<meta[^>]+\b(?:name|property)=["'](?:\w*:)?description["'][^>]*>/i;
  const tag = descriptionPattern.exec(body)?.[0] ?? null;
  const content = tag ? /content=["']([^"']*)["']/i.exec(tag)?.[1] ?? null : null;
  return { title, description: content ? content.replace(/\s+/g, " ").trim().slice(0, 400) : null };
}

/**
 * Fetches a user-supplied URL through the SSRF-safe fetcher and returns a
 * bounded preview: status, size, HTML title, meta description, and the
 * scam signals from URL analysis. Never runs page scripts or loads subresources.
 */
export async function previewUrl(rawUrl: string, deps: SafeFetchDeps = {}): Promise<LinkPreview> {
  const { url, status, contentType, bytes, truncated, body } = await fetchUrlSafely(rawUrl, deps);
  const { signals } = analyzeUrl(url);
  const content = contentType.includes("text/html") || contentType.includes("application/xhtml") || !contentType ? body : "";
  const { title, description } = extractMeta(content);
  return { url, status, content_type: contentType, bytes, truncated, title, description, signals };
}