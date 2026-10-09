export type ArtifactKind = "image" | "document" | "audio";

export const artifactLimits: Record<ArtifactKind, number> = {
  image: 5 * 1024 * 1024,
  document: 10 * 1024 * 1024,
  audio: 15 * 1024 * 1024
};

const startsWith = (bytes: Uint8Array, signature: number[], offset = 0): boolean =>
  signature.every((value, index) => bytes[offset + index] === value);

/** Sniffs a private upload's real type from magic bytes. SVG and unknown content return null. */
export function sniffArtifactKind(bytes: Uint8Array): ArtifactKind | null {
  if (startsWith(bytes, [0xff, 0xd8, 0xff]) || startsWith(bytes, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]) || startsWith(bytes, [0x47, 0x49, 0x46, 0x38]) || startsWith(bytes, [0x42, 0x4d])) return "image";
  if (startsWith(bytes, [0x52, 0x49, 0x46, 0x46]) && startsWith(bytes, [0x57, 0x45, 0x42, 0x50], 8)) return "image";
  if (startsWith(bytes, [0x25, 0x50, 0x44, 0x46, 0x2d])) return "document";
  if (startsWith(bytes, [0x4f, 0x67, 0x67, 0x53])) return "audio";
  if (startsWith(bytes, [0x49, 0x44, 0x33]) || startsWith(bytes, [0xff, 0xfb]) || startsWith(bytes, [0xff, 0xf3])) return "audio";
  if (startsWith(bytes, [0x52, 0x49, 0x46, 0x46]) && startsWith(bytes, [0x57, 0x41, 0x56, 0x45], 8)) return "audio";
  if (startsWith(bytes, [0x66, 0x74, 0x79, 0x70], 4)) return "audio";
  return null;
}

/** Rejects content whose declared type does not match its bytes, executable images and oversized uploads. */
export function validateArtifact(input: { bytes: Uint8Array; declaredType?: string; expectedKind?: ArtifactKind; maxBytes?: number }): { kind: ArtifactKind; bytes: number } {
  const kind = sniffArtifactKind(input.bytes);
  if (!kind) throw new Error("Unsupported or unrecognized file content");
  if (input.expectedKind && input.expectedKind !== kind) throw new Error(`Expected a ${input.expectedKind} but received a ${kind}`);
  if (input.declaredType) {
    if (/svg/i.test(input.declaredType)) throw new Error("SVG and other executable image formats are not accepted");
    const family = input.declaredType.split("/")[0];
    if (family && family !== "application" && family !== kind && !(family === "application" && kind === "document")) throw new Error("Declared file type does not match its contents");
  }
  const limit = input.maxBytes ?? artifactLimits[kind];
  if (input.bytes.length === 0 || input.bytes.length > limit) throw new Error(`File must be between 1 byte and ${Math.round(limit / 1024)} KiB`);
  return { kind, bytes: input.bytes.length };
}
