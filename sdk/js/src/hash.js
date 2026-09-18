/**
 * Hashing helpers. Raw signals (canvas images, font lists) never leave the
 * browser: everything identifying is hashed here first.
 */

const encoder = new TextEncoder();

export function stableStringify(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value) ?? "null";
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;

  const keys = Object.keys(value).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(",")}}`;
}

/** FNV-1a, used where SubtleCrypto is unavailable (insecure contexts). */
export function fallbackHash(text) {
  let hash = 0x811c9dc5;

  for (let index = 0; index < text.length; index += 1) {
    hash ^= text.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }

  return hash.toString(16).padStart(8, "0");
}

export async function hash(value, context = globalThis) {
  const text = typeof value === "string" ? value : stableStringify(value);
  const subtle = context.crypto && context.crypto.subtle;

  if (!subtle) return `f_${fallbackHash(text)}`;

  try {
    const digest = await subtle.digest("SHA-256", encoder.encode(text));
    return [...new Uint8Array(digest)]
      .map((byte) => byte.toString(16).padStart(2, "0"))
      .join("")
      .slice(0, 32);
  } catch {
    return `f_${fallbackHash(text)}`;
  }
}
