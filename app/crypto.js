/**
 * crypto.js — browser port of @dsh-remote/protocol's crypto layer.
 *
 * Source of truth (byte-for-byte):
 *   protocol/dist/src/crypto/keys.js   (KDF, nonce construction)
 *   protocol/dist/src/crypto/record.js (sealed record format)
 *   protocol/dist/src/crypto/bytes.js  (utf8 / base64 / concat)
 *
 * The package itself imports `node:crypto` and `node:buffer`, so it cannot run in a
 * browser. Everything below reproduces the same bytes using WebCrypto (SHA-512) and
 * tweetnacl (XSalsa20-Poly1305), both of which the frozen contract requires.
 *
 * Frozen shapes (getting any of these wrong yields "pairing succeeded but nothing
 * decrypts"):
 *   kdfHash    = SHA-512(p0 ‖ 0x1f ‖ p1 ‖ 0x1f ‖ … ‖ pn ‖ 0x1f), first 32 bytes
 *   ciphertext = base64( nonce(24B) ‖ nacl.secretbox(utf8(JSON.stringify(payload)), nonce, key) )
 *
 * `nacl` comes from vendor/nacl-fast.js loaded before this module.
 */
/**
 * `nacl` comes from vendor/nacl-fast.js (a classic script that sets a global) or, in
 * Node tests, from an assignment to globalThis.nacl. It is read lazily because ESM
 * import hoisting can evaluate this module before a harness sets the global.
 */
function naclLib() {
  const lib = globalThis.nacl;
  if (!lib?.secretbox) {
    throw new Error('tweetnacl 未加载（浏览器请先引 vendor/nacl-fast.js）');
  }
  return lib;
}

export const KDF_NAMESPACE = 'dsh-rc/v1';
export const NONCE_NAMESPACE = 'dsh-rc/v1/nonce';
const UNIT_SEPARATOR = 0x1f;
export const KEY_BYTES = 32;
export const NONCE_BYTES = 24;
export const PSK_BYTES = 16;
export const NONCE_PREFIX_BYTES = NONCE_BYTES - 8;
const MAC_BYTES = 16;
const MIN_RECORD_BYTES = NONCE_BYTES + MAC_BYTES;

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: false });

/** string → UTF-8 bytes. */
export function utf8(text) {
  return encoder.encode(text);
}

/** UTF-8 bytes → string (non-fatal, like the protocol's decoder). */
export function fromUtf8(bytes) {
  return decoder.decode(bytes);
}

/** bytes → standard base64 with padding. */
export function toBase64(bytes) {
  let binary = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

/**
 * standard base64 → bytes, deliberately lenient like Buffer.from(s, 'base64').
 * Safety rests on the Poly1305 MAC downstream, exactly as documented upstream.
 */
export function fromBase64(text) {
  let s = String(text ?? '').replace(/\s+/g, '').replace(/[^A-Za-z0-9+/=]/g, '');
  const pad = s.indexOf('=');
  if (pad >= 0) s = s.slice(0, pad);
  if (s.length % 4 === 1) s = s.slice(0, s.length - 1);
  while (s.length % 4 !== 0) s += '=';
  const binary = atob(s);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

/** Concatenate byte segments. */
export function concat(parts) {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

/** Cryptographically secure random bytes. */
export function randomBytes(n) {
  const out = new Uint8Array(n);
  crypto.getRandomValues(out);
  return out;
}

async function sha512(bytes) {
  const digest = await crypto.subtle.digest('SHA-512', bytes);
  return new Uint8Array(digest);
}

/** SHA-512(parts joined by 0x1f, trailing separator included) → first 32 bytes. */
export async function kdfHash(parts) {
  const encoded = parts.map((p) => (typeof p === 'string' ? utf8(p) : p));
  const total = encoded.reduce((n, b) => n + b.length + 1, 0);
  const joined = new Uint8Array(total);
  let at = 0;
  for (const bytes of encoded) {
    joined.set(bytes, at);
    at += bytes.length;
    joined[at++] = UNIT_SEPARATOR;
  }
  return (await sha512(joined)).subarray(0, KEY_BYTES);
}

/** Decode the PSK and require exactly 16 bytes (a truncated PSK silently breaks every frame). */
export function pskBytes(pskBase64) {
  const bytes = fromBase64(pskBase64);
  if (bytes.length !== PSK_BYTES) {
    throw new Error(`PSK must decode to ${PSK_BYTES} bytes, got ${bytes.length}`);
  }
  return bytes;
}

/** Session key for one conversation and one direction. */
export async function derivePskKey(pskBase64, direction, conversationId) {
  return kdfHash([KDF_NAMESPACE, direction, conversationId, pskBytes(pskBase64)]);
}

/** 16-byte prefix bound to (PSK, conversation, installId). */
export async function noncePrefix(pskBase64, conversationId, installId) {
  const full = await kdfHash([NONCE_NAMESPACE, installId, conversationId, pskBytes(pskBase64)]);
  return full.subarray(0, NONCE_PREFIX_BYTES);
}

/** prefix(16B) ‖ counter(8B big-endian) → 24-byte nonce. */
export function buildCounterNonce(prefix, counter) {
  if (prefix.length !== NONCE_PREFIX_BYTES) {
    throw new Error(`nonce prefix must be ${NONCE_PREFIX_BYTES} bytes, got ${prefix.length}`);
  }
  if (!Number.isInteger(counter) || counter < 0) {
    throw new Error(`nonce counter must be a non-negative integer, got ${String(counter)}`);
  }
  if (counter > Number.MAX_SAFE_INTEGER) {
    throw new Error('nonce counter exceeds safe integer range');
  }
  const high = Math.floor(counter / 0x100000000);
  const low = counter >>> 0;
  const tail = new Uint8Array([
    (high >>> 24) & 0xff, (high >>> 16) & 0xff, (high >>> 8) & 0xff, high & 0xff,
    (low >>> 24) & 0xff, (low >>> 16) & 0xff, (low >>> 8) & 0xff, low & 0xff,
  ]);
  return concat([prefix, tail]);
}

/** A random 24-byte nonce (the direction the protocol uses for host→client). */
export function randomNonce() {
  return randomBytes(NONCE_BYTES);
}

/** Seal a JSON payload into `{ ciphertext }`. */
export function seal(key, payload, nonce = randomNonce()) {
  if (key.length !== KEY_BYTES) throw new Error(`session key must be ${KEY_BYTES} bytes`);
  if (nonce.length !== NONCE_BYTES) throw new Error(`nonce must be ${NONCE_BYTES} bytes`);
  const text = JSON.stringify(payload);
  if (text === undefined) throw new Error('payload is not JSON-serializable');
  const box = naclLib().secretbox(utf8(text), nonce, key);
  return { ciphertext: toBase64(concat([nonce, box])) };
}

/** Open a sealed record. Any failure returns null (never throws), per the contract. */
export function open(key, record) {
  try {
    const ciphertext = record?.ciphertext;
    if (typeof ciphertext !== 'string') return null;
    const merged = fromBase64(ciphertext);
    if (merged.length < MIN_RECORD_BYTES) return null;
    const box = naclLib().secretbox.open(merged.subarray(NONCE_BYTES), merged.subarray(0, NONCE_BYTES), key);
    if (!box) return null;
    return JSON.parse(fromUtf8(box));
  } catch {
    return null;
  }
}

/** Round-trip self test — useful in the browser console when a frame will not decrypt. */
export async function selfTest() {
  const psk = toBase64(randomBytes(PSK_BYTES));
  const key = await derivePskKey(psk, 'self-test', 'conv-1');
  const prefix = await noncePrefix(psk, 'conv-1', 'install-1');
  const payload = { type: 'ping', n: 42, text: '你好' };
  const record = seal(key, payload, buildCounterNonce(prefix, 7));
  const back = open(key, record);
  const wrongKey = await derivePskKey(psk, 'self-test', 'conv-2');
  return {
    keyBytes: key.length,
    noncePrefixBytes: prefix.length,
    roundTrip: JSON.stringify(back) === JSON.stringify(payload),
    wrongKeyRejected: open(wrongKey, record) === null,
  };
}
