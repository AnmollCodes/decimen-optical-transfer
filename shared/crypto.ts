// AES-256-GCM encryption helpers using the browser-native SubtleCrypto API.
// Available in all modern browsers and Node.js 18+ (global crypto.subtle).
//
// Design decisions:
//   - Key: AES-256-GCM, generated fresh per session via crypto.subtle.generateKey.
//   - IV: 12 random bytes, generated fresh per encrypt call via crypto.getRandomValues.
//     Since we encrypt exactly once per session (the entire compressed payload),
//     the (key, IV) pair is always unique — IV reuse is structurally impossible.
//   - Wire format: [12 bytes IV][AES-GCM ciphertext (includes 16-byte auth tag)]
//     The IV is prepended to the ciphertext and travels with it transparently.
//   - Authentication: AES-GCM's built-in auth tag covers the entire ciphertext.
//     crypto.subtle.decrypt throws DOMException on any auth-tag failure — we do
//     NOT catch that; callers must handle it explicitly (the throw is the signal).
//
// These functions are in a separate module so they can be unit-tested in Node
// (Vitest) without pulling in browser-only DOM code.

const ALG = "AES-GCM";
const KEY_BITS = 256;
const IV_BYTES = 12;

/**
 * Copy a Uint8Array<ArrayBufferLike> into a fresh Uint8Array<ArrayBuffer>.
 * SubtleCrypto and related APIs require BufferSource (ArrayBuffer), not
 * ArrayBufferLike, so we ensure a plain ArrayBuffer backing before passing in.
 */
function toPlain(input: Uint8Array): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(input.length);
  out.set(input);
  return out;
}

/** Generate a new random AES-256-GCM key. Extractable so we can export it. */
export async function generateAesKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: ALG, length: KEY_BITS }, /* extractable */ true, [
    "encrypt",
    "decrypt",
  ]);
}

/**
 * Export a CryptoKey to a 32-byte Uint8Array (raw format).
 * Used to encode the key into a QR code for delivery to the receiver.
 */
export async function exportKeyBytes(key: CryptoKey): Promise<Uint8Array> {
  const raw = await crypto.subtle.exportKey("raw", key);
  return new Uint8Array(raw);
}

/**
 * Import a 32-byte Uint8Array as an AES-256-GCM CryptoKey.
 * Used on the receiver after scanning the key QR code.
 */
export async function importKeyBytes(bytes: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", toPlain(bytes), { name: ALG }, /* extractable */ false, [
    "encrypt",
    "decrypt",
  ]);
}

/**
 * Encrypt plaintext with AES-256-GCM.
 * Returns [12-byte IV || ciphertext-with-auth-tag].
 * A fresh random IV is generated for every call — callers must not reuse IVs.
 */
export async function aesGcmEncrypt(key: CryptoKey, plaintext: Uint8Array): Promise<Uint8Array> {
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const cipherBuffer = await crypto.subtle.encrypt(
    { name: ALG, iv },
    key,
    toPlain(plaintext),
  );
  const cipher = new Uint8Array(cipherBuffer);
  const out = new Uint8Array(IV_BYTES + cipher.length);
  out.set(iv, 0);
  out.set(cipher, IV_BYTES);
  return out;
}

/**
 * Decrypt AES-256-GCM ciphertext.
 * Expects input in the form produced by aesGcmEncrypt: [12-byte IV || ciphertext].
 *
 * Throws DOMException("OperationError") if the auth tag is invalid — caller must
 * handle this as an authentication failure, NOT as a soft error. Never silently
 * returns garbage on auth failure.
 */
export async function aesGcmDecrypt(key: CryptoKey, ivAndCipher: Uint8Array): Promise<Uint8Array> {
  if (ivAndCipher.length <= IV_BYTES) {
    throw new Error(`aesGcmDecrypt: input too short (${ivAndCipher.length} bytes, need >${IV_BYTES})`);
  }
  const plain = toPlain(ivAndCipher);
  const iv = plain.subarray(0, IV_BYTES);
  const cipher = plain.subarray(IV_BYTES);
  const plainBuffer = await crypto.subtle.decrypt({ name: ALG, iv }, key, cipher);
  return new Uint8Array(plainBuffer);
}
