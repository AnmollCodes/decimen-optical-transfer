/**
 * Tests for shared/crypto.ts — AES-256-GCM encrypt/decrypt via SubtleCrypto.
 *
 * These use the browser-native crypto.subtle API, which is available as a
 * Node.js global since Node 18. Vitest runs in Node 22 so no polyfill needed.
 *
 * NOTE: These tests exercise Node's SubtleCrypto implementation. AES-GCM is
 * a W3C standard with a normative test suite, so cross-engine risk is very
 * low. However, a real device-to-device transfer test is still needed to
 * verify end-to-end behavior in Chrome, Safari, and Firefox — see the Phase 2
 * status report for the full list of manual-verification requirements.
 */

import { describe, expect, it } from "vitest";
import {
  aesGcmDecrypt,
  aesGcmEncrypt,
  exportKeyBytes,
  generateAesKey,
  importKeyBytes,
} from "../shared/crypto";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Deterministic payload using splitmix32 (same PRNG as fountain codec). */
function makePayload(len: number, seed = 0xc0ffee): Uint8Array {
  let s = seed | 0;
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    s = (s + 0x9e3779b9) | 0;
    let t = s ^ (s >>> 16);
    t = Math.imul(t, 0x21f0aaad);
    t ^= t >>> 15;
    t = Math.imul(t, 0x735a2d97);
    t ^= t >>> 15;
    out[i] = (t >>> 0) & 0xff;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Key generation and export/import round-trip
// ---------------------------------------------------------------------------

describe("generateAesKey / exportKeyBytes / importKeyBytes", () => {
  it("generated key is 32 bytes when exported", async () => {
    const key = await generateAesKey();
    const raw = await exportKeyBytes(key);
    expect(raw.length).toBe(32);
  });

  it("export→import round-trip: re-imported key decrypts correctly", async () => {
    const key = await generateAesKey();
    const keyBytes = await exportKeyBytes(key);
    const reimported = await importKeyBytes(keyBytes);
    const plaintext = makePayload(64);
    const cipherBlob = await aesGcmEncrypt(key, plaintext);
    const recovered = await aesGcmDecrypt(reimported, cipherBlob);
    expect(recovered).toEqual(plaintext);
  });

  it("two generated keys produce different raw bytes", async () => {
    const a = await exportKeyBytes(await generateAesKey());
    const b = await exportKeyBytes(await generateAesKey());
    // 32 random bytes: probability of collision is 1/2^256, not worth testing for
    expect(a).not.toEqual(b);
  });
});

// ---------------------------------------------------------------------------
// Round-trip: encrypt then decrypt gives back original plaintext
// ---------------------------------------------------------------------------

describe("aesGcmEncrypt / aesGcmDecrypt — round-trip", () => {
  it("round-trip: small payload (16 bytes)", async () => {
    const key = await generateAesKey();
    const plaintext = makePayload(16);
    const cipherBlob = await aesGcmEncrypt(key, plaintext);
    const recovered = await aesGcmDecrypt(key, cipherBlob);
    expect(recovered).toEqual(plaintext);
  });

  it("round-trip: 1 KB payload, byte-for-byte identical", async () => {
    const key = await generateAesKey();
    const plaintext = makePayload(1024);
    const cipherBlob = await aesGcmEncrypt(key, plaintext);
    const recovered = await aesGcmDecrypt(key, cipherBlob);
    expect(recovered.length).toBe(plaintext.length);
    expect(recovered).toEqual(plaintext);
  });

  it("round-trip: 8 KB payload", async () => {
    const key = await generateAesKey();
    const plaintext = makePayload(8192);
    const cipherBlob = await aesGcmEncrypt(key, plaintext);
    const recovered = await aesGcmDecrypt(key, cipherBlob);
    expect(recovered.length).toBe(plaintext.length);
    expect(recovered).toEqual(plaintext);
  });

  it("cipherBlob length = 12 (IV) + plaintext.length + 16 (auth tag)", async () => {
    const key = await generateAesKey();
    const plaintext = makePayload(100);
    const cipherBlob = await aesGcmEncrypt(key, plaintext);
    expect(cipherBlob.length).toBe(12 + plaintext.length + 16);
  });
});

// ---------------------------------------------------------------------------
// Wrong-key rejection: decrypting with a different key must throw, not corrupt
// ---------------------------------------------------------------------------

describe("aesGcmDecrypt — wrong key rejection", () => {
  it("decrypting with a different key throws (does not return corrupted plaintext)", async () => {
    const encryptKey = await generateAesKey();
    const wrongKey = await generateAesKey(); // distinct random key
    const plaintext = makePayload(256);
    const cipherBlob = await aesGcmEncrypt(encryptKey, plaintext);
    await expect(aesGcmDecrypt(wrongKey, cipherBlob)).rejects.toThrow();
  });

  it("the error from wrong-key decryption is not swallowed (exception propagates)", async () => {
    const encryptKey = await generateAesKey();
    const wrongKey = await generateAesKey();
    const plaintext = makePayload(64);
    const cipherBlob = await aesGcmEncrypt(encryptKey, plaintext);
    let threw = false;
    try {
      await aesGcmDecrypt(wrongKey, cipherBlob);
    } catch {
      threw = true;
    }
    expect(threw).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Tampered-ciphertext rejection: auth tag catches bit flips
// ---------------------------------------------------------------------------

describe("aesGcmDecrypt — tampered ciphertext rejection", () => {
  it("flipping a byte in the ciphertext body causes decryption to throw", async () => {
    const key = await generateAesKey();
    const plaintext = makePayload(128);
    const cipherBlob = await aesGcmEncrypt(key, plaintext);
    // Flip a byte in the ciphertext body (after the 12-byte IV, before the 16-byte tag)
    const tampered = new Uint8Array(cipherBlob);
    tampered[16] ^= 0xff; // byte 16 = first byte of actual ciphertext
    await expect(aesGcmDecrypt(key, tampered)).rejects.toThrow();
  });

  it("flipping a byte in the auth tag causes decryption to throw", async () => {
    const key = await generateAesKey();
    const plaintext = makePayload(128);
    const cipherBlob = await aesGcmEncrypt(key, plaintext);
    // Flip the last byte (in the 16-byte auth tag)
    const tampered = new Uint8Array(cipherBlob);
    tampered[tampered.length - 1] ^= 0x01;
    await expect(aesGcmDecrypt(key, tampered)).rejects.toThrow();
  });

  it("flipping a byte in the IV causes decryption to throw", async () => {
    const key = await generateAesKey();
    const plaintext = makePayload(128);
    const cipherBlob = await aesGcmEncrypt(key, plaintext);
    // Flip a byte in the IV (first 12 bytes)
    const tampered = new Uint8Array(cipherBlob);
    tampered[0] ^= 0x80;
    await expect(aesGcmDecrypt(key, tampered)).rejects.toThrow();
  });
});

// ---------------------------------------------------------------------------
// IV uniqueness: same plaintext + same key → different ciphertext each time
// ---------------------------------------------------------------------------

describe("IV uniqueness", () => {
  it("two encryptions of the same plaintext with the same key produce different ciphertexts", async () => {
    const key = await generateAesKey();
    const plaintext = makePayload(256);
    const cipher1 = await aesGcmEncrypt(key, plaintext);
    const cipher2 = await aesGcmEncrypt(key, plaintext);
    // The full blobs differ (different IVs → different ciphertexts)
    expect(cipher1).not.toEqual(cipher2);
  });

  it("the IVs (first 12 bytes) from two encryptions differ", async () => {
    const key = await generateAesKey();
    const plaintext = makePayload(64);
    const cipher1 = await aesGcmEncrypt(key, plaintext);
    const cipher2 = await aesGcmEncrypt(key, plaintext);
    const iv1 = cipher1.subarray(0, 12);
    const iv2 = cipher2.subarray(0, 12);
    expect(iv1).not.toEqual(iv2);
  });

  it("both encryptions still decrypt to the original plaintext despite different IVs", async () => {
    const key = await generateAesKey();
    const plaintext = makePayload(256);
    const cipher1 = await aesGcmEncrypt(key, plaintext);
    const cipher2 = await aesGcmEncrypt(key, plaintext);
    const r1 = await aesGcmDecrypt(key, cipher1);
    const r2 = await aesGcmDecrypt(key, cipher2);
    expect(r1).toEqual(plaintext);
    expect(r2).toEqual(plaintext);
  });
});

// ---------------------------------------------------------------------------
// Full pipeline: compress → encrypt → fountain → decrypt → decompress
// ---------------------------------------------------------------------------

describe("full pipeline integration: compress → encrypt → decrypt → decompress", () => {
  it("round-trips a 4 KB payload through compress+encrypt then decrypt+decompress", async () => {
    const { gzipCompress, gzipDecompress } = await import("../shared/compress");
    const original = makePayload(4096);
    const key = await generateAesKey();

    // Send path: compress → encrypt
    const compressed = await gzipCompress(original);
    const encrypted = await aesGcmEncrypt(key, compressed);

    // Receive path: decrypt → decompress
    const decrypted = await aesGcmDecrypt(key, encrypted);
    const recovered = await gzipDecompress(decrypted);

    expect(recovered.length).toBe(original.length);
    expect(recovered).toEqual(original);
  });
});
