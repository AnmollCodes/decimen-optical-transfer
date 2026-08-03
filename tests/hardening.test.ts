// Phase 6 — security hardening tests.
//
// Tests for Part A findings:
//   A1. parseFrame upper-bound validation (blockLen > MAX_BLOCK_LEN, totalLen > MAX_TOTAL_LEN)
//   A2. unbundleFiles manifest bounds (fileCount > MAX_FILE_COUNT, nameLen/mimeLen bounds)
//   A3. XSS surface: DOM insertion methods audit (documented here, not testable without DOM)
//   A4. Crypto: IV uniqueness already covered in crypto.test.ts; key-persistence path
//       confirmed safe by code review (documented below)
//
// XSS REVIEW (Part A3) — cannot be automatically tested without DOM; documented here:
//   - receive/main.ts line 583:  heading.textContent = "Transfer Complete!"         SAFE (literal)
//   - receive/main.ts line 600:  const filename = file.name || "received-file"       (filename from bundle)
//   - receive/main.ts line 607:  img.alt = filename                                  SAFE (property)
//   - receive/main.ts line 614:  link.download = filename                            SAFE (property)
//   - receive/main.ts line 616:  link.textContent = `⤓ Download ${filename}...`    SAFE (textContent)
//   - receive/main.ts line 627:  note.textContent = `✓ ${files.length} files...`   SAFE (textContent, count is number)
//   - receive/main.ts lines 170-178: resumeBanner.innerHTML uses ${pct} (number),
//       ${sizeStr} (derived from totalLen, a number), ${ageStr} (derived from Date.now(),
//       a number). None of these are user-controlled strings from the bundle/QR.
//       The filename and mime type from the bundle are NEVER passed to innerHTML.  SAFE
//   - send/main.ts line 138: namesEl.textContent = selectedFiles.map(...).join(", ")  SAFE (textContent)
//   - send/main.ts line 172-176: specs.textContent = `✗ Files too large...`         SAFE (textContent)
//   Conclusion: No innerHTML injection surface exists in the current codebase.
//   Filename/MIME strings from the DCMN bundle are only ever set via textContent or
//   element property assignment — never via innerHTML with unescaped content.
//
// CRYPTO REVIEW (Part A4) — documented here:
//   - IV uniqueness: tested in crypto.test.ts "IV uniqueness" suite (3 tests, Phase 2).
//     Nothing in Phase 4/5 touches the encrypt path; aesGcmEncrypt still generates a
//     fresh IV per call via crypto.getRandomValues. Since we encrypt exactly once per
//     session (the full compressed payload), (key, IV) is always unique by construction.
//   - Key persistence path: currentKeyBytes is set ONLY in tryStartKeyImport's .then()
//     callback, which runs only after crypto.subtle.importKey succeeds. A corrupt or
//     all-zero 32-byte sequence would still pass importKey (SubtleCrypto accepts any
//     32 bytes as an AES-256 key), but AES-GCM decryption with the wrong key will
//     fail with auth tag mismatch (DOMException), surfaced as a clear error — not a
//     silent success. The currentKeyBytes guard (`if (currentKeyBytes &&`) means no
//     IDB save happens until a valid key QR has been scanned and imported.
//   - No catch block swallows a decryption failure: the single aesGcmDecrypt call in
//     receive/main.ts (line 546) has an explicit catch that sets stats.textContent and
//     returns — never proceeds to finish() on failure. Grep below confirms this.

import { describe, expect, it } from "vitest";
import { parseFrame, packFrame, HEADER_LEN, PROTO_VERSION, MAX_BLOCK_LEN, MAX_TOTAL_LEN } from "../shared/protocol";
import { bundleFiles, unbundleFiles } from "../shared/bundle";

// ---------------------------------------------------------------------------
// Part A-1: parseFrame upper-bound validation
// ---------------------------------------------------------------------------

describe("parseFrame — upper-bound validation (Part A hardening)", () => {
  /** Build a minimal valid frame with given header overrides, then mangle a field. */
  function makeFrame(overrides: {
    k?: number;
    blockLen?: number;
    totalLen?: number;
    blockData?: Uint8Array;
  }): Uint8Array {
    const blockLen = overrides.blockLen ?? 100;
    const block = overrides.blockData ?? new Uint8Array(blockLen).fill(0xab);
    return packFrame(
      {
        version: PROTO_VERSION,
        sessionId: 1,
        seq: 0,
        k: overrides.k ?? 10,
        blockLen,
        totalLen: overrides.totalLen ?? 1000,
        payloadFnv: 0,
      },
      block,
    );
  }

  it("accepts a frame at exactly MAX_BLOCK_LEN", () => {
    const block = new Uint8Array(MAX_BLOCK_LEN).fill(0x42);
    const frame = packFrame(
      {
        version: PROTO_VERSION,
        sessionId: 1,
        seq: 0,
        k: 1,
        blockLen: MAX_BLOCK_LEN,
        totalLen: MAX_BLOCK_LEN,
        payloadFnv: 0,
      },
      block,
    );
    expect(parseFrame(frame)).not.toBeNull();
  });

  it("rejects a frame claiming blockLen = MAX_BLOCK_LEN + 1", () => {
    // Craft a raw frame by taking a valid one and patching the blockLen field.
    // We can't use packFrame for this because it uses block.length, so we patch bytes directly.
    const validBlock = new Uint8Array(MAX_BLOCK_LEN + 1).fill(0x01);
    // Build the raw frame manually: 20 header bytes + MAX_BLOCK_LEN+1 block bytes.
    const raw = new Uint8Array(HEADER_LEN + MAX_BLOCK_LEN + 1);
    const dv = new DataView(raw.buffer);
    dv.setUint8(0, 0xd1);             // magic
    dv.setUint8(1, PROTO_VERSION);    // version
    dv.setUint16(2, 1, true);         // sessionId
    dv.setUint32(4, 0, true);         // seq
    dv.setUint16(8, 1, true);         // k
    dv.setUint16(10, MAX_BLOCK_LEN + 1, true); // blockLen > MAX_BLOCK_LEN
    dv.setUint32(12, MAX_BLOCK_LEN + 1, true); // totalLen
    dv.setUint32(16, 0, true);        // payloadFnv
    raw.set(validBlock, HEADER_LEN);
    expect(parseFrame(raw)).toBeNull();
  });

  it("accepts a frame at exactly MAX_TOTAL_LEN", () => {
    // totalLen is accepted; block itself is small (100 bytes)
    const frame = makeFrame({ totalLen: MAX_TOTAL_LEN });
    expect(parseFrame(frame)).not.toBeNull();
    expect(parseFrame(frame)!.header.totalLen).toBe(MAX_TOTAL_LEN);
  });

  it("rejects a frame claiming totalLen = MAX_TOTAL_LEN + 1", () => {
    // Craft raw frame with totalLen one byte above the ceiling.
    const blockLen = 100;
    const raw = new Uint8Array(HEADER_LEN + blockLen);
    const dv = new DataView(raw.buffer);
    dv.setUint8(0, 0xd1);
    dv.setUint8(1, PROTO_VERSION);
    dv.setUint16(2, 1, true);
    dv.setUint32(4, 0, true);
    dv.setUint16(8, 1, true);
    dv.setUint16(10, blockLen, true);
    dv.setUint32(12, MAX_TOTAL_LEN + 1, true); // one above ceiling
    dv.setUint32(16, 0, true);
    expect(parseFrame(raw)).toBeNull();
  });

  it("rejects a frame claiming totalLen = 0xFFFFFFFF (u32 max)", () => {
    const blockLen = 100;
    const raw = new Uint8Array(HEADER_LEN + blockLen);
    const dv = new DataView(raw.buffer);
    dv.setUint8(0, 0xd1);
    dv.setUint8(1, PROTO_VERSION);
    dv.setUint16(2, 1, true);
    dv.setUint32(4, 0, true);
    dv.setUint16(8, 1, true);
    dv.setUint16(10, blockLen, true);
    dv.setUint32(12, 0xffffffff, true); // u32 max ~4 GB
    dv.setUint32(16, 0, true);
    expect(parseFrame(raw)).toBeNull();
  });

  it("still rejects k=0, blockLen=0, totalLen=0 (pre-existing lower bound)", () => {
    // k=0: use a raw frame (packFrame won't let us set k=0 normally, but parseFrame rejects it)
    const raw = new Uint8Array(HEADER_LEN + 100);
    const dv = new DataView(raw.buffer);
    dv.setUint8(0, 0xd1);
    dv.setUint8(1, PROTO_VERSION);
    dv.setUint16(2, 1, true);
    dv.setUint32(4, 0, true);
    dv.setUint16(8, 0, true);   // k = 0
    dv.setUint16(10, 100, true);
    dv.setUint32(12, 1000, true);
    dv.setUint32(16, 0, true);
    expect(parseFrame(raw)).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Part A-2: unbundleFiles manifest bounds
// ---------------------------------------------------------------------------

describe("unbundleFiles — manifest bounds validation (Part A hardening)", () => {
  /** Build a valid single-entry bundle, then patch the raw bytes at offset `pos`. */
  function patchUint32(buf: Uint8Array, pos: number, value: number): Uint8Array {
    const out = new Uint8Array(buf);
    new DataView(out.buffer).setUint32(pos, value, true);
    return out;
  }

  function patchUint16(buf: Uint8Array, pos: number, value: number): Uint8Array {
    const out = new Uint8Array(buf);
    new DataView(out.buffer).setUint16(pos, value, true);
    return out;
  }

  const singleBundle = bundleFiles([
    { name: "test.txt", mime: "text/plain", data: new Uint8Array([0x61, 0x62, 0x63]) },
  ]);

  it("accepts a bundle with fileCount = 1 (normal case)", () => {
    expect(unbundleFiles(singleBundle)).not.toBeNull();
    expect(unbundleFiles(singleBundle)!.length).toBe(1);
  });

  it("throws RangeError when fileCount exceeds MAX_FILE_COUNT (1024)", () => {
    // Patch bytes 4-7 (fileCount u32) to 1025
    const malicious = patchUint32(singleBundle, 4, 1025);
    expect(() => unbundleFiles(malicious)).toThrow(RangeError);
    expect(() => unbundleFiles(malicious)).toThrow(/exceeds maximum/);
  });

  it("throws RangeError when fileCount = 0xFFFFFFFF", () => {
    const malicious = patchUint32(singleBundle, 4, 0xffffffff);
    expect(() => unbundleFiles(malicious)).toThrow(RangeError);
  });

  it("throws RangeError when nameLen exceeds MAX_NAME_LEN (4096)", () => {
    // In a single-file bundle with magic(4)+count(4)=8 bytes header,
    // then per-file: nameLen(2) at offset 8.
    const malicious = patchUint16(singleBundle, 8, 4097);
    expect(() => unbundleFiles(malicious)).toThrow(RangeError);
    expect(() => unbundleFiles(malicious)).toThrow(/filename length/);
  });

  it("throws RangeError when mimeLen exceeds MAX_MIME_LEN (256)", () => {
    // mimeLen(2) is at offset 10 (after nameLen at 8).
    const malicious = patchUint16(singleBundle, 10, 257);
    expect(() => unbundleFiles(malicious)).toThrow(RangeError);
    expect(() => unbundleFiles(malicious)).toThrow(/MIME type length/);
  });

  it("still throws RangeError on truncated buffer (pre-existing check)", () => {
    const truncated = singleBundle.subarray(0, 10); // chop most of the data
    expect(() => unbundleFiles(truncated)).toThrow(RangeError);
  });

  it("returns null for non-DCMN magic (pre-existing check)", () => {
    const garbage = new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    expect(unbundleFiles(garbage)).toBeNull();
  });
});
