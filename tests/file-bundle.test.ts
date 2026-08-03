// Tests for shared/bundle.ts — bundleFiles / unbundleFiles round-trips.
//
// These run in Node (Vitest) with no DOM. The pipeline integration test
// exercises compress → encrypt → decrypt → decompress → unbundle using the
// browser-native CompressionStream / SubtleCrypto APIs available in Node 18+.

import { describe, expect, it } from "vitest";
import { gzipCompress, gzipDecompress } from "../shared/compress";
import { aesGcmDecrypt, aesGcmEncrypt, generateAesKey } from "../shared/crypto";
import { type BundleEntry, bundleFiles, isBundled, unbundleFiles } from "../shared/bundle";

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

function bytes(...vals: number[]): Uint8Array {
  return new Uint8Array(vals);
}

function text(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

// ---------------------------------------------------------------------------
// isBundled
// ---------------------------------------------------------------------------

describe("isBundled", () => {
  it("returns true for a real bundle", () => {
    const bundle = bundleFiles([{ name: "a.txt", mime: "text/plain", data: text("hi") }]);
    expect(isBundled(bundle)).toBe(true);
  });

  it("returns false for arbitrary bytes that don't start with DCMN", () => {
    expect(isBundled(bytes(0xd1, 0x02, 0x00, 0x00))).toBe(false);
  });

  it("returns false for empty buffer", () => {
    expect(isBundled(new Uint8Array(0))).toBe(false);
  });

  it("returns false for a buffer shorter than 4 bytes", () => {
    expect(isBundled(bytes(0x44, 0x43))).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// single-file round-trip
// ---------------------------------------------------------------------------

describe("bundleFiles / unbundleFiles — single file", () => {
  it("round-trips filename, MIME type, and content exactly", () => {
    const data = text("Hello, world! This is a test file.");
    const input: BundleEntry[] = [{ name: "hello.txt", mime: "text/plain", data }];
    const bundle = bundleFiles(input);
    const output = unbundleFiles(bundle);
    expect(output).not.toBeNull();
    expect(output!.length).toBe(1);
    expect(output![0]!.name).toBe("hello.txt");
    expect(output![0]!.mime).toBe("text/plain");
    expect(output![0]!.data).toEqual(data);
  });

  it("preserves an image MIME type", () => {
    const data = bytes(0x89, 0x50, 0x4e, 0x47); // PNG magic
    const input: BundleEntry[] = [{ name: "photo.png", mime: "image/png", data }];
    const output = unbundleFiles(bundleFiles(input))!;
    expect(output[0]!.mime).toBe("image/png");
    expect(output[0]!.data).toEqual(data);
  });

  it("round-trips a PDF with the correct MIME type", () => {
    const data = text("%PDF-1.4 mock content");
    const input: BundleEntry[] = [{ name: "doc.pdf", mime: "application/pdf", data }];
    const output = unbundleFiles(bundleFiles(input))!;
    expect(output[0]!.name).toBe("doc.pdf");
    expect(output[0]!.mime).toBe("application/pdf");
    expect(output[0]!.data).toEqual(data);
  });
});

// ---------------------------------------------------------------------------
// multi-file round-trip
// ---------------------------------------------------------------------------

describe("bundleFiles / unbundleFiles — multiple files", () => {
  it("round-trips all filenames, MIME types, and content in order", () => {
    const files: BundleEntry[] = [
      { name: "readme.txt",  mime: "text/plain",       data: text("readme content") },
      { name: "photo.jpg",   mime: "image/jpeg",       data: bytes(0xff, 0xd8, 0xff) },
      { name: "data.json",   mime: "application/json", data: text("{\"ok\":true}") },
    ];
    const output = unbundleFiles(bundleFiles(files))!;
    expect(output.length).toBe(3);
    for (let i = 0; i < files.length; i++) {
      expect(output[i]!.name).toBe(files[i]!.name);
      expect(output[i]!.mime).toBe(files[i]!.mime);
      expect(output[i]!.data).toEqual(files[i]!.data);
    }
  });

  it("preserves order of five files", () => {
    const files: BundleEntry[] = Array.from({ length: 5 }, (_, i) => ({
      name: `file${i}.bin`,
      mime: "application/octet-stream",
      data: new Uint8Array([i, i + 1, i + 2]),
    }));
    const output = unbundleFiles(bundleFiles(files))!;
    expect(output.map((f) => f.name)).toEqual(files.map((f) => f.name));
    for (let i = 0; i < files.length; i++) {
      expect(output[i]!.data).toEqual(files[i]!.data);
    }
  });
});

// ---------------------------------------------------------------------------
// edge cases
// ---------------------------------------------------------------------------

describe("bundleFiles / unbundleFiles — edge cases", () => {
  it("round-trips an empty file (0 bytes)", () => {
    const input: BundleEntry[] = [{ name: "empty.bin", mime: "application/octet-stream", data: new Uint8Array(0) }];
    const output = unbundleFiles(bundleFiles(input))!;
    expect(output[0]!.data.length).toBe(0);
    expect(output[0]!.name).toBe("empty.bin");
  });

  it("round-trips a file with a unicode filename", () => {
    const name = "文件名-résumé-日本語.txt";
    const data = text("content");
    const output = unbundleFiles(bundleFiles([{ name, mime: "text/plain", data }]))!;
    expect(output[0]!.name).toBe(name);
  });

  it("round-trips a very small file (1 byte)", () => {
    const data = bytes(0x42);
    const output = unbundleFiles(bundleFiles([{ name: "one.bin", mime: "application/octet-stream", data }]))!;
    expect(output[0]!.data).toEqual(data);
  });

  it("round-trips an empty filename (unnamed file)", () => {
    const data = text("anonymous");
    const output = unbundleFiles(bundleFiles([{ name: "", mime: "application/octet-stream", data }]))!;
    expect(output[0]!.name).toBe("");
    expect(output[0]!.data).toEqual(data);
  });

  it("round-trips a large synthetic file (1 MB)", () => {
    // Fill with a repeating byte pattern (0x00..0xFF) rather than
    // crypto.getRandomValues — getRandomValues caps at 65,536 bytes per call
    // in the Web Crypto spec, and we just need to verify byte-perfect round-trip.
    const data = new Uint8Array(1024 * 1024);
    for (let i = 0; i < data.length; i++) data[i] = i & 0xff;
    const output = unbundleFiles(bundleFiles([{ name: "big.bin", mime: "application/octet-stream", data }]))!;
    expect(output[0]!.data.length).toBe(1024 * 1024);
    // spot-check first and last bytes
    expect(output[0]!.data[0]).toBe(data[0]);
    expect(output[0]!.data[data.length - 1]).toBe(data[data.length - 1]);
  });

  it("unbundleFiles returns null for non-bundle bytes (no DCMN magic)", () => {
    const notBundle = text("Hello world");
    expect(unbundleFiles(notBundle)).toBeNull();
  });

  it("unbundleFiles returns null for QR frame header bytes (magic 0xD1)", () => {
    const frameHeader = bytes(0xd1, 0x02, 0x01, 0x00);
    expect(unbundleFiles(frameHeader)).toBeNull();
  });

  it("unbundleFiles throws RangeError on truncated buffer", () => {
    const bundle = bundleFiles([{ name: "a.txt", mime: "text/plain", data: text("hello") }]);
    // Truncate to just the header, cutting off file content
    const truncated = bundle.subarray(0, 12);
    expect(() => unbundleFiles(truncated)).toThrow(RangeError);
  });
});

// ---------------------------------------------------------------------------
// full pipeline integration: bundle → compress → encrypt → decrypt → decompress → unbundle
// ---------------------------------------------------------------------------

describe("full pipeline: bundle → compress → encrypt → decrypt → decompress → unbundle", () => {
  it("multi-file bundle survives the entire Phase 4 pipeline byte-for-byte", async () => {
    const files: BundleEntry[] = [
      { name: "note.txt",   mime: "text/plain",       data: text("This is note content. ".repeat(20)) },
      { name: "data.json",  mime: "application/json", data: text(JSON.stringify({ items: Array.from({ length: 50 }, (_, i) => i) })) },
      { name: "bytes.bin",  mime: "application/octet-stream", data: new Uint8Array(256).map((_, i) => i) },
    ];

    // bundle
    const bundled = bundleFiles(files);

    // compress
    const compressed = await gzipCompress(bundled);

    // encrypt
    const key = await generateAesKey();
    const encrypted = await aesGcmEncrypt(key, compressed);

    // decrypt
    const decrypted = await aesGcmDecrypt(key, encrypted);

    // decompress
    const decompressed = await gzipDecompress(decrypted);

    // unbundle
    const output = unbundleFiles(decompressed);
    expect(output).not.toBeNull();
    expect(output!.length).toBe(3);

    for (let i = 0; i < files.length; i++) {
      expect(output![i]!.name).toBe(files[i]!.name);
      expect(output![i]!.mime).toBe(files[i]!.mime);
      expect(output![i]!.data).toEqual(files[i]!.data);
    }
  });

  it("single-file bundle survives the entire pipeline (regression for single-file case)", async () => {
    const original = text("Single file content for regression test. ".repeat(100));
    const bundled = bundleFiles([{ name: "single.txt", mime: "text/plain", data: original }]);
    const compressed = await gzipCompress(bundled);
    const key = await generateAesKey();
    const encrypted = await aesGcmEncrypt(key, compressed);
    const decrypted = await aesGcmDecrypt(key, encrypted);
    const decompressed = await gzipDecompress(decrypted);
    const output = unbundleFiles(decompressed)!;
    expect(output.length).toBe(1);
    expect(output[0]!.name).toBe("single.txt");
    expect(output[0]!.data).toEqual(original);
  });
});
