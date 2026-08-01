// Compression helpers using the browser-native Compression Streams API
// (CompressionStream / DecompressionStream). Available in:
//   - Chrome 80+, Firefox 113+, Safari 16.4+
//   - Node.js 18+ (global, no import needed)
//
// These functions are in a separate module so they can be unit-tested in
// Node (Vitest) without importing browser-only DOM code from send/main.ts
// or receive/main.ts.

/**
 * Copy a Uint8Array<ArrayBufferLike> into a fresh Uint8Array<ArrayBuffer>.
 * WritableStreamDefaultWriter.write() requires ArrayBuffer, not ArrayBufferLike.
 */
function toPlainBuffer(input: Uint8Array): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(input.length);
  out.set(input);
  return out;
}

/** Compress bytes with gzip. Returns the compressed Uint8Array. */
export async function gzipCompress(input: Uint8Array): Promise<Uint8Array> {
  const cs = new CompressionStream("gzip");
  const writer = cs.writable.getWriter();
  const reader = cs.readable.getReader();

  void writer.write(toPlainBuffer(input)).then(() => writer.close());

  const chunks: Uint8Array[] = [];
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
  }
  return concat(chunks);
}

/** Decompress gzip-compressed bytes. Returns the original Uint8Array. */
export async function gzipDecompress(input: Uint8Array): Promise<Uint8Array> {
  const ds = new DecompressionStream("gzip");
  const writer = ds.writable.getWriter();
  const reader = ds.readable.getReader();

  void writer.write(toPlainBuffer(input)).then(() => writer.close());

  const chunks: Uint8Array[] = [];
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
  }
  return concat(chunks);
}

/** Concatenate an array of Uint8Arrays into one. */
function concat(chunks: Uint8Array[]): Uint8Array {
  const total = chunks.reduce((n, c) => n + c.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.length;
  }
  return out;
}
