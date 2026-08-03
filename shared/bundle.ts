// Bundle format for multi-file transfer.
//
// Metadata (filename, MIME type, size per file) lives INSIDE the compressed+
// encrypted payload — NOT in the QR frame header. This avoids a protocol-
// version bump and keeps all metadata protected by the same AES-256-GCM
// encryption as the file content.
//
// Format (all multi-byte integers are little-endian):
//
//   [4]  magic bytes 0x44 0x43 0x4D 0x4E  ("DCMN")
//   [4]  u32  fileCount
//   for each file:
//     [2]  u16  nameLen     (byte length of filename in UTF-8)
//     [2]  u16  mimeLen     (byte length of MIME type string in UTF-8)
//     [4]  u32  fileSize    (raw file byte length)
//     [nameLen]  filename   (UTF-8)
//     [mimeLen]  MIME type  (UTF-8)
//     [fileSize] file bytes
//
// The manifest header for each file is immediately followed by that file's
// content bytes — there is no separate data section. This keeps the format
// streamable and simple to parse without a two-pass approach.
//
// Single-file bundles have fileCount=1. The receiver checks the magic and
// always uses bundled filenames/MIME types, so the legacy "display as image"
// path is gated on the detected MIME type rather than assumed.

const MAGIC = new Uint8Array([0x44, 0x43, 0x4d, 0x4e]); // "DCMN"

export interface BundleEntry {
  name: string;
  mime: string;
  data: Uint8Array;
}

const enc = new TextEncoder();
const dec = new TextDecoder();

/**
 * Encode one or more files into a single DCMN bundle.
 * Returns a Uint8Array that can be passed directly to gzipCompress.
 */
export function bundleFiles(files: BundleEntry[]): Uint8Array {
  // Pre-calculate total byte count so we can allocate once.
  const nameBytes = files.map((f) => enc.encode(f.name));
  const mimeBytes = files.map((f) => enc.encode(f.mime));
  let total = 4 + 4; // magic + fileCount
  for (let i = 0; i < files.length; i++) {
    total += 2 + 2 + 4;              // nameLen + mimeLen + fileSize
    total += nameBytes[i]!.length;   // filename bytes
    total += mimeBytes[i]!.length;   // MIME bytes
    total += files[i]!.data.length;  // file content
  }

  const buf = new Uint8Array(total);
  const dv = new DataView(buf.buffer);
  let off = 0;

  // magic
  buf.set(MAGIC, off);
  off += 4;

  // fileCount
  dv.setUint32(off, files.length, true);
  off += 4;

  for (let i = 0; i < files.length; i++) {
    const nb = nameBytes[i]!;
    const mb = mimeBytes[i]!;
    const fb = files[i]!.data;

    dv.setUint16(off, nb.length, true);
    off += 2;
    dv.setUint16(off, mb.length, true);
    off += 2;
    dv.setUint32(off, fb.length, true);
    off += 4;

    buf.set(nb, off);
    off += nb.length;
    buf.set(mb, off);
    off += mb.length;
    buf.set(fb, off);
    off += fb.length;
  }

  return buf;
}

/**
 * Decode a DCMN bundle back into individual files.
 * Returns null if the magic bytes don't match (not a bundle — treat as raw).
 * Throws a RangeError if the buffer is truncated or structurally invalid.
 */
export function unbundleFiles(buf: Uint8Array): BundleEntry[] | null {
  if (buf.length < 8) return null;
  // Check magic
  if (buf[0] !== 0x44 || buf[1] !== 0x43 || buf[2] !== 0x4d || buf[3] !== 0x4e) return null;

  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const fileCount = dv.getUint32(4, true);
  let off = 8;

  const files: BundleEntry[] = [];
  for (let i = 0; i < fileCount; i++) {
    if (off + 8 > buf.length) throw new RangeError(`Bundle truncated at file ${i} header`);
    const nameLen = dv.getUint16(off, true);
    off += 2;
    const mimeLen = dv.getUint16(off, true);
    off += 2;
    const fileSize = dv.getUint32(off, true);
    off += 4;

    if (off + nameLen + mimeLen + fileSize > buf.length) {
      throw new RangeError(`Bundle truncated at file ${i} body (need ${nameLen + mimeLen + fileSize} bytes at off=${off}, have ${buf.length - off})`);
    }

    const name = dec.decode(buf.subarray(off, off + nameLen));
    off += nameLen;
    const mime = dec.decode(buf.subarray(off, off + mimeLen));
    off += mimeLen;
    const data = buf.slice(off, off + fileSize); // slice = fresh copy, not view
    off += fileSize;

    files.push({ name, mime, data });
  }

  return files;
}

/**
 * Check whether a Uint8Array starts with the DCMN bundle magic bytes.
 * Use this to distinguish legacy raw payloads from Phase-4 bundles.
 */
export function isBundled(buf: Uint8Array): boolean {
  return (
    buf.length >= 4 &&
    buf[0] === 0x44 &&
    buf[1] === 0x43 &&
    buf[2] === 0x4d &&
    buf[3] === 0x4e
  );
}
