// QR decode worker: zxing-cpp compiled to WASM. (Safari has never shipped
// BarcodeDetector — WebKit bug 281848 — so WASM is the only portable way.)\n// One camera frame in flight per worker; the main thread drops frames when
// all workers are busy. Frames are disposable — the fountain doesn't care.
//
// Phase 3 — multi-QR grid:
// - The main thread now sends { id, buf, w, h, maxSymbols } per message.
// - maxSymbols = gridCols * gridCols (e.g. 4 for a 2×2 grid).
// - The worker calls readBarcodes with maxNumberOfSymbols=maxSymbols so
//   zxing-wasm finds ALL QR codes in the image in a single WASM call.
//   No custom grid-splitting is needed — the library supports this natively.
// - Response is { id, results: Uint8Array[], cellDecodeMs: number }:
//   - results: one entry per successfully decoded QR code (empty array if none)
//   - cellDecodeMs: total wall-clock time for the zxing scan call (telemetry)
//
// Backward compatibility: if maxSymbols is 1 (single-QR mode), behavior is
// identical to Phase 2 — only the postMessage shape changes (results[] instead
// of bytes).

import wasmUrl from "zxing-wasm/reader/zxing_reader.wasm?url";
import { prepareZXingModule, readBarcodes } from "zxing-wasm/reader";

prepareZXingModule({
  overrides: {
    locateFile: (path: string, prefix: string) =>
      path.endsWith(".wasm") ? wasmUrl : prefix + path,
  },
});

const ctx = self as unknown as {
  onmessage: ((e: MessageEvent) => void) | null;
  postMessage(msg: unknown, transfer?: Transferable[]): void;
};

ctx.onmessage = async (e: MessageEvent) => {
  const { id, buf, w, h, maxSymbols } = e.data as {
    id: number;
    buf: ArrayBuffer;
    w: number;
    h: number;
    maxSymbols: number;
  };
  const t0 = Date.now();
  try {
    const img = new ImageData(new Uint8ClampedArray(buf), w, h);
    const rawResults = await readBarcodes(img, {
      formats: ["QRCode"],
      maxNumberOfSymbols: maxSymbols,
    });
    const cellDecodeMs = Date.now() - t0;
    // DIAGNOSTIC: track raw find count vs. valid-filter count separately
    const rawCount = rawResults.length;          // how many symbols zxing located
    const results = rawResults
      .filter((x) => x.isValid && x.bytes.length > 0)
      .map((x) => x.bytes);
    const validCount = results.length;           // how many passed isValid+bytes check
    ctx.postMessage({ id, results, cellDecodeMs, rawCount, validCount });
  } catch {
    ctx.postMessage({ id, results: [], cellDecodeMs: Date.now() - t0, rawCount: 0, validCount: 0 });
  }
};

// warm the WASM so the first real frame doesn't pay instantiation
void readBarcodes(new ImageData(8, 8), { formats: ["QRCode"] })
  .catch(() => undefined)
  .then(() => ctx.postMessage({ id: -1, results: [], cellDecodeMs: 0 }));
