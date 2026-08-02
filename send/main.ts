// Sender: turn a file into an endless fountain-coded QR stream.
//
// Tuning notes from the experiments this PoC is distilled from:
// - Frame payload sets the QR version; denser wins on goodput as long as the
//   receiver can still decode it. 1465 bytes ≈ V27 is a safe middle ground
//   for arbitrary monitors; 2953 (V40) is the ceiling and works phone-to-
//   phone at close range.
// - The mask pattern is pinned (any declared mask is valid to a decoder);
//   this skips the spec's 8-way mask evaluation and speeds generation ~4×.
// - Displays need each frame shown for ≥2 refresh cycles or captures catch
//   the transition; 24 fps on a 60 Hz screen is comfortable.
// - Error correction stays at L by default: the fountain layer already
//   handles erasures, and a frame is either decoded whole or discarded.
//
// Phase 2 — encryption:
// - Key delivery: a separate "key QR" is shown before the main stream.
//   The receiver scans it once to obtain the AES-256-GCM session key.
//   The key is encoded as "K:" + hex(32 raw key bytes) — 66 chars total,
//   fits comfortably in a V3/ECC-M QR code. The "K:" prefix lets the
//   receiver distinguish it from fountain-coded data frames.
// - IV: 12 bytes prepended to the ciphertext blob; generated fresh per session.
// - FNV hash and totalLen are over the encrypted blob (IV + ciphertext + tag).
//
// Phase 3 — multi-QR grid:
// - A "grid density" setting controls how many QR codes are rendered per
//   displayed frame (1, 4, 9, or 16 — i.e. 1×1, 2×2, 3×3, 4×4).
// - Each grid cell carries a DIFFERENT fountain frame (different seq, different
//   encoded block). The receiver's zxing worker decodes all cells in one pass
//   using maxNumberOfSymbols = gridCells, feeding each into the same LTDecoder.
// - The key QR is still rendered as a single separate QR (not part of the grid).
// - Throughput scales by up to gridCells× per displayed frame — actual gain
//   depends on whether the receiver's worker pool can decode them fast enough.
//   This must be verified with a real device test, not assumed from grid math.

import QRCode from "qrcode";
import { gzipCompress } from "../shared/compress";
import { aesGcmEncrypt, exportKeyBytes, generateAesKey } from "../shared/crypto";
import { LTEncoder } from "../shared/fountain";
import { HEADER_LEN, PROTO_VERSION, fnv1a, packFrame, type FrameHeader } from "../shared/protocol";

const MARGIN = 4;    // quiet-zone modules per cell (QR spec minimum)
// CELL_GAP: explicit white-pixel gap between adjacent cells in the grid,
// SEPARATE from each cell's MARGIN. Adjacent cells' quiet zones are not
// enough separation for zxing's finder-pattern detector — it needs physical
// blank space between symbol boundaries. 8px at scale=1 (scales up with the
// QR module scale, so at a typical scale=4 this becomes 32 display pixels).
const CELL_GAP = 8;
const LOOKAHEAD = 3;

const canvas = document.getElementById("qr") as HTMLCanvasElement;
const specs = document.getElementById("specs")!;
const cfgPayload = document.getElementById("cfg-payload") as HTMLSelectElement;
const cfgFps = document.getElementById("cfg-fps") as HTMLSelectElement;
const cfgBytes = document.getElementById("cfg-bytes") as HTMLSelectElement;
const cfgEcc = document.getElementById("cfg-ecc") as HTMLSelectElement;
const cfgSize = document.getElementById("cfg-size") as HTMLInputElement;
// Grid density control — added in Phase 3. Falls back to 1 if not found (for tests).
const cfgGrid = document.getElementById("cfg-grid") as HTMLSelectElement | null;

// Key-QR overlay — created dynamically so the HTML doesn't need modification.
const keyStage = document.createElement("div");
keyStage.id = "key-stage";
keyStage.style.cssText =
  "display:none;text-align:center;margin:16px 0;padding:12px;background:#1a1a2e;" +
  "border:2px solid #4ecca3;border-radius:8px;";
const keyCanvas = document.createElement("canvas");
const keyLabel = document.createElement("div");
keyLabel.style.cssText = "color:#4ecca3;font-size:14px;margin-top:8px;font-family:monospace;";
keyLabel.textContent = "① Scan this key QR on the receiver first, then the transfer begins.";
keyStage.append(keyCanvas, keyLabel);
canvas.parentElement!.insertAdjacentElement("beforebegin", keyStage);

const payloadCache = new Map<string, Uint8Array>();
let generation = 0; // bumped on every restart; stale loops see it and die

async function loadPayload(url: string): Promise<Uint8Array | null> {
  const hit = payloadCache.get(url);
  if (hit) return hit;
  const res = await fetch(url);
  if (!res.ok) return null;
  const bytes = new Uint8Array(await res.arrayBuffer());
  payloadCache.set(url, bytes);
  return bytes;
}

/** Render a string value into a canvas element as a QR code. */
async function renderKeyQr(text: string): Promise<void> {
  await QRCode.toCanvas(keyCanvas, text, {
    errorCorrectionLevel: "M",
    margin: 2,
    width: 200,
  });
}

async function main() {
  const controls = [cfgPayload, cfgFps, cfgBytes, cfgEcc, cfgSize];
  if (cfgGrid) controls.push(cfgGrid);
  for (const el of controls) {
    el.addEventListener("change", () => void startStream());
  }
  await startStream();
  try {
    await (navigator as Navigator & { wakeLock?: { request(t: "screen"): Promise<unknown> } })
      .wakeLock?.request("screen");
  } catch {
    /* fine without it */
  }
}

async function startStream() {
  const gen = ++generation;
  const rawPayload = await loadPayload(cfgPayload.value);
  if (!rawPayload) {
    specs.textContent = `✗ couldn't load ${cfgPayload.value}`;
    return;
  }
  if (gen !== generation) return; // superseded while fetching
  const txFps = Number(cfgFps.value);
  const frameBytes = Number(cfgBytes.value);
  const ecc = cfgEcc.value as "L" | "M" | "Q" | "H";
  const displayPx = Number(cfgSize.value);
  // gridCells: total cells per displayed frame (1, 4, 9, or 16).
  // gridCols: number of columns (and rows) — sqrt of gridCells.
  const gridCells = cfgGrid ? Number(cfgGrid.value) : 1;
  const gridCols = Math.round(Math.sqrt(gridCells));

  // Step 1: Compress.
  const compressed = await gzipCompress(rawPayload);

  // Step 2: Generate session key and render the key QR for the receiver to scan.
  // The key QR is always a single QR code — it is NOT part of the grid.
  const sessionKey = await generateAesKey();
  const keyBytes = await exportKeyBytes(sessionKey);
  const keyHex = Array.from(keyBytes).map((b) => b.toString(16).padStart(2, "0")).join("");
  keyStage.style.display = "block";
  await renderKeyQr(`K:${keyHex}`);

  // Step 3: Encrypt (compress → encrypt → fountain).
  const payload = await aesGcmEncrypt(sessionKey, compressed);

  if (gen !== generation) return;

  const sessionId = (Math.floor(Math.random() * 0xffff) + 1) & 0xffff;
  const blockLen = frameBytes - HEADER_LEN;
  const encoder = new LTEncoder(payload, blockLen, sessionId);
  const baseHeader: FrameHeader = {
    version: PROTO_VERSION,
    sessionId,
    seq: 0,
    k: encoder.k,
    blockLen,
    totalLen: payload.length,
    payloadFnv: fnv1a(payload),
  };

  let qrVersion: number | undefined; // locked after the first QR is generated
  let cellModules = 0;               // module count per cell (including margin)
  const staging = document.createElement("canvas");
  const queue: ImageData[] = [];
  let nextSeq = 0;

  /** Size the output canvas to fit a gridCols×gridCols grid of cells with
   * CELL_GAP white pixels of separation between adjacent cells (in addition
   * to each cell's own MARGIN quiet zone). Returns the computed values so
   * makeGridFrame can use them without re-computing.
   */
  let _cellPx = 0; // set once by sizeCanvas, read by makeGridFrame
  let _gapPx = 0;
  const sizeCanvas = () => {
    const dpr = window.devicePixelRatio || 1;
    const cellTotal = cellModules;
    const budget = Math.min(0.9 * Math.min(window.innerWidth, window.innerHeight), displayPx);
    // scale: how many physical pixels per QR module
    // Budget must fit gridCols cells + (gridCols-1) gaps.
    // We solve for scale first (ignore gaps for now), then derive gap in same units.
    const scale = Math.max(1, Math.floor((budget * dpr) / (cellTotal * gridCols + CELL_GAP * (gridCols - 1))));
    _cellPx = cellTotal * scale;
    // CELL_GAP is in screen-pixel units at scale=1; multiply by scale so the
    // gap is proportionally the same physical size regardless of display scale.
    _gapPx = CELL_GAP * scale;
    const gridPx = _cellPx * gridCols + _gapPx * (gridCols - 1);
    staging.width = gridPx;
    staging.height = gridPx;
    canvas.width = gridPx;
    canvas.height = gridPx;
    canvas.style.width = `${gridPx / dpr}px`;
    canvas.style.height = `${gridPx / dpr}px`;
  };

  /**
   * Render one QR code cell for fountain frame at seq `s` into ImageData.
   * Returns the ImageData for the cell AND the module size (for first-time sizing).
   */
  const makeCell = (s: number): { img: ImageData; modules: number } => {
    const bytes = packFrame({ ...baseHeader, seq: s }, encoder.encode(s));
    const qr = QRCode.create([{ data: bytes, mode: "byte" } as unknown as QRCode.QRCodeSegment], {
      errorCorrectionLevel: ecc,
      version: qrVersion,
      maskPattern: 4,
    });
    qrVersion = qr.version;
    const size = qr.modules.size;
    const total = size + 2 * MARGIN;
    const img = new ImageData(total, total);
    const px = new Uint32Array(img.data.buffer);
    px.fill(0xffffffff);
    const data = qr.modules.data;
    for (let y = 0; y < size; y++) {
      const row = (y + MARGIN) * total + MARGIN;
      const src = y * size;
      for (let x = 0; x < size; x++) {
        if (data[src + x]) px[row + x] = 0xff000000;
      }
    }
    return { img, modules: total };
  };

  /**
   * Build one grid ImageData: gridCols×gridCols cells, each a different fountain frame.
   * Advances nextSeq by gridCells.
   */
  const makeGridFrame = (): ImageData => {
    const cells: ImageData[] = [];
    for (let i = 0; i < gridCells; i++) {
      const { img, modules } = makeCell(nextSeq++);
      if (cellModules === 0) {
        // First cell ever: lock cell size and resize the output canvas.
        cellModules = modules;
        sizeCanvas();
        specs.textContent =
          `${txFps} FPS · ${frameBytes} B/frame · V${qrVersion!} · ECC ${ecc} · ` +
          `grid ${gridCols}×${gridCols} (${gridCells} cells/frame, gap=${CELL_GAP}px) · ` +
          `${Math.round(rawPayload.length / 1024)} KB raw → ` +
          `${Math.round(compressed.length / 1024)} KB compressed → ` +
          `${Math.round(payload.length / 1024)} KB encrypted · K=${encoder.k}`;
      }
      cells.push(img);
    }

    // Composite cells into the grid with CELL_GAP white separation between them.
    // Each cell is placed at: x = col * (cellPx + gapPx), y = row * (cellPx + gapPx).
    // The staging canvas is pre-filled white, so gaps are automatically white space.
    const ctx2d = staging.getContext("2d")!;
    ctx2d.fillStyle = "#fff";
    ctx2d.fillRect(0, 0, staging.width, staging.height);
    for (let i = 0; i < cells.length; i++) {
      const col = i % gridCols;
      const row = Math.floor(i / gridCols);
      const x = col * (_cellPx + _gapPx);
      const y = row * (_cellPx + _gapPx);
      // Draw via temporary canvas (putImageData doesn't support scaling).
      const tmp = document.createElement("canvas");
      tmp.width = cells[i]!.width;
      tmp.height = cells[i]!.height;
      tmp.getContext("2d")!.putImageData(cells[i]!, 0, 0);
      ctx2d.drawImage(tmp, x, y, _cellPx, _cellPx);
    }
    return ctx2d.getImageData(0, 0, staging.width, staging.height);
  };

  const pump = () => {
    if (gen !== generation) return;
    try {
      while (queue.length < LOOKAHEAD) queue.push(makeGridFrame());
    } catch (err) {
      specs.textContent = `✗ ${err instanceof Error ? err.message : String(err)}`;
      return;
    }
    setTimeout(pump, 0);
  };
  pump();

  const interval = 1000 / txFps;
  let nextAt = performance.now();
  const tick = (now: number) => {
    if (gen !== generation) return;
    requestAnimationFrame(tick);
    if (now < nextAt) return;
    const img = queue.shift();
    if (!img) {
      nextAt = now + interval;
      return;
    }
    canvas.getContext("2d")!.putImageData(img, 0, 0);
    nextAt += interval;
    if (now - nextAt > 3 * interval) nextAt = now + interval;
  };
  requestAnimationFrame(tick);
}

void main();
