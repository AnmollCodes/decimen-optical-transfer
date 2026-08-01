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

import QRCode from "qrcode";
import { gzipCompress } from "../shared/compress";
import { LTEncoder } from "../shared/fountain";
import { HEADER_LEN, PROTO_VERSION, fnv1a, packFrame, type FrameHeader } from "../shared/protocol";

const MARGIN = 4; // quiet-zone modules
const LOOKAHEAD = 3;

const canvas = document.getElementById("qr") as HTMLCanvasElement;
const specs = document.getElementById("specs")!;
const cfgPayload = document.getElementById("cfg-payload") as HTMLSelectElement;
const cfgFps = document.getElementById("cfg-fps") as HTMLSelectElement;
const cfgBytes = document.getElementById("cfg-bytes") as HTMLSelectElement;
const cfgEcc = document.getElementById("cfg-ecc") as HTMLSelectElement;
const cfgSize = document.getElementById("cfg-size") as HTMLInputElement;

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

async function main() {
  for (const el of [cfgPayload, cfgFps, cfgBytes, cfgEcc, cfgSize]) {
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

  // Compress before fountain encoding. The fountain layer transports the
  // compressed bytes; FNV is computed over those bytes so the receiver can
  // verify optical-channel integrity independently of decompression.
  const payload = await gzipCompress(rawPayload);

  const sessionId = (Math.floor(Math.random() * 0xffff) + 1) & 0xffff;
  const blockLen = frameBytes - HEADER_LEN;
  const encoder = new LTEncoder(payload, blockLen, sessionId);
  const header: FrameHeader = {
    version: PROTO_VERSION,
    sessionId,
    seq: 0,
    k: encoder.k,
    blockLen,
    totalLen: payload.length,     // compressed length
    payloadFnv: fnv1a(payload),   // FNV of compressed bytes
  };

  let version: number | undefined; // locked after the first frame
  let modules = 0;
  let scale = 1;
  const staging = document.createElement("canvas");
  const queue: ImageData[] = [];
  let nextSeq = 0;

  const sizeCanvas = () => {
    const dpr = window.devicePixelRatio || 1;
    const total = modules + 2 * MARGIN;
    const cssBudget = Math.min(0.9 * Math.min(window.innerWidth, window.innerHeight), displayPx);
    scale = Math.max(1, Math.floor((cssBudget * dpr) / total));
    staging.width = total;
    staging.height = total;
    canvas.width = total * scale;
    canvas.height = total * scale;
    canvas.style.width = `${(total * scale) / dpr}px`;
    canvas.style.height = `${(total * scale) / dpr}px`;
  };

  const makeFrame = (): ImageData => {
    const bytes = packFrame({ ...header, seq: nextSeq }, encoder.encode(nextSeq));
    nextSeq++;
    const qr = QRCode.create([{ data: bytes, mode: "byte" } as unknown as QRCode.QRCodeSegment], {
      errorCorrectionLevel: ecc,
      version,
      maskPattern: 4,
    });
    if (version === undefined) {
      version = qr.version;
      modules = qr.modules.size;
      sizeCanvas();
      specs.textContent =
        `${txFps} FPS · ${frameBytes} bytes per frame · V${version} · ECC ${ecc} · ` +
        `${Math.round(rawPayload.length / 1024)} KB raw → ${Math.round(payload.length / 1024)} KB compressed · K=${encoder.k}`;
    }
    const size = qr.modules.size;
    const data = qr.modules.data;
    const total = size + 2 * MARGIN;
    const img = new ImageData(total, total);
    const px = new Uint32Array(img.data.buffer);
    px.fill(0xffffffff);
    for (let y = 0; y < size; y++) {
      const row = (y + MARGIN) * total + MARGIN;
      const src = y * size;
      for (let x = 0; x < size; x++) {
        if (data[src + x]) px[row + x] = 0xff000000;
      }
    }
    return img;
  };

  const pump = () => {
    if (gen !== generation) return; // superseded by a settings change
    try {
      while (queue.length < LOOKAHEAD) queue.push(makeFrame());
    } catch (err) {
      // e.g. frame bytes over capacity for the chosen ECC level
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
    staging.getContext("2d")!.putImageData(img, 0, 0);
    const ctx = canvas.getContext("2d")!;
    ctx.imageSmoothingEnabled = false;
    ctx.drawImage(staging, 0, 0, canvas.width, canvas.height);
    nextAt += interval;
    if (now - nextAt > 3 * interval) nextAt = now + interval; // fell behind — don't burst
  };
  requestAnimationFrame(tick);
}

void main();
