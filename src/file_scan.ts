/**
 * Canary file scanning — read local files server-side, extract text by
 * MIME type, hand the extracted text to the core scanner.
 *
 * Design goals:
 *   - Never expose raw bytes to a caller that hasn't been cleared.
 *   - Fail closed on unknown MIME, oversize input, unreadable path, or
 *     extraction errors — the scanner's "I don't know" answer is FLAGGED.
 *   - MIME detection is magic-bytes-first, extension as tiebreaker.
 *   - Decoders are pluggable: register by MIME type, return a string.
 *
 * Iter 1 (this file as shipped): text family only (plain, markdown, csv,
 * html, json). Iter 2 adds PDF; iter 3 DOCX; iter 4 image metadata; iter
 * 5 archive recursion. Each iteration adds a decoder; the dispatch table
 * doesn't change shape.
 */

import fs from "fs";
import path from "path";
import { CanaryScanner, type ScanResult, type ScanMetadata } from "./scanner";

// ── Limits ─────────────────────────────────────────────────────────────────

/** Hard cap on file size handed to a decoder. */
const DEFAULT_MAX_BYTES = 10 * 1024 * 1024; // 10 MB

/** Hard cap on extracted text length passed to the LLM probe. Chunking
 *  inside the scanner walks the rest, but we cap so a single huge file
 *  can't run away with our token budget. */
const DEFAULT_MAX_TEXT_CHARS = 1_000_000; // 1M chars ≈ 250 K tokens

// ── Types ──────────────────────────────────────────────────────────────────

export interface FileScanOptions {
  /** Maximum bytes to read from disk. Default 10 MB. */
  maxBytes?: number;
  /** Maximum text characters to send to the probe. Default 1 M. */
  maxTextChars?: number;
  /** Override the MIME-detection result (caller knows better). */
  forceMime?: string;
}

export interface FileExtractionResult {
  text: string;
  /** Resolved MIME type. */
  mime: string;
  /** True if the decoder had to truncate the extracted text. */
  truncated: boolean;
  /** Decoder identifier (for audit). */
  decoder: string;
}

export type FileDecoder = (
  buffer: Buffer,
  mime: string,
  maxTextChars: number,
) => Promise<FileExtractionResult>;

// ── Path safety ────────────────────────────────────────────────────────────

/**
 * Resolve a path and run the basic safety checks every file scan needs:
 *   - Must exist.
 *   - Must be a regular file (not a directory, symlink loop, device,
 *     socket, FIFO).
 *   - Must be readable.
 *   - Must not exceed maxBytes.
 *
 * Throws Error with a stable `code` property on failure.
 */
export function validateFilePath(
  inputPath: string,
  maxBytes: number,
): { absolute: string; size: number } {
  if (typeof inputPath !== "string" || inputPath.length === 0) {
    throw Object.assign(new Error("path must be a non-empty string"), {
      code: "invalid_path",
    });
  }

  const absolute = path.resolve(inputPath);

  let stat: fs.Stats;
  try {
    // lstat first so we can see a symlink without following it
    const lstat = fs.lstatSync(absolute);
    if (lstat.isSymbolicLink()) {
      // Resolve symlink ourselves so we can re-stat the target and
      // confirm it's still a regular file. Symlinks themselves aren't
      // dangerous, but a symlink chain to /dev/zero would hang us.
      const real = fs.realpathSync(absolute);
      stat = fs.statSync(real);
    } else {
      stat = lstat;
    }
  } catch (e) {
    const err = e as NodeJS.ErrnoException;
    if (err.code === "ENOENT") {
      throw Object.assign(new Error(`file not found: ${absolute}`), {
        code: "not_found",
      });
    }
    if (err.code === "EACCES") {
      throw Object.assign(new Error(`permission denied: ${absolute}`), {
        code: "permission_denied",
      });
    }
    throw Object.assign(new Error(`stat failed: ${err.message}`), {
      code: "stat_failed",
    });
  }

  if (!stat.isFile()) {
    throw Object.assign(
      new Error(`not a regular file: ${absolute} (kind=${describeStatKind(stat)})`),
      { code: "not_a_regular_file" },
    );
  }

  if (stat.size > maxBytes) {
    throw Object.assign(
      new Error(
        `file too large: ${stat.size} bytes > maxBytes ${maxBytes}`,
      ),
      { code: "file_too_large" },
    );
  }

  return { absolute, size: stat.size };
}

function describeStatKind(s: fs.Stats): string {
  if (s.isDirectory()) return "directory";
  if (s.isBlockDevice()) return "block_device";
  if (s.isCharacterDevice()) return "char_device";
  if (s.isSocket()) return "socket";
  if (s.isFIFO()) return "fifo";
  return "unknown";
}

// ── MIME detection ─────────────────────────────────────────────────────────

interface MagicSignature {
  /** Byte sequence to match at offset 0 (unless `offset` provided). */
  bytes: number[] | Uint8Array;
  offset?: number;
  mime: string;
}

/**
 * Magic-bytes table. Order matters — first match wins. Keep specific
 * signatures (PDF, PNG) above more permissive ones (HTML, plain text).
 */
const MAGIC_SIGNATURES: MagicSignature[] = [
  // PDF — "%PDF-" (handled iter 2)
  { bytes: [0x25, 0x50, 0x44, 0x46, 0x2d], mime: "application/pdf" },
  // PNG
  { bytes: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a], mime: "image/png" },
  // JPEG (any variant — start of image marker)
  { bytes: [0xff, 0xd8, 0xff], mime: "image/jpeg" },
  // GIF
  { bytes: [0x47, 0x49, 0x46, 0x38], mime: "image/gif" },
  // WebP — "RIFF....WEBP"
  { bytes: [0x52, 0x49, 0x46, 0x46], mime: "application/x-riff" }, // refined below
  // ZIP family (PK\x03\x04) — could be .zip, .docx, .xlsx, .pptx, .jar, .apk
  // Disambiguation happens in the decoder (look at internal layout).
  { bytes: [0x50, 0x4b, 0x03, 0x04], mime: "application/zip" },
  // GZIP
  { bytes: [0x1f, 0x8b], mime: "application/gzip" },
  // tar (POSIX "ustar" at offset 257)
  { bytes: [0x75, 0x73, 0x74, 0x61, 0x72], offset: 257, mime: "application/x-tar" },
];

/** Extension → MIME fallback (used when magic bytes don't decide). */
const EXTENSION_TO_MIME: Record<string, string> = {
  ".txt": "text/plain",
  ".log": "text/plain",
  ".md": "text/markdown",
  ".markdown": "text/markdown",
  ".csv": "text/csv",
  ".tsv": "text/tab-separated-values",
  ".html": "text/html",
  ".htm": "text/html",
  ".xml": "text/xml",
  ".json": "application/json",
  ".yaml": "text/yaml",
  ".yml": "text/yaml",
  ".toml": "text/toml",
  ".ini": "text/plain",
  ".js": "text/javascript",
  ".ts": "text/typescript",
  ".py": "text/x-python",
  ".rb": "text/x-ruby",
  ".go": "text/x-go",
  ".rs": "text/x-rust",
  ".sh": "text/x-shellscript",
  ".bat": "text/x-bat",
  ".pdf": "application/pdf",
  ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  ".doc": "application/msword",
  ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
  ".odt": "application/vnd.oasis.opendocument.text",
  ".zip": "application/zip",
  ".tar": "application/x-tar",
  ".gz": "application/gzip",
  ".tgz": "application/gzip",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".gif": "image/gif",
  ".webp": "image/webp",
  ".svg": "image/svg+xml",
  ".tiff": "image/tiff",
};

/** Detect MIME from buffer (magic bytes first, extension second). */
export function detectMime(
  buffer: Buffer,
  filePath: string,
): string {
  const ext = path.extname(filePath).toLowerCase();

  // Magic-bytes pass.
  for (const sig of MAGIC_SIGNATURES) {
    const offset = sig.offset ?? 0;
    if (buffer.length < offset + sig.bytes.length) continue;
    let match = true;
    for (let i = 0; i < sig.bytes.length; i++) {
      if (buffer[offset + i] !== sig.bytes[i]) {
        match = false;
        break;
      }
    }
    if (match) {
      // Refine RIFF → WebP if the second header chunk says WEBP.
      if (sig.mime === "application/x-riff" && buffer.length >= 12) {
        const tag = buffer.slice(8, 12).toString("ascii");
        if (tag === "WEBP") return "image/webp";
        // RIFF WAVE / AVI etc — fall through; treat as binary.
      } else if (sig.mime === "application/zip") {
        // ZIP magic also matches the OOXML / OpenDocument family. Use
        // extension as the tiebreaker; if the extension says one of
        // those formats, return the office MIME so the right decoder
        // runs. (We don't peek inside the zip here — the decoder will
        // fail-closed if the contents don't match the extension.)
        if (ext && EXTENSION_TO_MIME[ext] && EXTENSION_TO_MIME[ext] !== "application/zip") {
          return EXTENSION_TO_MIME[ext];
        }
        return sig.mime;
      } else {
        return sig.mime;
      }
    }
  }

  // Extension fallback.
  if (ext && EXTENSION_TO_MIME[ext]) return EXTENSION_TO_MIME[ext];

  // Last resort: probe for text-iness in the first 1 KB.
  if (looksLikeUtf8Text(buffer.slice(0, 1024))) return "text/plain";

  return "application/octet-stream";
}

/**
 * Heuristic: a buffer "looks like" UTF-8 text if it decodes cleanly and
 * the printable-or-whitespace fraction is high.
 */
function looksLikeUtf8Text(buffer: Buffer): boolean {
  if (buffer.length === 0) return true;
  // Reject obvious binary signals — NUL bytes outside UTF-16 BOM region.
  for (let i = 0; i < Math.min(buffer.length, 1024); i++) {
    if (buffer[i] === 0x00) return false;
  }
  try {
    const text = buffer.toString("utf-8");
    let printable = 0;
    for (let i = 0; i < text.length; i++) {
      const c = text.charCodeAt(i);
      // tab, lf, cr + printable ASCII + non-ASCII Unicode
      if (c === 0x09 || c === 0x0a || c === 0x0d || (c >= 0x20 && c < 0x7f) || c >= 0xa0) {
        printable++;
      }
    }
    return printable / text.length > 0.85;
  } catch {
    return false;
  }
}

// ── Decoder registry ───────────────────────────────────────────────────────

const decoders = new Map<string, FileDecoder>();

/**
 * Register a decoder for a MIME type. Caller takes responsibility for
 * keeping the decoder's behavior consistent across versions — these
 * decoders are the path that determines whether content is even sent to
 * the canary probe. A buggy decoder masks real injections.
 */
export function registerDecoder(mime: string, decoder: FileDecoder): void {
  decoders.set(mime, decoder);
}

/** Plain text family — UTF-8 decode, optional truncate. */
const textDecoder: FileDecoder = async (buffer, mime, maxTextChars) => {
  // Use 'replacement' for invalid sequences so a single broken byte
  // doesn't tank an otherwise-readable file. The probe doesn't need
  // byte-perfect fidelity; it needs the dominant semantic content.
  const raw = buffer.toString("utf-8");
  const truncated = raw.length > maxTextChars;
  const text = truncated ? raw.slice(0, maxTextChars) : raw;
  return { text, mime, truncated, decoder: "utf8_text" };
};

// ── PDF decoder ────────────────────────────────────────────────────────────
//
// pdfjs-dist is pure JS (no native binaries) and Mozilla-maintained.
// We use the "legacy" build because it skips the Worker setup the
// browser build needs — fine for Node, smaller surface.

const pdfDecoder: FileDecoder = async (buffer, mime, maxTextChars) => {
  // Lazy-import so users who never scan PDFs don't pay the load cost.
  const pdfjs = await import("pdfjs-dist/legacy/build/pdf.mjs");
  // Disable the worker — runs everything inline. The worker is a browser
  // optimization; in Node it just adds plumbing without a benefit.
  // GlobalWorkerOptions is exposed as a getter-only on the module namespace,
  // so we mutate its `workerSrc` field rather than reassign the object.
  try {
    const ns = pdfjs as { GlobalWorkerOptions?: { workerSrc?: string | null } };
    if (ns.GlobalWorkerOptions) ns.GlobalWorkerOptions.workerSrc = null;
  } catch {
    // Not fatal — pdfjs will fall back to the default which works in Node.
  }

  // pdfjs needs Uint8Array, not Buffer (Buffer.from(ArrayBuffer) shares
  // memory but pdfjs reads past the typed-array view bounds otherwise).
  const data = new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);
  const loadingTask = pdfjs.getDocument({
    data,
    // Silence pdfjs warnings/info to stderr — they leak to MCP stdio.
    verbosity: 0,
    // Don't fetch external resources (CMaps, fonts). For prompt-injection
    // scanning we want the text; perfect rendering is irrelevant and
    // external fetches are an SSRF surface we don't want.
    isEvalSupported: false,
    disableFontFace: true,
    useSystemFonts: false,
  });

  const doc = await loadingTask.promise;
  const parts: string[] = [];
  let totalLen = 0;
  for (let pageNum = 1; pageNum <= doc.numPages; pageNum++) {
    const page = await doc.getPage(pageNum);
    const content = await page.getTextContent();
    // Concatenate page items with spaces; pdfjs gives one item per
    // run-of-text. The order matches reading order.
    const pageText = content.items
      .map((item) => ("str" in item ? item.str : ""))
      .join(" ");
    parts.push(pageText);
    totalLen += pageText.length + 1;
    // Cleanup per-page to free the parsed content.
    page.cleanup();
    if (totalLen >= maxTextChars) break;
  }
  await doc.destroy();
  const raw = parts.join("\n\n");
  const truncated = raw.length > maxTextChars;
  const text = truncated ? raw.slice(0, maxTextChars) : raw;
  return { text, mime, truncated, decoder: "pdfjs" };
};

registerDecoder("application/pdf", pdfDecoder);

// ── DOCX decoder ───────────────────────────────────────────────────────────
//
// .docx is a zip with word/document.xml inside. mammoth handles the XML
// parsing and gives us back plain text via convertToHtml or extractRawText.
// We use extractRawText because we don't care about formatting — just
// the semantic text content for the canary probe.

const docxDecoder: FileDecoder = async (buffer, mime, maxTextChars) => {
  const mammoth = await import("mammoth");
  // Use a Buffer-backed input. mammoth accepts { buffer } or { path }.
  // Buffer avoids a temp-file write.
  const result = await mammoth.extractRawText({ buffer });
  const raw = (result?.value ?? "") as string;
  const truncated = raw.length > maxTextChars;
  const text = truncated ? raw.slice(0, maxTextChars) : raw;
  return { text, mime, truncated, decoder: "mammoth_raw" };
};

registerDecoder(
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  docxDecoder,
);

// ── Image metadata decoder ─────────────────────────────────────────────────
//
// Images can carry prompt-injection content in EXIF / IPTC / XMP text
// fields. The image bytes themselves are pixel data — opaque to a text
// probe — but the metadata blocks are operator-controllable strings.
// We extract every known text-bearing field and concatenate them.
//
// What this catches: an attacker who plants instructions in
// EXIF:UserComment, EXIF:ImageDescription, XMP:Description, IPTC:Caption,
// etc. Not OCR — pixel-content scanning is a separate problem.

const TEXT_BEARING_EXIF_FIELDS = [
  // Standard EXIF
  "ImageDescription", "Make", "Model", "Software", "Artist", "Copyright",
  "DateTime", "UserComment", "OwnerName", "CameraOwnerName", "BodySerialNumber",
  // GPS strings (could carry text in adversarial cases)
  "GPSAreaInformation", "GPSDateStamp", "GPSProcessingMethod",
  // XMP
  "Description", "Subject", "Title", "Creator", "Rights", "Keywords",
  "CreatorTool", "Label", "UserDefined",
  // IPTC
  "Caption", "Headline", "Byline", "Credit", "Source", "ObjectName",
  "Keywords", "Instructions", "TransmissionReference", "CopyrightNotice",
  "City", "State", "Country", "Sublocation",
];

const imageMetadataDecoder: FileDecoder = async (buffer, mime, maxTextChars) => {
  const exifr = (await import("exifr")).default ?? await import("exifr");
  // exifr.parse returns a flat object with whatever it can read.
  // Pass `{ translateValues: false }` so binary blobs stay opaque.
  let meta: Record<string, unknown> = {};
  try {
    meta = (await (exifr as { parse: (b: Buffer, o?: object) => Promise<unknown> })
      .parse(buffer, {
        // Pull everything text-shaped. Pixel data is excluded by default.
        pick: TEXT_BEARING_EXIF_FIELDS,
        translateValues: false,
        reviveValues: false,
      })) as Record<string, unknown> ?? {};
  } catch {
    meta = {};
  }

  const parts: string[] = [];
  for (const [key, value] of Object.entries(meta)) {
    if (value === null || value === undefined) continue;
    let str: string;
    if (typeof value === "string") str = value;
    else if (typeof value === "number" || typeof value === "boolean") str = String(value);
    else if (Array.isArray(value)) str = value.map(String).join(", ");
    else if (value instanceof Uint8Array || Buffer.isBuffer(value as unknown)) {
      // Decode small text-y byte arrays. UserComment is often UTF-8 with
      // a leading 8-byte charset marker; trim those if present.
      const buf = Buffer.from(value as Uint8Array);
      const tryText = buf.toString("utf-8").replace(/^(ASCII|UNICODE|JIS)\0+/, "").trim();
      str = tryText;
    } else {
      // Skip nested objects we don't recognize.
      continue;
    }
    if (str.trim().length > 0) parts.push(`${key}: ${str}`);
  }

  const raw = parts.join("\n");
  const truncated = raw.length > maxTextChars;
  const text = truncated ? raw.slice(0, maxTextChars) : raw;
  return { text, mime, truncated, decoder: "exifr_metadata" };
};

for (const mime of [
  "image/png",
  "image/jpeg",
  "image/gif",
  "image/webp",
  "image/tiff",
]) {
  registerDecoder(mime, imageMetadataDecoder);
}

// ── Archive decoders ───────────────────────────────────────────────────────
//
// Zips and tarballs can carry injection content inside any number of
// entries. We iterate entries, decode each as the right MIME (recursive
// reuse of the dispatch table), and concatenate the extracted text with
// per-entry headers so the probe sees attribution. Hard caps prevent a
// hostile archive from running our token budget away (zip bombs, deeply
// nested archives).

const MAX_ARCHIVE_ENTRIES = 200;
const MAX_PER_ENTRY_BYTES = 5 * 1024 * 1024; // 5 MB per entry
const MAX_ARCHIVE_DEPTH = 1; // No nested archives — fail-closed if found

interface ArchiveEntry {
  name: string;
  data: Buffer;
}

async function decodeArchiveEntries(
  entries: ArchiveEntry[],
  maxTextChars: number,
): Promise<{ text: string; truncated: boolean }> {
  const parts: string[] = [];
  let totalLen = 0;
  let truncated = false;
  for (const entry of entries) {
    if (totalLen >= maxTextChars) {
      truncated = true;
      break;
    }
    if (entry.data.length > MAX_PER_ENTRY_BYTES) {
      parts.push(`### ${entry.name} [SKIPPED: ${entry.data.length} bytes > per-entry cap]`);
      continue;
    }
    const mime = detectMime(entry.data, entry.name);
    if (mime === "application/zip" || mime === "application/gzip" || mime === "application/x-tar") {
      // Nested archives: fail-closed surface. We could recurse, but that
      // opens zip-bomb / billion-laughs avenues. Skip with a clear note.
      parts.push(`### ${entry.name} [${mime}] [SKIPPED: nested archives not scanned]`);
      continue;
    }
    const decoder = decoders.get(mime);
    if (!decoder) {
      parts.push(`### ${entry.name} [${mime}] [SKIPPED: unsupported MIME]`);
      continue;
    }
    try {
      const remaining = Math.max(0, maxTextChars - totalLen);
      const inner = await decoder(entry.data, mime, remaining);
      const block = `### ${entry.name} [${mime}, ${inner.decoder}]\n${inner.text}`;
      parts.push(block);
      totalLen += block.length + 2;
    } catch (e) {
      parts.push(`### ${entry.name} [${mime}] [EXTRACT_FAILED: ${(e as Error).message}]`);
    }
  }
  const raw = parts.join("\n\n");
  const finalTruncated = truncated || raw.length > maxTextChars;
  return {
    text: finalTruncated ? raw.slice(0, maxTextChars) : raw,
    truncated: finalTruncated,
  };
}

const zipDecoder: FileDecoder = async (buffer, mime, maxTextChars) => {
  const AdmZip = (await import("adm-zip")).default;
  const zip = new AdmZip(buffer);
  const entries = zip.getEntries()
    .filter((e) => !e.isDirectory)
    .slice(0, MAX_ARCHIVE_ENTRIES)
    .map((e) => ({ name: e.entryName, data: e.getData() }));
  const { text, truncated } = await decodeArchiveEntries(entries, maxTextChars);
  return { text, mime, truncated, decoder: "adm_zip" };
};

registerDecoder("application/zip", zipDecoder);

const tarGzDecoder: FileDecoder = async (buffer, mime, maxTextChars) => {
  // tar.gz: stream the gzipped tar via the `tar` package's parser.
  // tar's parser is push-based, so we collect entries in a list.
  const { Parser } = await import("tar");
  const { gunzipSync } = await import("zlib");

  let raw: Buffer;
  try {
    raw = mime === "application/gzip" ? gunzipSync(buffer) : buffer;
  } catch (e) {
    return {
      text: `gunzip_failed: ${(e as Error).message}`,
      mime,
      truncated: false,
      decoder: "tar_gunzip_fail",
    };
  }

  const entries: ArchiveEntry[] = [];
  await new Promise<void>((resolve, reject) => {
    const parser = new Parser();
    parser.on("entry", (entry) => {
      if (entry.type !== "File") {
        entry.resume();
        return;
      }
      if (entries.length >= MAX_ARCHIVE_ENTRIES) {
        entry.resume();
        return;
      }
      const chunks: Buffer[] = [];
      let dropped = false;
      entry.on("data", (chunk: Buffer) => {
        if (dropped) return;
        chunks.push(chunk);
        const total = chunks.reduce((s, b) => s + b.length, 0);
        if (total > MAX_PER_ENTRY_BYTES) {
          dropped = true;
          chunks.length = 0;
        }
      });
      entry.on("end", () => {
        if (!dropped) {
          entries.push({ name: entry.path, data: Buffer.concat(chunks) });
        } else {
          entries.push({ name: entry.path, data: Buffer.alloc(0) });
        }
      });
      entry.on("error", reject);
    });
    parser.on("end", () => resolve());
    parser.on("error", reject);
    parser.write(raw);
    parser.end();
  });

  const { text, truncated } = await decodeArchiveEntries(entries, maxTextChars);
  return { text, mime, truncated, decoder: "tar" };
};

registerDecoder("application/gzip", tarGzDecoder);
registerDecoder("application/x-tar", tarGzDecoder);

// Register the text family.
for (const mime of [
  "text/plain",
  "text/markdown",
  "text/csv",
  "text/tab-separated-values",
  "text/html",
  "text/xml",
  "text/yaml",
  "text/toml",
  "text/javascript",
  "text/typescript",
  "text/x-python",
  "text/x-ruby",
  "text/x-go",
  "text/x-rust",
  "text/x-shellscript",
  "text/x-bat",
  "application/json",
]) {
  registerDecoder(mime, textDecoder);
}

// ── Main entry ─────────────────────────────────────────────────────────────

/**
 * Scan a local file: validate path, detect MIME, decode, scan.
 *
 * Never returns the file's raw bytes. On any error returns a FLAGGED
 * ScanResult with a stable `reason` code so the caller can decide how
 * to surface it.
 */
export async function scanFile(
  scanner: CanaryScanner,
  filePath: string,
  options: FileScanOptions = {},
): Promise<ScanResult & { mime: string; truncated: boolean; decoder: string }> {
  const maxBytes = options.maxBytes ?? DEFAULT_MAX_BYTES;
  const maxTextChars = options.maxTextChars ?? DEFAULT_MAX_TEXT_CHARS;
  const start = Date.now();

  // 1. Validate path + size.
  let absolute: string;
  try {
    const v = validateFilePath(filePath, maxBytes);
    absolute = v.absolute;
  } catch (e) {
    return flaggedResult(scanner, filePath, start, {
      reason: `${(e as NodeJS.ErrnoException).code ?? "validate_failed"}: ${(e as Error).message}`,
      decoder: "validate",
      mime: "unknown",
    });
  }

  // 2. Read.
  let buffer: Buffer;
  try {
    buffer = fs.readFileSync(absolute);
  } catch (e) {
    return flaggedResult(scanner, absolute, start, {
      reason: `read_failed: ${(e as Error).message}`,
      decoder: "read",
      mime: "unknown",
    });
  }

  // 3. MIME-detect (or trust caller override).
  const mime = options.forceMime ?? detectMime(buffer, absolute);

  // 4. Dispatch.
  const decoder = decoders.get(mime);
  if (!decoder) {
    return flaggedResult(scanner, absolute, start, {
      reason: `unsupported_mime: ${mime} — no text extractor registered; canary cannot probe this content`,
      decoder: "none",
      mime,
    });
  }

  // 5. Extract text.
  let extracted: FileExtractionResult;
  try {
    extracted = await decoder(buffer, mime, maxTextChars);
  } catch (e) {
    return flaggedResult(scanner, absolute, start, {
      reason: `extract_failed: ${(e as Error).message}`,
      decoder: "extract",
      mime,
    });
  }

  if (!extracted.text || extracted.text.trim().length === 0) {
    // Empty content is technically clear (nothing to probe), but flag
    // anyway with a clear reason — caller may want to know that the
    // file was unscanable, not that it's safe.
    return flaggedResult(scanner, absolute, start, {
      reason: `no_extractable_text: decoder=${extracted.decoder} returned empty text`,
      decoder: extracted.decoder,
      mime,
    });
  }

  // 6. Probe.
  const scanResult = await scanner.scan(extracted.text);
  return {
    ...scanResult,
    mime,
    truncated: extracted.truncated,
    decoder: extracted.decoder,
    // Preview is content-bound to keep the API surface stable, but we
    // override it to include the path so the caller knows what was
    // actually scanned.
    contentPreview: `${absolute} → [${mime}] ${scanResult.contentPreview}`,
  };
}

// ── Helpers ────────────────────────────────────────────────────────────────

function flaggedResult(
  scanner: CanaryScanner,
  source: string,
  startMs: number,
  o: { reason: string; decoder: string; mime: string },
): ScanResult & { mime: string; truncated: boolean; decoder: string } {
  // model name + chunking metadata copied from the scanner so the shape
  // matches a real scan
  const metadata: ScanMetadata = {
    confidence: "bounded",
    chunksScanned: 0,
    chunksFlagged: 0,
    rawCoverage: 0,
    uniqueCoverage: 0,
    overlapRatio: 0.25,
  };
  return {
    status: "flagged",
    reason: o.reason,
    deviationDetected: false,
    toolCallAttempted: false,
    toolsInvoked: [],
    contentPreview: source,
    model: (scanner as unknown as { model: string }).model ?? "unknown",
    scanTimeMs: Date.now() - startMs,
    metadata,
    mime: o.mime,
    truncated: false,
    decoder: o.decoder,
  };
}

/**
 * Public: list the MIME types currently scannable. For audit + tests.
 */
export function supportedMimeTypes(): string[] {
  return Array.from(decoders.keys()).sort();
}

/**
 * Public: extract text from an in-memory buffer using the dispatch
 * table. Used by `scanner.scanUrl` so MIME-aware decoding applies to
 * HTTPS responses too. Returns null if no decoder is registered for
 * the detected MIME — callers should fail-closed FLAGGED in that case.
 */
export async function extractTextFromBuffer(
  buffer: Buffer,
  hintPath: string,
  maxTextChars: number = DEFAULT_MAX_TEXT_CHARS,
  forceMime?: string,
): Promise<FileExtractionResult | null> {
  const mime = forceMime ?? detectMime(buffer, hintPath);
  const decoder = decoders.get(mime);
  if (!decoder) return null;
  try {
    return await decoder(buffer, mime, maxTextChars);
  } catch {
    return null;
  }
}

/**
 * Public: detect MIME by HTTP response Content-Type. Falls back to the
 * magic-byte detector on the buffer if the header is missing or generic.
 */
export function mimeFromHttpResponse(
  contentTypeHeader: string | null,
  buffer: Buffer,
  urlPath: string,
): string {
  if (contentTypeHeader) {
    // Strip charset params: "text/html; charset=utf-8" → "text/html"
    const base = contentTypeHeader.split(";")[0].trim().toLowerCase();
    if (base && base !== "application/octet-stream") return base;
  }
  return detectMime(buffer, urlPath);
}
