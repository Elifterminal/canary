/**
 * Canary Telemetry — opt-in, anonymous usage statistics.
 *
 * What we collect:
 *   - Canary version
 *   - Scan count (not content)
 *   - Result distribution (CLEAR vs FLAGGED)
 *   - Which detection channel fired (text deviation vs tool call)
 *   - Canary model used
 *
 * What we NEVER collect:
 *   - No scanned content, no URLs, no IPs, no user IDs
 *   - No fingerprinting, no tracking, no cookies
 *   - Nothing that could identify what you're scanning or why
 *
 * Consent is stored in ~/.canary/config.json alongside trust.json.
 * Change anytime: `canary telemetry on` / `canary telemetry off`
 */

import fs from "fs";
import path from "path";
import https from "https";

// ── Config persistence ───────────────────────────────────────────────────────

const CONFIG_DIR = path.join(
  process.env.HOME || process.env.USERPROFILE || ".",
  ".canary"
);
const CONFIG_FILE = path.join(CONFIG_DIR, "config.json");

interface CanaryUserConfig {
  telemetryConsent?: boolean;
  telemetryAsked?: boolean;
  installId?: string;
}

function readConfig(): CanaryUserConfig {
  try {
    return JSON.parse(fs.readFileSync(CONFIG_FILE, "utf-8"));
  } catch {
    return {};
  }
}

function writeConfig(config: CanaryUserConfig): void {
  fs.mkdirSync(CONFIG_DIR, { recursive: true });
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2) + "\n");
}

// ── Consent ──────────────────────────────────────────────────────────────────

export function hasBeenAsked(): boolean {
  return readConfig().telemetryAsked === true;
}

export function isEnabled(): boolean {
  // env var override takes precedence over the config file. this lets
  // non-interactive contexts (the MCP server, CI, anything wrapping
  // canary in a script) opt in without ever seeing the TTY prompt —
  // which is most of the install base, since the prompt only fires
  // in raw-mode-capable terminals. set CANARY_TELEMETRY=1 to enable,
  // =0 to force-disable. config file is checked only when the env
  // var is absent.
  const envOverride = process.env.CANARY_TELEMETRY;
  if (envOverride === "1" || envOverride === "true") return true;
  if (envOverride === "0" || envOverride === "false") return false;
  return readConfig().telemetryConsent === true;
}

export function setConsent(enabled: boolean): void {
  const config = readConfig();
  config.telemetryConsent = enabled;
  config.telemetryAsked = true;
  if (enabled && !config.installId) {
    // Random ID — not tied to any user identity, just differentiates installs
    config.installId = randomHex(16);
  }
  writeConfig(config);
}

function getInstallId(): string {
  const config = readConfig();
  if (!config.installId) {
    const id = randomHex(16);
    writeConfig({ ...config, installId: id });
    return id;
  }
  return config.installId;
}

function randomHex(bytes: number): string {
  const array = new Uint8Array(bytes);
  for (let i = 0; i < bytes; i++) {
    array[i] = Math.floor(Math.random() * 256);
  }
  return Array.from(array, (b) => b.toString(16).padStart(2, "0")).join("");
}

// ── Event buffering & reporting ──────────────────────────────────────────────

interface ScanEvent {
  status: "clear" | "flagged";
  deviationDetected: boolean;
  toolCallAttempted: boolean;
  model: string;
  scanTimeMs: number;
  chunksScanned: number;
}

const EVENTS_FILE = path.join(CONFIG_DIR, "telemetry_buffer.json");
const REPORT_ENDPOINT = "https://canary-telemetry.elifterminal.workers.dev/report";
// 3 felt right: small enough that low-volume users (1-3 scans then walk
// away) ship something, big enough that we're not making an HTTP call
// after literally every scan. paired with flushEvents() at CLI startup,
// this makes the worst-case latency "next time you use the tool."
const FLUSH_THRESHOLD = 3;

function readEvents(): ScanEvent[] {
  try {
    return JSON.parse(fs.readFileSync(EVENTS_FILE, "utf-8"));
  } catch {
    return [];
  }
}

function writeEvents(events: ScanEvent[]): void {
  fs.mkdirSync(CONFIG_DIR, { recursive: true });
  fs.writeFileSync(EVENTS_FILE, JSON.stringify(events) + "\n");
}

export function recordScan(event: ScanEvent): void {
  if (!isEnabled()) return;

  const events = readEvents();
  events.push(event);
  writeEvents(events);

  if (events.length >= FLUSH_THRESHOLD) {
    flushEvents().catch(() => {});
  }
}

export async function flushEvents(): Promise<void> {
  if (!isEnabled()) return;

  const events = readEvents();
  if (events.length === 0) return;

  // Build aggregate report — no individual event data sent
  const report = buildReport(events);

  try {
    await sendReport(report);
    // Clear buffer on success
    writeEvents([]);
  } catch {
    // Silently fail — telemetry should never break the tool
  }
}

// ── Report building ──────────────────────────────────────────────────────────

interface TelemetryReport {
  installId: string;
  version: string;
  period: { from: string; to: string };
  totalScans: number;
  clearCount: number;
  flaggedCount: number;
  deviationCount: number;
  toolCallCount: number;
  avgScanTimeMs: number;
  avgChunksPerScan: number;
  modelsUsed: string[];
}

function getVersion(): string {
  try {
    const pkg = JSON.parse(
      fs.readFileSync(path.join(__dirname, "..", "package.json"), "utf-8")
    );
    return pkg.version || "unknown";
  } catch {
    return "unknown";
  }
}

function buildReport(events: ScanEvent[]): TelemetryReport {
  const now = new Date().toISOString();
  const models = [...new Set(events.map((e) => e.model))];

  return {
    installId: getInstallId(),
    version: getVersion(),
    period: { from: now, to: now },
    totalScans: events.length,
    clearCount: events.filter((e) => e.status === "clear").length,
    flaggedCount: events.filter((e) => e.status === "flagged").length,
    deviationCount: events.filter((e) => e.deviationDetected).length,
    toolCallCount: events.filter((e) => e.toolCallAttempted).length,
    avgScanTimeMs: Math.round(
      events.reduce((s, e) => s + e.scanTimeMs, 0) / events.length
    ),
    avgChunksPerScan: Math.round(
      events.reduce((s, e) => s + e.chunksScanned, 0) / events.length
    ),
    modelsUsed: models,
  };
}

// ── HTTP ─────────────────────────────────────────────────────────────────────

function sendReport(report: TelemetryReport): Promise<void> {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(report);
    const url = new URL(REPORT_ENDPOINT);

    const req = https.request(
      {
        hostname: url.hostname,
        path: url.pathname,
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(data),
        },
        timeout: 5000,
      },
      (res) => {
        res.resume();
        if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
          resolve();
        } else {
          reject(new Error(`HTTP ${res.statusCode}`));
        }
      }
    );

    req.on("error", reject);
    req.on("timeout", () => {
      req.destroy();
      reject(new Error("Timeout"));
    });
    req.write(data);
    req.end();
  });
}

// ── CLI prompt helper ────────────────────────────────────────────────────────

export function promptConsent(): Promise<boolean> {
  return new Promise((resolve) => {
    if (typeof process.stdin.setRawMode !== "function") {
      // Non-interactive (piped, CI, etc.) — default to no
      setConsent(false);
      resolve(false);
      return;
    }

    const message = [
      "",
      "  Help improve Canary?",
      "",
      "  We collect anonymous usage stats only:",
      "  scan counts, detection rates, and model used.",
      "  No content, no URLs, no IPs — nothing personal. Ever.",
      "  You can change this anytime: canary telemetry off",
      "",
      "  Send anonymous stats? (y/N) ",
    ].join("\n");

    process.stdout.write(message);

    const rl = await_keypress((answer) => {
      const yes = answer.toLowerCase() === "y";
      setConsent(yes);
      console.log(yes ? "  Thanks! Telemetry enabled.\n" : "  No problem. Telemetry disabled.\n");
      resolve(yes);
    });
  });
}

function await_keypress(callback: (key: string) => void): void {
  const stdin = process.stdin;
  const wasRaw = stdin.isRaw;

  stdin.setRawMode(true);
  stdin.resume();
  stdin.setEncoding("utf-8");

  stdin.once("data", (key: string) => {
    stdin.setRawMode(wasRaw);
    stdin.pause();
    process.stdout.write("\n");
    callback(key.trim());
  });
}
