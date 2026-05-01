#!/usr/bin/env node
/**
 * Canary MCP Server
 *
 * Provides prompt injection scanning as an MCP tool.
 * Any AI agent can call `canary_scan` before reading untrusted content.
 *
 * Usage:
 *   CANARY_API_KEY=... npx tsx src/mcp-server.ts
 *
 * Add to claude_desktop_config.json or .claude/settings.json:
 *   {
 *     "mcpServers": {
 *       "canary": {
 *         "command": "npx",
 *         "args": ["tsx", "/path/to/canary/src/mcp-server.ts"],
 *         "env": { "CANARY_API_KEY": "your-key" }
 *       }
 *     }
 *   }
 */

import { CanaryScanner, type ScanResult } from "./scanner";
import { recordScan, flushEvents, isEnabled as telemetryEnabled } from "./telemetry";

const API_KEY = process.env.CANARY_API_KEY || process.env.OPENROUTER_API_KEY || "";
const BASE_URL = process.env.CANARY_BASE_URL || "https://openrouter.ai/api/v1";
const MODEL = process.env.CANARY_MODEL || "stepfun/step-3.5-flash";

// Best-effort flush of anything buffered from a previous run. never
// blocks startup, never errors stdio.
flushEvents().catch(() => {});

function recordIfScan(result: ScanResult): void {
  // MCP server runs non-interactively, so telemetry is governed by
  // CANARY_TELEMETRY=1 in the env. When unset, isEnabled() returns
  // false and recordScan is a no-op — no data leaves.
  recordScan({
    status: result.status,
    deviationDetected: result.deviationDetected,
    toolCallAttempted: result.toolCallAttempted,
    model: result.model,
    scanTimeMs: result.scanTimeMs,
    chunksScanned: result.metadata.chunksScanned,
  });
}

if (!API_KEY) {
  console.error("CANARY_API_KEY or OPENROUTER_API_KEY required");
  process.exit(1);
}

const scanner = new CanaryScanner({
  apiKey: API_KEY,
  baseUrl: BASE_URL,
  model: MODEL,
});

// MCP protocol over stdio
const TOOLS = [
  {
    name: "canary_scan_url",
    description:
      "Scan a URL for prompt injection indicators before reading it. Uses a weak LLM as a behavioral probe — sends content with a verbatim echo instruction and checks for deviation. Returns CLEAR (no deviation detected under test conditions — not a safety guarantee) or FLAGGED (behavioral deviation detected — human review recommended).",
    inputSchema: {
      type: "object",
      properties: {
        url: { type: "string", description: "The URL to scan" },
      },
      required: ["url"],
    },
  },
  {
    name: "canary_scan_text",
    description:
      "Scan raw text for prompt injection indicators. Uses a weak LLM as a behavioral probe — sends content with a verbatim echo instruction and checks for deviation. Returns CLEAR (no deviation detected) or FLAGGED (behavioral deviation detected — human review recommended).",
    inputSchema: {
      type: "object",
      properties: {
        text: { type: "string", description: "The text content to scan" },
      },
      required: ["text"],
    },
  },
  {
    name: "canary_trust",
    description: "Manually mark a source as trusted (clear) or flagged after human review.",
    inputSchema: {
      type: "object",
      properties: {
        source: { type: "string", description: "The source identifier (URL or content hash)" },
        status: { type: "string", enum: ["clear", "flagged"], description: "Trust status" },
      },
      required: ["source", "status"],
    },
  },
];

// MCP stdio transport: newline-delimited JSON, one message per line.
// (Earlier versions used LSP-style Content-Length framing — wrong wire format,
// the Claude Code MCP client never got a reply and timed out at 30s.)
let buffer = "";

process.stdin.setEncoding("utf-8");
process.stdin.on("data", (chunk: string) => {
  buffer += chunk;
  processBuffer();
});

function processBuffer() {
  while (true) {
    const newlineIdx = buffer.indexOf("\n");
    if (newlineIdx === -1) break;

    const line = buffer.slice(0, newlineIdx).trim();
    buffer = buffer.slice(newlineIdx + 1);

    if (!line) continue;

    try {
      const msg = JSON.parse(line);
      handleMessage(msg);
    } catch {
      // skip — partial / malformed lines shouldn't take the server down
    }
  }
}

function sendMessage(msg: any) {
  // single line, terminated by \n. JSON.stringify never produces literal newlines,
  // so this stays single-frame even with multi-line text content inside the payload.
  process.stdout.write(JSON.stringify(msg) + "\n");
}

async function handleMessage(msg: any) {
  if (msg.method === "initialize") {
    sendMessage({
      jsonrpc: "2.0",
      id: msg.id,
      result: {
        protocolVersion: "2024-11-05",
        capabilities: { tools: {} },
        serverInfo: { name: "canary", version: "0.2.11" },
      },
    });
  } else if (msg.method === "notifications/initialized") {
    // No response needed
  } else if (msg.method === "tools/list") {
    sendMessage({
      jsonrpc: "2.0",
      id: msg.id,
      result: { tools: TOOLS },
    });
  } else if (msg.method === "tools/call") {
    const { name, arguments: args } = msg.params;
    let result;

    try {
      if (name === "canary_scan_url") {
        result = await scanner.scanUrl(args.url);
        recordIfScan(result);
      } else if (name === "canary_scan_text") {
        result = await scanner.scan(args.text);
        recordIfScan(result);
      } else if (name === "canary_trust") {
        scanner.setTrust(args.source, args.status);
        result = { status: args.status, source: args.source, message: `Source ${args.status === "clear" ? "trusted" : "flagged"}` };
      } else {
        throw new Error(`Unknown tool: ${name}`);
      }

      sendMessage({
        jsonrpc: "2.0",
        id: msg.id,
        result: {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
        },
      });
    } catch (error: any) {
      sendMessage({
        jsonrpc: "2.0",
        id: msg.id,
        result: {
          content: [{ type: "text", text: `Error: ${error.message}` }],
          isError: true,
        },
      });
    }
  }
}

// Log to stderr so it doesn't interfere with MCP stdio
console.error("Canary MCP server started (v0.2.11 — echo + tool detection)");
console.error(`Model: ${MODEL}`);
console.error(`Telemetry: ${telemetryEnabled() ? "ENABLED (CANARY_TELEMETRY=1)" : "disabled (set CANARY_TELEMETRY=1 to opt in)"}`);
console.error("Waiting for connections...");
