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

import { CanaryScanner } from "./scanner";

const API_KEY = process.env.CANARY_API_KEY || process.env.OPENROUTER_API_KEY || "";
const BASE_URL = process.env.CANARY_BASE_URL || "https://openrouter.ai/api/v1";
const MODEL = process.env.CANARY_MODEL || "arcee-ai/trinity-mini:free";

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

// Simplified MCP stdio transport
let buffer = "";

process.stdin.setEncoding("utf-8");
process.stdin.on("data", (chunk: string) => {
  buffer += chunk;
  processBuffer();
});

function processBuffer() {
  while (true) {
    const headerEnd = buffer.indexOf("\r\n\r\n");
    if (headerEnd === -1) break;

    const header = buffer.slice(0, headerEnd);
    const contentLengthMatch = header.match(/Content-Length: (\d+)/i);
    if (!contentLengthMatch) {
      buffer = buffer.slice(headerEnd + 4);
      continue;
    }

    const contentLength = parseInt(contentLengthMatch[1]);
    const bodyStart = headerEnd + 4;
    if (buffer.length < bodyStart + contentLength) break;

    const body = buffer.slice(bodyStart, bodyStart + contentLength);
    buffer = buffer.slice(bodyStart + contentLength);

    try {
      const msg = JSON.parse(body);
      handleMessage(msg);
    } catch {
      // Skip malformed messages
    }
  }
}

function sendMessage(msg: any) {
  const body = JSON.stringify(msg);
  const header = `Content-Length: ${Buffer.byteLength(body)}\r\n\r\n`;
  process.stdout.write(header + body);
}

async function handleMessage(msg: any) {
  if (msg.method === "initialize") {
    sendMessage({
      jsonrpc: "2.0",
      id: msg.id,
      result: {
        protocolVersion: "2024-11-05",
        capabilities: { tools: {} },
        serverInfo: { name: "canary", version: "0.2.0" },
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
      } else if (name === "canary_scan_text") {
        result = await scanner.scan(args.text);
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
console.error("Canary MCP server started (v0.2.0 — echo + tool detection)");
console.error(`Model: ${MODEL}`);
console.error("Waiting for connections...");
