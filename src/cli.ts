#!/usr/bin/env node
/**
 * Canary CLI — Scan URLs or text for prompt injection indicators
 *
 * Usage:
 *   canary scan https://example.com
 *   canary scan --text "some content to check"
 *   canary calibrate
 *   canary trust list
 *   canary trust add https://example.com
 *   canary flag https://example.com
 *
 * Environment:
 *   CANARY_API_KEY    — OpenRouter (or compatible) API key (required)
 *   CANARY_BASE_URL   — API base URL (default: https://openrouter.ai/api/v1)
 *   CANARY_MODEL      — Model to use (default: mistralai/qwen3-4b:free)
 */

import { CanaryScanner, type ScanResult, type CalibrationResult } from "./scanner";

const API_KEY = process.env.CANARY_API_KEY || process.env.OPENROUTER_API_KEY || "";
const BASE_URL = process.env.CANARY_BASE_URL || "https://openrouter.ai/api/v1";
const MODEL = process.env.CANARY_MODEL || "arcee-ai/trinity-mini:free";

function printUsage() {
  console.log(`
Canary — Prompt Injection Behavioral Detection

  Uses a weak LLM as a behavioral probe. Content is sent to a small model
  with a verbatim echo instruction. Any deviation in output or attempted
  tool use indicates the content influenced the model's behavior.

  FLAGGED = content caused behavioral deviation. Human review recommended.
  CLEAR   = no deviation detected under test conditions. Not a safety guarantee.

Usage:
  canary scan <url>              Scan a URL
  canary scan --text "content"   Scan raw text
  canary calibrate               Test model echo fidelity and tool call rate
  canary trust list              Show trusted/flagged sources
  canary trust add <source>      Manually trust a source
  canary flag <source>           Manually flag a source

Environment:
  CANARY_API_KEY     API key for LLM provider (OpenRouter, etc.)
  CANARY_BASE_URL    API base URL (default: OpenRouter)
  CANARY_MODEL       Model ID (default: qwen3-4b:free)

The default model is small and free — on purpose.
A gullible model is a more sensitive detector.
`);
}

async function main() {
  const args = process.argv.slice(2);

  if (args.length === 0 || args[0] === "--help" || args[0] === "-h") {
    printUsage();
    process.exit(0);
  }

  if (!API_KEY) {
    console.error("Error: CANARY_API_KEY or OPENROUTER_API_KEY environment variable required");
    process.exit(1);
  }

  const scanner = new CanaryScanner({
    apiKey: API_KEY,
    baseUrl: BASE_URL,
    model: MODEL,
  });

  const command = args[0];

  if (command === "scan") {
    if (args[1] === "--text") {
      const text = args.slice(2).join(" ");
      if (!text) {
        console.error("Error: provide text to scan");
        process.exit(1);
      }
      const result = await scanner.scan(text);
      printResult(result);
    } else if (args[1]) {
      const url = args[1];
      console.log(`Scanning ${url}...`);
      const result = await scanner.scanUrl(url);
      printResult(result);
    } else {
      console.error("Error: provide a URL or --text");
      process.exit(1);
    }
  } else if (command === "calibrate") {
    console.log(`Calibrating model: ${MODEL}`);
    console.log("Running echo fidelity and tool call tests...\n");
    const result = await scanner.calibrate();
    printCalibration(result);
  } else if (command === "trust") {
    if (args[1] === "list") {
      const lists = scanner.getTrustList();
      console.log("Trusted:", lists.trusted.length ? lists.trusted.join(", ") : "(none)");
      console.log("Flagged:", lists.flagged.length ? lists.flagged.join(", ") : "(none)");
    } else if (args[1] === "add" && args[2]) {
      scanner.setTrust(args[2], "clear");
      console.log(`Trusted: ${args[2]}`);
    } else {
      console.error("Usage: canary trust list | canary trust add <source>");
    }
  } else if (command === "flag") {
    if (args[1]) {
      scanner.setTrust(args[1], "flagged");
      console.log(`Flagged: ${args[1]}`);
    } else {
      console.error("Usage: canary flag <source>");
    }
  } else {
    printUsage();
  }
}

function printResult(result: ScanResult) {
  const label = result.status === "clear" ? "CLEAR" : "FLAGGED";
  console.log(`\n  Status:     ${label}`);
  console.log(`  Model:      ${result.model}`);
  console.log(`  Time:       ${result.scanTimeMs}ms`);
  console.log(`  Preview:    ${result.contentPreview}`);

  console.log(`  Deviation:  ${result.deviationDetected ? "YES" : "no"}`);
  console.log(`  Tool call:  ${result.toolCallAttempted ? "YES — " + result.toolsInvoked.join(", ") : "no"}`);

  if (result.reason) {
    console.log(`  Detail:     ${result.reason}`);
  }

  const m = result.metadata;
  console.log(`  Chunks:     ${m.chunksScanned} scanned, ${m.chunksFlagged} flagged`);
  console.log(`  Coverage:   ${Math.round(m.uniqueCoverage * 100)}% unique, ${Math.round(m.rawCoverage * 100)}% raw`);
  console.log(`  Overlap:    ${Math.round(m.overlapRatio * 100)}%`);

  console.log();

  if (result.status === "flagged") {
    console.log("  This content caused behavioral deviation in the canary model.");
    console.log("  Human review recommended before processing.\n");
  } else {
    console.log("  No deviation detected under test conditions.");
    console.log("  This does not guarantee the content is safe.\n");
  }
}

function printCalibration(result: CalibrationResult) {
  console.log(`  Model:           ${result.model}`);
  console.log(`  Echo fidelity:   ${Math.round(result.echoFidelity * 100)}% raw`);
  if (result.artifacts.length > 0) {
    console.log(`  Adjusted:        ${Math.round(result.adjustedEchoFidelity * 100)}% (with ${result.artifacts.length} artifact(s) filtered)`);
  }
  console.log(`  Tool call rate:  ${Math.round(result.toolCallRate * 100)}%`);
  console.log(`  Suitable:        ${result.suitable ? "YES" : "NO"}`);

  if (result.artifacts.length > 0) {
    console.log(`\n  Artifacts found (model-specific noise to filter):`);
    for (const artifact of result.artifacts) {
      console.log(`    "${artifact}"`);
    }
    console.log(`\n  Pass these to CanaryConfig.calibrationArtifacts to reduce false positives.`);
  }

  if (result.details.length > 0) {
    console.log(`\n  Details:`);
    for (const detail of result.details) {
      console.log(`    - ${detail}`);
    }
  }

  if (!result.suitable) {
    console.log("\n  This model may produce too many false positives.");
    if (result.adjustedEchoFidelity < 0.85) {
      console.log("  Echo fidelity below 85% — model struggles with verbatim reproduction.");
    }
    if (result.toolCallRate > 0.05) {
      console.log("  Tool call rate above 5% — model calls tools on clean input.");
    }
  }

  console.log();
}

main().catch((err) => {
  console.error("Error:", err.message);
  process.exit(1);
});
