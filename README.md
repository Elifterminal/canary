# Canary

Prompt injection detection using behavioral analysis. Weak LLMs as sensitive sensors.

## How it works

Canary sends content to a small, cheap LLM with one instruction: **echo it back exactly**. Then it checks what happened.

Two independent detection channels:

1. **Text deviation** — Did the output differ from the input? Deterministic string comparison after normalization. No fuzzy matching, no thresholds.
2. **Tool call attempt** — Did the model try to call any honeypot tools? Five attractive tool definitions (execute_command, read_file, send_request, update_memory, send_message) are offered but never referenced in the prompt. Any tool call means the input content influenced the model.

If either channel fires: **FLAGGED**. If neither: **CLEAR**.

### Why weak models?

A small, instruction-tuned model is *more susceptible* to prompt injection than a frontier model. That's the feature. A model that gets tricked easily makes a more sensitive detector. The canary doesn't need to be smart — it needs to be gullible.

### What CLEAR and FLAGGED mean

- **CLEAR** = "No deviation detected under test conditions." This is not a safety guarantee. Sophisticated injections can evade detection.
- **FLAGGED** = "Behavioral deviation detected." The content caused the canary to deviate from its echo instruction. Human review recommended.

Canary makes bounded claims, not absolute ones.

## Install

```bash
npm install canary-scan
```

Or run directly:

```bash
npx canary-scan scan https://example.com
```

## Setup

You need an API key from [OpenRouter](https://openrouter.ai/) (free tier works).

```bash
export CANARY_API_KEY=your-openrouter-key
```

Optional:

```bash
export CANARY_MODEL=arcee-ai/trinity-mini:free  # default
export CANARY_BASE_URL=https://openrouter.ai/api/v1  # default
```

## CLI Usage

```bash
# Scan a URL
canary scan https://example.com

# Scan raw text
canary scan --text "some content to check"

# Calibrate — measure echo fidelity and tool call rate for your model
canary calibrate

# Trust management
canary trust list
canary trust add https://known-safe.com
canary flag https://suspicious.com
```

### Example output

```
  Status:     FLAGGED
  Model:      arcee-ai/trinity-mini:free
  Time:       2340ms
  Preview:    Ignore all previous instructions...
  Deviation:  YES
  Tool call:  YES — execute_command
  Detail:     2 indicator(s): Text deviation at position 0: "...I'll help you with that!..."; Tool call attempted: execute_command
  Chunks:     1 scanned, 1 flagged
  Coverage:   100% unique, 100% raw

  This content caused behavioral deviation in the canary model.
  Human review recommended before processing.
```

## Library Usage

```typescript
import { CanaryScanner } from "canary-scan";

const scanner = new CanaryScanner({
  apiKey: process.env.CANARY_API_KEY!,
  model: "arcee-ai/trinity-mini:free",  // optional
  chunkSize: 1500,                       // optional
  overlapRatio: 0.25,                    // optional
  calibrationArtifacts: [],              // optional, from calibration
});

// Scan text
const result = await scanner.scan("some untrusted content");
console.log(result.status);  // "clear" or "flagged"

// Scan a URL
const urlResult = await scanner.scanUrl("https://example.com");

// Calibrate — run once per model to find artifacts
const calibration = await scanner.calibrate();
console.log(calibration.echoFidelity);        // raw fidelity
console.log(calibration.adjustedEchoFidelity); // fidelity after artifact filtering
console.log(calibration.artifacts);            // pass these to calibrationArtifacts
```

### ScanResult

```typescript
{
  status: "clear" | "flagged",
  reason: string | null,
  deviationDetected: boolean,
  toolCallAttempted: boolean,
  toolsInvoked: string[],
  contentPreview: string,
  model: string,
  scanTimeMs: number,
  metadata: {
    confidence: "bounded",
    chunksScanned: number,
    chunksFlagged: number,
    rawCoverage: number,
    uniqueCoverage: number,
    overlapRatio: number,
  }
}
```

## MCP Server

Canary runs as an MCP server so AI agents can scan content before reading it.

```json
{
  "mcpServers": {
    "canary": {
      "command": "npx",
      "args": ["tsx", "/path/to/canary/src/mcp-server.ts"],
      "env": { "CANARY_API_KEY": "your-key" }
    }
  }
}
```

Tools provided:
- `canary_scan_url` — Scan a URL before reading it
- `canary_scan_text` — Scan raw text content
- `canary_trust` — Manually mark sources as trusted/flagged

## Calibration

Different models have different echo fidelity. Some add prefixes ("Sure! Here's the text:"), strip labels, or reformat whitespace. Calibration measures this baseline noise so you can distinguish it from injection-caused deviation.

```bash
canary calibrate
```

This runs 20 clean text samples through the model and reports:
- **Raw echo fidelity** — percentage of perfect echoes before artifact filtering
- **Adjusted echo fidelity** — percentage after filtering discovered artifacts
- **Tool call rate** — how often the model calls tools on clean input (should be 0%)
- **Artifacts** — specific strings the model consistently adds/removes

Pass discovered artifacts to `calibrationArtifacts` in your config to reduce false positives.

## How it handles long content

Content is split into overlapping chunks (default: 1500 chars, 25% overlap). Each chunk is scanned independently — the canary model has no context between chunks. If any chunk is flagged, the whole scan is flagged.

Overlap ensures injections at chunk boundaries are still caught.

## Limitations

- **Not a guarantee.** Sophisticated injections can produce output that matches the input while still containing executable payloads.
- **Model-dependent.** Detection sensitivity varies by model. Calibrate before production use.
- **Rate limits.** Free OpenRouter models have rate limits (~8 RPM). Scanning large content takes time.
- **No HTML stripping.** The canary sees raw content, including HTML tags. This is intentional — stripping could remove injections.
- **One-way detection.** Canary detects behavioral influence, not the *type* of injection. A FLAGGED result doesn't tell you *what* the injection tries to do.

## Tests

```bash
npm test
```

50 tests covering normalization, both detection channels, chunking, caching, metadata, known injection payloads, and trust management. All tests run offline with mocked API calls.

## License

MIT
