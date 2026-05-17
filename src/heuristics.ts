/**
 * Canary heuristics — deterministic prompt-injection pre-screen.
 *
 * The LLM probe is the second line of defense. This module is the first:
 * a cheap, fast, deterministic scan for known injection shapes. Anything
 * that hits a heuristic is FLAGGED before the LLM probe even runs — the
 * probe is non-deterministic and can false-clear, so we don't trust it
 * for cases we can recognize structurally.
 *
 * Each heuristic carries:
 *   - id           — short stable identifier for the rule
 *   - description  — human-readable explanation
 *   - severity     — high / medium (informational on its own; one HIGH
 *                    or two MEDIUMs FLAG the content)
 *   - regex        — the actual pattern (case-insensitive, multiline)
 *
 * False-positive philosophy: prefer FLAGGED with a clear reason over
 * silent-CLEAR. Each rule is reviewable; operators can tune via
 * AVIARY_CANARY_HEURISTIC_DISABLE or call canary_trust(source, "clear")
 * after human review.
 *
 * The set below was hand-crafted against the canary test fixture matrix
 * (txt, md, json, html, csv, pdf, docx, jpg-EXIF, zip, tar.gz) plus
 * standard prompt-injection corpora.
 */

export interface HeuristicHit {
  id: string;
  description: string;
  severity: "high" | "medium";
  match: string;
  position: number;
}

export interface HeuristicResult {
  hits: HeuristicHit[];
  /** True if hits trip the FLAG threshold (1 HIGH or 2 MEDIUMs). */
  flagged: boolean;
}

interface Rule {
  id: string;
  description: string;
  severity: "high" | "medium";
  regex: RegExp;
}

// ── Rules ──────────────────────────────────────────────────────────────────

const RULES: Rule[] = [
  // ── Direct override instructions ─────────────────────────────────────────
  {
    id: "ignore-prior-instructions",
    description: "Direct instruction to ignore previous/prior/all instructions",
    severity: "high",
    regex: /\bignore\s+(all\s+)?(your\s+)?(previous|prior|earlier|preceding|above|the\s+above)\s+(instructions?|directives?|rules?|prompts?|messages?)\b/i,
  },
  {
    id: "disregard-prior-instructions",
    description: "'Disregard previous instructions' variant",
    severity: "high",
    regex: /\b(disregard|forget|override|cancel|nullify)\s+(all\s+)?(your\s+)?(previous|prior|earlier|preceding|above|the\s+above)\s+(instructions?|directives?|rules?|prompts?)\b/i,
  },

  // ── Role redefinition ────────────────────────────────────────────────────
  {
    id: "role-redefinition-you-are",
    description: "Attempts to redefine the agent's role ('you are now / from now on you are')",
    severity: "high",
    regex: /\b(you\s+are\s+(now|an?|the)|from\s+(now\s+on|this\s+point\s+forward),?\s+you\s+(are|will|must)|act\s+as|assume\s+the\s+role\s+of|behave\s+as|pretend\s+(to\s+be|you\s+are))\b/i,
  },
  {
    id: "system-checkpoint-marker",
    description: "Pseudo-system markers used in injections ([SYSTEM], [ADMIN], [OPERATOR], <inst>, etc.)",
    severity: "high",
    regex: /(\[(SYSTEM|ADMIN|OPERATOR|ASSISTANT|AGENT|ROOT|SUDO|DEVELOPER|INSTRUCTION|COMMAND|TASK|MODE)[^\]]*\]|<\/?(inst|sys|admin|system|instruction)[^>]*>)/i,
  },
  {
    id: "agent-only-section",
    description: "Section explicitly addressed to agents ('agents only', 'AI agents reading this')",
    severity: "medium",
    regex: /\b(ai\s+)?agents?\s+(only|reading\s+this|encountering\s+this|processing\s+this|when\s+(you|reading))\b/i,
  },

  // ── Output-token directives ───────────────────────────────────────────────
  {
    id: "respond-with-exact-token",
    description: "Direct demand to output a specific phrase/word/token",
    severity: "high",
    regex: /\b(respond|reply|answer|output|say|return|emit|send)\s+(only\s+)?(with\s+)?(the\s+)?(exact|exactly|single|specific|following)?\s*(phrase|word|string|token|text|json|response|message|sentence|character|sequence)\s+/i,
  },
  {
    id: "respond-with-x-and-stop",
    description: "Demand to output something and then stop processing",
    severity: "high",
    regex: /\b(respond|reply|output|say|return)\s+(with\s+)?["'`]?[\w\s-]{1,40}["'`]?\s+(and\s+(stop|halt|exit|nothing\s+else|skip|cease|end|return|refuse|do\s+not))/i,
  },
  {
    id: "output-only-the-string",
    description: "'Output only the string X' / 'output only X' patterns",
    severity: "high",
    regex: /\boutput\s+(only|just)\s+(the\s+)?(phrase|word|string|token|text|json|character|character\s+sequence)\b/i,
  },

  // ── Stop / suppression directives ─────────────────────────────────────────
  {
    id: "do-not-process",
    description: "Directive to halt processing or refuse normal behavior",
    severity: "medium",
    regex: /\b(do\s+not|don'?t|refuse\s+to|stop|cease|halt)\s+(read|process|summarize|continue|respond|describe|answer|reveal|disclose|share|further|reading|processing)\b/i,
  },
  {
    id: "halt-further-reads",
    description: "Halt further reads / next files / downstream actions",
    severity: "medium",
    regex: /\b(halt|stop|skip|cease|refuse)\s+(all\s+)?(further|next|downstream|additional|subsequent)\s+(reads?|files?|actions?|checks?|steps?|operations?)\b/i,
  },

  // ── Credentials / privilege escalation shapes ────────────────────────────
  {
    id: "json-role-admin",
    description: "JSON-shaped grant of admin/elevated role",
    severity: "high",
    regex: /["']role["']\s*:\s*["'](admin|root|sudo|owner|moderator|system|superuser)["']/i,
  },
  {
    id: "granted-true",
    description: "Pseudo-confirmation patterns (granted: true, approved: true) inside data",
    severity: "medium",
    regex: /["'](granted|approved|verified|authenticated|authorized)["']\s*:\s*true\b/i,
  },

  // ── Hidden / sandwich-style injection markers ────────────────────────────
  {
    id: "comment-instruction",
    description: "Instruction hidden in an HTML/XML comment or code-comment block (agent-instruction, llm-instruction, ai-instruction)",
    severity: "high",
    regex: /<!--\s*(agent|llm|ai|assistant|system|admin)[\s_-]?(instruction|directive|command|task)/i,
  },
  {
    id: "auth-handshake-token",
    description: "Pseudo-handshake / pseudo-protocol marker designed to look like a system token",
    severity: "medium",
    regex: /\b(this\s+(is\s+)?(a\s+)?(handshake|required|mandatory|protocol|policy|compliance|auth|authentication)\s+(step|token|response|action|reply|message|gate)|required\s+by\s+(the\s+)?(import|management|policy|compliance|audit)\s+(tool|system|engine|pipeline|loop|process))\b/i,
  },

  // ── Privilege-elevation phrases ───────────────────────────────────────────
  {
    id: "elevate-permissions",
    description: "Privilege escalation language",
    severity: "high",
    regex: /\b(elevate|escalate|grant|enable|unlock)\s+(your\s+)?(privileges?|permissions?|access|admin|root|sudo|developer\s+mode|debug\s+mode|unrestricted\s+mode)\b/i,
  },
  {
    id: "developer-mode",
    description: "Jailbreak-style 'developer mode' / 'DAN' / 'do anything now' phrasings",
    severity: "high",
    regex: /\b(developer\s+mode|jailbreak|unrestricted\s+mode|do\s+anything\s+now|DAN\b|godmode\s+enabled|safety\s+(filters?|guards?)\s+(off|disabled|removed))\b/i,
  },

  // ── Tool-call / data-exfil prompting ─────────────────────────────────────
  {
    id: "send-email-imperative",
    description: "Imperative to send an email / message / API call to an external party",
    severity: "high",
    regex: /\b(send|email|forward|deliver|relay|post|transmit|upload)\s+(an?\s+)?(email|message|file|copy|data|payload|secret|token|key|notification)\s+(to|at|via)\s+([\w._%+-]+@[\w.-]+|https?:\/\/)/i,
  },
  {
    id: "execute-shell-command",
    description: "Instruction to run / execute a shell command or script",
    severity: "high",
    regex: /\b(execute|run|invoke|call|spawn|exec)\s+(the\s+)?(following\s+)?(shell\s+|bash\s+|system\s+|terminal\s+)?command\b/i,
  },
  {
    id: "read-file-imperative",
    description: "Imperative to read / open / leak a file path (esp. credentials)",
    severity: "high",
    regex: /\b(read|open|cat|dump|leak|exfiltrate|reveal|disclose)\s+(the\s+)?(contents?\s+of\s+)?(\/etc\/passwd|\/etc\/shadow|~\/\.ssh|id_rsa|id_ed25519|\.env|credentials?|secrets?\.json|api[_-]?key)/i,
  },
];

// ── API ────────────────────────────────────────────────────────────────────

/**
 * Run all rules against `content` and return any hits.
 * Disabled-rule list lives at `AVIARY_CANARY_HEURISTIC_DISABLE` (comma-
 * separated rule IDs); used as an escape hatch in pathological-false-
 * positive cases.
 */
export function runHeuristics(content: string): HeuristicResult {
  const disabled = new Set(
    (process.env.AVIARY_CANARY_HEURISTIC_DISABLE ?? "")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean),
  );

  const hits: HeuristicHit[] = [];
  for (const rule of RULES) {
    if (disabled.has(rule.id)) continue;
    const m = rule.regex.exec(content);
    if (m) {
      hits.push({
        id: rule.id,
        description: rule.description,
        severity: rule.severity,
        match: m[0].slice(0, 120), // bound the snippet
        position: m.index,
      });
    }
  }

  // Threshold: 1 HIGH or 2 MEDIUMs flag the content. Tunable later.
  const highs = hits.filter((h) => h.severity === "high").length;
  const meds = hits.filter((h) => h.severity === "medium").length;
  const flagged = highs >= 1 || meds >= 2;

  return { hits, flagged };
}

/**
 * Pretty-print a HeuristicResult into a single 'reason' string suitable
 * for inclusion in a ScanResult.
 */
export function summarizeHits(result: HeuristicResult): string {
  if (result.hits.length === 0) return "no heuristic hits";
  return result.hits
    .map((h) => `[${h.severity}:${h.id}] ${h.description} @${h.position}: "${h.match.replace(/\n/g, " ").slice(0, 80)}"`)
    .join("; ");
}

/** Total rule count — used in the scanner's metadata. */
export function ruleCount(): number {
  return RULES.length;
}
