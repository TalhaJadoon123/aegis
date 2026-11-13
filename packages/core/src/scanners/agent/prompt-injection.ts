import type { Finding, Severity } from '../../types.js';

/**
 * Static prompt-injection analysis.
 *
 * Two surfaces matter in an agent codebase:
 *
 *  - **Instructions**: system prompts and templates. Injection here changes
 *    the agent's goals for the rest of the session.
 *  - **Untrusted data**: anything that becomes part of a prompt later — tool
 *    output, retrieved documents, file contents, API responses. Injection here
 *    is *indirect*, and is far harder to prevent than direct injection because
 *    the attacker is not the user.
 *
 * The analyzer scores both, and reports the structural defect (no separation
 * between instruction and data) rather than trying to judge the semantics of
 * an English sentence.
 */

export interface InjectionSignal {
  id: string;
  title: string;
  severity: Severity;
  confidence: Finding['confidence'];
  description: string;
  evidence: string;
  line: number;
  remediation: string;
  compliance: Finding['compliance'];
}

interface SignalDefinition {
  id: string;
  title: string;
  severity: Severity;
  confidence: Finding['confidence'];
  /** How much evidence to require before reporting. */
  threshold: number;
  patterns: RegExp[];
  description: string;
  remediation: string;
  compliance: Finding['compliance'];
}

const CONTROL_MAPPINGS = {
  owasp: { framework: 'owasp-agentic', control: 'ASI01', title: 'Agent Goal Hijacking', relevant: true },
  output: { framework: 'owasp-agentic', control: 'ASI07', title: 'Insecure Inter-Agent Communication', relevant: true },
  atlas: { framework: 'mitre-atlas', control: 'AML.T0051', title: 'LLM Prompt Injection', relevant: true },
  eu: { framework: 'eu-ai-act', control: 'Art. 15', title: 'Accuracy, robustness and cybersecurity', relevant: true },
} as const;

const SIGNAL_DEFINITIONS: SignalDefinition[] = [
  {
    id: 'injection-jailbreak-scaffold',
    title: 'Prompt contains jailbreak or manipulation language',
    severity: 'high',
    confidence: 'high',
    threshold: 1,
    description:
      'The prompt text contains instructions that try to disable the model\'s safety behaviour or ' +
      'reassign its identity. Legitimate application prompts should never need these. When present in a ' +
      'shipped agent they either weaken the production model or indicate a red-team harness left in place.',
    patterns: [
      /\b(?:ignore|disregard|forget|override)\s+(?:all\s+)?(?:previous|prior|above|earlier|preceding)\s+(?:instructions?|prompts?|rules?|context)\b/i,
      /\byou\s+are\s+(?:now\s+)?(?:DAN|dan)\b/,
      /\bdo\s+anything\s+now\b/i,
      /\b(?:developer|debug|god|sudo|unrestricted|unfiltered)\s+mode\b/i,
      /\bpretend\s+(?:you\s+are|to\s+be|that\s+you)\s+(?:an?\s+)?(?:unrestricted|unfiltered|uncensored|amoral|without\s+restrictions)\b/i,
      /\b(?:bypass|circumvent|disable|turn\s+off|remove)\s+(?:your\s+|all\s+|the\s+)?(?:safety|security|guardrails?|content\s+polic\w+|restrictions?|filters?|guidelines?)\b/i,
      /\bthere\s+are\s+no\s+(?:restrictions|rules|limits|guidelines)\s+(?:that\s+apply\s+to\s+you|for\s+you)\b/i,
      /^\s*\[?(?:system|inst)\]?\s*[:>]/im,
    ],
    remediation:
      'Remove the manipulation language from the shipped prompt. If this is a deliberate safety test, move it ' +
      'to a clearly-marked red-team fixture outside the production bundle. A prompt that disables guardrails ' +
      'in production is an OWASP Agentic ASI09 finding regardless of intent.',
    compliance: [CONTROL_MAPPINGS.owasp as never, CONTROL_MAPPINGS.eu as never],
  },
  {
    id: 'injection-hidden-instruction',
    title: 'Prompt contains hidden or zero-width instruction text',
    severity: 'critical',
    confidence: 'high',
    threshold: 1,
    description:
      'The prompt contains invisible characters used to smuggle instructions past human review. The model ' +
      'reads the full text; a reviewer looking at the rendered prompt does not. This is an attack signature, ' +
      'not a formatting quirk.',
    patterns: [
      // Zero-width and bidi-control characters. Written as escapes because the
      // literal characters are invisible — and unreviewable — in a source file.
      /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF]/,
      /<\s*(?:system|assistant|user)\s*>[\s\S]{0,80}?<\s*\/\s*(?:system|assistant|user)\s*>/i,
      /\[(?:INST|\/INST|SYS|SYSTEM)\]/i,
      /```(?:system|instruction)[\s\S]{0,40}?```/i,
      /\bBEGIN\s+SYSTEM\s+(?:PROMPT|INSTRUCTIONS)\b/i,
    ],
    remediation:
      'Strip zero-width and bidi-control characters from all prompt inputs, and strip role-tag markup from ' +
      'untrusted content before it enters the context. Reject rather than silently clean, so the attempt is ' +
      'auditable.',
    compliance: [CONTROL_MAPPINGS.owasp as never, CONTROL_MAPPINGS.atlas as never],
  },
  {
    id: 'injection-unseparated-data',
    title: 'Untrusted input concatenated into the instruction layer',
    severity: 'high',
    confidence: 'high',
    threshold: 2,
    description:
      'User-controlled or externally-sourced text is interpolated into a system/instruction string with no ' +
      'delimiter. Anyone who controls any fragment of the prompt can restate the agent\'s instructions and ' +
      'Aegis treats that as goal hijacking.',
    patterns: [
      /(?:system_prompt|systemPrompt|system_message|SYSTEM_PROMPT|instructions)\s*(?:\+=|=)\s*f?["'`][^"'`]*\{/i,
      /(?:prompt|instructions)\s*=\s*f?["'`][^"'`]*\{(?:user_input|user_query|request|query|input|message|body|content|args|question)\b/i,
      /(?:system_prompt|systemPrompt)\s*=\s*(?:f?["'`][^"'`]*["'`]\s*\+\s*(?:user|input|request|body|params))/i,
      /\.format\(\s*(?:user_input|user_query|request|body|input)\b/,
      /\{\{\s*(?:user_input|user_query|user_message|request\.(?:body|query)|args)\s*\}\}/,
    ],
    remediation:
      'Move untrusted content out of the instruction layer entirely: pass it as a separate message or a ' +
      'delimited data block, state explicitly that the block is data and not instructions, and re-assert the ' +
      'goal after the block.',
    compliance: [CONTROL_MAPPINGS.owasp as never, CONTROL_MAPPINGS.eu as never],
  },
  {
    id: 'injection-indirect-surface',
    title: 'Retrieved or fetched content injected into context without boundaries',
    severity: 'high',
    confidence: 'medium',
    threshold: 2,
    description:
      'Content from an external source (documents, web pages, tool output, API responses) is placed into the ' +
      'agent context with no provenance marker and no instruction/data separation. If any upstream user can ' +
      'influence that content, they control the agent.',
    patterns: [
      // A variable named for retrieved content being assembled into a string.
      /\b(?:context|documents?|chunks?|retrieved|passages?|results?|sources?|corpus)\b\s*(?:\+?=|:\s*\w+\s*=)[^;\n]{0,80}\b(?:join|append|extend|concat)\b/i,
      /\bcontext\s*=\s*["']{0,2}\s*\)?\.?join\s*\(/i,
      /\b(?:documents?|chunks?|passages?|results?)\s*:\s*str\s*=\s*["'][^"']*["']\s*\.join\s*\(/i,
      // Retrieved content flowing into a prompt or message list.
      /(?:prompt|messages|system_prompt|systemPrompt|instructions)\s*(?:\+=|=)[^;\n]{0,200}\b(?:retrieved|documents?|context|chunks?|results?|corpus|passages?)\b/i,
      /\b(?:retrieved|documents?|context|chunks?|results?)\b[^;\n]{0,120}(?:prompt|messages)\s*(?:\+=|=|\.append)/i,
      // A web/document fetch whose output reaches the prompt.
      /(?:\bfetch|requests\.get|urlopen|axios\.get|httpx\.get|WebClient)[\s\S]{0,240}?(?:prompt|messages|context)\s*(?:\+=|=|\.append)/,
      /\b(?:browse|scrape|crawl|read_url|fetch_url|web_fetch|websearch|search_web)\s*\(/i,
    ],
    remediation:
      'Wrap every retrieved chunk in a delimited block carrying its provenance, cap its length, strip active ' +
      'content, and instruct the model that content inside the block is to be analysed, never obeyed.',
    compliance: [CONTROL_MAPPINGS.owasp as never, CONTROL_MAPPINGS.atlas as never],
  },
  {
    id: 'injection-output-trust',
    title: 'Model or tool output promoted to an instruction context',
    severity: 'high',
    confidence: 'medium',
    threshold: 1,
    description:
      'A model response or tool result is inserted into a system/developer role, or forwarded to another ' +
      'agent as instructions. One compromised hop launders the injection into every downstream consumer.',
    patterns: [
      /role\s*[:=]\s*["']?(?:system|developer)["']?[^)\n]{0,100}(?:tool_result|tool_response|tool_output|function_response|mcp_result|completion|response)/i,
      /(?:next_agent|sub_agent|handoff|delegate|forward)\s*\(\s*(?:response|resp|result|completion|agent_response|output)\b/i,
      /(?:system_prompt|systemPrompt|instructions)\s*(?:\+=|=)[^;\n]*(?:response|resp|completion|tool_result|agent_output)\b/i,
    ],
    remediation:
      'Deliver tool and agent results in a data role with an explicit untrusted marker. Never let one agent\'s ' +
      'output become another agent\'s instructions — re-assert a fixed system prompt at every hop.',
    compliance: [CONTROL_MAPPINGS.output as never, CONTROL_MAPPINGS.atlas as never],
  },
  {
    id: 'injection-prompt-leak',
    title: 'Prompt exposes its own instructions at runtime',
    severity: 'medium',
    confidence: 'medium',
    threshold: 1,
    description:
      'The code can be induced to reveal the system prompt verbatim to the end user. System prompt leakage ' +
      'is usually treated as cosmetic, but in an agent system the prompt typically carries tool policies, ' +
      'internal identifiers, and occasionally credentials.',
    patterns: [
      /(?:print|return|log|send|respond_with)\s*\([^)\n]{0,80}(?:system_prompt|systemPrompt|SYSTEM_PROMPT)\b/i,
      /(?:reveal|repeat|print|show|display|tell\s+me)\s+(?:me\s+)?(?:your\s+)?(?:system\s+)?(?:prompt|instructions)\b/i,
      /\[\[:\s*system\s*\]\]/i,
    ],
    remediation:
      'Refuse requests to disclose the system prompt, and design the prompt so that leaking it is not ' +
      'recoverable: no secrets, no internal endpoints, and policy expressed as behaviour rather than as a ' +
      'copyable configuration.',
    compliance: [CONTROL_MAPPINGS.owasp as never],
  },
  {
    id: 'injection-memory-write',
    title: 'Untrusted content written to agent memory',
    severity: 'high',
    confidence: 'medium',
    threshold: 1,
    description:
      'User or tool content is persisted into agent memory or a vector store without sanitisation. Poisoned ' +
      'memory re-injects on every subsequent turn, so a single successful injection persists for the life of ' +
      'the session — or the index.',
    patterns: [
      /(?:memory|vectorstore|vector_store|chroma|qdrant|faiss|pinecone|weaviate)\s*\.\s*(?:add|upsert|insert|add_texts|add_documents|add_embedding)\s*\([^)\n]{0,120}(?:user|input|content|response|completion|message|llm|result)/i,
      /(?:save_memory|add_to_memory|remember|store_memory|write_memory|update_memory)\s*\(\s*(?:user|input|content|response|completion|message|llm|result)/i,
      /(?:messages|history)\s*\.\s*(?:push|append)\s*\(\s*\{\s*["']?role["']?\s*:\s*["']system/i,
    ],
    remediation:
      'Never let user or tool content enter the instruction tier of memory. Tag each memory entry with source ' +
      'and trust level, reject instruction-shaped content, and give the operator a way to inspect and purge ' +
      'the store.',
    compliance: [
      { framework: 'owasp-agentic', control: 'ASI06', title: 'Memory and Context Poisoning', relevant: true },
      CONTROL_MAPPINGS.owasp as never,
    ],
  },
];

export interface PromptAnalysisInput {
  path: string;
  content: string;
  /**
   * Analyse the content regardless of the path's extension. Used when the
   * "file" is really a string being piped in from an MCP schema or a runtime
   * transcript rather than a source file on disk.
   */
  skipPathFilter?: boolean;
}

/**
 * Tool-poisoning signals.
 *
 * Kept separate from the prompt-file signals because MCP tool descriptions have
 * a distinct vocabulary: they instruct the model about *tool ordering* and
 * *concealment*, which never appear in a legitimate application prompt because
 * an application has no reason to tell the model to lie to its user.
 */
const TOOL_POISONING_SIGNALS: Array<{ pattern: RegExp; note: string }> = [
  {
    pattern: /\bbefore\s+(?:using|calling|invoking)\s+(?:any\s+)?(?:other|another|this)\s+tool\b/i,
    note: 'prescribes tool ordering',
  },
  {
    pattern: /\b(?:always|must|first)\s+(?:call|invoke|use|run)\s+this\s+(?:tool\s+)?(?:first|before)\b/i,
    note: 'demands to be called first',
  },
  {
    pattern: /\b(?:do|don'?t|never)\s+(?:not\s+)?(?:tell|inform|notify|mention|reveal|disclose|show)\s+(?:the\s+)?(?:user|human|operator|anyone)\b/i,
    note: 'instructs concealment from the user',
  },
  {
    // Require the concealment to be directed at an action or an audience. A
    // bare "silently" matches ordinary prose in any code comment.
    pattern:
      /\b(?:secretly|silently|covertly)\s+(?:do|execute|perform|run|send|append|call|include|add|forward|report|leak|exfiltrate)\b|\bwithout\s+(?:telling|informing|notifying|asking|logging|recording)\b/i,
    note: 'requests covert operation',
  },
  {
    pattern: /\b(?:ignore|disregard|forget|override)\s+(?:all\s+)?(?:previous|prior|above|earlier|other|any)\s+(?:instructions?|prompts?|rules?|tool\s+descriptions?)\b/i,
    note: 'attempts to override instructions',
  },
  {
    pattern: /\b(?:read|include|send|append|copy|upload|exfiltrate|leak)\b[^.]{0,60}(?:\.env|id_rsa|\.ssh|credentials?|api[_\s-]?key|token|\/etc\/passwd|private\s+key)/i,
    note: 'coerces reading or sending credential material',
  },
  {
    pattern: /\b(?:include|append|send|include)\b[^.]{0,40}(?:contents?|value|result)\b[^.]{0,40}\bin\s+(?:your|the)\s+(?:response|answer|reply)\b/i,
    note: 'coerces disclosure into the response',
  },
  {
    pattern: /\bthis\s+(?:tool|server)\s+is\s+(?:required|mandatory|essential)\b/i,
    note: 'claims to be mandatory',
  },
  {
    pattern: /(?:^|\n)\s*(?:SYSTEM|IMPORTANT|CRITICAL|!!!)\s*[:!]/i,
    note: 'uses an attention-grabbing pseudo-header',
  },
];

/**
 * Detect tool-poisoning language in an MCP tool (or resource/prompt) description.
 *
 * Returns one note per distinct technique, because knowing *how* a description
 * is poisoned is what tells a reviewer whether this is a sloppy description or
 * a deliberate attack.
 */
export function analyzeToolPoisoning(text: string): Array<{ note: string; match: string }> {
  const out: Array<{ note: string; match: string }> = [];
  for (const signal of TOOL_POISONING_SIGNALS) {
    const m = new RegExp(signal.pattern.source, signal.pattern.flags.replace('g', '')).exec(text);
    if (m) out.push({ note: signal.note, match: m[0].slice(0, 160) });
  }
  return out;
}

/** Languages where prompting constructs are meaningful. */
const PROMPT_LANGUAGES = /(?:\.ts|\.tsx|\.js|\.jsx|\.mjs|\.py|\.md|\.mdx|\.txt|\.prompt|\.jinja|\.j2|\.ya?ml)$/i;

export function analyzePromptInjection(
  input: PromptAnalysisInput,
): InjectionSignal[] {
  const { path, content } = input;
  if (!input.skipPathFilter && !PROMPT_LANGUAGES.test(path)) return [];
  // Skip lockfiles and generated bundles: they are noise, not attack surface.
  if (/(?:package-lock\.json|pnpm-lock\.yaml|yarn\.lock|\.min\.js|bundle\.js)$/i.test(path)) return [];

  const out: InjectionSignal[] = [];
  const lower = content;

  for (const def of SIGNAL_DEFINITIONS) {
    const hits: Array<{ pattern: RegExp; line: number; text: string }> = [];
    for (const pattern of def.patterns) {
      const re = new RegExp(pattern.source, pattern.flags.includes('g') ? pattern.flags : `${pattern.flags}g`);
      let m: RegExpExecArray | null;
      while ((m = re.exec(content)) !== null) {
        const line = content.slice(0, m.index).split('\n').length;
        hits.push({
          pattern,
          line,
          text: content.split('\n')[line - 1]?.trim().slice(0, 200) ?? '',
        });
        if (hits.length > 8) break;
      }
      if (hits.length > 8) break;
    }

    if (hits.length < def.threshold) continue;

    // The hidden-instruction signal is critical on its own; the rest need
    // corroboration, which the threshold already encodes.
    const first = hits[0]!;
    out.push({
      id: def.id,
      title: def.title,
      severity: def.severity,
      confidence: def.confidence,
      description: def.description,
      evidence: `${first.text}\n    // matched ${hits.length} signal(s): ${hits
        .slice(0, 4)
        .map((h) => `L${h.line}`)
        .join(', ')}`,
      line: first.line,
      remediation: def.remediation,
      compliance: def.compliance as Finding['compliance'],
    });
  }

  void lower;
  return out;
}

export function signalsToFindings(
  path: string,
  signals: readonly InjectionSignal[],
  source = 'agent',
): Finding[] {
  return signals.map((signal) => ({
    id: `AEGIS-${signal.id}.${path}:${signal.line}`,
    ruleId: `AEGIS-PI-${signal.id}`,
    title: signal.title,
    description: signal.description,
    severity: signal.severity,
    confidence: signal.confidence,
    location: { file: path, line: signal.line },
    evidence: signal.evidence,
    remediation: { title: signal.title, description: signal.remediation, automated: false, effort: 'medium' as const },
    compliance: signal.compliance,
    source,
    cwe: 'CWE-1427',
    tags: ['prompt-injection', signal.id],
    fingerprint: `pi:${signal.id}:${path}`,
    createdAt: new Date().toISOString(),
  }));
}

/**
 * Check a specific string (an MCP tool description, a retrieved chunk) rather
 * than a source file. Used by the MCP scanner and the red-team engine.
 */
export function analyzeUntrustedText(
  text: string,
  context: { path: string; line?: number; severity?: Severity },
): Finding[] {
  // MCP tool descriptions, resource metadata and prompt templates are analysed
  // as free text, not as a file. The `analyzePromptInjection` file filter only
  // admits prompt-shaped paths (`prompts/x.md`, `agent.ts`), so the check is
  // bypassed here and the signals run directly against the text.
  const signals = analyzePromptInjection({
    path: 'mcp://tool-description',
    content: text,
    skipPathFilter: true,
  });
  return signalsToFindings(context.path, signals, 'mcp').map((f) => ({
    ...f,
    severity: context.severity ?? f.severity,
    location: { file: context.path, line: context.line ?? 1 },
  }));
}