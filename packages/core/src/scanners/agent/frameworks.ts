/**
 * Framework detection.
 *
 * Aegis adapts its analysis to the framework it finds: an AutoGen agent and a
 * Vercel AI SDK agent have different orchestration risks, different trust
 * boundaries, and different places where a human-in-the-loop gate belongs.
 * Detection is evidence-based (imports plus API usage) rather than a single
 * version string, because most repos do not pin the framework version anywhere
 * a scanner can read it.
 */
import type { Confidence, DetectedFramework } from '../../types.js';

interface FrameworkSignature {
  id: string;
  name: string;
  /** Import specifiers that indicate the framework is in use. */
  imports: RegExp[];
  /** API calls that confirm actual usage, not just a transitive dep. */
  usage: RegExp[];
  /** Languages this framework targets. */
  languages: string[];
}

export const FRAMEWORK_SIGNATURES: FrameworkSignature[] = [
  {
    id: 'langchain',
    name: 'LangChain',
    imports: [/from\s+langchain[\w.]*\s+import/i, /require\(['"]langchain/, /import\s+langchain/],
    usage: [/\b(LangChain|ChatOpenAI|ChatAnthropic|AgentExecutor|create_react_agent|LLMChain|RetrievalQA)\b/],
    languages: ['python', 'typescript', 'javascript'],
  },
  {
    id: 'langgraph',
    name: 'LangGraph',
    imports: [/from\s+langgraph[\w.]*\s+import/i, /require\(['"]langgraph/],
    usage: [/\b(StateGraph|MessageGraph|Graph|CompiledStateGraph|interrupt_before|checkpointer)\b/],
    languages: ['python', 'typescript'],
  },
  {
    id: 'llama-index',
    name: 'LlamaIndex',
    imports: [/from\s+llama_index[\w.]*\s+import/i, /require\(['"]llama_index/, /from\s+llama_index\s+import/],
    usage: [/\b(VectorStoreIndex|SimpleDirectoryReader|QueryEngineTool|ServiceContext|Document)\b/],
    languages: ['python', 'typescript'],
  },
  {
    id: 'crewai',
    name: 'CrewAI',
    imports: [/from\s+crewai[\w.]*\s+import/i, /require\(['"]crewai/, /import\s+crewai/],
    usage: [/\b(Crew|Agent\(|Task\(|Process\.|kickoff\(|SequentialProcess|HierarchicalProcess)\b/],
    languages: ['python'],
  },
  {
    id: 'autogen',
    name: 'AutoGen',
    imports: [/from\s+autogen[\w.]*\s+import/i, /require\(['"]autogen/, /import\s+autogen/],
    usage: [/\b(AssistantAgent|UserProxyAgent|GroupChat|GroupChatManager|ConversableAgent|register_reply)\b/],
    languages: ['python'],
  },
  {
    id: 'openai-agents',
    name: 'OpenAI Agents SDK',
    imports: [
      /from\s+agents[\w.]*\s+import/i,
      /require\(['"]agents/,
      /from\s+agents\s+import/,
      /from\s+['"]@openai\/agents/,
      /require\(['"]@openai\/agents/,
    ],
    usage: [
      /\bRunner\.run\b/,
      /\bfunction_tool\b/,
      /\b(?:input_)?guardrail\b/i,
      /\b(?:new\s+)?Agent\s*\([^)]*\b(?:model|instructions|tools)\s*=/i,
      /\bAgent\s*\(\s*name\s*=/,
      /\bhandoffs\b/,
    ],
    languages: ['python', 'typescript'],
  },
  {
    id: 'anthropic-sdk',
    name: 'Anthropic Claude SDK',
    imports: [/from\s+anthropic[\w.]*\s+import/i, /require\(['"]@anthropic-ai/, /new\s+Anthropic\(/],
    usage: [/\b(client|messages|anthropic)\.(messages\.)?create\(/i, /\btool_use\b|\btool_result\b/],
    languages: ['python', 'typescript', 'javascript'],
  },
  {
    id: 'vercel-ai-sdk',
    name: 'Vercel AI SDK',
    imports: [/from\s+['"]ai['"]/, /require\(['"]ai['"]/, /from\s+['"]ai\/react['"]/, /@ai-sdk\//],
    usage: [/\b(generateText|streamText|generateObject|streamObject|useChat|tool\(\s*\()/],
    languages: ['typescript', 'javascript', 'tsx'],
  },
  {
    id: 'mastra',
    name: 'Mastra',
    imports: [/from\s+['"]@mastra\//, /require\(['"]@mastra\//],
    usage: [/\b(new\s+Mastra|new\s+Agent\(|createWorkflow|registerTool)\b/],
    languages: ['typescript', 'tsx'],
  },
  {
    id: 'semantic-kernel',
    name: 'Microsoft Semantic Kernel',
    imports: [/from\s+semantic_kernel[\w.]*\s+import/i, /require\(['"]@azure\/ai/],
    usage: [/\b(Kernel\.|KernelFunction|KernelPlugin|AzureChatCompletion)\b/],
    languages: ['python', 'typescript'],
  },
  {
    id: 'haystack',
    name: 'Haystack',
    imports: [/from\s+haystack[\w.]*\s+import/i, /require\(['"]@haystack/],
    usage: [/\b(Pipeline|AutoRetriever|DocumentStore|AnswerBuilder)\b/],
    languages: ['python'],
  },
  {
    id: 'dspy',
    name: 'DSPy',
    imports: [/import\s+dspy\b/, /from\s+dspy[\w.]*\s+import/],
    usage: [/\b(dspy\.(Predict|ChainOfThought|Retrieve|ReAct)|\.compile\(\)|signature)\b/],
    languages: ['python'],
  },
  {
    id: 'pydantic-ai',
    name: 'Pydantic AI',
    imports: [/from\s+pydantic_ai[\w.]*\s+import/i, /require\(['"]pydantic_ai/],
    usage: [/\b(Agent\(|run\(|RunResult|ModelRetry|tools\()/],
    languages: ['python'],
  },
  {
    id: 'smolagents',
    name: 'smolagents',
    imports: [/from\s+smolagents[\w.]*\s+import/i, /require\(['"]smolagents/],
    usage: [/\b(CodeAgent|ToolCallingAgent|CodeExecutor|tool\b)/],
    languages: ['python'],
  },
  {
    id: 'google-adk',
    name: 'Google Agent Development Kit',
    imports: [/from\s+google\.adk[\w.]*\s+import/i, /from\s+google\.genai[\w.]*\s+import/],
    usage: [/\b(Agent\(|LlmAgent|SequentialAgent|Runner|adk\.)/],
    languages: ['python'],
  },
  {
    id: 'mcp-sdk',
    name: 'Model Context Protocol SDK',
    imports: [/@modelcontextprotocol\/sdk/, /from\s+mcp[\w.]*\s+import/, /require\(['"]@modelcontextprotocol/],
    usage: [/\b(McpServer|Server\(|StdioServerTransport|StreamableHTTPServerTransport|setRequestHandler)\b/],
    languages: ['typescript', 'javascript', 'python'],
  },
  {
    id: 'autogen-studio',
    name: 'OpenAI Assistants / Swarm',
    imports: [/from\s+swarm\s+import/, /require\(['"]swarm['"]/, /openai\.beta\.threads/],
    usage: [/\b(Swarm|Function\(|client\.beta\.threads\.create|assistants\.create)\b/],
    languages: ['python', 'typescript'],
  },
];

export interface DetectionInput {
  path: string;
  content: string;
  language: string;
}

/**
 * Detect which agent frameworks a codebase uses.
 *
 * A framework is only reported when an *import* and at least one *API usage*
 * both appear, which filters out transitive dependencies that happen to be in
 * the lockfile. Confidence reflects how much corroborating evidence was found.
 */
export function detectFrameworks(files: readonly DetectionInput[]): DetectedFramework[] {
  const evidence = new Map<string, string[]>();
  const fileCounts = new Map<string, Set<string>>();

  for (const file of files) {
    for (const signature of FRAMEWORK_SIGNATURES) {
      if (!signature.languages.includes(file.language)) continue;
      const imported = signature.imports.some((re) => re.test(file.content));
      if (!imported) continue;

      const bucket = evidence.get(signature.id) ?? [];
      if (signature.usage.some((re) => re.test(file.content))) {
        const line = firstMatchLine(file.content, signature.usage);
        bucket.push(`${file.path}:${line} (import + usage)`);
      } else {
        bucket.push(`${file.path} (import only)`);
      }
      evidence.set(signature.id, bucket);
      fileCounts.set(signature.id, (fileCounts.get(signature.id) ?? new Set()).add(file.path));
    }
  }

  const out: DetectedFramework[] = [];
  for (const signature of FRAMEWORK_SIGNATURES) {
    const found = evidence.get(signature.id);
    if (!found || found.length === 0) continue;
    const strong = found.filter((e) => e.includes('import + usage')).length;
    const confidence: Confidence = strong >= 2 ? 'confirmed' : strong === 1 ? 'high' : 'medium';
    const versions = collectVersions(files, signature.id);
    out.push({
      id: signature.id,
      name: signature.name,
      ...(versions[0] ? { version: versions[0] } : {}),
      evidence: found.slice(0, 5),
      confidence,
      fileCount: fileCounts.get(signature.id)?.size ?? 0,
    });
  }

  return out.sort((a, b) => b.evidence.length - a.evidence.length);
}

function firstMatchLine(content: string, patterns: RegExp[]): number {
  let best = Number.MAX_SAFE_INTEGER;
  for (const pattern of patterns) {
    const re = new RegExp(pattern.source, pattern.flags.includes('g') ? pattern.flags : `${pattern.flags}g`);
    const match = re.exec(content);
    if (match) best = Math.min(best, content.slice(0, match.index).split('\n').length);
  }
  return best === Number.MAX_SAFE_INTEGER ? 1 : best;
}

function collectVersions(files: readonly DetectionInput[], frameworkId: string): string[] {
  const versions = new Set<string>();
  const manifestPattern = /["']([\w@.\-/@]+)["']\s*:\s*["']?[\^~]?(\d+\.\d+\.\d+)/g;
  for (const file of files) {
    if (!/package\.json$|requirements.*\.txt$|pyproject\.toml$/i.test(file.path)) continue;
    manifestPattern.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = manifestPattern.exec(file.content)) !== null) {
      if (m[1]!.toLowerCase().includes(frameworkId.split('-')[0]!.toLowerCase())) {
        versions.add(m[2]!);
      }
    }
  }
  return [...versions];
}

/** Trust-boundary descriptions keyed by framework, used by the threat model. */
export const FRAMEWORK_TRUST_MODEL: Record<string, { trustBoundaries: string[]; risks: string[] }> = {
  langchain: {
    trustBoundaries: ['user input → prompt', 'retrieved documents → context', 'tool output → agent loop'],
    risks: ['arbitrary code in custom tools', 'RAG context poisoning', 'unbounded agent iterations'],
  },
  langgraph: {
    trustBoundaries: ['checkpoint state → resume', 'inter-node state', 'interrupt boundary'],
    risks: ['state poisoning across checkpoints', 'resume-time privilege escalation'],
  },
  'llama-index': {
    trustBoundaries: ['document reader → index', 'retriever → synthesizer'],
    risks: ['document-level prompt injection at ingestion', 'code-execution query engine'],
  },
  crewai: {
    trustBoundaries: ['task description → agent', 'agent → agent handoff', 'delegation authority'],
    risks: ['agent delegation without approval', 'shared memory across agents'],
  },
  autogen: {
    trustBoundaries: ['user proxy → group chat', 'agent → group chat', 'group chat → termination'],
    risks: ['prompt injection through conversation', 'auto-reply loops'],
  },
  'openai-agents': {
    trustBoundaries: ['handoff → next agent', 'tool result → agent', 'guardrail boundary'],
    risks: ['unbounded handoff chains', 'guardrail bypass via tool output'],
  },
  'anthropic-sdk': {
    trustBoundaries: ['user turn → assistant turn', 'tool_use → tool_result', 'system prompt → all turns'],
    risks: ['tool result trust', 'system prompt leakage', 'context overflow'],
  },
  'vercel-ai-sdk': {
    trustBoundaries: ['user message → model', 'tool call → tool result'],
    risks: ['tool argument injection', 'streamed output rendered unsafely'],
  },
  mastra: {
    trustBoundaries: ['workflow step → step', 'memory → context'],
    risks: ['workflow state injection', 'memory poisoning'],
  },
  'mcp-sdk': {
    trustBoundaries: ['client → server tools', 'tool description → model', 'server resources → context'],
    risks: ['tool poisoning', 'credential exposure to servers', 'prompt injection via resources'],
  },
};