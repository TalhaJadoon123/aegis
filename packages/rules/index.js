/**
 * @aegis/rules — rule pack index.
 *
 * Static data package. The engine (@aegis/core) loads these files at runtime
 * rather than importing them, so users can point `--rules` at their own fork.
 */
import { readdirSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));

/** Directory containing the shipped YAML packs. */
export const RULES_DIR = join(here, 'rules');

/** Pack ids shipped with Aegis, in load order. */
export const PACK_IDS = Object.freeze([
  'owasp-agentic-top10',
  'mcp-security',
  'prompt-injection',
  'supply-chain',
  'secrets',
  'general-code-security',
]);

/** Absolute path of a pack file by id. */
export function packPath(id) {
  return join(RULES_DIR, `${id}.yaml`);
}

/** Every shipped pack file path. */
export function listPackFiles() {
  if (!existsSync(RULES_DIR)) return [];
  return readdirSync(RULES_DIR)
    .filter((f) => f.endsWith('.yaml') || f.endsWith('.yml'))
    .map((f) => join(RULES_DIR, f));
}

export default { RULES_DIR, PACK_IDS, packPath, listPackFiles };
