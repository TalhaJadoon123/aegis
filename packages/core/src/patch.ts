/**
 * Minimal unified-diff application.
 *
 * Aegis only ever emits diffs it generated itself, so this handles the narrow
 * case of contiguous single-hunk replacements. It deliberately refuses anything
 * ambiguous rather than guessing — a patch tool that silently applies the wrong
 * hunk is a supply-chain attack on your codebase.
 */

export interface FileEdit {
  path: string;
  /** Exact text to find. Must be unique in the file. */
  find: string;
  /** Replacement text. */
  replace: string;
  /** Require exactly one occurrence. Default true. */
  unique?: boolean;
}

export interface EditResult {
  ok: boolean;
  path: string;
  applied: boolean;
  reason?: string;
}

export function applyEdits(content: string, edits: readonly FileEdit[]): { content: string; results: EditResult[] } {
  let next = content;
  const results: EditResult[] = [];

  for (const edit of edits) {
    const count = countOccurrences(next, edit.find);
    if (count === 0) {
      results.push({ ok: false, path: edit.path, applied: false, reason: 'target text not found' });
      continue;
    }
    if (edit.unique !== false && count > 1) {
      results.push({
        ok: false,
        path: edit.path,
        applied: false,
        reason: `target text appears ${count} times; refusing to guess which one to change`,
      });
      continue;
    }
    if (edit.unique === false) {
      next = next.split(edit.find).join(edit.replace);
    } else {
      next = next.replace(edit.find, edit.replace);
    }
    results.push({ ok: true, path: edit.path, applied: true });
  }

  return { content: next, results };
}

export function countOccurrences(haystack: string, needle: string): number {
  if (needle === '') return 0;
  let count = 0;
  let index = haystack.indexOf(needle);
  while (index !== -1) {
    count++;
    index = haystack.indexOf(needle, index + needle.length);
  }
  return count;
}

/** Parse an Aegis-generated unified diff back into edits. */
export function parseUnifiedDiff(diff: string): Array<{ path: string; before: string; after: string }> {
  const lines = diff.split('\n');
  const out: Array<{ path: string; before: string; after: string }> = [];
  let path = '';
  let before: string[] = [];
  let after: string[] = [];
  let inHunk = false;

  const flush = () => {
    if (inHunk && path) out.push({ path, before: before.join('\n'), after: after.join('\n') });
    before = [];
    after = [];
    inHunk = false;
  };

  for (const line of lines) {
    if (line.startsWith('--- ')) {
      flush();
      continue;
    }
    if (line.startsWith('+++ ')) {
      path = line.slice(4).replace(/^b\//, '');
      continue;
    }
    if (line.startsWith('@@')) {
      inHunk = true;
      continue;
    }
    if (!inHunk) continue;
    if (line.startsWith('-')) before.push(line.slice(1));
    else if (line.startsWith('+')) after.push(line.slice(1));
  }
  flush();
  return out;
}