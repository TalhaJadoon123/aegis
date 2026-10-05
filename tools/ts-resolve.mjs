import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const EXTENSION_FALLBACKS = ['.ts', '.mts', '.cts', '.tsx'];

/**
 * If a relative `.js` specifier cannot be resolved, try the TypeScript source
 * that `tsc` would have compiled it from.
 */
export async function resolve(specifier, context, nextResolve) {
  try {
    return await nextResolve(specifier, context);
  } catch (error) {
    if (!specifier.startsWith('.') && !specifier.startsWith('/')) throw error;

    const candidates = specifier.endsWith('.js')
      ? [`${specifier.slice(0, -3)}.ts`, `${specifier.slice(0, -3)}.tsx`]
      : EXTENSION_FALLBACKS.map((ext) => `${specifier}${ext}`);

    for (const candidate of candidates) {
      try {
        const url = new URL(candidate, context.parentURL);
        if (existsSync(fileURLToPath(url))) {
          return await nextResolve(candidate, context);
        }
      } catch {
        // Try the next candidate.
      }
    }
    throw error;
  }
}