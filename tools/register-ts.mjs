/**
 * ESM resolve hook: TypeScript sources use `.js` specifiers (required for a
 * `tsc` build), but Node runs the `.ts` files directly via native type
 * stripping. This hook bridges the two so tests need no build step.
 *
 * Usage: node --import ./tools/register-ts.mjs --test packages/core/test/*.test.ts
 */
import { register } from 'node:module';

register('./ts-resolve.mjs', import.meta.url);