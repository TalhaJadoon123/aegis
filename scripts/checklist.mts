/**
 * Spec Kit Checklist Runner
 *
 * Runs all declarative checklists for Spec Kit compliance.
 * Exits with non-zero code if any checklist item is unchecked.
 */

import { readFileSync, existsSync, readdirSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(here, '..');

interface ChecklistItem {
  text: string;
  checked: boolean;
  required: boolean;
}

interface ChecklistResult {
  spec: string;
  total: number;
  passed: number;
  failed: number;
  items: ChecklistItem[];
}

function parseChecklist(filePath: string): ChecklistItem[] {
  const content = readFileSync(filePath, 'utf8');
  const lines = content.split('\n');
  const items: ChecklistItem[] = [];

  for (const line of lines) {
    const match = line.match(/^[-*]\s+\[([ x])\]\s*(.+)/);
    if (match) {
      items.push({
        checked: match[1] === 'x',
        text: match[2].trim(),
        required: !match[2].includes('[optional]') && !match[2].includes('[P2]'),
      });
    }
  }
  return items;
}

function runChecklist(specDir: string): ChecklistResult {
  const checklistPath = join(specDir, 'checklist.md');
  if (!existsSync(checklistPath)) {
    return {
      spec: specDir,
      total: 0,
      passed: 0,
      failed: 0,
      items: [],
    };
  }

  const items = parseChecklist(checklistPath);
  const passed = items.filter((i) => i.checked).length;
  const failed = items.filter((i) => !i.checked && i.required).length;

  return {
    spec: specDir,
    total: items.length,
    passed,
    failed,
    items,
  };
}

function main() {
  const specsDir = join(ROOT, 'specs');
  if (!existsSync(specsDir)) {
    console.error('No specs directory found');
    process.exit(1);
  }

  const specDirs = readdirSync(specsDir, { withFileTypes: true })
    .filter((d) => d.isDirectory())
    .map((d) => join(specsDir, d.name));

  const results: ChecklistResult[] = [];
  let totalRequired = 0;
  let totalPassed = 0;

  for (const specDir of specDirs) {
    const result = runChecklist(specDir);
    results.push(result);

    const requiredItems = result.items.filter((i) => i.required);
    totalRequired += requiredItems.length;
    totalPassed += requiredItems.filter((i) => i.checked).length;

    console.log(`\n📋 ${result.spec}: ${result.passed}/${result.total} passed`);
    if (result.failed > 0) {
      console.log(`   ❌ ${result.failed} required items failed:`);
      for (const item of result.items) {
        if (!item.checked && item.required) {
          console.log(`   - [ ] ${item.text}`);
        }
      }
    }
  }

  console.log('\n' + '='.repeat(60));
  console.log(`SUMMARY: ${totalPassed}/${totalRequired} required checks passed`);

  if (totalPassed < totalRequired) {
    console.log('❌ SPEC KIT CHECKLIST FAILED');
    process.exit(1);
  } else {
    console.log('✅ SPEC KIT CHECKLIST PASSED');
    process.exit(0);
  }
}

main();